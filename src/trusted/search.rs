//! Searching the delegation graph for a target (5.6.7).

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::metadata::{FileVerifier, RoleType, TargetFile, Targets};

/// A target file found by a [`TargetSearch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    /// The target path.
    pub path: String,
    /// The role whose metadata lists the target.
    pub role: String,
    /// The trusted length, hashes and custom data of the target.
    pub file: TargetFile,
}

impl TargetInfo {
    /// Checks downloaded target data against its trusted length and hashes.
    pub fn verify(&self, data: &[u8]) -> crate::Result<()> {
        self.file.verify(&self.path, data)
    }

    /// Whether the file at `path` is this target, e.g. a previous download
    /// that need not be repeated.
    pub fn matches_file(&self, path: &Path) -> io::Result<bool> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let Ok(mut verifier) = FileVerifier::for_target(&self.path, &self.file) else {
            return Ok(false);
        };
        let mut chunk = vec![0; 64 * 1024];
        loop {
            let len = file.read(&mut chunk)?;
            if len == 0 {
                return Ok(verifier.finish().is_ok());
            }
            if verifier.update(&chunk[..len]).is_err() {
                return Ok(false);
            }
        }
    }
}

/// The next role a [`TargetSearch`] needs: the metadata of `role`, verified
/// with the keys `delegator` delegates to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchStep {
    pub role: String,
    pub delegator: String,
}

/// A pre-order depth-first search of the delegation graph for a target path,
/// independent of how metadata is obtained.
///
/// The search starts at the top-level targets role. Each role's delegations
/// that are trusted for the path are explored in order of priority, and a
/// matching terminating delegation cuts off all delegations of lower
/// priority. Roles are visited at most once, so cycles are harmless.
///
/// ```
/// # use rftuf::metadata::Targets;
/// # use rftuf::trusted::{TargetInfo, TargetSearch};
/// # fn load(role: &str, delegator: &str) -> Targets { unimplemented!() }
/// fn find(path: &str) -> Option<TargetInfo> {
///     let mut search = TargetSearch::new(path, 32);
///     while let Some(step) = search.next_step() {
///         let targets = load(&step.role, &step.delegator);
///         if let Some(found) = search.visit(&step, &targets) {
///             return Some(found);
///         }
///     }
///     None
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TargetSearch {
    path: String,
    /// Roles still to visit; the last one is next.
    pending: Vec<SearchStep>,
    visited: HashSet<String>,
    remaining: usize,
}

impl TargetSearch {
    /// Starts a search that visits at most `max_roles` roles, so that
    /// attackers cannot make the client waste time and bandwidth.
    pub fn new(path: impl Into<String>, max_roles: usize) -> Self {
        TargetSearch {
            path: path.into(),
            pending: vec![SearchStep {
                role: RoleType::Targets.as_str().to_owned(),
                delegator: RoleType::Root.as_str().to_owned(),
            }],
            visited: HashSet::new(),
            remaining: max_roles,
        }
    }

    /// The next role to visit, or `None` when the search is over. Pass the
    /// role's verified metadata to [`visit`](Self::visit).
    pub fn next_step(&mut self) -> Option<SearchStep> {
        if self.remaining == 0 {
            return None;
        }
        let mut step = self.pending.pop()?;
        while self.visited.contains(&step.role) {
            step = self.pending.pop()?;
        }
        Some(step)
    }

    /// Visits the role of `step`, given its verified targets metadata.
    /// Returns the target if the role lists it; otherwise queues the role's
    /// delegations that are trusted for the path.
    pub fn visit(&mut self, step: &SearchStep, metadata: &Targets) -> Option<TargetInfo> {
        if let Some(file) = metadata.targets.get(&self.path) {
            return Some(TargetInfo {
                path: self.path.clone(),
                role: step.role.clone(),
                file: file.clone(),
            });
        }
        self.visited.insert(step.role.clone());
        self.remaining = self.remaining.saturating_sub(1);

        let Some(delegations) = &metadata.delegations else {
            return None;
        };
        let mut children = Vec::new();
        for delegated in delegations.roles_for_target(&self.path) {
            children.push(SearchStep {
                role: delegated.name.clone(),
                delegator: step.role.clone(),
            });
            if delegated.terminating {
                // Nothing of lower priority may be consulted, including roles
                // left over from earlier levels of the search.
                self.pending.clear();
                break;
            }
        }
        // The stack pops from the end, so push the highest priority last.
        self.pending.extend(children.into_iter().rev());
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::crypto::HashAlgorithm;
    use crate::metadata::{DelegatedRole, Delegations};

    /// A delegation graph: role name -> (targets listed, delegations).
    struct Graph(HashMap<&'static str, Targets>);

    impl Graph {
        fn new() -> Self {
            Graph(HashMap::new())
        }

        fn role(
            mut self,
            name: &'static str,
            targets: &[&str],
            delegations: &[(&str, &str, bool)],
        ) -> Self {
            let mut metadata = Targets::new(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap());
            for path in targets {
                metadata.targets.insert(
                    path.to_string(),
                    TargetFile::from_bytes(name.as_bytes(), &[HashAlgorithm::Sha256]),
                );
            }
            if !delegations.is_empty() {
                let mut delegations_obj = Delegations::new();
                for (child, pattern, terminating) in delegations {
                    let mut role = DelegatedRole::new(*child, Vec::new(), 1);
                    role.paths = Some(vec![pattern.to_string()]);
                    role.terminating = *terminating;
                    delegations_obj.roles.push(role);
                }
                metadata.delegations = Some(delegations_obj);
            }
            self.0.insert(name, metadata);
            self
        }

        /// Runs a search; returns the role that provided the target (if any)
        /// and the roles visited, in order.
        fn search(&self, path: &str, max_roles: usize) -> (Option<String>, Vec<String>) {
            let mut search = TargetSearch::new(path, max_roles);
            let mut visited = Vec::new();
            while let Some(step) = search.next_step() {
                visited.push(step.role.clone());
                let Some(metadata) = self.0.get(step.role.as_str()) else {
                    continue;
                };
                if let Some(found) = search.visit(&step, metadata) {
                    return (Some(found.role), visited);
                }
            }
            (None, visited)
        }
    }

    #[test]
    fn finds_targets_in_top_level_role() {
        let graph = Graph::new().role("targets", &["a.txt"], &[]);
        assert_eq!(
            graph.search("a.txt", 32),
            (Some("targets".into()), vec!["targets".into()])
        );
        assert_eq!(graph.search("b.txt", 32).0, None);
    }

    #[test]
    fn explores_delegations_depth_first_in_priority_order() {
        let graph = Graph::new()
            .role("targets", &[], &[("A", "*", false), ("B", "*", false)])
            .role("A", &[], &[("A1", "*", false)])
            .role("A1", &[], &[])
            .role("B", &["f"], &[]);
        assert_eq!(
            graph.search("f", 32),
            (
                Some("B".into()),
                vec!["targets".into(), "A".into(), "A1".into(), "B".into()]
            )
        );
    }

    #[test]
    fn earlier_delegations_take_precedence() {
        let graph = Graph::new()
            .role("targets", &[], &[("A", "*", false), ("B", "*", false)])
            .role("A", &["f"], &[])
            .role("B", &["f"], &[]);
        assert_eq!(graph.search("f", 32).0, Some("A".into()));
    }

    #[test]
    fn only_follows_delegations_trusted_for_the_path() {
        let graph = Graph::new()
            .role("targets", &[], &[("A", "a/*", false), ("B", "b/*", false)])
            .role("A", &["b/f"], &[])
            .role("B", &["b/f"], &[]);
        assert_eq!(
            graph.search("b/f", 32),
            (Some("B".into()), vec!["targets".into(), "B".into()])
        );
    }

    #[test]
    fn terminating_delegations_cut_off_lower_priorities() {
        let graph = Graph::new()
            .role("targets", &[], &[("A", "*", false), ("B", "*", false)])
            .role(
                "A",
                &[],
                &[("A1", "*", false), ("A2", "*", true), ("A3", "*", false)],
            )
            .role("A1", &[], &[])
            .role("A2", &[], &[])
            .role("A3", &["f"], &[])
            .role("B", &["f"], &[]);
        assert_eq!(
            graph.search("f", 32),
            (
                None,
                vec!["targets".into(), "A".into(), "A1".into(), "A2".into()]
            )
        );
    }

    #[test]
    fn terminating_delegation_still_searches_its_own_subtree() {
        let graph = Graph::new()
            .role("targets", &[], &[("A", "*", true), ("B", "*", false)])
            .role("A", &[], &[("A1", "*", false)])
            .role("A1", &["f"], &[])
            .role("B", &["f"], &[]);
        assert_eq!(graph.search("f", 32).0, Some("A1".into()));
    }

    #[test]
    fn cycles_are_visited_once() {
        let graph = Graph::new()
            .role("targets", &[], &[("A", "*", false)])
            .role("A", &[], &[("B", "*", false)])
            .role("B", &[], &[("A", "*", false), ("C", "*", false)])
            .role("C", &["f"], &[]);
        assert_eq!(
            graph.search("f", 32),
            (
                Some("C".into()),
                vec!["targets".into(), "A".into(), "B".into(), "C".into()]
            )
        );
    }

    #[test]
    fn stops_after_the_maximum_number_of_roles() {
        let graph = Graph::new()
            .role("targets", &[], &[("A", "*", false)])
            .role("A", &[], &[("B", "*", false)])
            .role("B", &["f"], &[]);
        assert_eq!(
            graph.search("f", 2),
            (None, vec!["targets".into(), "A".into()])
        );
        assert_eq!(graph.search("f", 3).0, Some("B".into()));
    }

    #[test]
    fn matches_file_checks_length_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let info = TargetInfo {
            path: "f".into(),
            role: "targets".into(),
            file: TargetFile::from_bytes(b"content", &[HashAlgorithm::Sha256]),
        };
        let path = dir.path().join("f");
        assert!(!info.matches_file(&path).unwrap());
        std::fs::write(&path, b"content").unwrap();
        assert!(info.matches_file(&path).unwrap());
        std::fs::write(&path, b"Content").unwrap();
        assert!(!info.matches_file(&path).unwrap());
        std::fs::write(&path, b"content and more").unwrap();
        assert!(!info.matches_file(&path).unwrap());
    }
}
