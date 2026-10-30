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
///
/// That holds even if the role's metadata was already verified through
/// another delegation: [`TrustedMetadata::delegated_targets`] checks it again
/// for this one.
///
/// [`TrustedMetadata::delegated_targets`]: super::TrustedMetadata::delegated_targets
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
/// # use tuffet::metadata::Targets;
/// # use tuffet::trusted::{TargetInfo, TargetSearch};
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
            if !self.pending.is_empty() {
                tracing::debug!("stopped searching after visiting the maximum number of roles");
            }
            return None;
        }
        let mut step = self.pending.pop()?;
        while self.visited.contains(&step.role) {
            step = self.pending.pop()?;
        }
        Some(step)
    }

    /// Visits the role of `step`, given its targets metadata as verified for
    /// the step's delegation (see [`SearchStep`]). Returns the target if the
    /// role lists it; otherwise queues the role's delegations that are trusted
    /// for the path.
    pub fn visit(&mut self, step: &SearchStep, metadata: &Targets) -> Option<TargetInfo> {
        if let Some(file) = metadata.targets.get(&self.path) {
            tracing::debug!(role = step.role, "found target");
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
            tracing::trace!(
                role = delegated.name,
                delegator = step.role,
                terminating = delegated.terminating,
                "queued delegation"
            );
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
