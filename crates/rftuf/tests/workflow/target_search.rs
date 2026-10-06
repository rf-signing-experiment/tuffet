//! 5.6.7 Search the delegation graph for a target.
//!
//! "Perform a pre-order depth-first search for metadata about the desired
//! target, beginning with the top-level targets role." `TargetSearch`
//! implements the search without I/O, and the first tests run it over
//! graphs of unsigned targets payloads. The `Updater` tests check that
//! delegated metadata is downloaded and verified as the search needs it.

use std::collections::HashMap;

use rftuf::crypto::HashAlgorithm;
use rftuf::metadata::{DelegatedRole, Delegations, TargetFile, Targets};
use rftuf::transport::TransportError;
use rftuf::trusted::TargetSearch;
use rftuf::{Error, UpdaterConfig};

use crate::support::{Delegation, TestRepo, assert_err, far_future};

/// A delegation in a [`Graph`].
struct Edge {
    role: &'static str,
    pattern: &'static str,
    terminating: bool,
}

/// A non-terminating delegation to `role` for the paths matching `pattern`.
fn to(role: &'static str, pattern: &'static str) -> Edge {
    Edge {
        role,
        pattern,
        terminating: false,
    }
}

/// A terminating delegation to `role` for the paths matching `pattern`.
fn terminating(role: &'static str, pattern: &'static str) -> Edge {
    Edge {
        role,
        pattern,
        terminating: true,
    }
}

/// A delegation graph of (unsigned) targets payloads, by role name.
#[derive(Default)]
struct Graph(HashMap<&'static str, Targets>);

impl Graph {
    /// Adds a role that lists `targets` and has `delegations`, in order.
    fn role(mut self, name: &'static str, targets: &[&str], delegations: &[Edge]) -> Self {
        let mut payload = Targets::new(far_future());
        for path in targets {
            let file = TargetFile::from_bytes(name.as_bytes(), &[HashAlgorithm::Sha256]);
            payload.targets.insert(path.to_string(), file);
        }
        if !delegations.is_empty() {
            let mut roles = Delegations::new();
            for edge in delegations {
                let mut role = DelegatedRole::new(edge.role, Vec::new(), 1);
                role.paths = Some(vec![edge.pattern.to_owned()]);
                role.terminating = edge.terminating;
                roles.roles.push(role);
            }
            payload.delegations = Some(roles);
        }
        self.0.insert(name, payload);
        self
    }

    /// Searches for `path`, visiting at most `max_roles` roles. Returns the
    /// role that lists the target, if any, and the roles visited, in order.
    fn search(&self, path: &str, max_roles: usize) -> (Option<&'static str>, Vec<String>) {
        let mut search = TargetSearch::new(path, max_roles);
        let mut visited = Vec::new();
        while let Some(step) = search.next_step() {
            visited.push(step.role.clone());
            let (&name, payload) = self.0.get_key_value(step.role.as_str()).unwrap();
            if let Some(found) = search.visit(&step, payload) {
                assert_eq!(found.role, name);
                return (Some(name), visited);
            }
        }
        (None, visited)
    }

    /// The role that lists the target at `path`, if any.
    fn found(&self, path: &str) -> Option<&'static str> {
        self.search(path, 32).0
    }

    /// The roles visited when searching for `path`, in order.
    fn visited(&self, path: &str) -> Vec<String> {
        self.search(path, 32).1
    }
}

/// 5.6.7: the search begins with the top-level targets role, and 5.6.7.1:
/// "if this role contains metadata about the desired target", it ends there,
/// before any of its delegations.
#[test]
fn the_search_begins_with_the_top_level_targets_role() {
    let graph = Graph::default()
        .role("targets", &["f"], &[to("A", "*")])
        .role("A", &["f", "g"], &[]);
    assert_eq!(graph.found("f"), Some("targets"));
    assert_eq!(graph.visited("f"), ["targets"]);
    assert_eq!(graph.found("g"), Some("A"));
    assert_eq!(graph.found("h"), None);
}

/// 5.6.7, 5.6.7.2: the search is "pre-order depth-first", and "recursively
/// search[es] the list of delegations in order of appearance".
#[test]
fn delegations_are_searched_depth_first_in_order_of_appearance() {
    let graph = Graph::default()
        .role("targets", &[], &[to("A", "*"), to("B", "*")])
        .role("A", &[], &[to("A1", "*"), to("A2", "*")])
        .role("A1", &[], &[])
        .role("A2", &[], &[])
        .role("B", &["f"], &[]);
    assert_eq!(graph.visited("f"), ["targets", "A", "A1", "A2", "B"]);
    assert_eq!(graph.found("f"), Some("B"));
}

/// 4.5 (prioritized delegations): "the first delegation is trusted over the
/// second one", and 5.6.7.2.2: "Stop the search ... as soon as a delegation
/// returns a result."
#[test]
fn earlier_delegations_are_trusted_over_later_ones() {
    let graph = Graph::default()
        .role("targets", &[], &[to("A", "*"), to("B", "*")])
        .role("A", &["f"], &[])
        .role("B", &["f"], &[]);
    assert_eq!(graph.found("f"), Some("A"));
    assert_eq!(graph.visited("f"), ["targets", "A"]);
}

/// 4.5 ("paths"): a delegated role is only trusted for the paths its
/// delegation lists, so the search only follows delegations whose paths
/// match the target.
#[test]
fn only_delegations_trusted_for_the_target_path_are_followed() {
    let graph = Graph::default()
        .role("targets", &[], &[to("A", "a/*"), to("B", "b/*")])
        .role("A", &["b/f"], &[])
        .role("B", &["b/f"], &[]);
    assert_eq!(graph.found("b/f"), Some("B"));
    assert_eq!(graph.visited("b/f"), ["targets", "B"]);
}

/// 4.5 ("paths"): "Clients MUST check that a target is in one of the trusted
/// paths of all roles in a delegation chain, not just in a trusted path of
/// the role that describes the target file."
#[test]
fn a_target_must_be_in_the_trusted_paths_of_every_role_in_the_chain() {
    // "A" is trusted for a/* only, but delegates more than that to "B".
    let graph = Graph::default()
        .role("targets", &[], &[to("A", "a/*")])
        .role("A", &[], &[to("B", "*/*")])
        .role("B", &["a/f", "b/f"], &[]);
    assert_eq!(graph.found("a/f"), Some("B"));
    assert_eq!(graph.found("b/f"), None);
    assert_eq!(graph.visited("b/f"), ["targets"]);
}

/// 5.6.7.2.1: "If the current delegation is a terminating delegation, then
/// jump to step 5.7": no delegation of lower priority is searched, at any
/// level of the search.
#[test]
fn a_terminating_delegation_ends_the_search() {
    let graph = Graph::default()
        .role("targets", &[], &[to("A", "*"), to("B", "*")])
        .role(
            "A",
            &[],
            &[to("A1", "*"), terminating("A2", "*"), to("A3", "*")],
        )
        .role("A1", &[], &[])
        .role("A2", &[], &[])
        .role("A3", &["f"], &[])
        .role("B", &["f"], &[]);
    assert_eq!(graph.found("f"), None);
    assert_eq!(graph.visited("f"), ["targets", "A", "A1", "A2"]);
}

/// 4.5 (TERMINATING): a terminating delegation "stops the delegation
/// processing once this delegation (and its descendants) have been
/// processed".
#[test]
fn a_terminating_delegation_is_searched_with_its_descendants() {
    let graph = Graph::default()
        .role("targets", &[], &[terminating("A", "*"), to("B", "*")])
        .role("A", &[], &[to("A1", "*")])
        .role("A1", &["f"], &[])
        .role("B", &["f"], &[]);
    assert_eq!(graph.found("f"), Some("A1"));
}

/// 4.5 (TERMINATING): only a terminating delegation that matches the target
/// path ends the search: it concerns the targets "that match this
/// delegation's pattern".
#[test]
fn a_terminating_delegation_for_other_paths_does_not_end_the_search() {
    let graph = Graph::default()
        .role("targets", &[], &[terminating("A", "a/*"), to("B", "*")])
        .role("A", &[], &[])
        .role("B", &["f"], &[]);
    assert_eq!(graph.found("f"), Some("B"));
    assert_eq!(graph.visited("f"), ["targets", "B"]);
}

/// 5.6.7.1: "If this role has been visited before, then skip this role (so
/// that cycles in the delegation graph are avoided)."
#[test]
fn roles_visited_before_are_skipped() {
    let graph = Graph::default()
        .role("targets", &[], &[to("A", "*")])
        .role("A", &[], &[to("B", "*")])
        .role("B", &[], &[to("A", "*"), to("C", "*")])
        .role("C", &["f"], &[]);
    assert_eq!(graph.visited("f"), ["targets", "A", "B", "C"]);
    assert_eq!(graph.found("f"), Some("C"));
}

/// 5.6.7.1: "if an application-specific maximum number of roles have been
/// visited, then go to step 5.7 (so that attackers cannot cause the client
/// to waste excessive bandwidth or time)".
#[test]
fn the_search_visits_at_most_the_maximum_number_of_roles() {
    let graph = Graph::default()
        .role("targets", &[], &[to("A", "*")])
        .role("A", &[], &[to("B", "*")])
        .role("B", &["f"], &[]);
    assert_eq!(
        graph.search("f", 2),
        (None, vec!["targets".to_owned(), "A".to_owned()])
    );
    assert_eq!(graph.search("f", 3).0, Some("B"));
}

/// The updater downloads delegated metadata only when the search reaches its
/// role, and reuses what it has verified for later lookups.
#[test]
fn delegated_metadata_is_downloaded_when_the_search_needs_it() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["a/*"]));
    repo.delegate("targets", Delegation::to("b").paths(&["b/*"]));
    repo.add_target("b", "b/file", b"data");
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();
    repo.requests();

    assert_eq!(client.find("b/file").as_deref(), Some("b"));
    assert_eq!(repo.requests(), ["b.json"]);
    assert_eq!(client.find("b/other"), None);
    assert!(repo.requests().is_empty());
    assert_eq!(client.stored("b.json"), Some(repo.file("b.json")));
    assert_eq!(client.stored("a.json"), None);
}

/// 4.5 (prioritized delegations), through the updater: of two roles trusted
/// for a path, the target is the one the first role lists, and downloads
/// are checked against what that role lists.
#[test]
fn the_updater_searches_delegations_in_order_of_priority() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["a/*"]));
    repo.delegate("targets", Delegation::to("b").paths(&["a/*", "b"]));
    repo.add_target("a", "a/shared", b"from a");
    repo.add_target("b", "a/shared", b"from b");
    repo.add_target("b", "a/only-b", b"b");
    repo.add_target("b", "b", b"b");
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();

    assert_eq!(client.find("a/shared").as_deref(), Some("a"));
    assert_eq!(client.find("a/only-b").as_deref(), Some("b"));
    assert_eq!(client.find("b").as_deref(), Some("b"));
    assert_eq!(client.find("c"), None);

    // The repository serves one file per path: here, the one "b" lists. It
    // does not match what the role trusted for the path, "a", lists.
    let target = client.get_target_info("a/shared").unwrap().unwrap();
    assert_err!(client.download(&target), Error::HashMismatch { .. });
    repo.serve_target("a/shared", b"from a");
    assert_eq!(client.download(&target).unwrap(), b"from a");
}

/// 5.6.7.2.1, through the updater: a terminating delegation hides what lower
/// priority roles list for its paths.
#[test]
fn the_updater_stops_at_terminating_delegations() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["a/*"]).terminating());
    repo.delegate("targets", Delegation::to("b").paths(&["*"]));
    repo.add_target("b", "a/file", b"data");
    repo.add_target("b", "file", b"data");
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();

    assert_eq!(client.find("a/file"), None);
    assert_eq!(client.find("file").as_deref(), Some("b"));
}

/// 4.5 ("path_hash_prefixes"): roles can be delegated the target paths whose
/// SHA-256 hashes start with given prefixes, to "split a large number of
/// targets into separate bins".
#[test]
fn the_updater_follows_hash_prefix_delegations() {
    let bin = |path: &str| {
        let digest = HashAlgorithm::Sha256.digest(path.as_bytes());
        if digest[0] < 0x80 { "bin-0" } else { "bin-1" }
    };
    let mut repo = TestRepo::new();
    repo.delegate(
        "targets",
        Delegation::to("bin-0").path_hash_prefixes(&["0", "1", "2", "3", "4", "5", "6", "7"]),
    );
    repo.delegate(
        "targets",
        Delegation::to("bin-1").path_hash_prefixes(&["8", "9", "a", "b", "c", "d", "e", "f"]),
    );
    let paths = ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt", "f.txt"];
    for path in paths {
        repo.add_target(bin(path), path, path.as_bytes());
    }
    repo.commit();
    assert!(paths.iter().any(|path| bin(path) == "bin-0"));
    assert!(paths.iter().any(|path| bin(path) == "bin-1"));

    let mut client = repo.client();
    client.refresh().unwrap();
    for path in paths {
        assert_eq!(client.find(path).as_deref(), Some(bin(path)), "{path}");
    }
}

/// 5.6.7.1: the maximum number of roles to visit is
/// `UpdaterConfig::max_delegations`.
#[test]
fn the_updater_visits_at_most_max_delegations_roles() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["*"]));
    repo.delegate("a", Delegation::to("b").paths(&["*"]));
    repo.add_target("b", "file", b"data");
    repo.commit();

    let mut config = UpdaterConfig::default();
    config.max_delegations = 2;
    let mut client = repo.client_with(config.clone());
    client.refresh().unwrap();
    assert_eq!(client.find("file"), None);

    config.max_delegations = 3;
    let mut client = repo.client_with(config);
    client.refresh().unwrap();
    assert_eq!(client.find("file").as_deref(), Some("b"));
}

/// 5.6.7: "If any metadata requested in steps 5.6.7.1 - 5.6.7.2 cannot be
/// downloaded nor validated, end the search and report that the target
/// cannot be found." rftuf reports why.
#[test]
fn reports_delegated_metadata_that_cannot_be_downloaded_or_validated() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["*"]));
    repo.commit();

    repo.remove("a.json");
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_err!(
        client.get_target_info("file"),
        Error::Transport(TransportError::NotFound(name)) if name == "a.json"
    );

    let signed_by_another_key = repo.sign("targets", &repo.targets["a"]);
    repo.write("a.json", signed_by_another_key);
    assert_err!(
        client.get_target_info("file"),
        Error::SignatureThreshold { role, .. } if role == "a"
    );
}

/// A role delegated to by two roles with different keys must satisfy the
/// delegation the search reaches it through, also when its metadata was
/// verified and persisted through the other one (see
/// `update_targets::a_role_must_satisfy_each_delegation_it_is_used_through`).
#[test]
fn a_role_reached_through_another_delegation_is_verified_again() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["a/*"]));
    repo.delegate("targets", Delegation::to("b").paths(&["b/*"]));
    repo.delegate("a", Delegation::to("shared").paths(&["a/*"]));
    // "b" delegates to "shared" too, but to a key that does not sign it.
    repo.delegate("b", Delegation::to("shared").paths(&["b/*"]));
    repo.add_target("shared", "a/file", b"trusted");
    repo.add_target("shared", "b/file", b"malicious");
    repo.commit();

    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.find("a/file").as_deref(), Some("shared"));
    assert_err!(
        client.get_target_info("b/file"),
        Error::SignatureThreshold { role, .. } if role == "shared"
    );

    // A restarted client that reaches "shared" through "b" first, from the
    // metadata it persisted.
    let mut restarted = client.restart();
    restarted.refresh().unwrap();
    assert_err!(
        restarted.get_target_info("b/file"),
        Error::SignatureThreshold { role, .. } if role == "shared"
    );
}

/// A role that two roles delegate to, with the same keys, is trusted
/// through either of them.
#[test]
fn a_role_delegated_to_twice_with_the_same_keys_is_trusted_through_both() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["a/*"]));
    repo.delegate("targets", Delegation::to("b").paths(&["b/*"]));
    repo.delegate("a", Delegation::to("shared").paths(&["a/*"]));
    let shared_keys = repo.signers["shared"].clone();
    repo.delegate(
        "b",
        Delegation::to("shared")
            .paths(&["b/*"])
            .signed_by(&shared_keys),
    );
    repo.add_target("shared", "a/file", b"a");
    repo.add_target("shared", "b/file", b"b");
    repo.commit();

    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.find("a/file").as_deref(), Some("shared"));
    assert_eq!(client.find("b/file").as_deref(), Some("shared"));
}
