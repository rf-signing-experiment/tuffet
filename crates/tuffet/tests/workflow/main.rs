//! The detailed client workflow: section 5 of the specification, step by
//! step.
//!
//! Each module covers one section, and each test names the step it checks.
//! The verification rules are tested on `TrustedMetadata`, which applies
//! them without I/O; what the `Updater` adds (downloading, size limits,
//! file names, persistence) is tested on the `Updater`.

#[path = "../support/mod.rs"]
mod support;

// 5.1 Record fixed update start time
mod update_start_time;

// 5.2 Load trusted root metadata
mod trusted_root;

// 5.3 Update the root role
mod update_root;

// 5.4 Update the timestamp role
mod update_timestamp;

// 5.5 Update the snapshot role
mod update_snapshot;

// 5.6.1 to 5.6.6 Update the targets role
mod update_targets;

// 5.6.7 Search the delegation graph
mod target_search;

// 5.7 Fetch target
mod fetch_target;

// 6.2 Consistent snapshots, as read in 5.5.1, 5.6.1 and 5.7.3
mod consistent_snapshots;

// Updating again, after success or failure (the introduction of section 5)
mod update_cycles;

// The order of the workflow, as `TrustedMetadata` enforces it
mod call_order;

// TAP 11: the metadata format is a POUF
mod pouf;

use tuffet::UpdaterConfig;

/// The limits the specification leaves to the application, which an
/// `Updater` takes from its `UpdaterConfig`, default to those of the
/// reference implementation: W (5.3.3), X (5.4.1), Y (5.3.3 and 5.5.1), Z
/// (5.6.1), and the maximum number of roles to visit (5.6.7.1).
#[test]
fn the_default_limits_are_those_of_the_reference_implementation() {
    let config = UpdaterConfig::default();
    assert_eq!(config.root_max_length, 512_000); // W
    assert_eq!(config.max_root_rotations, 256); // Y, for root versions
    assert_eq!(config.timestamp_max_length, 16_384); // X
    assert_eq!(config.snapshot_max_length, 2_000_000); // Y, for snapshot metadata
    assert_eq!(config.targets_max_length, 5_000_000); // Z
    assert_eq!(config.max_delegations, 32);
    assert!(config.prefix_targets_with_hash);
}
