//! 5.1 Record fixed update start time.
//!
//! Every expiry check of an update compares against the time the update
//! began: the `reference_time` of `TrustedMetadata::new`, and of
//! `Updater::refresh_at` (`Updater::refresh` uses the current time).

use std::assert_matches;

use jiff::SignedDuration;
use tuffet::Error;
use tuffet::metadata::RoleType;

use crate::support::{TestRepo, now};

/// Publishes metadata of a top-level role that expires at `expires`.
fn publish_expiring(repo: &mut TestRepo, role: RoleType, expires: jiff::Timestamp) {
    match role {
        RoleType::Root => {
            repo.root.expires = expires;
            repo.publish_root();
        }
        RoleType::Timestamp => {
            repo.timestamp.expires = expires;
            repo.publish_timestamp();
        }
        RoleType::Snapshot => {
            repo.snapshot.expires = expires;
            repo.publish_snapshot();
        }
        RoleType::Targets => {
            repo.targets_mut("targets").expires = expires;
            repo.commit();
        }
    }
}

/// 5.1: expiry is checked against the update start time, not against the
/// clock, so the same metadata is valid in an update that starts before it
/// expires and expired in one that starts after.
#[test]
fn expiry_is_checked_against_the_update_start_time() {
    let mut repo = TestRepo::new();
    publish_expiring(
        &mut repo,
        RoleType::Timestamp,
        now() + SignedDuration::from_hours(1),
    );
    let mut client = repo.client();

    client.time = now() + SignedDuration::from_mins(59);
    client.refresh().unwrap();
    assert_eq!(
        client.trusted().reference_time(),
        now() + SignedDuration::from_mins(59)
    );

    client.time = now() + SignedDuration::from_mins(61);
    assert_matches!(client.refresh(), Err(Error::Expired { role, .. }) if role == "timestamp");
}

/// 5.3.10, 5.4.4, 5.5.6 and 5.6.5: an expiration timestamp "MUST be higher
/// than the fixed update start time", so metadata of any role that expires
/// exactly when the update starts has expired.
#[test]
fn metadata_that_expires_at_the_update_start_time_has_expired() {
    for role in [
        RoleType::Root,
        RoleType::Timestamp,
        RoleType::Snapshot,
        RoleType::Targets,
    ] {
        let mut repo = TestRepo::new();
        publish_expiring(&mut repo, role, now());
        let mut client = repo.client();
        let result = client.refresh();
        assert_matches!(
            result,
            Err(Error::Expired { role: r, expires }) if r == role.as_str() && expires == now(),
            "{role}"
        );

        client.time = now() - SignedDuration::from_secs(1);
        client.refresh().unwrap();
    }
}
