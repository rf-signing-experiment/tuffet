//! The fields every role has: SPEC_VERSION, VERSION and EXPIRES are
//! described for root.json (4.3), and each other role refers to them ("are
//! the same as is described for the root.json file").

use rftuf::Error;
use rftuf::metadata::{Root, Snapshot, Targets, Timestamp};
use serde_json::{Value, json};

use crate::{decode, python_tuf_payload};

/// A role's name, a valid payload of that role, and a function that decodes
/// a payload as that role.
type RoleCase = (&'static str, Value, fn(Value) -> rftuf::Result<()>);

fn every_role() -> [RoleCase; 4] {
    [
        ("root", python_tuf_payload("root.json"), |payload| {
            decode::<Root>(payload).map(drop)
        }),
        (
            "timestamp",
            python_tuf_payload("timestamp.json"),
            |payload| decode::<Timestamp>(payload).map(drop),
        ),
        ("snapshot", python_tuf_payload("snapshot.json"), |payload| {
            decode::<Snapshot>(payload).map(drop)
        }),
        ("targets", python_tuf_payload("targets.json"), |payload| {
            decode::<Targets>(payload).map(drop)
        }),
    ]
}

/// SPEC_VERSION: "clients MUST verify that "spec_version" matches the
/// expected version number. Adopters are free to determine what is
/// considered a match". rftuf, like the reference implementation, accepts
/// `MAJOR.MINOR` and `MAJOR.MINOR.PATCH` with the major version it
/// implements, 1.
#[test]
fn spec_version_must_have_the_supported_major_version() {
    for (role, payload, decode) in every_role() {
        let with = |spec_version: &str| {
            let mut payload = payload.clone();
            payload["spec_version"] = json!(spec_version);
            decode(payload)
        };
        for supported in ["1.0", "1.0.0", "1.0.36", "1.99.0"] {
            with(supported).unwrap_or_else(|e| panic!("{role} {supported}: {e}"));
        }
        for (unsupported, reason) in [
            ("2.0.0", "unsupported spec_version"),
            ("0.9", "unsupported spec_version"),
            ("1", "malformed spec_version"),
            ("1.0.x", "malformed spec_version"),
            ("1.0.0.0", "malformed spec_version"),
            ("1.0.0-rc.1", "malformed spec_version"),
            ("", "malformed spec_version"),
        ] {
            let result = with(unsupported);
            assert!(
                matches!(&result, Err(Error::InvalidMetadata(r)) if r.contains(reason)),
                "{role} {unsupported:?}: {result:?}"
            );
        }
    }
}

/// VERSION: "An integer that is greater than 0."
#[test]
fn version_must_be_an_integer_greater_than_zero() {
    for (role, payload, decode) in every_role() {
        let with = |version: Value| {
            let mut payload = payload.clone();
            payload["version"] = version;
            decode(payload)
        };
        with(json!(1)).unwrap();
        with(json!(u64::MAX)).unwrap();
        let zero = with(json!(0));
        assert!(
            matches!(&zero, Err(Error::InvalidMetadata(r)) if r.contains("version must be greater than 0")),
            "{role}: {zero:?}"
        );
        for not_an_integer in [json!(-1), json!(1.0), json!("1"), json!(null)] {
            let result = with(not_an_integer.clone());
            assert!(
                matches!(result, Err(Error::Decode(_))),
                "{role} {not_an_integer}"
            );
        }
    }
}

/// SPEC_VERSION, VERSION and EXPIRES are required. (The format of EXPIRES is
/// tested in `date_time`.)
#[test]
fn common_fields_are_required() {
    for (role, payload, decode) in every_role() {
        for field in ["_type", "spec_version", "version", "expires"] {
            let mut payload = payload.clone();
            payload.as_object_mut().unwrap().remove(field);
            assert!(
                matches!(decode(payload), Err(Error::Decode(_))),
                "{role} without {field}"
            );
        }
    }
}
