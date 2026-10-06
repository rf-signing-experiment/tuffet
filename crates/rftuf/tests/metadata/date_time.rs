//! 4.2.3 Date-time: "The expected format of the combined date and time
//! string is "YYYY-MM-DDTHH:MM:SSZ". Time is always in UTC, and the "Z" time
//! zone designator is attached to indicate a zero UTC offset."

use rftuf::Error;
use rftuf::metadata::{Metadata, Timestamp};
use serde_json::{Value, json};

use crate::{decode, python_tuf_payload};

fn timestamp_expiring(expires: Value) -> rftuf::Result<Metadata<Timestamp>> {
    let mut payload = python_tuf_payload("timestamp.json");
    payload["expires"] = expires;
    decode(payload)
}

/// "An example date-time string is "1985-10-21T01:21:00Z"." It is decoded as
/// that time in UTC, and encoded in the same format.
#[test]
fn expires_is_a_utc_date_time() {
    let timestamp = timestamp_expiring(json!("1985-10-21T01:21:00Z")).unwrap();
    assert_eq!(
        timestamp.signed().expires,
        "1985-10-21T01:21:00Z".parse::<jiff::Timestamp>().unwrap()
    );
    let encoded: Value = serde_json::from_slice(&timestamp.to_bytes().unwrap()).unwrap();
    assert_eq!(encoded["signed"]["expires"], "1985-10-21T01:21:00Z");
}

/// Only the specified format is accepted, so that a re-encoded file has the
/// same bytes, and therefore the same signature, as the original.
#[test]
fn other_date_time_formats_are_rejected() {
    for other in [
        "1985-10-21T01:21:00",
        "1985-10-21T01:21:00.5Z",
        "1985-10-21T01:21:00+00:00",
        "1985-10-21T03:21:00+02:00",
        "1985-10-21 01:21:00Z",
        "1985-10-21t01:21:00z",
        "1985-1-21T01:21:00Z",
        "1985-10-21T1:21:00Z",
        "1985-10-21",
        "1985-02-30T01:21:00Z",
    ] {
        assert!(
            matches!(timestamp_expiring(json!(other)), Err(Error::Decode(_))),
            "{other}"
        );
    }
    assert!(matches!(
        timestamp_expiring(json!(499_137_660)),
        Err(Error::Decode(_))
    ));
}
