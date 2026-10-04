//! Metadata date-times: ISO 8601 in UTC, formatted exactly as
//! `YYYY-MM-DDTHH:MM:SSZ`.
//!
//! Used with `#[serde(with = "datetime")]`.

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serializer};

const FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

pub(crate) fn serialize<S: Serializer>(
    time: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&time.format(FORMAT))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<DateTime<Utc>, D::Error> {
    let text = std::borrow::Cow::<str>::deserialize(deserializer)?;
    parse(&text).map_err(D::Error::custom)
}

fn parse(text: &str) -> Result<DateTime<Utc>, String> {
    let time = NaiveDateTime::parse_from_str(text, FORMAT)
        .map_err(|e| format!("invalid date-time {text:?}: {e}"))?
        .and_utc();
    // chrono tolerates some variations (such as unpadded fields). Insist on
    // the exact format, so that re-encoding reproduces the signed bytes.
    if time.format(FORMAT).to_string() != text {
        return Err(format!(
            "date-time {text:?} is not formatted as YYYY-MM-DDTHH:MM:SSZ"
        ));
    }
    Ok(time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn parses_the_specified_format_only() {
        assert_eq!(
            parse("1985-10-21T01:21:00Z").unwrap(),
            Utc.with_ymd_and_hms(1985, 10, 21, 1, 21, 0).unwrap()
        );
        for bad in [
            "1985-10-21T01:21:00",
            "1985-10-21T01:21:00.5Z",
            "1985-10-21T01:21:00+00:00",
            "1985-10-21 01:21:00Z",
            "1985-1-21T01:21:00Z",
        ] {
            assert!(parse(bad).is_err(), "{bad} should be rejected");
        }
    }
}
