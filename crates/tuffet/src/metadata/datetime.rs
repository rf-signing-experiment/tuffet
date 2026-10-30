//! Metadata date-times: ISO 8601 in UTC, formatted exactly as
//! `YYYY-MM-DDTHH:MM:SSZ`.
//!
//! Used with `#[serde(with = "datetime")]`.

use jiff::Timestamp;
use jiff::civil::DateTime;
use jiff::tz::Offset;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serializer};

const FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

pub(crate) fn serialize<S: Serializer>(time: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&time.strftime(FORMAT))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Timestamp, D::Error> {
    let text = std::borrow::Cow::<str>::deserialize(deserializer)?;
    parse(&text).map_err(D::Error::custom)
}

fn parse(text: &str) -> Result<Timestamp, String> {
    let time = DateTime::strptime(FORMAT, text)
        .and_then(|time| Offset::UTC.to_timestamp(time))
        .map_err(|e| format!("invalid date-time {text:?}: {e}"))?;
    // `strptime` tolerates some variations (such as unpadded fields). Insist
    // on the exact format, so that re-encoding reproduces the signed bytes.
    if time.strftime(FORMAT).to_string() != text {
        return Err(format!(
            "date-time {text:?} is not formatted as YYYY-MM-DDTHH:MM:SSZ"
        ));
    }
    Ok(time)
}
