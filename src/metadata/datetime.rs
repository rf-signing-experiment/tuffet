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
