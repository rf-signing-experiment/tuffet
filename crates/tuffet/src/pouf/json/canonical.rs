//! Canonical JSON, the encoding that TUF JSON metadata is signed over.
//!
//! This is the [OLPC dialect] as produced by the reference implementation:
//!
//! - no whitespace outside strings;
//! - object members sorted by key, comparing UTF-8 bytes (equivalently,
//!   Unicode code points);
//! - in strings, only `"` and `\` are escaped (with a backslash); all other
//!   characters, including control characters, are written as raw UTF-8;
//! - numbers must be integers.
//!
//! [OLPC dialect]: https://web.archive.org/web/20251209150702/http://wiki.laptop.org/go/Canonical_JSON

use serde_json::Value;

/// A value that canonical JSON cannot represent.
#[derive(Debug, thiserror::Error)]
#[error("canonical JSON only supports integers, found {0}")]
pub struct NonIntegerError(String);

/// Encodes `value` as canonical JSON.
pub fn to_vec(value: &Value) -> Result<Vec<u8>, NonIntegerError> {
    let mut out = Vec::new();
    write_value(&mut out, value)?;
    Ok(out)
}

fn write_value(out: &mut Vec<u8>, value: &Value) -> Result<(), NonIntegerError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            // serde_json stores every integer that fits in 64 bits as one;
            // anything else is a float.
            if !(number.is_i64() || number.is_u64()) {
                return Err(NonIntegerError(number.to_string()));
            }
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => write_string(out, string),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            // Sort explicitly: serde_json's map is only sorted when its
            // `preserve_order` feature is off, which another crate may change.
            let mut members: Vec<_> = members.iter().collect();
            members.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, (key, value)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, key);
                out.push(b':');
                write_value(out, value)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(out: &mut Vec<u8>, string: &str) {
    out.push(b'"');
    for byte in string.bytes() {
        if byte == b'"' || byte == b'\\' {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out.push(b'"');
}
