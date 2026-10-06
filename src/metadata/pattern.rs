//! Matching target paths against delegation `PATHPATTERN`s.
//!
//! The specification defines patterns by the Unix shell's pattern matching
//! convention, [glob(7)], and says that wildcards should not match the path
//! separator. As in python-tuf and go-tuf, pattern and path are therefore
//! split on `/`, and each segment is matched with the [`glob`] crate:
//!
//! - `*` matches any run of characters and `?` any single character;
//! - `[...]` matches one of the characters it encloses and `[!...]` one
//!   character it does not enclose. A `]` right after the opening `[` or `[!`
//!   is enclosed rather than closing, `a-z` is a range, and a `-` first or
//!   last stands for itself.
//!
//! There is no escape character. A pattern that `glob` rejects, such as one
//! with an unclosed `[`, matches nothing, as in go-tuf. Unlike pathname
//! expansion in a shell, a leading `.` does not have to be matched explicitly.
//!
//! [glob(7)]: https://man7.org/linux/man-pages/man7/glob.7.html

use glob::{MatchOptions, Pattern};

const OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: true,
    // Segments contain no `/`, and on Windows this would make `glob` treat
    // `\` as a separator.
    require_literal_separator: false,
    require_literal_leading_dot: false,
};

/// Whether `path` matches the shell-style `pattern`.
pub(crate) fn matches_path(pattern: &str, path: &str) -> bool {
    let patterns: Vec<&str> = pattern.split('/').collect();
    let segments: Vec<&str> = path.split('/').collect();
    patterns.len() == segments.len()
        && patterns
            .iter()
            .zip(&segments)
            .all(|(pattern, segment)| matches_segment(pattern, segment))
}

fn matches_segment(pattern: &str, segment: &str) -> bool {
    // Within a segment `**` means the same as `*`, but `glob` only accepts it
    // as a whole path component, so collapse runs of `*`.
    let mut collapsed = String::with_capacity(pattern.len());
    for c in pattern.chars() {
        if c != '*' || !collapsed.ends_with('*') {
            collapsed.push(c);
        }
    }
    Pattern::new(&collapsed).is_ok_and(|pattern| pattern.matches_with(segment, OPTIONS))
}
