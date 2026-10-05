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

#[cfg(test)]
mod tests {
    use super::matches_path;

    /// Whether `pattern` matches each of the single characters in `chars`.
    fn matches_each(pattern: &str, chars: &str) -> Vec<bool> {
        chars
            .chars()
            .map(|c| matches_path(pattern, &c.to_string()))
            .collect()
    }

    #[test]
    fn examples_from_the_specification() {
        assert!(matches_path("targets/*.tgz", "targets/foo.tgz"));
        assert!(matches_path("targets/*.tgz", "targets/bar.tgz"));
        assert!(!matches_path("targets/*.tgz", "targets/foo.txt"));
        assert!(matches_path("foo-version-?.tgz", "foo-version-2.tgz"));
        assert!(matches_path("foo-version-?.tgz", "foo-version-a.tgz"));
        assert!(!matches_path("foo-version-?.tgz", "foo-version-alpha.tgz"));
        assert!(matches_path("*.tgz", "foo.tgz"));
        assert!(matches_path("*.tgz", "bar.tgz"));
        assert!(!matches_path("*.tgz", "targets/foo.tgz"));
        assert!(matches_path("foo.tgz", "foo.tgz"));
        assert!(!matches_path("foo.tgz", "bar.tgz"));
    }

    #[test]
    fn wildcards_do_not_cross_directories() {
        assert!(!matches_path("*", "a/b"));
        assert!(!matches_path("a/*", "a/b/c"));
        assert!(!matches_path("a?b", "a/b"));
        assert!(!matches_path("a[/]b", "a/b"));
        assert!(!matches_path("a/**/c", "a/b/x/c"));
        assert!(matches_path("a/**/c", "a/b/c"));
        assert!(matches_path("*/*", "a/b"));
        assert!(matches_path("*", ""));
        assert!(!matches_path("a/", "a"));
    }

    #[test]
    fn stars_backtrack() {
        assert!(matches_path("*a*b", "xaxxab"));
        assert!(matches_path("a*b*c", "abbbbc"));
        assert!(!matches_path("a*b*c", "abbbb"));
        assert!(matches_path("***", "anything"));
        assert!(matches_path("foo**.tgz", "foo-1.tgz"));
        assert!(matches_path("*.tar.gz", "pkg.tar.gz"));
        assert!(!matches_path("*.tar.gz", "pkg.tar.gzip"));
    }

    /// The bracket expression examples of glob(7).
    #[test]
    fn bracket_expressions_from_glob7() {
        // "[][!]" matches the three characters '[', ']' and '!'.
        assert_eq!(matches_each("[][!]", "[]!a"), [true, true, true, false]);
        // "[]-]" matches just the two characters ']' and '-'.
        assert_eq!(matches_each("[]-]", "]-a"), [true, true, false]);
        // "[--0]" matches the three characters '-', '.' and '0'.
        assert_eq!(
            matches_each("[--0]", "-.0,1"),
            [true, true, true, false, false]
        );
        // "[!]a-]" matches any single character except ']', 'a' and '-'.
        assert_eq!(
            matches_each("[!]a-]", "]a-bé"),
            [false, false, false, true, true]
        );
        // "[[?*\]" matches the four characters '[', '?', '*' and '\'.
        assert_eq!(
            matches_each("[[?*\\]", "[?*\\a"),
            [true, true, true, true, false]
        );
    }

    #[test]
    fn bracket_expressions() {
        assert!(matches_path("file[0-9].txt", "file7.txt"));
        assert!(!matches_path("file[0-9].txt", "filex.txt"));
        assert!(matches_path("file[!0-9].txt", "filex.txt"));
        assert!(!matches_path("file[!0-9].txt", "file7.txt"));
        assert_eq!(
            matches_each("[A-Fa-f0-9]", "Ca9gG"),
            [true, true, true, false, false]
        );
        assert_eq!(matches_each("[a-]", "a-b"), [true, true, false]);
        // `^` does not negate.
        assert_eq!(matches_each("[^a-c]", "b^d"), [true, true, false]);
        // A reversed range matches nothing.
        assert_eq!(matches_each("[z-a]", "amz"), [false, false, false]);
        // Brackets are the way to match special characters literally.
        assert!(matches_path("a[*]b", "a*b"));
        assert!(!matches_path("a[*]b", "axb"));
        assert!(matches_path("[[]a]", "[a]"));
    }

    #[test]
    fn backslashes_are_ordinary_characters() {
        assert!(matches_path("a\\*b", "a\\xb"));
        assert!(!matches_path("a\\*b", "a*b"));
        assert!(matches_path("a\\b", "a\\b"));
        assert!(!matches_path("a\\b", "ab"));
    }

    #[test]
    fn malformed_patterns_match_nothing() {
        assert!(!matches_path("x[ab", "x[ab"));
        assert!(!matches_path("[]", "[]"));
        assert!(!matches_path("[!", "[!"));
        assert!(!matches_path("dir/x[ab", "dir/x[ab"));
    }

    #[test]
    fn leading_dots_need_no_explicit_match() {
        assert!(matches_path("*", ".hidden"));
        assert!(matches_path("dir/?config", "dir/.config"));
    }

    #[test]
    fn matches_unicode_characters() {
        assert!(matches_path("caf?", "café"));
        assert!(matches_path("*é", "café"));
        assert!(matches_path("[à-ï]", "é"));
    }
}
