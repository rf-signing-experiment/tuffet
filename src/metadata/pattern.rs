//! Matching target paths against delegation `PATHPATTERN`s.

/// Whether `path` matches the shell-style `pattern`.
///
/// This follows the reference implementation: pattern and path are split on
/// `/` and must have the same number of segments, and each segment is
/// matched with `fnmatch` rules. Wildcards therefore never match a `/`.
///
/// Within a segment, `*` matches any run of characters, `?` matches one
/// character, `[seq]` matches one character in `seq` (which may contain
/// ranges like `a-z`) and `[!seq]` one character not in `seq`. A `[` without
/// a closing `]` is an ordinary character.
pub(crate) fn matches_path(pattern: &str, path: &str) -> bool {
    let mut patterns = pattern.split('/');
    let mut segments = path.split('/');
    loop {
        match (patterns.next(), segments.next()) {
            (Some(pattern), Some(segment)) => {
                let pattern: Vec<char> = pattern.chars().collect();
                let segment: Vec<char> = segment.chars().collect();
                if !matches_segment(&pattern, &segment) {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn matches_segment(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    // Where to resume if the current attempt fails: the pattern position after
    // the most recent `*`, and the text position that `*` currently extends to.
    let mut backtrack: Option<(usize, usize)> = None;
    while t < text.len() {
        let step = match pattern.get(p) {
            Some('*') => {
                backtrack = Some((p + 1, t));
                p += 1;
                continue;
            }
            Some('?') => Some(p + 1),
            Some('[') => match match_bracket(pattern, p, text[t]) {
                Some((true, next)) => Some(next),
                Some((false, _)) => None,
                None if text[t] == '[' => Some(p + 1),
                None => None,
            },
            Some(&c) if c == text[t] => Some(p + 1),
            _ => None,
        };
        match (step, backtrack) {
            (Some(next), _) => {
                p = next;
                t += 1;
            }
            // Let the last `*` absorb one more character and try again.
            (None, Some((star_next, star_end))) => {
                p = star_next;
                t = star_end + 1;
                backtrack = Some((star_next, star_end + 1));
            }
            (None, None) => return false,
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

/// Evaluates the bracket expression that starts at `pattern[start]` (a `[`)
/// against `c`. Returns whether `c` matched and the index just past the
/// expression, or `None` if the bracket is never closed.
fn match_bracket(pattern: &[char], start: usize, c: char) -> Option<(bool, usize)> {
    let mut first = start + 1;
    let negated = pattern.get(first) == Some(&'!');
    if negated {
        first += 1;
    }
    // A `]` right at the start is a member rather than the end.
    let search_from = if pattern.get(first) == Some(&']') {
        first + 1
    } else {
        first
    };
    let close = search_from
        + pattern
            .get(search_from..)?
            .iter()
            .position(|&ch| ch == ']')?;

    let members = &pattern[first..close];
    let mut matched = false;
    let mut i = 0;
    while i < members.len() {
        if i + 2 < members.len() && members[i + 1] == '-' {
            matched |= (members[i]..=members[i + 2]).contains(&c);
            i += 3;
        } else {
            matched |= members[i] == c;
            i += 1;
        }
    }
    Some((matched != negated, close + 1))
}

#[cfg(test)]
mod tests {
    use super::matches_path;

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
        assert!(matches_path("*.tar.gz", "pkg.tar.gz"));
        assert!(!matches_path("*.tar.gz", "pkg.tar.gzip"));
    }

    #[test]
    fn bracket_expressions() {
        assert!(matches_path("file[0-9].txt", "file7.txt"));
        assert!(!matches_path("file[0-9].txt", "filex.txt"));
        assert!(matches_path("file[!0-9].txt", "filex.txt"));
        assert!(!matches_path("file[!0-9].txt", "file7.txt"));
        assert!(matches_path("[]]", "]"));
        assert!(matches_path("[!]]", "a"));
        assert!(matches_path("[a-]", "-"));
        assert!(matches_path("x[ab", "x[ab"));
        assert!(!matches_path("[z-a]", "m"));
    }

    #[test]
    fn matches_unicode_characters() {
        assert!(matches_path("caf?", "café"));
        assert!(matches_path("*é", "café"));
    }
}
