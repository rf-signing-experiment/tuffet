//! 4.5: the target paths a delegated role is trusted for, given by "paths"
//! (PATHPATTERNs) or by "path_hash_prefixes".
//!
//! PATHPATTERN "supports the Unix shell pattern matching convention for paths
//! (globbing pathnames)", glob(7), and "A path separator in a path SHOULD
//! NOT be matched by a wildcard in the PATHPATTERN". As in python-tuf and
//! go-tuf, tuffet splits pattern and path on `/` and matches segment by
//! segment, so `*` matches any run of characters within a segment, `?` one
//! character, and `[...]` one character of a set.

use tuffet::crypto::HashAlgorithm;
use tuffet::metadata::DelegatedRole;

/// A delegation trusted for the paths that match `patterns`.
fn role_for(patterns: &[&str]) -> DelegatedRole {
    let mut role = DelegatedRole::new("role", Vec::new(), 1);
    role.paths = Some(patterns.iter().map(|p| p.to_string()).collect());
    role
}

/// Whether `pattern` matches `path`.
fn matches(pattern: &str, path: &str) -> bool {
    role_for(&[pattern]).is_delegated_path(path)
}

/// Whether `pattern` matches each of the single characters in `chars`.
fn matches_each(pattern: &str, chars: &str) -> Vec<bool> {
    chars
        .chars()
        .map(|c| matches(pattern, &c.to_string()))
        .collect()
}

/// "Some example PATHPATTERNs and expected matches".
#[test]
fn examples_of_the_specification() {
    // "targets/*.tgz" would match file paths "targets/foo.tgz" and
    // "targets/bar.tgz", but not "targets/foo.txt".
    assert!(matches("targets/*.tgz", "targets/foo.tgz"));
    assert!(matches("targets/*.tgz", "targets/bar.tgz"));
    assert!(!matches("targets/*.tgz", "targets/foo.txt"));
    // "foo-version-?.tgz" matches "foo-version-2.tgz" and
    // "foo-version-a.tgz", but not "foo-version-alpha.tgz".
    assert!(matches("foo-version-?.tgz", "foo-version-2.tgz"));
    assert!(matches("foo-version-?.tgz", "foo-version-a.tgz"));
    assert!(!matches("foo-version-?.tgz", "foo-version-alpha.tgz"));
    // "*.tgz" would match "foo.tgz" and "bar.tgz", but not "targets/foo.tgz".
    assert!(matches("*.tgz", "foo.tgz"));
    assert!(matches("*.tgz", "bar.tgz"));
    assert!(!matches("*.tgz", "targets/foo.tgz"));
    // "foo.tgz" would match only "foo.tgz".
    assert!(matches("foo.tgz", "foo.tgz"));
    assert!(!matches("foo.tgz", "bar.tgz"));
}

/// "A path separator in a path SHOULD NOT be matched by a wildcard in the
/// PATHPATTERN": patterns match a path with as many segments as they have.
#[test]
fn wildcards_do_not_match_the_path_separator() {
    assert!(!matches("*", "a/b"));
    assert!(!matches("a/*", "a/b/c"));
    assert!(!matches("a?b", "a/b"));
    assert!(!matches("a[/]b", "a/b"));
    assert!(!matches("a/**/c", "a/b/x/c"));
    assert!(matches("a/**/c", "a/b/c"));
    assert!(matches("*/*", "a/b"));
    assert!(matches("*", ""));
    assert!(!matches("a/", "a"));
}

/// `*` matches any run of characters (backtracking as needed), and `**` is
/// the same as `*`.
#[test]
fn stars_match_any_run_of_characters() {
    assert!(matches("*a*b", "xaxxab"));
    assert!(matches("a*b*c", "abbbbc"));
    assert!(!matches("a*b*c", "abbbb"));
    assert!(matches("***", "anything"));
    assert!(matches("foo**.tgz", "foo-1.tgz"));
    assert!(matches("*.tar.gz", "pkg.tar.gz"));
    assert!(!matches("*.tar.gz", "pkg.tar.gzip"));
}

/// The examples of bracket expressions in glob(7).
#[test]
fn bracket_expressions_of_glob7() {
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
    assert!(matches("file[0-9].txt", "file7.txt"));
    assert!(!matches("file[0-9].txt", "filex.txt"));
    assert!(matches("file[!0-9].txt", "filex.txt"));
    assert!(!matches("file[!0-9].txt", "file7.txt"));
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
    assert!(matches("a[*]b", "a*b"));
    assert!(!matches("a[*]b", "axb"));
    assert!(matches("[[]a]", "[a]"));
}

/// glob(7)'s backslash escapes are not supported: a backslash is an ordinary
/// character, as in go-tuf.
#[test]
fn backslashes_are_ordinary_characters() {
    assert!(matches("a\\*b", "a\\xb"));
    assert!(!matches("a\\*b", "a*b"));
    assert!(matches("a\\b", "a\\b"));
    assert!(!matches("a\\b", "ab"));
}

/// A pattern that is not a valid glob, such as one with an unclosed `[`,
/// matches nothing.
#[test]
fn malformed_patterns_match_nothing() {
    assert!(!matches("x[ab", "x[ab"));
    assert!(!matches("[]", "[]"));
    assert!(!matches("[!", "[!"));
    assert!(!matches("dir/x[ab", "dir/x[ab"));
}

/// Unlike pathname expansion in a shell, a leading `.` need not be matched
/// explicitly.
#[test]
fn leading_dots_need_no_explicit_match() {
    assert!(matches("*", ".hidden"));
    assert!(matches("dir/?config", "dir/.config"));
}

#[test]
fn patterns_match_characters_not_bytes() {
    assert!(matches("caf?", "café"));
    assert!(matches("*é", "café"));
    assert!(matches("[à-ï]", "é"));
}

/// "paths": "A list of strings, where each string is a PATHPATTERN
/// describing a path that the delegated role is trusted to provide", so the
/// role is trusted for the paths that match any of them.
#[test]
fn a_role_is_trusted_for_the_paths_matching_any_of_its_patterns() {
    let role = role_for(&["dir/*.txt", "exact"]);
    assert!(role.is_delegated_path("dir/a.txt"));
    assert!(role.is_delegated_path("exact"));
    assert!(!role.is_delegated_path("dir/sub/a.txt"));
    assert!(!role.is_delegated_path("other"));
    assert!(!role_for(&[]).is_delegated_path("anything"));
}

/// A role with neither "paths" nor "path_hash_prefixes" is trusted for no
/// paths.
#[test]
fn a_role_without_paths_is_trusted_for_none() {
    let role = DelegatedRole::new("role", Vec::new(), 1);
    assert!(!role.is_delegated_path("anything"));
    assert!(!role.is_delegated_path(""));
}

/// "path_hash_prefixes": "each target path, when hashed with the SHA-256 hash
/// function to produce a 64-byte hexadecimal digest (HEX_DIGEST), must share
/// the same prefix as one of the prefixes".
#[test]
fn path_hash_prefixes_match_the_sha256_of_the_path() {
    let digest = hex::encode(HashAlgorithm::Sha256.digest(b"file1.txt"));
    let mut role = DelegatedRole::new("role", Vec::new(), 1);
    let trusted_for = |role: &mut DelegatedRole, prefixes: &[&str]| {
        role.path_hash_prefixes = Some(prefixes.iter().map(|p| p.to_string()).collect());
        role.is_delegated_path("file1.txt")
    };

    assert!(trusted_for(&mut role, &[&digest[..4]]));
    assert!(trusted_for(&mut role, &[&digest]));
    // The empty prefix is a prefix of every digest.
    assert!(trusted_for(&mut role, &[""]));
    assert!(trusted_for(&mut role, &["ffff", &digest[..2]]));
    assert!(!trusted_for(&mut role, &[&format!("{}x", &digest[..3])]));
    assert!(!trusted_for(&mut role, &[]));
    // Digits found elsewhere in the digest are not a prefix of it.
    assert_ne!(digest[1..5], digest[..4]);
    assert!(!trusted_for(&mut role, &[&digest[1..5]]));
    // The target path itself is hashed, exactly as written.
    let other = hex::encode(HashAlgorithm::Sha256.digest(b"/file1.txt"));
    assert_ne!(other[..8], digest[..8]);
    assert!(!trusted_for(&mut role, &[&other[..8]]));
}
