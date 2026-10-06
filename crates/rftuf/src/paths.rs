//! Mapping names from metadata to local file paths without letting them
//! escape their directory.

use std::path::{Path, PathBuf};

/// Converts a single file name (e.g. `timestamp.json`) to a path, if it is
/// one ordinary path component.
pub(crate) fn file_name(name: &str) -> Option<&Path> {
    is_safe_component(name).then(|| Path::new(name))
}

/// Converts a `/`-separated target path to a relative path, if every
/// segment is an ordinary path component. Absolute paths, empty segments,
/// `.` and `..` are rejected.
pub(crate) fn relative_path(path: &str) -> Option<PathBuf> {
    path.split('/')
        .map(|segment| is_safe_component(segment).then_some(segment))
        .collect()
}

fn is_safe_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
        // Reject drive prefixes and alternate data streams on Windows.
        && !(cfg!(windows) && name.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        assert_eq!(file_name("3.root.json"), Some(Path::new("3.root.json")));
        assert_eq!(file_name("a%2Fb.json"), Some(Path::new("a%2Fb.json")));
        assert_eq!(
            relative_path("a/b/c.txt"),
            Some(PathBuf::from("a").join("b").join("c.txt"))
        );
        assert_eq!(relative_path("...txt"), Some(PathBuf::from("...txt")));
    }

    #[test]
    fn rejects_escaping_names() {
        for name in ["", ".", "..", "a/b", "a\\b", "nul\0"] {
            assert_eq!(file_name(name), None, "{name:?}");
        }
        for path in [
            "",
            "/etc/passwd",
            "a/../b",
            "../a",
            "a//b",
            "a/",
            "./a",
            "a\\..\\b",
        ] {
            assert_eq!(relative_path(path), None, "{path:?}");
        }
    }

    #[test]
    fn colons_are_only_rejected_on_windows() {
        assert_eq!(file_name("a:b").is_some(), !cfg!(windows));
        assert_eq!(relative_path("dir/c:file").is_some(), !cfg!(windows));
    }
}
