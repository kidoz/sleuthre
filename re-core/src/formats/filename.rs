//! Portable leaf names for files named by untrusted format metadata.

use std::path::Path;

pub fn is_safe_file_name(name: &str) -> bool {
    if name.is_empty()
        || name.ends_with(['.', ' '])
        || name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
        || name.chars().any(char::is_control)
        || Path::new(name).file_name() != Some(name.as_ref())
    {
        return false;
    }
    // Windows device names remain reserved with an extension.
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) && !["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_accepts_portable_leaf_names() {
        for name in [
            "",
            ".",
            "..",
            "sub/file",
            r"sub\file",
            "C:name",
            "file:stream",
            "NUL.txt",
            "COM¹.pdb",
            "a.",
        ] {
            assert!(!is_safe_file_name(name), "{name}");
        }
        assert!(is_safe_file_name("level 1.bmp"));
    }
}
