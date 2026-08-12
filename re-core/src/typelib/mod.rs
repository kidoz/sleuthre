mod builtin;

use crate::types::{CompoundType, FunctionSignature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A type library containing function signatures and compound types for a platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeLibrary {
    pub name: String,
    pub platform: String,
    pub types: BTreeMap<String, CompoundType>,
    pub function_signatures: BTreeMap<String, FunctionSignature>,
}

/// Manages multiple type libraries for resolving function signatures by name.
#[derive(Default)]
pub struct TypeLibraryManager {
    pub libraries: Vec<TypeLibrary>,
}

impl TypeLibraryManager {
    /// Load built-in type libraries matching a platform string.
    ///
    /// Platform strings: "linux_x86_64", "linux_x86", "linux_arm64",
    /// "windows_x86_64", "windows_x86", "macos_x86_64", "macos_arm64", etc.
    pub fn load_for_platform(&mut self, platform: &str) {
        // Always load libc for Unix-like platforms
        if platform.contains("linux") || platform.contains("macos") {
            self.libraries.push(builtin::libc_library());
        }

        // Load Win32 for Windows platforms
        if platform.contains("windows") {
            self.libraries.push(builtin::win32_library());
        }

        // If platform is unknown, load both as fallback
        if !platform.contains("linux")
            && !platform.contains("macos")
            && !platform.contains("windows")
        {
            self.libraries.push(builtin::libc_library());
            self.libraries.push(builtin::win32_library());
        }
    }

    /// Resolve a function signature by name from loaded libraries.
    pub fn resolve_function(&self, name: &str) -> Option<&FunctionSignature> {
        for lib in &self.libraries {
            if let Some(sig) = lib.function_signatures.get(name) {
                return Some(sig);
            }
        }
        None
    }

    /// Resolve a function signature from a symbol as it appears in a binary,
    /// trying progressively less decorated spellings.
    ///
    /// Linkers decorate the same API many ways — `_malloc` (Mach-O/x86 cdecl),
    /// `_GetVersion@0` / `@f@4` (MSVC stdcall/fastcall), `MessageBoxA` vs. the
    /// generic `MessageBox`, `memcpy@GLIBC_2.14` (ELF versioned symbols),
    /// `__imp_CreateFileW` (import stubs) — and a library keyed by the plain
    /// name would otherwise miss all of them.
    pub fn resolve_symbol(&self, symbol: &str) -> Option<&FunctionSignature> {
        for candidate in symbol_name_candidates(symbol) {
            if let Some(sig) = self.resolve_function(&candidate) {
                return Some(sig);
            }
        }
        None
    }

    /// Resolve a compound type by name from loaded libraries.
    pub fn resolve_type(&self, name: &str) -> Option<&CompoundType> {
        for lib in &self.libraries {
            if let Some(ty) = lib.types.get(name) {
                return Some(ty);
            }
        }
        None
    }
}

/// Progressively undecorated spellings of `symbol`, most specific first.
/// Deterministic and duplicate-free.
pub fn symbol_name_candidates(symbol: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        if !s.is_empty() && !out.iter().any(|e| e == s) {
            out.push(s.to_string());
        }
    };

    push(symbol);
    let mut name = symbol;

    // ELF symbol versioning: `memcpy@GLIBC_2.14` / `memcpy@@GLIBC_2.14`.
    if let Some(idx) = name.find('@')
        && name[idx..].starts_with("@@")
    {
        name = &name[..idx];
        push(name);
    }

    // MSVC import stubs.
    for prefix in ["__imp_", "_imp_", "__imp__"] {
        if let Some(stripped) = name.strip_prefix(prefix) {
            name = stripped;
            push(name);
            break;
        }
    }

    // MSVC stdcall/fastcall decoration: `_Foo@12`, `@Foo@12`.
    let undecorated = name
        .rsplit_once('@')
        .filter(|(head, tail)| !head.is_empty() && tail.chars().all(|c| c.is_ascii_digit()))
        .map(|(head, _)| head)
        .unwrap_or(name);
    let undecorated = undecorated.strip_prefix('@').unwrap_or(undecorated);
    push(undecorated);

    // Leading underscore (cdecl on Mach-O and MSVC x86).
    let bare = undecorated.strip_prefix('_').unwrap_or(undecorated);
    push(bare);

    // Win32 ANSI/wide variants share one signature shape in the library.
    if bare.len() > 1
        && (bare.ends_with('A') || bare.ends_with('W'))
        && bare
            .chars()
            .rev()
            .nth(1)
            .is_some_and(|c| c.is_ascii_lowercase())
    {
        push(&bare[..bare.len() - 1]);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_linux_libraries() {
        let mut mgr = TypeLibraryManager::default();
        mgr.load_for_platform("linux_x86_64");
        assert!(!mgr.libraries.is_empty());
        assert!(mgr.resolve_function("printf").is_some());
        assert!(mgr.resolve_function("malloc").is_some());
    }

    #[test]
    fn load_windows_libraries() {
        let mut mgr = TypeLibraryManager::default();
        mgr.load_for_platform("windows_x86_64");
        assert!(!mgr.libraries.is_empty());
        assert!(mgr.resolve_function("CreateFileW").is_some());
        assert!(mgr.resolve_function("VirtualAlloc").is_some());

        // Check new Win32 & DirectX types
        assert!(mgr.resolve_type("POINT").is_some());
        assert!(mgr.resolve_type("RECT").is_some());
        assert!(mgr.resolve_type("MSG").is_some());
        assert!(mgr.resolve_type("IDirectDrawSurface7").is_some());
    }

    #[test]
    fn unknown_function_returns_none() {
        let mut mgr = TypeLibraryManager::default();
        mgr.load_for_platform("linux_x86_64");
        assert!(mgr.resolve_function("nonexistent_xyz_123").is_none());
    }

    #[test]
    fn candidates_strip_common_decorations() {
        assert_eq!(
            symbol_name_candidates("_GetVersion@0"),
            vec!["_GetVersion@0", "_GetVersion", "GetVersion"]
        );
        assert_eq!(
            symbol_name_candidates("@fastcall_fn@8"),
            vec!["@fastcall_fn@8", "fastcall_fn"]
        );
        assert_eq!(symbol_name_candidates("_malloc"), vec!["_malloc", "malloc"]);
        assert_eq!(
            symbol_name_candidates("memcpy@@GLIBC_2.14"),
            vec!["memcpy@@GLIBC_2.14", "memcpy"]
        );
        assert_eq!(
            symbol_name_candidates("__imp_CreateFileW"),
            vec!["__imp_CreateFileW", "CreateFileW", "CreateFile"]
        );
        // An all-caps trailing letter is part of the name, not an A/W variant.
        assert_eq!(symbol_name_candidates("RtlZeroMemoryW").len(), 2);
        assert_eq!(symbol_name_candidates("HEAP"), vec!["HEAP"]);
    }

    #[test]
    fn resolve_symbol_matches_decorated_spellings() {
        let mut mgr = TypeLibraryManager::default();
        mgr.load_for_platform("windows_x86");
        // Undecorated lookup still works.
        assert!(mgr.resolve_symbol("VirtualAlloc").is_some());
        // stdcall-decorated and import-stub spellings now resolve too.
        assert!(mgr.resolve_symbol("_VirtualAlloc@16").is_some());
        assert!(mgr.resolve_symbol("__imp_VirtualAlloc").is_some());

        let mut unix = TypeLibraryManager::default();
        unix.load_for_platform("macos_x86_64");
        assert!(unix.resolve_symbol("_malloc").is_some());
        assert!(unix.resolve_symbol("memcpy@@GLIBC_2.14").is_some());
    }
}
