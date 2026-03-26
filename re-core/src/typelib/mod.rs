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
}
