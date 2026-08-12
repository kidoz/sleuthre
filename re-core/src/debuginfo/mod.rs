mod dwarf;
mod pdb_parser;
mod source_map;
mod type_mapper;
pub mod unwind;

use crate::types::{ClassInfo, CompoundType, FunctionSignature, SourceLineInfo, VariableInfo};
use std::collections::BTreeMap;
use std::path::Path;

/// Unified result from debug info extraction (DWARF or PDB).
#[derive(Debug, Default)]
pub struct DebugInfo {
    pub types: Vec<CompoundType>,
    pub function_signatures: BTreeMap<u64, FunctionSignature>,
    pub global_variables: BTreeMap<u64, VariableInfo>,
    pub local_variables: BTreeMap<u64, Vec<VariableInfo>>,
    pub source_lines: BTreeMap<u64, SourceLineInfo>,
    /// C++ class metadata (base-class edges) keyed by qualified class name.
    pub classes: BTreeMap<String, ClassInfo>,
}

/// Extract debug info from an ELF/Mach-O binary (DWARF format).
///
/// Returns `Ok(Default)` if no debug info is present.
pub fn extract_debug_info(
    bytes: &[u8],
    arch: crate::arch::Architecture,
) -> crate::Result<DebugInfo> {
    dwarf::extract_dwarf_info(bytes, arch)
}

/// Extract debug info from a PDB file (Windows debug symbols). `image_base` is
/// the PE load base, used to map section-relative symbol offsets to virtual
/// addresses matching the loaded segments.
pub fn extract_pdb_info(
    pdb_path: &Path,
    arch: crate::arch::Architecture,
    image_base: u64,
) -> crate::Result<DebugInfo> {
    pdb_parser::extract_pdb_info(pdb_path, arch, image_base)
}

/// Extract debug info from in-memory PDB (MSF container) bytes. Same as
/// [`extract_pdb_info`] without touching the filesystem — also the entry
/// point the fuzz harness drives with arbitrary bytes.
pub fn extract_pdb_from_bytes(
    bytes: &[u8],
    arch: crate::arch::Architecture,
    image_base: u64,
) -> crate::Result<DebugInfo> {
    pdb_parser::extract_pdb_from_bytes(bytes, arch, image_base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_empty_returns_default() {
        // A bare ELF magic with no headers is not an object file — extraction
        // must yield an empty result, never a panic.
        let info = extract_debug_info(&[0x7f, 0x45, 0x4c, 0x46], crate::arch::Architecture::X86_64)
            .expect("truncated ELF magic yields empty debug info");
        assert!(info.function_signatures.is_empty());
        assert!(info.types.is_empty());
        assert!(info.global_variables.is_empty());
        assert!(info.local_variables.is_empty());
        assert!(info.source_lines.is_empty());
        assert!(info.classes.is_empty());
    }

    #[test]
    fn extract_from_non_elf_returns_default() {
        let result = extract_debug_info(b"not an elf", crate::arch::Architecture::X86_64);
        let info = result.unwrap();
        assert!(info.function_signatures.is_empty());
        assert!(info.types.is_empty());
    }

    #[test]
    fn extract_pdb_from_garbage_errors_cleanly() {
        let result =
            extract_pdb_from_bytes(b"not a pdb", crate::arch::Architecture::X86_64, 0x40_0000);
        assert!(result.is_err());
    }
}
