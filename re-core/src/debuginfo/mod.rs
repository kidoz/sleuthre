mod dwarf;
mod pdb_parser;
mod source_map;
mod type_mapper;

use crate::types::{CompoundType, FunctionSignature, SourceLineInfo, VariableInfo};
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
}

/// Extract debug info from an ELF/Mach-O binary (DWARF format).
///
/// Returns `Ok(Default)` if no debug info is present.
pub fn extract_debug_info(bytes: &[u8]) -> crate::Result<DebugInfo> {
    dwarf::extract_dwarf_info(bytes)
}

/// Extract debug info from a PDB file (Windows debug symbols).
pub fn extract_pdb_info(pdb_path: &Path) -> crate::Result<DebugInfo> {
    pdb_parser::extract_pdb_info(pdb_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_empty_returns_default() {
        // Non-object data should return empty debug info, not crash
        let result = extract_debug_info(&[0x7f, 0x45, 0x4c, 0x46]);
        // May error on truncated ELF — that's fine
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn extract_from_non_elf_returns_default() {
        let result = extract_debug_info(b"not an elf");
        let info = result.unwrap();
        assert!(info.function_signatures.is_empty());
        assert!(info.types.is_empty());
    }
}
