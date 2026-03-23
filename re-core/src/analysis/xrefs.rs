use crate::Result;
use crate::disasm::Disassembler;
use crate::memory::MemoryMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XrefType {
    Call,
    Jump,
    DataRead,
    DataWrite,
    StringRef,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Xref {
    pub from_address: u64,
    pub to_address: u64,
    pub xref_type: XrefType,
}

pub struct XrefManager {
    pub to_address_xrefs: HashMap<u64, Vec<Xref>>,
    pub from_address_xrefs: HashMap<u64, Vec<Xref>>,
}

impl Default for XrefManager {
    fn default() -> Self {
        Self::new()
    }
}

impl XrefManager {
    pub fn new() -> Self {
        Self {
            to_address_xrefs: HashMap::new(),
            from_address_xrefs: HashMap::new(),
        }
    }

    pub fn add_xref(&mut self, xref: Xref) {
        self.to_address_xrefs
            .entry(xref.to_address)
            .or_default()
            .push(xref);
        self.from_address_xrefs
            .entry(xref.from_address)
            .or_default()
            .push(xref);
    }

    pub fn scan_xrefs(
        &mut self,
        memory: &MemoryMap,
        disasm: &Disassembler,
        functions: &crate::analysis::functions::FunctionManager,
    ) -> Result<()> {
        self.scan_all(memory, disasm, functions, &[])
    }

    /// Unified single-pass scan: collects code xrefs, data xrefs, and string
    /// xrefs in one disassembly walk. Pass an empty slice for `strings` to
    /// skip string-ref detection.
    pub fn scan_all(
        &mut self,
        memory: &MemoryMap,
        disasm: &Disassembler,
        functions: &crate::analysis::functions::FunctionManager,
        strings: &[crate::analysis::strings::DiscoveredString],
    ) -> Result<()> {
        self.to_address_xrefs.clear();
        self.from_address_xrefs.clear();

        let string_addrs: std::collections::HashSet<u64> =
            strings.iter().map(|s| s.address).collect();

        let func_starts: Vec<u64> = functions.functions.keys().copied().collect();

        for (idx, &start_addr) in func_starts.iter().enumerate() {
            let end_boundary = func_starts
                .get(idx + 1)
                .copied()
                .unwrap_or(start_addr + 0x10000);

            let mut addr = start_addr;
            while addr < end_boundary {
                let insn = match disasm.disassemble_one(memory, addr) {
                    Ok(i) => i,
                    Err(_) => break,
                };

                let mnemonic = insn.mnemonic.to_lowercase();

                // Code xrefs: call/jump targets
                if mnemonic == "call" || mnemonic.starts_with('j') {
                    if let Some(target_addr) = parse_address(&insn.op_str) {
                        let xref_type = if mnemonic == "call" {
                            XrefType::Call
                        } else {
                            XrefType::Jump
                        };
                        self.add_xref(Xref {
                            from_address: insn.address,
                            to_address: target_addr,
                            xref_type,
                        });
                    } else if insn.op_str.contains('[')
                        && let Some(target_addr) = parse_hex_from_bracket(&insn.op_str)
                        && memory.contains_address(target_addr)
                    {
                        let xref_type = if mnemonic == "call" {
                            XrefType::Call
                        } else {
                            XrefType::Jump
                        };
                        self.add_xref(Xref {
                            from_address: insn.address,
                            to_address: target_addr,
                            xref_type,
                        });
                    }
                }

                // Data xrefs
                self.extract_data_xrefs(&insn.mnemonic, &insn.op_str, insn.address, memory);

                // String xrefs (only when string addresses are provided)
                if !string_addrs.is_empty() {
                    if (mnemonic == "lea" || mnemonic == "adr" || mnemonic == "adrp")
                        && let Some(target) = self.extract_effective_address(&insn, addr)
                        && string_addrs.contains(&target)
                    {
                        self.add_xref(Xref {
                            from_address: insn.address,
                            to_address: target,
                            xref_type: XrefType::StringRef,
                        });
                    }
                    if (mnemonic == "mov" || mnemonic == "movabs")
                        && let Some(target) = parse_address_from_operands(&insn.op_str)
                        && string_addrs.contains(&target)
                    {
                        self.add_xref(Xref {
                            from_address: insn.address,
                            to_address: target,
                            xref_type: XrefType::StringRef,
                        });
                    }
                }

                if mnemonic == "ret" || mnemonic == "retn" {
                    break;
                }
                addr += insn.bytes.len() as u64;
            }
        }
        Ok(())
    }

    fn extract_data_xrefs(
        &mut self,
        mnemonic: &str,
        op_str: &str,
        from_addr: u64,
        memory: &MemoryMap,
    ) {
        // Look for [0xHEX] patterns in operand string
        let mut remaining = op_str;
        while let Some(bracket_start) = remaining.find('[') {
            if let Some(bracket_end) = remaining[bracket_start..].find(']') {
                let inner = &remaining[bracket_start + 1..bracket_start + bracket_end];
                if let Some(target) = parse_hex_from_bracket(inner)
                    && memory.contains_address(target)
                {
                    let mn = mnemonic.to_lowercase();
                    let xref_type = if is_write_mnemonic(&mn) {
                        XrefType::DataWrite
                    } else {
                        XrefType::DataRead
                    };
                    self.add_xref(Xref {
                        from_address: from_addr,
                        to_address: target,
                        xref_type,
                    });
                }
                remaining = &remaining[bracket_start + bracket_end + 1..];
            } else {
                break;
            }
        }
    }

    /// Scan for string references in disassembled code.
    /// For each discovered string, find instructions that reference its address
    /// via RIP-relative addressing (lea reg, [rip + offset]) or immediate loads.
    pub fn scan_string_xrefs(
        &mut self,
        memory: &MemoryMap,
        disasm: &Disassembler,
        functions: &crate::analysis::functions::FunctionManager,
        strings: &[crate::analysis::strings::DiscoveredString],
    ) -> Result<()> {
        // Build a set of string addresses for quick lookup
        let string_addrs: std::collections::HashSet<u64> =
            strings.iter().map(|s| s.address).collect();

        let func_starts: Vec<u64> = functions.functions.keys().copied().collect();

        for (idx, &start_addr) in func_starts.iter().enumerate() {
            let end_boundary = func_starts
                .get(idx + 1)
                .copied()
                .unwrap_or(start_addr + 0x10000);
            let mut addr = start_addr;
            while addr < end_boundary {
                let insn = match disasm.disassemble_one(memory, addr) {
                    Ok(i) => i,
                    Err(_) => break,
                };
                let mn = insn.mnemonic.to_lowercase();

                // Check for LEA instructions (RIP-relative string loading)
                // Pattern: lea reg, [rip + 0x????] where the effective address is a string
                if (mn == "lea" || mn == "adr" || mn == "adrp")
                    && let Some(target) = self.extract_effective_address(&insn, addr)
                    && string_addrs.contains(&target)
                {
                    self.add_xref(Xref {
                        from_address: insn.address,
                        to_address: target,
                        xref_type: XrefType::StringRef,
                    });
                }

                // Also check for immediate address loads that point to strings
                // Pattern: mov reg, 0x???? where the immediate is a string address
                if (mn == "mov" || mn == "movabs")
                    && let Some(target) = parse_address_from_operands(&insn.op_str)
                    && string_addrs.contains(&target)
                {
                    self.add_xref(Xref {
                        from_address: insn.address,
                        to_address: target,
                        xref_type: XrefType::StringRef,
                    });
                }

                if mn == "ret" || mn == "retn" {
                    break;
                }
                addr += insn.bytes.len() as u64;
            }
        }
        Ok(())
    }

    fn extract_effective_address(
        &self,
        insn: &crate::disasm::Instruction,
        insn_addr: u64,
    ) -> Option<u64> {
        // Parse [rip + 0xNNNN] or [pc, #NNNN] patterns
        let op = &insn.op_str;
        if let Some(bracket_start) = op.find('[')
            && let Some(bracket_end) = op[bracket_start..].find(']')
        {
            let inner = &op[bracket_start + 1..bracket_start + bracket_end];
            // RIP-relative: [rip + 0xNNNN]
            if inner.contains("rip") {
                if let Some(plus_pos) = inner.find('+') {
                    let offset_str = inner[plus_pos + 1..].trim().trim_start_matches("0x");
                    if let Ok(offset) = u64::from_str_radix(offset_str, 16) {
                        // RIP-relative uses next instruction address as base
                        return Some(insn_addr + insn.bytes.len() as u64 + offset);
                    }
                }
                if let Some(minus_pos) = inner.find('-') {
                    let offset_str = inner[minus_pos + 1..].trim().trim_start_matches("0x");
                    if let Ok(offset) = u64::from_str_radix(offset_str, 16) {
                        return Some(insn_addr + insn.bytes.len() as u64 - offset);
                    }
                }
            }
        }
        None
    }
}

fn is_write_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "mov"
            | "movs"
            | "stos"
            | "push"
            | "xchg"
            | "add"
            | "sub"
            | "inc"
            | "dec"
            | "and"
            | "or"
            | "xor"
            | "not"
            | "neg"
    )
}

fn parse_address(op_str: &str) -> Option<u64> {
    let cleaned = op_str
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("loc_");
    u64::from_str_radix(cleaned, 16).ok()
}

fn parse_hex_from_bracket(inner: &str) -> Option<u64> {
    // Try to find a standalone hex value like "0x401000" or just "401000"
    // within bracket contents like "rip + 0x401000" or plain "0x401000"
    for token in inner.split(|c: char| c == '+' || c == '-' || c == '*' || c.is_whitespace()) {
        let trimmed = token.trim().trim_start_matches("0x");
        if trimmed.is_empty() {
            continue;
        }
        // Must look like a large hex address (at least 5 hex digits to avoid register offsets)
        if trimmed.len() >= 5
            && let Ok(val) = u64::from_str_radix(trimmed, 16)
        {
            return Some(val);
        }
    }
    None
}

fn parse_address_from_operands(op_str: &str) -> Option<u64> {
    // Look for the last operand that looks like a hex address
    for part in op_str.split(',') {
        let trimmed = part.trim();
        if let Some(hex) = trimmed.strip_prefix("0x")
            && hex.len() >= 5
            && let Ok(val) = u64::from_str_radix(hex, 16)
        {
            return Some(val);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_address_hex_variants() {
        assert_eq!(parse_address("0x401000"), Some(0x401000));
        assert_eq!(parse_address("401000"), Some(0x401000));
        assert_eq!(parse_address("loc_401000"), Some(0x401000));
        assert_eq!(parse_address("rax"), None); // register, not an address
    }

    #[test]
    fn parse_hex_from_bracket_works() {
        assert_eq!(parse_hex_from_bracket("0x401000"), Some(0x401000));
        assert_eq!(parse_hex_from_bracket("rip + 0x401000"), Some(0x401000));
        assert_eq!(parse_hex_from_bracket("rax"), None); // too short
        assert_eq!(parse_hex_from_bracket("0x10"), None); // too short
    }

    #[test]
    fn write_mnemonic_detection() {
        assert!(is_write_mnemonic("mov"));
        assert!(is_write_mnemonic("push"));
        assert!(!is_write_mnemonic("cmp"));
        assert!(!is_write_mnemonic("test"));
    }

    #[test]
    fn parse_address_from_operands_works() {
        // Standard hex immediate
        assert_eq!(parse_address_from_operands("rax, 0x402000"), Some(0x402000));
        // Multiple operands, first is register
        assert_eq!(parse_address_from_operands("rdi, 0x601234"), Some(0x601234));
        // Short hex values should not match (not a plausible address)
        assert_eq!(parse_address_from_operands("rax, 0x10"), None);
        // No hex at all
        assert_eq!(parse_address_from_operands("rax, rbx"), None);
        // Just a register
        assert_eq!(parse_address_from_operands("rax"), None);
    }

    #[test]
    fn string_xref_type_variant() {
        // Verify the StringRef variant exists and can be created/compared
        let xref = Xref {
            from_address: 0x1000,
            to_address: 0x2000,
            xref_type: XrefType::StringRef,
        };
        assert_eq!(xref.xref_type, XrefType::StringRef);
        assert_ne!(xref.xref_type, XrefType::Call);
    }

    #[test]
    fn string_xref_manager_add_and_lookup() {
        let mut mgr = XrefManager::new();
        mgr.add_xref(Xref {
            from_address: 0x401000,
            to_address: 0x602000,
            xref_type: XrefType::StringRef,
        });
        let to_xrefs = mgr.to_address_xrefs.get(&0x602000).unwrap();
        assert_eq!(to_xrefs.len(), 1);
        assert_eq!(to_xrefs[0].xref_type, XrefType::StringRef);
        assert_eq!(to_xrefs[0].from_address, 0x401000);

        let from_xrefs = mgr.from_address_xrefs.get(&0x401000).unwrap();
        assert_eq!(from_xrefs.len(), 1);
        assert_eq!(from_xrefs[0].xref_type, XrefType::StringRef);
    }

    #[test]
    fn extract_effective_address_rip_relative() {
        let mgr = XrefManager::new();
        // Simulate a LEA instruction: lea rdi, [rip + 0x2000]
        // instruction at 0x1000, 7 bytes long
        let insn = crate::disasm::Instruction {
            address: 0x1000,
            bytes: vec![0x48, 0x8d, 0x3d, 0x00, 0x20, 0x00, 0x00], // 7 bytes
            mnemonic: "lea".to_string(),
            op_str: "rdi, [rip + 0x2000]".to_string(),
            groups: vec![],
        };
        let result = mgr.extract_effective_address(&insn, 0x1000);
        // Expected: 0x1000 + 7 + 0x2000 = 0x3007
        assert_eq!(result, Some(0x3007));
    }

    #[test]
    fn extract_effective_address_rip_minus() {
        let mgr = XrefManager::new();
        let insn = crate::disasm::Instruction {
            address: 0x5000,
            bytes: vec![0x48, 0x8d, 0x3d, 0x00, 0x10, 0x00, 0x00], // 7 bytes
            mnemonic: "lea".to_string(),
            op_str: "rdi, [rip - 0x1000]".to_string(),
            groups: vec![],
        };
        let result = mgr.extract_effective_address(&insn, 0x5000);
        // Expected: 0x5000 + 7 - 0x1000 = 0x4007
        assert_eq!(result, Some(0x4007));
    }

    #[test]
    fn extract_effective_address_no_rip() {
        let mgr = XrefManager::new();
        let insn = crate::disasm::Instruction {
            address: 0x1000,
            bytes: vec![0x48, 0x8d, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00],
            mnemonic: "lea".to_string(),
            op_str: "rax, [rbx + 0x10]".to_string(),
            groups: vec![],
        };
        let result = mgr.extract_effective_address(&insn, 0x1000);
        assert_eq!(result, None);
    }
}
