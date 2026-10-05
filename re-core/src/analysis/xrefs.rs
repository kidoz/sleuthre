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
        let ranges: Vec<(u64, u64)> = func_starts
            .iter()
            .enumerate()
            .map(|(idx, &start_addr)| {
                let end_boundary = func_starts
                    .get(idx + 1)
                    .copied()
                    .unwrap_or(start_addr + 0x10000);
                (start_addr, end_boundary)
            })
            .collect();

        // Each function's range is walked independently, so the scan is split
        // across threads (each with its own `Disassembler`, since Capstone is
        // `!Send`). Replaying the per-chunk results in range order reproduces
        // the sequential insertion order exactly.
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(ranges.len())
            .max(1);
        let chunk_len = ranges.len().div_ceil(workers).max(1);
        let arch = disasm.arch;
        let string_addrs = &string_addrs;
        let per_chunk: Vec<Vec<Xref>> = std::thread::scope(|scope| {
            let handles: Vec<_> = ranges
                .chunks(chunk_len)
                .map(|chunk| {
                    scope.spawn(move || {
                        let mut out = Vec::new();
                        let Ok(d) = Disassembler::new(arch) else {
                            return out;
                        };
                        for &(start, end) in chunk {
                            collect_range_xrefs(memory, &d, start, end, string_addrs, &mut out);
                        }
                        out
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_default())
                .collect()
        });

        for xref in per_chunk.into_iter().flatten() {
            self.add_xref(xref);
        }
        Ok(())
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
                let insn = match disasm.disassemble_one_fast(memory, addr) {
                    Ok(i) => i,
                    Err(_) => break,
                };
                let mn = insn.mnemonic.to_lowercase();

                // Check for LEA instructions (RIP-relative string loading)
                // Pattern: lea reg, [rip + 0x????] where the effective address is a string
                if (mn == "lea" || mn == "adr" || mn == "adrp")
                    && let Some(target) =
                        memory_operand_address(&insn.op_str, insn.address, insn.bytes.len())
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
}

/// The absolute address a statically-known memory operand refers to.
///
/// * `[0x1234]` — absolute displacement.
/// * `[rip + 0x10]` / `[rip - 0x10]` — relative to the next instruction.
///
/// Indexed (`[rip + rax*4]`), register-based (`[rbp - 8]`) and segment-relative
/// (`gs:[0x30]`, `fs:[...]`) references depend on runtime values and have no
/// static target. Resolving RIP-relative operands matters on x86-64, where
/// globals and import slots are almost always addressed this way.
fn memory_operand_address(op_str: &str, insn_addr: u64, insn_len: usize) -> Option<u64> {
    let bracket_start = op_str.find('[')?;
    let bracket_end = bracket_start + op_str[bracket_start..].find(']')?;
    let inner = op_str[bracket_start + 1..bracket_end].trim();
    let lower = crate::disasm::lower_text(inner);

    let prefix = crate::disasm::lower_text(&op_str[..bracket_start]);
    let prefix = prefix.trim_end();
    if prefix.ends_with("gs:") || prefix.ends_with("fs:") {
        return None;
    }

    if lower.contains("rip") {
        let next_ip = insn_addr.wrapping_add(insn_len as u64);
        let rest = lower.replacen("rip", "", 1);
        let rest = rest.trim();
        if rest.is_empty() {
            return Some(next_ip);
        }
        let sign = match rest.as_bytes()[0] {
            b'+' => 1i64,
            b'-' => -1i64,
            _ => return None,
        };
        let value = parse_hex_value(rest[1..].trim())?;
        return Some(if sign > 0 {
            next_ip.wrapping_add(value)
        } else {
            next_ip.wrapping_sub(value)
        });
    }

    parse_hex_value(&lower)
}

/// Parse a capstone-printed displacement ("0x1234" or decimal digits).
fn parse_hex_value(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && !s.is_empty() {
        u64::from_str_radix(s, 16).ok()
    } else {
        None
    }
}

/// Append the data xrefs implied by one instruction's operands.
fn collect_data_xrefs(
    mnemonic: &str,
    op_str: &str,
    from_addr: u64,
    insn_len: usize,
    memory: &MemoryMap,
    out: &mut Vec<Xref>,
) {
    let Some(target) = memory_operand_address(op_str, from_addr, insn_len) else {
        return;
    };
    if !memory.contains_address(target) {
        return;
    }
    let mn = crate::disasm::lower_text(mnemonic);
    // Intel syntax puts the destination first: `mov [mem], rax` writes the
    // address, `mov rax, [mem]` only reads it. Testing the mnemonic alone
    // would label every load a write.
    let dest_is_memory = op_str
        .split(',')
        .next()
        .is_some_and(|first| first.contains('['));
    let xref_type = if dest_is_memory && is_write_mnemonic(&mn) {
        XrefType::DataWrite
    } else {
        XrefType::DataRead
    };
    out.push(Xref {
        from_address: from_addr,
        to_address: target,
        xref_type,
    });
}

/// Walk `[start, end)` and append every xref found, in instruction order.
fn collect_range_xrefs(
    memory: &MemoryMap,
    disasm: &Disassembler,
    start: u64,
    end: u64,
    string_addrs: &std::collections::HashSet<u64>,
    out: &mut Vec<Xref>,
) {
    let mut addr = start;
    while addr < end {
        let insn = match disasm.disassemble_one_fast(memory, addr) {
            Ok(i) => i,
            Err(_) => break,
        };

        let mnemonic = crate::disasm::lower_text(&insn.mnemonic);

        // Code xrefs: call/jump targets
        if mnemonic == "call" || mnemonic.starts_with('j') {
            if let Some(target_addr) = parse_address(&insn.op_str) {
                let xref_type = if mnemonic == "call" {
                    XrefType::Call
                } else {
                    XrefType::Jump
                };
                out.push(Xref {
                    from_address: insn.address,
                    to_address: target_addr,
                    xref_type,
                });
            } else if let Some(target_addr) =
                memory_operand_address(&insn.op_str, insn.address, insn.bytes.len())
                && memory.contains_address(target_addr)
            {
                let xref_type = if mnemonic == "call" {
                    XrefType::Call
                } else {
                    XrefType::Jump
                };
                out.push(Xref {
                    from_address: insn.address,
                    to_address: target_addr,
                    xref_type,
                });
            }
        }

        // Data xrefs
        collect_data_xrefs(
            &insn.mnemonic,
            &insn.op_str,
            insn.address,
            insn.bytes.len(),
            memory,
            out,
        );

        // String xrefs (only when string addresses are provided)
        if !string_addrs.is_empty() {
            if (mnemonic == "lea" || mnemonic == "adr" || mnemonic == "adrp")
                && let Some(target) =
                    memory_operand_address(&insn.op_str, insn.address, insn.bytes.len())
                && string_addrs.contains(&target)
            {
                out.push(Xref {
                    from_address: insn.address,
                    to_address: target,
                    xref_type: XrefType::StringRef,
                });
            }
            if (mnemonic == "mov" || mnemonic == "movabs")
                && let Some(target) = parse_address_from_operands(&insn.op_str)
                && string_addrs.contains(&target)
            {
                out.push(Xref {
                    from_address: insn.address,
                    to_address: target,
                    xref_type: XrefType::StringRef,
                });
            }
        }

        // Do not stop at a `ret`: multi-exit functions have code (and xrefs)
        // after their first return; the walk is already bounded by `end`.
        addr += insn.bytes.len() as u64;
    }
}

/// Mnemonics that write their (memory) destination operand. `push`/`pop` are
/// deliberately absent: `push [mem]` reads the address, and treating it as a
/// write would mislabel the reference.
fn is_write_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "mov"
            | "movs"
            | "stos"
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
    fn write_mnemonic_detection() {
        assert!(is_write_mnemonic("mov"));
        assert!(!is_write_mnemonic("push"), "push reads its memory source");
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
    fn memory_operand_address_rip_relative() {
        // lea rdi, [rip + 0x2000] at 0x1000, 7 bytes: 0x1000 + 7 + 0x2000.
        assert_eq!(
            memory_operand_address("rdi, [rip + 0x2000]", 0x1000, 7),
            Some(0x3007)
        );
        // mov rax, qword ptr [rip - 0x1000] at 0x5000, 7 bytes.
        assert_eq!(
            memory_operand_address("rax, qword ptr [rip - 0x1000]", 0x5000, 7),
            Some(0x4007)
        );
    }

    #[test]
    fn memory_operand_address_rejects_runtime_bases() {
        // Register-relative, indexed and segment-relative references have no
        // static target.
        assert_eq!(memory_operand_address("rax, [rbx + 0x10]", 0x1000, 4), None);
        assert_eq!(
            memory_operand_address("rcx, [rip + rax*4]", 0x1000, 7),
            None
        );
        assert_eq!(
            memory_operand_address("rax, qword ptr gs:[0x30]", 0x1000, 9),
            None
        );
        assert_eq!(
            memory_operand_address("rax, qword ptr [rbp - 8]", 0x1000, 4),
            None
        );
    }

    #[test]
    fn memory_operand_address_absolute_displacement() {
        // mov rax, qword ptr [0x1234] — no base register.
        assert_eq!(
            memory_operand_address("rax, qword ptr [0x1234]", 0x1000, 8),
            Some(0x1234)
        );
    }

    #[test]
    fn data_xref_direction_follows_operand_position() {
        use crate::memory::{MemorySegment, Permissions};
        let mut text = vec![0x90u8; 32];
        // mov [rip + 0xff9], rax at 0x1000 (writes 0x2000)
        text[..7].copy_from_slice(&[0x48, 0x89, 0x05, 0xF9, 0x0F, 0x00, 0x00]);
        // mov rax, [rip + 0xff2] at 0x1007 (reads 0x2000)
        text[7..14].copy_from_slice(&[0x48, 0x8B, 0x05, 0xF2, 0x0F, 0x00, 0x00]);

        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: ".text".to_string(),
            start: 0x1000,
            size: text.len() as u64,
            data: text,
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();
        map.add_segment(MemorySegment {
            name: ".data".to_string(),
            start: 0x2000,
            size: 8,
            data: vec![0; 8],
            permissions: Permissions::READ | Permissions::WRITE,
        })
        .unwrap();

        let disasm = crate::disasm::Disassembler::new(crate::arch::Architecture::X86_64).unwrap();
        let mut out = Vec::new();
        collect_range_xrefs(&map, &disasm, 0x1000, 0x100e, &Default::default(), &mut out);

        assert!(out.iter().any(|x| x.from_address == 0x1000
            && x.to_address == 0x2000
            && x.xref_type == XrefType::DataWrite));
        assert!(out.iter().any(|x| x.from_address == 0x1007
            && x.to_address == 0x2000
            && x.xref_type == XrefType::DataRead));
    }

    #[test]
    fn call_through_rip_relative_iat_slot_produces_call_xref() {
        use crate::memory::MemorySegment;
        let mut map = MemoryMap::default();
        // Instruction at 0x1000 (6 bytes): call qword ptr [rip + 0xffa] →
        // slot at 0x2000, which is mapped in a data segment. The code segment
        // is padded past capstone's 15-byte read window.
        let mut text = vec![0x90u8; 16];
        text[..6].copy_from_slice(&[0xFF, 0x15, 0xFA, 0x0F, 0x00, 0x00]);
        map.add_segment(MemorySegment {
            name: ".text".to_string(),
            start: 0x1000,
            size: text.len() as u64,
            data: text,
            permissions: crate::memory::Permissions::READ | crate::memory::Permissions::EXECUTE,
        })
        .unwrap();
        map.add_segment(MemorySegment {
            name: ".idata".to_string(),
            start: 0x2000,
            size: 8,
            data: vec![0; 8],
            permissions: crate::memory::Permissions::READ | crate::memory::Permissions::WRITE,
        })
        .unwrap();

        let disasm = crate::disasm::Disassembler::new(crate::arch::Architecture::X86_64).unwrap();
        let mut out = Vec::new();
        collect_range_xrefs(&map, &disasm, 0x1000, 0x1006, &Default::default(), &mut out);

        // The same instruction also reads the slot, so a Call and a DataRead
        // xref are both expected.
        let call = out
            .iter()
            .find(|x| x.xref_type == XrefType::Call)
            .expect("call xref through the IAT slot");
        assert_eq!(call.from_address, 0x1000);
        assert_eq!(call.to_address, 0x2000);
        assert!(
            out.iter()
                .any(|x| x.xref_type == XrefType::DataRead && x.to_address == 0x2000)
        );
    }
}
