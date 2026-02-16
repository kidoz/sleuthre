use crate::Result;
use crate::arch::Architecture;
use crate::disasm::Disassembler;
use crate::loader::{Symbol, SymbolKind};
use crate::memory::{MemoryMap, Permissions};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};

/// Calling convention.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallingConvention {
    #[default]
    Unknown,
    Cdecl,
    Stdcall,
    Fastcall,
    SysVAmd64,
    Win64,
    ArmAapcs,
}

impl std::fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CallingConvention::Unknown => "unknown",
            CallingConvention::Cdecl => "cdecl",
            CallingConvention::Stdcall => "stdcall",
            CallingConvention::Fastcall => "fastcall",
            CallingConvention::SysVAmd64 => "sysv_amd64",
            CallingConvention::Win64 => "win64",
            CallingConvention::ArmAapcs => "arm_aapcs",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub start_address: u64,
    pub end_address: Option<u64>,
    #[serde(default)]
    pub calling_convention: CallingConvention,
    #[serde(default)]
    pub stack_frame_size: u64,
}

#[derive(Default)]
pub struct FunctionManager {
    pub functions: BTreeMap<u64, Function>,
}

impl FunctionManager {
    pub fn add_function(&mut self, func: Function) {
        self.functions.insert(func.start_address, func);
    }

    pub fn get_function(&self, address: u64) -> Option<&Function> {
        self.functions.get(&address)
    }

    /// Find the start address of the function that contains `addr`.
    pub fn find_function_containing(&self, addr: u64) -> Option<u64> {
        // Since functions is a BTreeMap, we can iterate in reverse to find the
        // closest start address <= addr.
        for (&start, func) in self.functions.iter().rev() {
            if addr >= start {
                if let Some(end) = func.end_address {
                    if addr < end {
                        return Some(start);
                    }
                } else {
                    // For now, assume unbounded functions continue until next func?
                    // Or return Some(start).
                    return Some(start);
                }
            }
        }
        None
    }

    /// Apply symbol names to discovered functions, or create new functions from symbols
    pub fn apply_symbols(&mut self, symbols: &[Symbol]) {
        for sym in symbols {
            if sym.kind != SymbolKind::Function || sym.address == 0 {
                continue;
            }
            let end_addr = if sym.size > 0 {
                Some(sym.address + sym.size)
            } else {
                None
            };
            if let Some(func) = self.functions.get_mut(&sym.address) {
                // Only rename auto-generated names
                if func.name.starts_with("sub_") || func.name == "entry_point" {
                    func.name = sym.name.clone();
                }
                if func.end_address.is_none() {
                    func.end_address = end_addr;
                }
            } else {
                self.add_function(Function {
                    name: sym.name.clone(),
                    start_address: sym.address,
                    end_address: end_addr,
                    calling_convention: CallingConvention::default(),
                    stack_frame_size: 0,
                });
            }
        }
    }

    /// Prologue-based function discovery with multi-architecture support
    pub fn discover_functions(
        &mut self,
        memory: &MemoryMap,
        _disasm: &Disassembler,
        entry_point: u64,
        arch: Architecture,
    ) -> Result<()> {
        // Always add entry point
        self.add_function(Function {
            name: "entry_point".to_string(),
            start_address: entry_point,
            end_address: None,
            calling_convention: CallingConvention::default(),
            stack_frame_size: 0,
        });

        for segment in &memory.segments {
            if !segment.permissions.contains(Permissions::EXECUTE) {
                continue;
            }
            let data = &segment.data;
            let mut offset = 0;
            while offset < data.len() {
                let addr = segment.start + offset as u64;
                let remaining = &data[offset..];

                if self.check_prologue(remaining, addr, arch) {
                    offset += 1;
                    continue;
                }

                offset += 1;
            }
        }
        Ok(())
    }

    /// Check for architecture-specific function prologues and add function if found.
    /// Returns true if a prologue was detected.
    fn check_prologue(&mut self, data: &[u8], addr: u64, arch: Architecture) -> bool {
        match arch {
            Architecture::X86_64 => self.check_x86_64_prologue(data, addr),
            Architecture::X86 => self.check_x86_prologue(data, addr),
            Architecture::Arm => self.check_arm_prologue(data, addr),
            Architecture::Arm64 => self.check_arm64_prologue(data, addr),
            Architecture::Mips | Architecture::Mips64 => self.check_mips_prologue(data, addr),
        }
    }

    fn check_x86_64_prologue(&mut self, data: &[u8], addr: u64) -> bool {
        // push rbp; mov rbp, rsp (55 48 89 e5)
        if data.len() >= 4
            && data[0] == 0x55
            && data[1] == 0x48
            && data[2] == 0x89
            && data[3] == 0xe5
        {
            self.add_discovered(addr);
            return true;
        }
        // push rbp; mov rbp, rsp with REX prefix variants (48 55 48 89 e5)
        if data.len() >= 5
            && data[0] == 0x48
            && data[1] == 0x55
            && data[2] == 0x48
            && data[3] == 0x89
            && data[4] == 0xe5
        {
            self.add_discovered(addr);
            return true;
        }
        // sub rsp, imm8 (48 83 ec XX) — leaf function prologue
        if data.len() >= 4 && data[0] == 0x48 && data[1] == 0x83 && data[2] == 0xec {
            self.add_discovered(addr);
            return true;
        }
        false
    }

    fn check_x86_prologue(&mut self, data: &[u8], addr: u64) -> bool {
        // push ebp; mov ebp, esp (55 89 e5)
        if data.len() >= 3 && data[0] == 0x55 && data[1] == 0x89 && data[2] == 0xe5 {
            self.add_discovered(addr);
            return true;
        }
        // push ebp; mov ebp, esp (alternate encoding 55 8b ec)
        if data.len() >= 3 && data[0] == 0x55 && data[1] == 0x8b && data[2] == 0xec {
            self.add_discovered(addr);
            return true;
        }
        false
    }

    fn check_arm_prologue(&mut self, data: &[u8], addr: u64) -> bool {
        if data.len() < 4 {
            return false;
        }
        // ARM mode: push {r11, lr} or push {fp, lr} or STMDB SP!, {..., LR}
        // Encoding: e92d4800 = push {r11, lr}
        // More general: e92dXXXX where bit 14 (LR) is set
        let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        // STMDB SP! (push) with LR: 0xe92d???? where register list includes LR (bit 14)
        if (word & 0xFFFF0000) == 0xe92d0000 && (word & (1 << 14)) != 0 {
            self.add_discovered(addr);
            return true;
        }
        // Thumb PUSH {... LR}: b5XX
        if data.len() >= 2 {
            let hw = u16::from_le_bytes([data[0], data[1]]);
            // PUSH with LR: 0xb5xx (bit 8 = LR)
            if (hw & 0xFF00) == 0xb500 {
                self.add_discovered(addr);
                return true;
            }
        }
        false
    }

    fn check_arm64_prologue(&mut self, data: &[u8], addr: u64) -> bool {
        if data.len() < 4 {
            return false;
        }
        let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        // STP X29, X30, [SP, #imm]! (pre-indexed, writeback)
        // Bits 31:22 = 1010100110, imm7 at 21:15, Rt2=x30(14:10), Rn=sp(9:5), Rt=x29(4:0)
        // Mask out imm7 (bits 21:15): mask = 0xFFC0_7FFF
        if (word & 0xFFC0_7FFF) == 0xA980_7BFD {
            self.add_discovered(addr);
            return true;
        }
        // STP X29, X30, [SP, #imm] (signed offset, no writeback)
        // Bits 25:23 = 010 instead of 011
        if (word & 0xFFC0_7FFF) == 0xA900_7BFD {
            self.add_discovered(addr);
            return true;
        }
        false
    }

    fn check_mips_prologue(&mut self, data: &[u8], addr: u64) -> bool {
        if data.len() < 8 {
            return false;
        }
        // MIPS: addiu sp, sp, -N followed by sw ra, N(sp)
        // addiu sp, sp, imm: 27bdXXXX (big-endian) or XXXX bd27 (little-endian)
        // Try little-endian first (most common MIPS Linux)
        let word0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let word1 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        // addiu $sp, $sp, -N: opcode=001001, rs=sp(29), rt=sp(29)
        // Encoding: 0x27BD???? (big-endian) = bits 31:16 = 0x27BD
        // In little-endian: upper 16 bits of word = 0x27BD
        let is_addiu_sp_le = (word0 >> 16) == 0x27BD;
        // sw $ra, N($sp): opcode=101011, base=sp(29), rt=ra(31)
        // Encoding: 0xAFBF???? (big-endian)
        let is_sw_ra_le = (word1 >> 16) == 0xAFBF;

        if is_addiu_sp_le && is_sw_ra_le {
            self.add_discovered(addr);
            return true;
        }

        // Try big-endian
        let word0_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let word1_be = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let is_addiu_sp_be = (word0_be >> 16) == 0x27BD;
        let is_sw_ra_be = (word1_be >> 16) == 0xAFBF;

        if is_addiu_sp_be && is_sw_ra_be {
            self.add_discovered(addr);
            return true;
        }

        false
    }

    fn add_discovered(&mut self, addr: u64) {
        if !self.functions.contains_key(&addr) {
            self.add_function(Function {
                name: format!("sub_{:x}", addr),
                start_address: addr,
                end_address: None,
                calling_convention: CallingConvention::default(),
                stack_frame_size: 0,
            });
        }
    }

    /// Recursive descent: discover functions by following call targets from known functions
    pub fn discover_functions_recursive(
        &mut self,
        memory: &MemoryMap,
        disasm: &Disassembler,
    ) -> Result<()> {
        let mut queue: VecDeque<u64> = self.functions.keys().copied().collect();
        let mut visited: HashSet<u64> = HashSet::new();

        while let Some(func_addr) = queue.pop_front() {
            if !visited.insert(func_addr) {
                continue;
            }

            let mut addr = func_addr;
            let mut instructions_seen = 0u32;
            let max_instructions = 10_000;

            while instructions_seen < max_instructions {
                let insn = match disasm.disassemble_one(memory, addr) {
                    Ok(i) => i,
                    Err(_) => break,
                };
                instructions_seen += 1;

                let mnemonic = insn.mnemonic.to_lowercase();

                // Check for call instructions — their targets are new functions
                if is_call_mnemonic(&mnemonic)
                    && let Some(target) = parse_target(&insn.op_str)
                    && memory.contains_address(target)
                    && !self.functions.contains_key(&target)
                {
                    self.add_function(Function {
                        name: format!("sub_{:x}", target),
                        start_address: target,
                        end_address: None,
                        calling_convention: CallingConvention::default(),
                        stack_frame_size: 0,
                    });
                    queue.push_back(target);
                }

                // Follow unconditional jumps within function
                if (mnemonic == "jmp" || mnemonic == "b")
                    && let Some(target) = parse_target(&insn.op_str)
                    && !visited.contains(&target)
                    && memory.contains_address(target)
                {
                    addr = target;
                    continue;
                }
                if mnemonic == "jmp" || mnemonic == "b" {
                    break;
                }

                // Conditional branches: follow both paths
                if is_conditional_branch(&mnemonic)
                    && let Some(target) = parse_target(&insn.op_str)
                    && memory.contains_address(target)
                    && !visited.contains(&target)
                {
                    let next = insn.address + insn.bytes.len() as u64;
                    self.scan_for_calls(memory, disasm, target, &mut queue, &mut visited);
                    addr = next;
                    continue;
                }

                if mnemonic == "ret" || mnemonic == "retn" || mnemonic == "bx" {
                    break;
                }

                if is_padding(&insn.mnemonic, &insn.bytes) {
                    break;
                }

                addr = insn.address + insn.bytes.len() as u64;
            }
        }

        Ok(())
    }

    /// Scan a code path for call instructions without treating the path itself as a function
    fn scan_for_calls(
        &mut self,
        memory: &MemoryMap,
        disasm: &Disassembler,
        start: u64,
        queue: &mut VecDeque<u64>,
        visited: &mut HashSet<u64>,
    ) {
        if !visited.insert(start) {
            return;
        }
        let mut addr = start;
        let mut count = 0u32;
        while count < 1000 {
            let insn = match disasm.disassemble_one(memory, addr) {
                Ok(i) => i,
                Err(_) => break,
            };
            count += 1;
            let mnemonic = insn.mnemonic.to_lowercase();

            if is_call_mnemonic(&mnemonic)
                && let Some(target) = parse_target(&insn.op_str)
                && memory.contains_address(target)
                && !self.functions.contains_key(&target)
            {
                self.add_function(Function {
                    name: format!("sub_{:x}", target),
                    start_address: target,
                    end_address: None,
                    calling_convention: CallingConvention::default(),
                    stack_frame_size: 0,
                });
                queue.push_back(target);
            }

            if mnemonic == "ret" || mnemonic == "retn" || mnemonic == "jmp" || mnemonic == "bx" {
                break;
            }
            if is_padding(&insn.mnemonic, &insn.bytes) {
                break;
            }
            addr = insn.address + insn.bytes.len() as u64;
        }
    }
}

impl FunctionManager {
    /// Detect calling conventions and stack frame sizes for all functions.
    pub fn analyze_calling_conventions(
        &mut self,
        memory: &MemoryMap,
        disasm: &Disassembler,
        arch: Architecture,
    ) {
        let addrs: Vec<u64> = self.functions.keys().copied().collect();
        for addr in addrs {
            let (cc, frame_size) = detect_calling_convention(memory, disasm, arch, addr);
            if let Some(func) = self.functions.get_mut(&addr) {
                func.calling_convention = cc;
                func.stack_frame_size = frame_size;
            }
        }
    }
}

/// Detect calling convention and stack frame size for a single function.
fn detect_calling_convention(
    memory: &MemoryMap,
    disasm: &Disassembler,
    arch: Architecture,
    addr: u64,
) -> (CallingConvention, u64) {
    let mut frame_size: u64 = 0;

    // Default convention based on architecture
    let default_cc = match arch {
        Architecture::X86_64 => CallingConvention::SysVAmd64,
        Architecture::X86 => CallingConvention::Cdecl,
        Architecture::Arm | Architecture::Arm64 => CallingConvention::ArmAapcs,
        _ => CallingConvention::Unknown,
    };

    // Disassemble the first ~20 instructions of the function to analyze prologue
    let Ok(insns) = disasm.disassemble_range(memory, addr, 100) else {
        return (default_cc, 0);
    };

    for insn in insns.iter().take(20) {
        let mn = insn.mnemonic.to_lowercase();
        let ops = &insn.op_str;

        // Detect stack frame allocation: sub rsp/esp, N
        if mn == "sub" {
            let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let reg = parts[0].to_lowercase();
                if reg == "rsp" || reg == "esp" || reg == "sp" {
                    let val_str = parts[1]
                        .trim()
                        .trim_start_matches("0x")
                        .trim_start_matches("0X");
                    if let Ok(val) = u64::from_str_radix(val_str, 16) {
                        frame_size = val;
                    } else if let Ok(val) = parts[1].trim().parse::<u64>() {
                        frame_size = val;
                    }
                }
            }
        }

        // ARM64: stp with sp decrement
        if mn == "stp"
            && ops.contains("sp")
            && let Some(start) = ops.find('#')
        {
            let num_str = &ops[start + 1..];
            let num_str = num_str
                .trim_start_matches('-')
                .split(']')
                .next()
                .unwrap_or("");
            if let Ok(val) = num_str.parse::<u64>() {
                frame_size = val;
            }
        }

        // Stop at first call or branch — we only care about the prologue
        if mn == "call" || mn == "bl" || mn == "ret" {
            break;
        }
    }

    (default_cc, frame_size)
}

fn is_call_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "call" | "bl" | "blr" | "jal")
}

fn parse_target(op_str: &str) -> Option<u64> {
    let cleaned = op_str
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches('#')
        .trim_start_matches("0x")
        .trim_start_matches("loc_");
    u64::from_str_radix(cleaned, 16).ok()
}

fn is_conditional_branch(mnemonic: &str) -> bool {
    // x86 conditional jumps
    if mnemonic.starts_with('j') && mnemonic != "jmp" {
        return true;
    }
    // ARM conditional branches
    if mnemonic.starts_with("b.")
        || (mnemonic.starts_with('b')
            && mnemonic.len() > 1
            && mnemonic != "bl"
            && mnemonic != "blr"
            && mnemonic != "bx")
    {
        return true;
    }
    // MIPS branches
    matches!(mnemonic, "beq" | "bne" | "bgtz" | "blez" | "bltz" | "bgez")
}

fn is_padding(mnemonic: &str, bytes: &[u8]) -> bool {
    let mn = mnemonic.to_lowercase();
    // x86 NOP
    if mn == "nop" {
        return true;
    }
    // x86 INT3 (0xCC)
    if bytes == [0xCC] {
        return true;
    }
    // Multi-byte NOP (0x66 0x90)
    if bytes.len() >= 2 && bytes[0] == 0x66 && bytes[1] == 0x90 {
        return true;
    }
    false
}
