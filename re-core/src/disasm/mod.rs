use crate::Result;
use crate::arch::Architecture;
use crate::error::Error;
use crate::memory::MemoryMap;
use capstone::prelude::*;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Lowercase instruction text without allocating when it is already lowercase.
///
/// Capstone emits lowercase mnemonics, so the borrowed path is taken for
/// essentially every instruction — worth avoiding a heap allocation for, given
/// the decode loops run over millions of instructions. Non-ASCII input falls
/// back to the Unicode-aware `to_lowercase`, so results match it exactly.
pub fn lower_text(s: &str) -> Cow<'_, str> {
    if !s.is_ascii() {
        Cow::Owned(s.to_lowercase())
    } else if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
    pub groups: Vec<String>,
}

/// A borrowed view of one decoded instruction, valid only for the duration of
/// the [`Disassembler::decode_one`] callback that produced it.
#[derive(Debug, Clone, Copy)]
pub struct InstructionRef<'a> {
    pub address: u64,
    pub bytes: &'a [u8],
    pub mnemonic: &'a str,
    pub op_str: &'a str,
}

pub struct Disassembler {
    cs: Capstone,
    /// A second handle with Capstone's detail mode off. Decoding fills the
    /// detail structures eagerly, which is pure overhead for the analysis
    /// passes that only read mnemonic/operand text — they use this handle and
    /// get instructions with an empty `groups`.
    cs_no_detail: Capstone,
    pub arch: Architecture,
}

impl Disassembler {
    pub fn new(arch: Architecture) -> Result<Self> {
        Ok(Self {
            cs: Self::build_capstone(arch, true)?,
            cs_no_detail: Self::build_capstone(arch, false)?,
            arch,
        })
    }

    fn build_capstone(arch: Architecture, detail: bool) -> Result<Capstone> {
        let cs = match arch {
            Architecture::X86 => Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode32)
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .detail(detail)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode64)
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .detail(detail)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::Arm => Capstone::new()
                .arm()
                .mode(capstone::arch::arm::ArchMode::Arm)
                .detail(detail)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::Arm64 => Capstone::new()
                .arm64()
                .mode(capstone::arch::arm64::ArchMode::Arm)
                .detail(detail)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::Mips => Capstone::new()
                .mips()
                .mode(capstone::arch::mips::ArchMode::Mips32)
                .detail(detail)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::Mips64 => Capstone::new()
                .mips()
                .mode(capstone::arch::mips::ArchMode::Mips64)
                .detail(detail)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::RiscV32 => Capstone::new()
                .riscv()
                .mode(capstone::arch::riscv::ArchMode::RiscV32)
                .extra_mode(
                    [capstone::arch::riscv::ArchExtraMode::RiscVC]
                        .iter()
                        .copied(),
                )
                .detail(detail)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::RiscV64 => Capstone::new()
                .riscv()
                .mode(capstone::arch::riscv::ArchMode::RiscV64)
                .extra_mode(
                    [capstone::arch::riscv::ArchExtraMode::RiscVC]
                        .iter()
                        .copied(),
                )
                .detail(detail)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
        };

        Ok(cs)
    }

    pub fn disassemble_one(&self, memory: &MemoryMap, address: u64) -> Result<Instruction> {
        let data = memory
            .get_data(address, 15)
            .ok_or_else(|| Error::Analysis(format!("Failed to read memory at 0x{:x}", address)))?;

        let insns = self
            .cs
            .disasm_count(data, address, 1)
            .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?;

        if let Some(insn) = insns.first() {
            let detail = self
                .cs
                .insn_detail(insn)
                .map_err(|e| Error::Analysis(e.to_string()))?;
            let groups = detail
                .groups()
                .iter()
                .map(|g| self.cs.group_name(*g).unwrap_or_default())
                .collect();

            Ok(Instruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                op_str: insn.op_str().unwrap_or("").to_string(),
                groups,
            })
        } else {
            Err(Error::Analysis(
                "Failed to disassemble instruction".to_string(),
            ))
        }
    }

    /// Decode one instruction and hand a borrowed view of it to `f`.
    ///
    /// Nothing is allocated for the instruction, unlike
    /// [`Self::disassemble_one_fast`], which copies the bytes and both text
    /// fields onto the heap. The walking passes decode millions of
    /// instructions and only need to classify each one, so they use this.
    pub fn decode_one<T>(
        &self,
        memory: &MemoryMap,
        address: u64,
        f: impl FnOnce(InstructionRef<'_>) -> T,
    ) -> Result<T> {
        let data = memory
            .get_data(address, 15)
            .ok_or_else(|| Error::Analysis(format!("Failed to read memory at 0x{:x}", address)))?;

        let insns = self
            .cs_no_detail
            .disasm_count(data, address, 1)
            .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?;

        let insn = insns
            .first()
            .ok_or_else(|| Error::Analysis("Failed to disassemble instruction".to_string()))?;
        Ok(f(InstructionRef {
            address: insn.address(),
            bytes: insn.bytes(),
            mnemonic: insn.mnemonic().unwrap_or(""),
            op_str: insn.op_str().unwrap_or(""),
        }))
    }

    /// Like [`Self::disassemble_one`] but skips Capstone's detail pass. The
    /// returned instruction has an empty `groups`; use the detailed variant
    /// when that field is read.
    pub fn disassemble_one_fast(&self, memory: &MemoryMap, address: u64) -> Result<Instruction> {
        let data = memory
            .get_data(address, 15)
            .ok_or_else(|| Error::Analysis(format!("Failed to read memory at 0x{:x}", address)))?;

        let insns = self
            .cs_no_detail
            .disasm_count(data, address, 1)
            .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?;

        let insn = insns
            .first()
            .ok_or_else(|| Error::Analysis("Failed to disassemble instruction".to_string()))?;
        Ok(Instruction {
            address: insn.address(),
            bytes: insn.bytes().to_vec(),
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            op_str: insn.op_str().unwrap_or("").to_string(),
            groups: Vec::new(),
        })
    }

    /// Like [`Self::disassemble_range`] but skips Capstone's detail pass. The
    /// returned instructions have an empty `groups`; use the detailed variant
    /// when that field is read.
    pub fn disassemble_range_fast(
        &self,
        memory: &MemoryMap,
        address: u64,
        size: usize,
    ) -> Result<Vec<Instruction>> {
        let data = memory
            .get_data(address, size)
            .ok_or_else(|| Error::Analysis(format!("Failed to read memory at 0x{:x}", address)))?;

        let insns = self
            .cs_no_detail
            .disasm_all(data, address)
            .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?;

        Ok(insns
            .iter()
            .map(|insn| Instruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                op_str: insn.op_str().unwrap_or("").to_string(),
                groups: Vec::new(),
            })
            .collect())
    }

    pub fn disassemble_range(
        &self,
        memory: &MemoryMap,
        address: u64,
        size: usize,
    ) -> Result<Vec<Instruction>> {
        let data = memory
            .get_data(address, size)
            .ok_or_else(|| Error::Analysis(format!("Failed to read memory at 0x{:x}", address)))?;

        let insns = self
            .cs
            .disasm_all(data, address)
            .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?;

        let mut results = Vec::new();
        for insn in insns.iter() {
            let detail = self
                .cs
                .insn_detail(insn)
                .map_err(|e| Error::Analysis(e.to_string()))?;
            let groups = detail
                .groups()
                .iter()
                .map(|g| self.cs.group_name(*g).unwrap_or_default())
                .collect();

            results.push(Instruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                op_str: insn.op_str().unwrap_or("").to_string(),
                groups,
            });
        }
        Ok(results)
    }

    /// Disassemble a raw byte slice that is not part of any `MemoryMap`.
    ///
    /// Useful for one-off buffers — for example, the `.text` section of a
    /// freshly-compiled object file during recompile-diff verification.
    pub fn disassemble_bytes(&self, data: &[u8], base: u64) -> Result<Vec<Instruction>> {
        let insns = self
            .cs
            .disasm_all(data, base)
            .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?;
        let mut results = Vec::new();
        for insn in insns.iter() {
            let detail = self
                .cs
                .insn_detail(insn)
                .map_err(|e| Error::Analysis(e.to_string()))?;
            let groups = detail
                .groups()
                .iter()
                .map(|g| self.cs.group_name(*g).unwrap_or_default())
                .collect();
            results.push(Instruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                op_str: insn.op_str().unwrap_or("").to_string(),
                groups,
            });
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemorySegment, Permissions};

    #[test]
    fn create_each_arch() {
        for arch in [
            Architecture::X86,
            Architecture::X86_64,
            Architecture::Arm,
            Architecture::Arm64,
            Architecture::Mips,
            Architecture::Mips64,
            Architecture::RiscV32,
            Architecture::RiscV64,
        ] {
            let d = Disassembler::new(arch);
            assert!(d.is_ok(), "Failed to create disassembler for {}", arch);
            assert_eq!(d.unwrap().arch, arch);
        }
    }

    #[test]
    fn disassemble_x86_64_nop() {
        let disasm = Disassembler::new(Architecture::X86_64).unwrap();
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: "code".to_string(),
            start: 0x1000,
            size: 16,
            data: vec![0x90; 16], // NOP sled
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();

        let insn = disasm.disassemble_one(&map, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "nop");
        assert_eq!(insn.bytes, vec![0x90]);
    }

    #[test]
    fn disassemble_x86_32_nop() {
        let disasm = Disassembler::new(Architecture::X86).unwrap();
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: "code".to_string(),
            start: 0x1000,
            size: 16,
            data: vec![0x90; 16],
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();

        let insn = disasm.disassemble_one(&map, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "nop");
    }
}
