use crate::Result;
use crate::arch::Architecture;
use crate::error::Error;
use crate::memory::MemoryMap;
use capstone::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
    pub groups: Vec<String>,
}

pub struct Disassembler {
    cs: Capstone,
    pub arch: Architecture,
}

impl Disassembler {
    pub fn new(arch: Architecture) -> Result<Self> {
        let cs = match arch {
            Architecture::X86 => Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode32)
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode64)
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::Arm => Capstone::new()
                .arm()
                .mode(capstone::arch::arm::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::Arm64 => Capstone::new()
                .arm64()
                .mode(capstone::arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::Mips => Capstone::new()
                .mips()
                .mode(capstone::arch::mips::ArchMode::Mips32)
                .detail(true)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
            Architecture::Mips64 => Capstone::new()
                .mips()
                .mode(capstone::arch::mips::ArchMode::Mips64)
                .detail(true)
                .build()
                .map_err(|e: capstone::Error| Error::Analysis(e.to_string()))?,
        };

        Ok(Self { cs, arch })
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
