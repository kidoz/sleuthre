use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Architecture {
    X86,
    #[default]
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

impl Architecture {
    pub fn pointer_size(self) -> usize {
        match self {
            Self::X86 | Self::Arm | Self::Mips => 4,
            Self::X86_64 | Self::Arm64 | Self::Mips64 => 8,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "ARM",
            Self::Arm64 => "ARM64",
            Self::Mips => "MIPS",
            Self::Mips64 => "MIPS64",
        }
    }

    /// Default endianness for this architecture (can be overridden by binary headers)
    pub fn default_endianness(self) -> Endianness {
        match self {
            Self::X86 | Self::X86_64 | Self::Arm | Self::Arm64 => Endianness::Little,
            Self::Mips | Self::Mips64 => Endianness::Big,
        }
    }

    /// Get the general-purpose register names for this architecture
    pub fn gpr_names(self) -> &'static [&'static str] {
        match self {
            Self::X86 => &["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"],
            Self::X86_64 => &[
                "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
                "r12", "r13", "r14", "r15",
            ],
            Self::Arm => &[
                "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
                "sp", "lr", "pc",
            ],
            Self::Arm64 => &[
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24",
                "x25", "x26", "x27", "x28", "x29", "x30", "sp",
            ],
            Self::Mips | Self::Mips64 => &[
                "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$t0", "$t1", "$t2",
                "$t3", "$t4", "$t5", "$t6", "$t7", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6",
                "$s7", "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
            ],
        }
    }

    /// Get special register names (flags, program counter, etc.)
    pub fn special_register_names(self) -> &'static [&'static str] {
        match self {
            Self::X86 => &["eip", "eflags"],
            Self::X86_64 => &["rip", "rflags"],
            Self::Arm => &["cpsr"],
            Self::Arm64 => &["pc", "nzcv", "fpcr", "fpsr"],
            Self::Mips | Self::Mips64 => &["pc", "hi", "lo"],
        }
    }

    /// Get floating-point register names
    pub fn fp_register_names(self) -> &'static [&'static str] {
        match self {
            Self::X86 => &["st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"],
            Self::X86_64 => &[
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
                "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
            ],
            Self::Arm => &[
                "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12",
                "s13", "s14", "s15",
            ],
            Self::Arm64 => &[
                "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12",
                "v13", "v14", "v15",
            ],
            Self::Mips | Self::Mips64 => &[
                "$f0", "$f1", "$f2", "$f3", "$f4", "$f5", "$f6", "$f7", "$f8", "$f9", "$f10",
                "$f11", "$f12", "$f13", "$f14", "$f15",
            ],
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

impl Endianness {
    /// Read a u16 value according to this endianness
    pub fn read_u16(self, data: &[u8]) -> u16 {
        match self {
            Endianness::Little => u16::from_le_bytes([data[0], data[1]]),
            Endianness::Big => u16::from_be_bytes([data[0], data[1]]),
        }
    }

    /// Read a u32 value according to this endianness
    pub fn read_u32(self, data: &[u8]) -> u32 {
        match self {
            Endianness::Little => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            Endianness::Big => u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        }
    }

    /// Read a u64 value according to this endianness
    pub fn read_u64(self, data: &[u8]) -> u64 {
        match self {
            Endianness::Little => u64::from_le_bytes(data[..8].try_into().unwrap()),
            Endianness::Big => u64::from_be_bytes(data[..8].try_into().unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_sizes() {
        assert_eq!(Architecture::X86.pointer_size(), 4);
        assert_eq!(Architecture::X86_64.pointer_size(), 8);
        assert_eq!(Architecture::Arm.pointer_size(), 4);
        assert_eq!(Architecture::Arm64.pointer_size(), 8);
        assert_eq!(Architecture::Mips.pointer_size(), 4);
        assert_eq!(Architecture::Mips64.pointer_size(), 8);
    }

    #[test]
    fn display_names() {
        assert_eq!(Architecture::X86.display_name(), "x86");
        assert_eq!(Architecture::X86_64.display_name(), "x86_64");
        assert_eq!(Architecture::Arm.display_name(), "ARM");
        assert_eq!(Architecture::Arm64.display_name(), "ARM64");
        assert_eq!(Architecture::Mips.display_name(), "MIPS");
        assert_eq!(Architecture::Mips64.display_name(), "MIPS64");
    }

    #[test]
    fn display_impl() {
        assert_eq!(format!("{}", Architecture::X86_64), "x86_64");
        assert_eq!(format!("{}", Architecture::Arm), "ARM");
    }

    #[test]
    fn endianness_defaults() {
        assert_eq!(Architecture::X86.default_endianness(), Endianness::Little);
        assert_eq!(
            Architecture::X86_64.default_endianness(),
            Endianness::Little
        );
        assert_eq!(Architecture::Arm.default_endianness(), Endianness::Little);
        assert_eq!(Architecture::Mips.default_endianness(), Endianness::Big);
    }

    #[test]
    fn endian_reads() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(Endianness::Little.read_u16(&data), 0x0201);
        assert_eq!(Endianness::Big.read_u16(&data), 0x0102);
        assert_eq!(Endianness::Little.read_u32(&data), 0x04030201);
        assert_eq!(Endianness::Big.read_u32(&data), 0x01020304);
    }

    #[test]
    fn gpr_names_populated() {
        assert!(!Architecture::X86.gpr_names().is_empty());
        assert!(!Architecture::X86_64.gpr_names().is_empty());
        assert!(!Architecture::Arm.gpr_names().is_empty());
        assert!(!Architecture::Arm64.gpr_names().is_empty());
        assert!(!Architecture::Mips.gpr_names().is_empty());
    }

    #[test]
    fn special_registers_populated() {
        assert!(
            Architecture::X86_64
                .special_register_names()
                .contains(&"rip")
        );
        assert!(Architecture::Arm.special_register_names().contains(&"cpsr"));
    }
}
