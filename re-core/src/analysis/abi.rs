//! ABI register model.
//!
//! Maps a calling convention to the machine registers that hold integer/pointer
//! arguments and the return value. This is the substrate for register-based
//! interprocedural type inference: knowing that, e.g., SysV-x64 passes the
//! first argument in `rdi` and returns in `rax` lets the type propagator follow
//! values across call boundaries.
//!
//! Only register-passing conventions are modelled. Stack-passed arguments (x86
//! `cdecl`/`stdcall`) yield an empty `arg_regs` — recovering those needs stack
//! reasoning that is out of scope here.

use crate::analysis::functions::CallingConvention;
use crate::arch::Architecture;
use crate::loader::BinaryFormat;

/// The registers an ABI uses for the first integer/pointer arguments (in order)
/// and for the integer/pointer return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiRegisters {
    /// Argument registers, in argument order. Empty for stack-only conventions.
    pub arg_regs: &'static [&'static str],
    /// Register holding the integer/pointer return value.
    pub ret_reg: &'static str,
}

/// Resolve the ABI register layout for `(arch, calling convention, format)`.
///
/// `format` only disambiguates x86-64 (SysV vs. Microsoft x64) when the
/// calling convention itself is unknown. Returns `None` for architectures whose
/// ABI is not modelled yet (currently MIPS).
pub fn abi_registers(
    arch: Architecture,
    cc: CallingConvention,
    format: BinaryFormat,
) -> Option<AbiRegisters> {
    const SYSV64: &[&str] = &["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    const WIN64: &[&str] = &["rcx", "rdx", "r8", "r9"];
    const AAPCS64: &[&str] = &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
    const AAPCS32: &[&str] = &["r0", "r1", "r2", "r3"];
    const RISCV: &[&str] = &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"];

    Some(match arch {
        Architecture::X86_64 => {
            // Microsoft x64 when the convention says so, or when it is unknown
            // on a PE image; SysV otherwise.
            let win64 = cc == CallingConvention::Win64
                || (cc == CallingConvention::Unknown && format == BinaryFormat::Pe);
            AbiRegisters {
                arg_regs: if win64 { WIN64 } else { SYSV64 },
                ret_reg: "rax",
            }
        }
        Architecture::Arm64 => AbiRegisters {
            arg_regs: AAPCS64,
            ret_reg: "x0",
        },
        Architecture::Arm => AbiRegisters {
            arg_regs: AAPCS32,
            ret_reg: "r0",
        },
        Architecture::RiscV32 | Architecture::RiscV64 => AbiRegisters {
            arg_regs: RISCV,
            ret_reg: "a0",
        },
        Architecture::X86 => match cc {
            // Register-passing x86 conventions; cdecl/stdcall pass on the stack.
            CallingConvention::Fastcall => AbiRegisters {
                arg_regs: &["ecx", "edx"],
                ret_reg: "eax",
            },
            CallingConvention::Thiscall => AbiRegisters {
                arg_regs: &["ecx"],
                ret_reg: "eax",
            },
            _ => AbiRegisters {
                arg_regs: &[],
                ret_reg: "eax",
            },
        },
        // MIPS register naming needs verifying against the MIPS lifter first.
        Architecture::Mips | Architecture::Mips64 => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_sysv_on_elf() {
        let abi = abi_registers(
            Architecture::X86_64,
            CallingConvention::SysVAmd64,
            BinaryFormat::Elf,
        )
        .unwrap();
        assert_eq!(abi.arg_regs.first(), Some(&"rdi"));
        assert_eq!(abi.ret_reg, "rax");
    }

    #[test]
    fn x86_64_unknown_on_pe_is_win64() {
        let abi = abi_registers(
            Architecture::X86_64,
            CallingConvention::Unknown,
            BinaryFormat::Pe,
        )
        .unwrap();
        assert_eq!(abi.arg_regs, &["rcx", "rdx", "r8", "r9"]);
        assert_eq!(abi.ret_reg, "rax");
    }

    #[test]
    fn explicit_convention_overrides_format() {
        // SysV convention on a PE image stays SysV (convention wins over format).
        let abi = abi_registers(
            Architecture::X86_64,
            CallingConvention::SysVAmd64,
            BinaryFormat::Pe,
        )
        .unwrap();
        assert_eq!(abi.arg_regs.first(), Some(&"rdi"));
    }

    #[test]
    fn arm64_aapcs() {
        let abi = abi_registers(
            Architecture::Arm64,
            CallingConvention::ArmAapcs,
            BinaryFormat::Elf,
        )
        .unwrap();
        assert_eq!(abi.arg_regs.first(), Some(&"x0"));
        assert_eq!(abi.ret_reg, "x0");
    }

    #[test]
    fn x86_stack_conventions_have_no_arg_regs() {
        let abi = abi_registers(
            Architecture::X86,
            CallingConvention::Cdecl,
            BinaryFormat::Pe,
        )
        .unwrap();
        assert!(abi.arg_regs.is_empty());
        assert_eq!(abi.ret_reg, "eax");
    }

    #[test]
    fn mips_abi_not_modelled_yet() {
        assert!(
            abi_registers(
                Architecture::Mips,
                CallingConvention::Unknown,
                BinaryFormat::Elf
            )
            .is_none()
        );
    }
}
