pub mod hlil;
pub mod lifter_arm;
pub mod lifter_arm64;
pub mod lifter_mips;
pub mod lifter_riscv;
pub mod lifter_x86;
pub mod llil;
pub mod mlil;
pub mod structuring;

use crate::arch::Architecture;
use crate::disasm::Instruction;
use llil::LlilFunction;

/// Lift a function's instructions to LLIL using the lifter for `arch`.
///
/// Single dispatch point so every caller (analysis passes, structuring, the
/// MCP IL tools) lifts with the correct per-architecture lifter. The match is
/// exhaustive: adding an `Architecture` variant is a compile error here until
/// it is mapped to a lifter.
pub fn lift_function(
    arch: Architecture,
    name: &str,
    entry: u64,
    instructions: &[Instruction],
) -> LlilFunction {
    match arch {
        Architecture::Arm => lifter_arm::lift_function(name, entry, instructions),
        Architecture::Arm64 => lifter_arm64::lift_function(name, entry, instructions),
        Architecture::Mips | Architecture::Mips64 => {
            lifter_mips::lift_function(name, entry, instructions)
        }
        Architecture::RiscV32 | Architecture::RiscV64 => {
            lifter_riscv::lift_function(name, entry, instructions)
        }
        Architecture::X86 | Architecture::X86_64 => {
            lifter_x86::lift_function(name, entry, instructions)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(mnemonic: &str, op_str: &str) -> Instruction {
        Instruction {
            address: 0x1000,
            bytes: vec![],
            mnemonic: mnemonic.to_string(),
            op_str: op_str.to_string(),
            groups: vec![],
        }
    }

    #[test]
    fn arm_dispatches_to_arm_lifter_not_x86() {
        // `bx lr` is a return the ARM lifter understands; the x86 lifter does
        // not. If ARM were (mis)routed to the x86 lifter the two would match.
        let insns = [insn("bx", "lr")];
        let arm = lift_function(Architecture::Arm, "f", 0x1000, &insns);
        let x86 = lift_function(Architecture::X86, "f", 0x1000, &insns);
        assert_ne!(
            format!("{:?}", arm.instructions),
            format!("{:?}", x86.instructions),
            "ARM must be lifted by the ARM lifter, not the x86 lifter"
        );
    }
}
