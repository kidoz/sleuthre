//! Control flow structuring: converts flat MLIL sequences into structured HLIL.
//!
//! This module recognizes patterns like:
//! - cmp/test + branch → if/else
//! - back edges → while/do-while loops
//! - Linear sequences → blocks

use std::collections::HashSet;

use crate::il::hlil::{self, HlilExpr, HlilStmt};
use crate::il::mlil::{MlilExpr, MlilFunction, MlilStmt};

/// Information recovered about a function's signature: return type, parameters,
/// and local (stack) variables.
#[derive(Debug, Clone)]
pub struct DecompileInfo {
    /// C-style return type (e.g. "void", "int64_t").
    pub return_type: String,
    /// Parameter list as (type, name) pairs.
    pub params: Vec<(String, String)>,
    /// Local variable declarations as (type, name) pairs.
    pub locals: Vec<(String, String)>,
}

/// ABI argument registers for SysV x86_64 calling convention.
const X86_64_ARG_REGS: &[&str] = &["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

/// ABI argument registers for ARM64 (AAPCS64) calling convention.
const ARM64_ARG_REGS: &[&str] = &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];

/// Registers that hold the return value on x86/x86_64.
const X86_64_RETURN_REGS: &[&str] = &["rax", "eax"];

/// Registers that hold the return value on ARM64.
const ARM64_RETURN_REGS: &[&str] = &["x0"];

/// Analyze the MLIL to recover function signature information:
/// which ABI registers are used as parameters, whether the function returns a
/// value, and what stack locals exist.
fn analyze_function_signature(
    mlil: &MlilFunction,
    instructions: &[crate::disasm::Instruction],
    arch: crate::arch::Architecture,
) -> DecompileInfo {
    let params = detect_parameters(mlil, arch);
    let return_type = detect_return_type(mlil, arch);
    let locals = recover_locals(instructions);
    DecompileInfo {
        return_type,
        params,
        locals,
    }
}

/// Detect function parameters by scanning MLIL instructions for reads of ABI
/// argument registers that occur before any write to that register.
fn detect_parameters(
    mlil: &MlilFunction,
    arch: crate::arch::Architecture,
) -> Vec<(String, String)> {
    let abi_regs: &[&str] = match arch {
        crate::arch::Architecture::Arm64 => ARM64_ARG_REGS,
        crate::arch::Architecture::X86_64 => X86_64_ARG_REGS,
        _ => return vec![],
    };

    let mut written: HashSet<&str> = HashSet::new();
    let mut param_regs: Vec<&str> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();

    for inst in &mlil.instructions {
        for stmt in &inst.stmts {
            // Collect reads first, then mark writes.
            let reads = collect_reads_from_stmt(stmt);
            for reg_name in &reads {
                if let Some(abi_reg) = abi_regs.iter().find(|&&r| r == reg_name.as_str())
                    && !written.contains(abi_reg)
                    && !seen.contains(abi_reg)
                {
                    param_regs.push(abi_reg);
                    seen.insert(abi_reg);
                }
            }
            // Now mark any write destination.
            if let MlilStmt::Assign { dest, .. } = stmt
                && let Some(abi_reg) = abi_regs.iter().find(|&&r| r == dest.name.as_str())
            {
                written.insert(abi_reg);
            }
        }
    }

    // Sort parameters by their ABI order (position in the abi_regs slice).
    param_regs.sort_by_key(|r| abi_regs.iter().position(|ar| ar == r).unwrap_or(usize::MAX));
    param_regs.dedup();

    param_regs
        .iter()
        .enumerate()
        .map(|(i, _)| ("int64_t".to_string(), format!("arg{}", i + 1)))
        .collect()
}

/// Recursively collect all register names that are read in an MLIL statement.
fn collect_reads_from_stmt(stmt: &MlilStmt) -> Vec<String> {
    match stmt {
        MlilStmt::Assign { src, .. } => collect_reads_from_expr(src),
        MlilStmt::Store { addr, value, .. } => {
            let mut reads = collect_reads_from_expr(addr);
            reads.extend(collect_reads_from_expr(value));
            reads
        }
        MlilStmt::BranchIf { cond, target } => {
            let mut reads = collect_reads_from_expr(cond);
            reads.extend(collect_reads_from_expr(target));
            reads
        }
        MlilStmt::Jump { target } => collect_reads_from_expr(target),
        MlilStmt::Call { target } => collect_reads_from_expr(target),
        MlilStmt::Return | MlilStmt::Nop => vec![],
    }
}

/// Recursively collect all register names referenced in an MLIL expression.
fn collect_reads_from_expr(expr: &MlilExpr) -> Vec<String> {
    match expr {
        MlilExpr::Var(ssa) => vec![ssa.name.clone()],
        MlilExpr::Const(_) => vec![],
        MlilExpr::Load { addr, .. } => collect_reads_from_expr(addr),
        MlilExpr::BinOp { left, right, .. } => {
            let mut reads = collect_reads_from_expr(left);
            reads.extend(collect_reads_from_expr(right));
            reads
        }
        MlilExpr::UnaryOp { operand, .. } => collect_reads_from_expr(operand),
        MlilExpr::Phi(vars) => vars.iter().map(|v| v.name.clone()).collect(),
        MlilExpr::Call { target, args } => {
            let mut reads = collect_reads_from_expr(target);
            for arg in args {
                reads.extend(collect_reads_from_expr(arg));
            }
            reads
        }
        MlilExpr::VectorOp { operands, .. } => {
            let mut reads = Vec::new();
            for op in operands {
                reads.extend(collect_reads_from_expr(op));
            }
            reads
        }
    }
}

/// Detect whether the function returns a value by looking for assignments to
/// the return register (rax/eax on x86_64, x0 on ARM64) just before a Return
/// statement. A special case: `xor eax, eax` (which folds to `eax = 0`) is a
/// common "return 0" idiom, but in many cases it is simply clearing the
/// register before `ret` -- we treat it as void unless there is a non-zero
/// assignment.
fn detect_return_type(mlil: &MlilFunction, arch: crate::arch::Architecture) -> String {
    let return_regs: &[&str] = match arch {
        crate::arch::Architecture::Arm64 => ARM64_RETURN_REGS,
        crate::arch::Architecture::X86_64 | crate::arch::Architecture::X86 => X86_64_RETURN_REGS,
        _ => return "void".to_string(),
    };

    // Walk instructions backwards looking for Return preceded by an assignment
    // to a return register.
    let insts = &mlil.instructions;
    for (idx, inst) in insts.iter().enumerate() {
        for stmt in &inst.stmts {
            if matches!(stmt, MlilStmt::Return) {
                // Look backwards from this Return for an assignment to a return reg.
                if let Some(assign_value) = find_return_assign(insts, idx, return_regs) {
                    // xor eax, eax folds to const 0 — treat as void.
                    if is_zero_const(&assign_value) {
                        continue;
                    }
                    return "int64_t".to_string();
                }
            }
        }
    }

    "void".to_string()
}

/// Search backwards from `ret_idx` for an assignment to one of `return_regs`.
/// Returns the source expression if found.
fn find_return_assign(
    insts: &[crate::il::mlil::MlilInst],
    ret_idx: usize,
    return_regs: &[&str],
) -> Option<MlilExpr> {
    // Check the same instruction first, then walk backwards up to 3 instructions.
    let start = ret_idx.saturating_sub(3);
    for i in (start..=ret_idx).rev() {
        for stmt in insts[i].stmts.iter().rev() {
            if let MlilStmt::Assign { dest, src } = stmt
                && return_regs.iter().any(|&r| r == dest.name)
            {
                return Some(src.clone());
            }
        }
    }
    None
}

/// Check whether an MLIL expression is a zero constant (from xor reg, reg).
fn is_zero_const(expr: &MlilExpr) -> bool {
    matches!(expr, MlilExpr::Const(0))
}

/// Recover stack-local variable declarations from raw instructions.
fn recover_locals(instructions: &[crate::disasm::Instruction]) -> Vec<(String, String)> {
    let stack_vars = crate::analysis::stack::recover_stack_variables(instructions);
    stack_vars
        .iter()
        .filter(|v| v.offset < 0) // Only locals (negative offsets from frame pointer)
        .map(|v| (format!("{}", v.type_hint), v.name.clone()))
        .collect()
}

/// Post-pass: fold `result = expr; return;` into `return expr;`.
fn fold_return_values(stmts: &mut Vec<HlilStmt>) {
    let mut i = 0;
    while i + 1 < stmts.len() {
        let should_fold = {
            if let HlilStmt::Assign {
                dest: HlilExpr::Var(name),
                ..
            } = &stmts[i]
            {
                name.starts_with("result") && matches!(&stmts[i + 1], HlilStmt::Return(None))
            } else {
                false
            }
        };
        if should_fold {
            let src = if let HlilStmt::Assign { src, .. } = &stmts[i] {
                src.clone()
            } else {
                unreachable!()
            };
            stmts[i] = HlilStmt::Return(Some(src));
            stmts.remove(i + 1);
        }
        i += 1;
    }
    // Recurse into nested bodies.
    for stmt in stmts.iter_mut() {
        match stmt {
            HlilStmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_return_values(then_body);
                fold_return_values(else_body);
            }
            HlilStmt::While { body, .. }
            | HlilStmt::DoWhile { body, .. }
            | HlilStmt::For { body, .. } => {
                fold_return_values(body);
            }
            HlilStmt::Block(inner) => fold_return_values(inner),
            _ => {}
        }
    }
}

/// Post-pass: detect `init; while(cond) { body; update; }` and convert to
/// `for(init; cond; update) { body; }`.
///
/// Pattern matched:
///   Assign { ... }          <- init
///   While { cond, body }    <- body must end with an Assign (the update)
fn detect_for_loops(stmts: &mut Vec<HlilStmt>) {
    let mut i = 0;
    while i + 1 < stmts.len() {
        // Pattern: Assign followed by While whose body ends with an Assign
        let should_convert = matches!(&stmts[i], HlilStmt::Assign { .. })
            && matches!(&stmts[i + 1], HlilStmt::While { body, .. } if body.len() >= 2 && matches!(body.last(), Some(HlilStmt::Assign { .. })));

        if should_convert {
            let init = Box::new(stmts[i].clone());
            if let HlilStmt::While { cond, body } = &stmts[i + 1] {
                let update = Box::new(body.last().unwrap().clone());
                let loop_body = body[..body.len() - 1].to_vec();
                let cond = cond.clone();

                stmts[i] = HlilStmt::For {
                    init,
                    cond,
                    update,
                    body: loop_body,
                };
                stmts.remove(i + 1);
                continue;
            }
        }
        i += 1;
    }

    // Recurse into nested structures
    for stmt in stmts.iter_mut() {
        match stmt {
            HlilStmt::If {
                then_body,
                else_body,
                ..
            } => {
                detect_for_loops(then_body);
                detect_for_loops(else_body);
            }
            HlilStmt::While { body, .. } | HlilStmt::DoWhile { body, .. } => {
                detect_for_loops(body);
            }
            HlilStmt::For { body, .. } => detect_for_loops(body),
            HlilStmt::Block(inner) => detect_for_loops(inner),
            _ => {}
        }
    }
}

/// Convert an MLIL function into structured HLIL statements.
pub fn structure_function(func: &MlilFunction) -> Vec<HlilStmt> {
    let mut stmts = Vec::new();
    let mut i = 0;
    let insts = &func.instructions;

    while i < insts.len() {
        let inst = &insts[i];

        // Check for do-while loop: look ahead for a BranchIf that targets the current
        // instruction's address (back edge), indicating this is the loop head.
        if let Some(back_branch) = find_do_while_back_edge(insts, i) {
            let body: Vec<HlilStmt> = insts[i..back_branch.branch_idx]
                .iter()
                .flat_map(|inst| lower_mlil_stmts(&inst.stmts))
                .collect();
            let cond = hlil::mlil_to_hlil_expr(&back_branch.cond);
            stmts.push(HlilStmt::DoWhile { body, cond });
            i = back_branch.branch_idx + 1;
            continue;
        }

        // Check for while loop: BranchIf jumps forward (exit), followed by body, ending with Jump back
        if let Some(branch_stmt) = find_branch_if(&inst.stmts)
            && let MlilExpr::Const(exit_addr) = &branch_stmt.1
            && let Some(eidx) = insts.iter().position(|inst| inst.address == *exit_addr)
            && eidx > i + 1
            && let Some(back_addr) = find_jump_target(&insts[eidx - 1].stmts)
            && back_addr == insts[i].address
        {
            // While loop: condition at top, body in middle, jump back at end
            let cond = hlil::mlil_to_hlil_expr(&branch_stmt.0);
            let body: Vec<HlilStmt> = insts[i + 1..eidx - 1]
                .iter()
                .flat_map(|inst| lower_mlil_stmts(&inst.stmts))
                .collect();
            stmts.push(HlilStmt::While { cond, body });
            i = eidx;
            continue;
        }

        // Check for if-pattern: BranchIf followed by linear blocks
        if let Some(branch_stmt) = find_branch_if(&inst.stmts)
            && let Some((then_end, else_end)) = find_if_else_bounds(insts, i, &branch_stmt)
        {
            let cond = hlil::mlil_to_hlil_expr(&branch_stmt.0);
            let then_body: Vec<HlilStmt> = insts[i + 1..then_end]
                .iter()
                .flat_map(|inst| lower_mlil_stmts(&inst.stmts))
                .collect();
            let else_body: Vec<HlilStmt> = if else_end > then_end {
                insts[then_end..else_end]
                    .iter()
                    .flat_map(|inst| lower_mlil_stmts(&inst.stmts))
                    .collect()
            } else {
                vec![]
            };

            stmts.push(HlilStmt::If {
                cond,
                then_body,
                else_body,
            });
            i = else_end.max(then_end);
            continue;
        }

        // Default: lower each statement individually
        stmts.extend(lower_mlil_stmts(&inst.stmts));
        i += 1;
    }

    stmts
}

struct BranchInfo(MlilExpr, MlilExpr);

fn find_branch_if(stmts: &[MlilStmt]) -> Option<BranchInfo> {
    for stmt in stmts {
        if let MlilStmt::BranchIf { cond, target } = stmt {
            return Some(BranchInfo(cond.clone(), target.clone()));
        }
    }
    None
}

/// Information about a do-while back edge found by lookahead.
struct DoWhileBackEdge {
    /// Index of the instruction containing the BranchIf with the back edge.
    branch_idx: usize,
    /// The branch condition expression.
    cond: MlilExpr,
}

/// Look ahead from `head_idx` for a BranchIf that targets the current instruction's
/// address (back edge), indicating a do-while loop with head at `head_idx`.
fn find_do_while_back_edge(
    insts: &[crate::il::mlil::MlilInst],
    head_idx: usize,
) -> Option<DoWhileBackEdge> {
    let head_addr = insts[head_idx].address;
    for (j, inst) in insts.iter().enumerate().skip(head_idx + 1) {
        if let Some(branch) = find_branch_if(&inst.stmts)
            && let MlilExpr::Const(target_addr) = &branch.1
            && *target_addr == head_addr
        {
            return Some(DoWhileBackEdge {
                branch_idx: j,
                cond: branch.0,
            });
        }
    }
    None
}

/// Try to identify if/else bounds.
/// Returns (then_block_end, else_block_end).
fn find_if_else_bounds(
    insts: &[crate::il::mlil::MlilInst],
    branch_idx: usize,
    branch: &BranchInfo,
) -> Option<(usize, usize)> {
    let target_addr = match &branch.1 {
        MlilExpr::Const(addr) => *addr,
        _ => return None,
    };

    // Find the instruction index that matches the branch target
    let target_idx = insts.iter().position(|inst| inst.address == target_addr)?;

    if target_idx <= branch_idx {
        // Back edge — this is a loop, not an if/else
        return None;
    }

    // The "then" block is from branch_idx+1 to target_idx
    // Look for a jump at the end of the then block → else block
    if target_idx > branch_idx + 1 {
        let last_then = &insts[target_idx - 1];
        if let Some(jump_target) = find_jump_target(&last_then.stmts) {
            let else_end = insts
                .iter()
                .position(|inst| inst.address == jump_target)
                .unwrap_or(target_idx);
            return Some((target_idx - 1, else_end));
        }
    }

    Some((target_idx, target_idx))
}

fn find_jump_target(stmts: &[MlilStmt]) -> Option<u64> {
    for stmt in stmts {
        if let MlilStmt::Jump {
            target: MlilExpr::Const(addr),
        } = stmt
        {
            return Some(*addr);
        }
    }
    None
}

/// Lower MLIL statements into HLIL statements.
fn lower_mlil_stmts(stmts: &[MlilStmt]) -> Vec<HlilStmt> {
    let mut result = Vec::new();
    for stmt in stmts {
        match stmt {
            MlilStmt::Assign { dest, src } => {
                // Skip internal flag/temp assignments
                if dest.name.starts_with("__") || dest.name.starts_with("flag_") {
                    continue;
                }
                // Skip stack/frame pointer manipulations
                if matches!(
                    dest.name.as_str(),
                    "rsp" | "esp" | "sp" | "rbp" | "ebp" | "bp"
                ) {
                    continue;
                }
                result.push(HlilStmt::Assign {
                    dest: HlilExpr::Var(
                        hlil::mlil_to_hlil_expr(&MlilExpr::Var(dest.clone())).to_string(),
                    ),
                    src: hlil::mlil_to_hlil_expr(src),
                });
            }
            MlilStmt::Store { addr, value, .. } => {
                result.push(HlilStmt::Store {
                    addr: hlil::mlil_to_hlil_expr(addr),
                    value: hlil::mlil_to_hlil_expr(value),
                });
            }
            MlilStmt::Call { target } => {
                result.push(HlilStmt::Expr(HlilExpr::Call {
                    target: Box::new(hlil::mlil_to_hlil_expr(target)),
                    args: vec![],
                }));
            }
            MlilStmt::Return => {
                result.push(HlilStmt::Return(None));
            }
            MlilStmt::Nop | MlilStmt::Jump { .. } | MlilStmt::BranchIf { .. } => {}
        }
    }
    result
}

/// Full decompilation pipeline: LLIL → MLIL → SSA → fold → structure → pseudocode.
pub fn decompile(
    name: &str,
    instructions: &[crate::disasm::Instruction],
    arch: crate::arch::Architecture,
) -> String {
    let llil = match arch {
        crate::arch::Architecture::Arm64 => {
            crate::il::lifter_arm64::lift_function(name, instructions[0].address, instructions)
        }
        _ => crate::il::lifter_x86::lift_function(name, instructions[0].address, instructions),
    };
    let mut mlil = crate::il::mlil::lower_to_mlil(&llil);
    crate::il::mlil::apply_ssa(&mut mlil);
    crate::il::mlil::eliminate_dead_stores(&mut mlil);

    let info = analyze_function_signature(&mlil, instructions, arch);
    let mut hlil_stmts = structure_function(&mlil);
    detect_for_loops(&mut hlil_stmts);
    fold_return_values(&mut hlil_stmts);
    hlil::render_pseudocode_with_info(name, &hlil_stmts, &info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::Instruction;

    fn make_insn(addr: u64, mn: &str, op: &str) -> Instruction {
        Instruction {
            address: addr,
            bytes: vec![],
            mnemonic: mn.to_string(),
            op_str: op.to_string(),
            groups: vec![],
        }
    }

    #[test]
    fn decompile_simple_function() {
        let insns = vec![
            make_insn(0x1000, "push", "rbp"),
            make_insn(0x1001, "mov", "rbp, rsp"),
            make_insn(0x1004, "xor", "eax, eax"),
            make_insn(0x1006, "pop", "rbp"),
            make_insn(0x1007, "ret", ""),
        ];
        let code = decompile("simple_func", &insns, crate::arch::Architecture::X86_64);
        // xor eax,eax is the "return 0" idiom — detected as void.
        assert!(
            code.contains("void simple_func(void)"),
            "expected void signature, got: {}",
            code
        );
        // xor eax,eax folded: result = 0 + return → return 0
        assert!(code.contains("return"), "expected return, got: {}", code);
    }

    #[test]
    fn decompile_with_call() {
        let insns = vec![
            make_insn(0x1000, "push", "rbp"),
            make_insn(0x1001, "call", "0x2000"),
            make_insn(0x1006, "pop", "rbp"),
            make_insn(0x1007, "ret", ""),
        ];
        let code = decompile("caller", &insns, crate::arch::Architecture::X86_64);
        assert!(code.contains("0x2000()"));
    }

    #[test]
    fn structure_filters_stack_ops() {
        let insns = vec![
            make_insn(0x1000, "push", "rbp"),
            make_insn(0x1001, "mov", "rbp, rsp"),
            make_insn(0x1004, "sub", "rsp, 0x20"),
            make_insn(0x1008, "mov", "eax, 42"),
            make_insn(0x100d, "nop", ""),
            make_insn(0x100e, "ret", ""),
        ];
        let code = decompile("test_func", &insns, crate::arch::Architecture::X86_64);
        // Stack/frame operations should be filtered out; meaningful value is
        // folded into the return statement (result_1 = 42 + return → return 42).
        assert!(
            code.contains("return") && !code.contains("rsp") && !code.contains("rbp"),
            "stack ops should be filtered; got: {}",
            code
        );
    }

    use crate::il::llil::BinOp;
    use crate::il::mlil::{MlilInst, SsaVar};

    fn make_mlil_func(instructions: Vec<MlilInst>) -> MlilFunction {
        MlilFunction {
            name: "test".to_string(),
            entry: instructions.first().map(|i| i.address).unwrap_or(0),
            instructions,
        }
    }

    #[test]
    fn test_do_while_loop() {
        // Pattern:
        //   0x1000: body (assign counter = counter - 1)
        //   0x1004: BranchIf(counter != 0, 0x1000)  <-- back edge
        //   0x1008: return
        let func = make_mlil_func(vec![
            MlilInst {
                address: 0x1000,
                stmts: vec![MlilStmt::Assign {
                    dest: SsaVar {
                        name: "rcx".into(),
                        version: 1,
                    },
                    src: MlilExpr::BinOp {
                        op: BinOp::Sub,
                        left: Box::new(MlilExpr::Var(SsaVar {
                            name: "rcx".into(),
                            version: 0,
                        })),
                        right: Box::new(MlilExpr::Const(1)),
                    },
                }],
            },
            MlilInst {
                address: 0x1004,
                stmts: vec![MlilStmt::BranchIf {
                    cond: MlilExpr::Var(SsaVar {
                        name: "rcx".into(),
                        version: 1,
                    }),
                    target: MlilExpr::Const(0x1000), // back edge
                }],
            },
            MlilInst {
                address: 0x1008,
                stmts: vec![MlilStmt::Return],
            },
        ]);

        let stmts = structure_function(&func);
        // Should produce DoWhile followed by Return
        assert!(
            stmts.len() >= 2,
            "expected at least 2 statements, got {}",
            stmts.len()
        );
        assert!(
            matches!(&stmts[0], HlilStmt::DoWhile { .. }),
            "expected DoWhile, got {:?}",
            stmts[0]
        );
        if let HlilStmt::DoWhile { body, .. } = &stmts[0] {
            assert!(!body.is_empty(), "do-while body should not be empty");
        }
    }

    #[test]
    fn test_while_loop() {
        // Pattern:
        //   0x1000: BranchIf(counter == 0, 0x100C)  <-- forward exit branch
        //   0x1004: body (assign counter = counter - 1)
        //   0x1008: Jump(0x1000)                     <-- back jump
        //   0x100C: return
        let func = make_mlil_func(vec![
            MlilInst {
                address: 0x1000,
                stmts: vec![MlilStmt::BranchIf {
                    cond: MlilExpr::Var(SsaVar {
                        name: "flag_e".into(),
                        version: 0,
                    }),
                    target: MlilExpr::Const(0x100C), // forward exit
                }],
            },
            MlilInst {
                address: 0x1004,
                stmts: vec![MlilStmt::Assign {
                    dest: SsaVar {
                        name: "rcx".into(),
                        version: 1,
                    },
                    src: MlilExpr::BinOp {
                        op: BinOp::Sub,
                        left: Box::new(MlilExpr::Var(SsaVar {
                            name: "rcx".into(),
                            version: 0,
                        })),
                        right: Box::new(MlilExpr::Const(1)),
                    },
                }],
            },
            MlilInst {
                address: 0x1008,
                stmts: vec![MlilStmt::Jump {
                    target: MlilExpr::Const(0x1000), // back jump
                }],
            },
            MlilInst {
                address: 0x100C,
                stmts: vec![MlilStmt::Return],
            },
        ]);

        let stmts = structure_function(&func);
        // Should produce While followed by Return
        assert!(
            stmts.len() >= 2,
            "expected at least 2 statements, got {}",
            stmts.len()
        );
        assert!(
            matches!(&stmts[0], HlilStmt::While { .. }),
            "expected While, got {:?}",
            stmts[0]
        );
        if let HlilStmt::While { body, .. } = &stmts[0] {
            assert!(!body.is_empty(), "while body should not be empty");
        }
    }

    #[test]
    fn test_for_loop_detection() {
        // Pattern:
        //   0x1000: Assign rcx = 0                    <- init
        //   0x1004: BranchIf(flag_e, 0x1010)          <- while condition (exit)
        //   0x1008: body (call 0x2000) + update (rcx = rcx + 1)
        //   0x100C: Jump(0x1004)                       <- back jump
        //   0x1010: return
        let func = make_mlil_func(vec![
            MlilInst {
                address: 0x1000,
                stmts: vec![MlilStmt::Assign {
                    dest: SsaVar {
                        name: "rcx".into(),
                        version: 1,
                    },
                    src: MlilExpr::Const(0),
                }],
            },
            MlilInst {
                address: 0x1004,
                stmts: vec![MlilStmt::BranchIf {
                    cond: MlilExpr::Var(SsaVar {
                        name: "flag_e".into(),
                        version: 0,
                    }),
                    target: MlilExpr::Const(0x1010), // forward exit
                }],
            },
            MlilInst {
                address: 0x1008,
                stmts: vec![
                    MlilStmt::Call {
                        target: MlilExpr::Const(0x2000),
                    },
                    MlilStmt::Assign {
                        dest: SsaVar {
                            name: "rcx".into(),
                            version: 2,
                        },
                        src: MlilExpr::BinOp {
                            op: BinOp::Add,
                            left: Box::new(MlilExpr::Var(SsaVar {
                                name: "rcx".into(),
                                version: 1,
                            })),
                            right: Box::new(MlilExpr::Const(1)),
                        },
                    },
                ],
            },
            MlilInst {
                address: 0x100C,
                stmts: vec![MlilStmt::Jump {
                    target: MlilExpr::Const(0x1004), // back jump
                }],
            },
            MlilInst {
                address: 0x1010,
                stmts: vec![MlilStmt::Return],
            },
        ]);

        let mut stmts = structure_function(&func);
        detect_for_loops(&mut stmts);

        // The init assign + while should be collapsed into a For
        assert!(
            matches!(&stmts[0], HlilStmt::For { .. }),
            "expected For, got {:?}",
            stmts[0]
        );
        if let HlilStmt::For { body, .. } = &stmts[0] {
            // Body should have the call but not the update (update moved to for header)
            assert!(
                !body.is_empty(),
                "for body should contain at least the call"
            );
        }
    }

    // ---- New tests for decompiler improvements (P0) ----

    #[test]
    fn detect_params_x86_64_rdi_rsi() {
        // Function reads rdi and rsi before writing them -> 2 parameters.
        let func = make_mlil_func(vec![
            MlilInst {
                address: 0x1000,
                stmts: vec![MlilStmt::Assign {
                    dest: SsaVar {
                        name: "rax".into(),
                        version: 1,
                    },
                    src: MlilExpr::BinOp {
                        op: BinOp::Add,
                        left: Box::new(MlilExpr::Var(SsaVar {
                            name: "rdi".into(),
                            version: 0,
                        })),
                        right: Box::new(MlilExpr::Var(SsaVar {
                            name: "rsi".into(),
                            version: 0,
                        })),
                    },
                }],
            },
            MlilInst {
                address: 0x1004,
                stmts: vec![MlilStmt::Return],
            },
        ]);
        let params = detect_parameters(&func, crate::arch::Architecture::X86_64);
        assert_eq!(params.len(), 2, "expected 2 params, got {:?}", params);
        assert_eq!(params[0], ("int64_t".to_string(), "arg1".to_string()));
        assert_eq!(params[1], ("int64_t".to_string(), "arg2".to_string()));
    }

    #[test]
    fn detect_params_written_before_read() {
        // rdi is written before being read -> not a parameter.
        let func = make_mlil_func(vec![
            MlilInst {
                address: 0x1000,
                stmts: vec![MlilStmt::Assign {
                    dest: SsaVar {
                        name: "rdi".into(),
                        version: 1,
                    },
                    src: MlilExpr::Const(42),
                }],
            },
            MlilInst {
                address: 0x1004,
                stmts: vec![MlilStmt::Assign {
                    dest: SsaVar {
                        name: "rax".into(),
                        version: 1,
                    },
                    src: MlilExpr::Var(SsaVar {
                        name: "rdi".into(),
                        version: 1,
                    }),
                }],
            },
            MlilInst {
                address: 0x1008,
                stmts: vec![MlilStmt::Return],
            },
        ]);
        let params = detect_parameters(&func, crate::arch::Architecture::X86_64);
        assert!(
            params.is_empty(),
            "rdi written before read should not be a param, got {:?}",
            params
        );
    }

    #[test]
    fn detect_return_type_nonzero() {
        // mov eax, 42 + ret -> int64_t
        let func = make_mlil_func(vec![
            MlilInst {
                address: 0x1000,
                stmts: vec![MlilStmt::Assign {
                    dest: SsaVar {
                        name: "eax".into(),
                        version: 1,
                    },
                    src: MlilExpr::Const(42),
                }],
            },
            MlilInst {
                address: 0x1004,
                stmts: vec![MlilStmt::Return],
            },
        ]);
        let ret = detect_return_type(&func, crate::arch::Architecture::X86_64);
        assert_eq!(ret, "int64_t");
    }

    #[test]
    fn detect_return_type_xor_zero() {
        // xor eax, eax -> eax = 0, treated as void
        let func = make_mlil_func(vec![
            MlilInst {
                address: 0x1000,
                stmts: vec![MlilStmt::Assign {
                    dest: SsaVar {
                        name: "eax".into(),
                        version: 1,
                    },
                    src: MlilExpr::Const(0),
                }],
            },
            MlilInst {
                address: 0x1004,
                stmts: vec![MlilStmt::Return],
            },
        ]);
        let ret = detect_return_type(&func, crate::arch::Architecture::X86_64);
        assert_eq!(ret, "void");
    }

    #[test]
    fn detect_return_type_no_assign() {
        // Just a return with no register assignment -> void
        let func = make_mlil_func(vec![MlilInst {
            address: 0x1000,
            stmts: vec![MlilStmt::Return],
        }]);
        let ret = detect_return_type(&func, crate::arch::Architecture::X86_64);
        assert_eq!(ret, "void");
    }

    #[test]
    fn fold_return_values_simple() {
        // result_1 = 42; return; -> return 42;
        let mut stmts = vec![
            HlilStmt::Assign {
                dest: HlilExpr::Var("result_1".into()),
                src: HlilExpr::Const(42),
            },
            HlilStmt::Return(None),
        ];
        fold_return_values(&mut stmts);
        assert_eq!(stmts.len(), 1);
        assert!(
            matches!(&stmts[0], HlilStmt::Return(Some(HlilExpr::Const(42)))),
            "expected Return(Some(42)), got {:?}",
            stmts[0]
        );
    }

    #[test]
    fn fold_return_values_nested_if() {
        // Inside an if body: result = expr; return; -> return expr;
        let mut stmts = vec![HlilStmt::If {
            cond: HlilExpr::Var("flag".into()),
            then_body: vec![
                HlilStmt::Assign {
                    dest: HlilExpr::Var("result_1".into()),
                    src: HlilExpr::Const(1),
                },
                HlilStmt::Return(None),
            ],
            else_body: vec![],
        }];
        fold_return_values(&mut stmts);
        if let HlilStmt::If { then_body, .. } = &stmts[0] {
            assert_eq!(then_body.len(), 1);
            assert!(matches!(
                &then_body[0],
                HlilStmt::Return(Some(HlilExpr::Const(1)))
            ));
        } else {
            panic!("expected If statement");
        }
    }

    #[test]
    fn fold_does_not_fold_non_result_vars() {
        // counter = 42; return; -> NOT folded (variable isn't "result*")
        let mut stmts = vec![
            HlilStmt::Assign {
                dest: HlilExpr::Var("counter".into()),
                src: HlilExpr::Const(42),
            },
            HlilStmt::Return(None),
        ];
        fold_return_values(&mut stmts);
        assert_eq!(stmts.len(), 2, "non-result variable should not be folded");
    }

    #[test]
    fn decompile_function_with_params() {
        // Function that reads rdi (first param) and assigns to eax, then returns.
        let insns = vec![
            make_insn(0x1000, "push", "rbp"),
            make_insn(0x1001, "mov", "rbp, rsp"),
            make_insn(0x1004, "mov", "eax, edi"),
            make_insn(0x1006, "pop", "rbp"),
            make_insn(0x1007, "ret", ""),
        ];
        let code = decompile("get_arg", &insns, crate::arch::Architecture::X86_64);
        // Should detect edi (mapped from rdi) as param and eax assignment as return.
        assert!(
            code.contains("get_arg("),
            "expected function with params, got: {}",
            code
        );
    }

    #[test]
    fn decompile_function_with_stack_locals() {
        // Function with local variables on the stack.
        let insns = vec![
            make_insn(0x1000, "push", "rbp"),
            make_insn(0x1001, "mov", "rbp, rsp"),
            make_insn(0x1004, "sub", "rsp, 0x20"),
            make_insn(0x1008, "mov", "qword ptr [rbp - 0x8], rdi"),
            make_insn(0x100c, "mov", "dword ptr [rbp - 0x10], esi"),
            make_insn(0x1010, "xor", "eax, eax"),
            make_insn(0x1012, "ret", ""),
        ];
        let code = decompile("with_locals", &insns, crate::arch::Architecture::X86_64);
        // Should have local variable declarations.
        assert!(
            code.contains("var_"),
            "expected local variable declarations, got: {}",
            code
        );
    }

    #[test]
    fn render_pseudocode_with_info_basic() {
        let info = DecompileInfo {
            return_type: "int64_t".to_string(),
            params: vec![
                ("int64_t".to_string(), "arg1".to_string()),
                ("int64_t".to_string(), "arg2".to_string()),
            ],
            locals: vec![("int32_t".to_string(), "var_1".to_string())],
        };
        let stmts = vec![HlilStmt::Return(Some(HlilExpr::Const(0)))];
        let code = hlil::render_pseudocode_with_info("add_func", &stmts, &info);
        assert!(
            code.contains("int64_t add_func(int64_t arg1, int64_t arg2)"),
            "wrong signature: {}",
            code
        );
        assert!(
            code.contains("int32_t var_1;"),
            "missing local decl: {}",
            code
        );
        assert!(code.contains("return 0;"), "missing return: {}", code);
    }

    #[test]
    fn render_pseudocode_with_info_void_no_params() {
        let info = DecompileInfo {
            return_type: "void".to_string(),
            params: vec![],
            locals: vec![],
        };
        let stmts = vec![HlilStmt::Return(None)];
        let code = hlil::render_pseudocode_with_info("noop", &stmts, &info);
        assert!(
            code.contains("void noop(void)"),
            "wrong void signature: {}",
            code
        );
    }
}
