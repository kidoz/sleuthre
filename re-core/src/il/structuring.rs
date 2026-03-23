//! Control flow structuring: converts flat MLIL sequences into structured HLIL.
//!
//! This module recognizes patterns like:
//! - cmp/test + branch → if/else
//! - back edges → while/do-while loops
//! - Linear sequences → blocks

use std::collections::{HashMap, HashSet};

use crate::analysis::stack::StackVariable;
use crate::analysis::type_propagation::FunctionTypeInfo;
use crate::il::hlil::{self, HlilExpr, HlilStmt};
use crate::il::mlil::{MlilExpr, MlilFunction, MlilStmt};
use crate::types::{PrimitiveType, TypeManager, TypeRef};

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
    /// Types that need to be defined before this function.
    pub required_types: HashSet<String>,
    /// Header files that need to be included.
    pub includes: HashSet<String>,
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
    _symbols: &HashMap<u64, String>,
    type_info: Option<&FunctionTypeInfo>,
    _types: &TypeManager,
) -> (DecompileInfo, HashMap<i64, StackVariable>) {
    let mut params = detect_parameters(mlil, arch);
    let mut return_type = detect_return_type(mlil, arch);
    let mut required_types = HashSet::new();
    let mut includes = HashSet::new();

    // Default includes
    includes.insert("stdint.h".to_string());
    includes.insert("stdbool.h".to_string());

    // Override with propagated type info if available
    if let Some(sig) = type_info.and_then(|ti| ti.signature.as_ref()) {
        return_type = sig.return_type.display_name();
        params = sig
            .parameters
            .iter()
            .map(|p| (p.type_ref.display_name(), p.name.clone()))
            .collect();

        // Track required types from signature
        collect_required_types(&sig.return_type, &mut required_types);
        for p in &sig.parameters {
            collect_required_types(&p.type_ref, &mut required_types);
        }
    }

    let stack_vars = recover_locals(instructions);

    let locals: Vec<(String, String)> = stack_vars
        .iter()
        .map(|v| (format!("{}", v.type_hint), v.name.clone()))
        .collect();

    let mut stack_map = HashMap::new();
    for var in &stack_vars {
        stack_map.insert(var.offset, var.clone());
    }

    (
        DecompileInfo {
            return_type,
            params,
            locals,
            required_types,
            includes,
        },
        stack_map,
    )
}

fn collect_required_types(ty: &TypeRef, required: &mut HashSet<String>) {
    match ty {
        TypeRef::Primitive(p) => {
            if matches!(
                p,
                PrimitiveType::U8
                    | PrimitiveType::U16
                    | PrimitiveType::U32
                    | PrimitiveType::U64
                    | PrimitiveType::I8
                    | PrimitiveType::I16
                    | PrimitiveType::I32
                    | PrimitiveType::I64
            ) {
                // stdint.h handles these
            }
        }
        TypeRef::Named(name) => {
            required.insert(name.clone());
        }
        TypeRef::Pointer(inner)
        | TypeRef::Array { element: inner, .. }
        | TypeRef::Const(inner)
        | TypeRef::Volatile(inner) => {
            collect_required_types(inner, required);
        }
        TypeRef::FunctionPointer {
            return_type,
            params,
            ..
        } => {
            collect_required_types(return_type, required);
            for p in params {
                collect_required_types(p, required);
            }
        }
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
fn recover_locals(instructions: &[crate::disasm::Instruction]) -> Vec<StackVariable> {
    crate::analysis::stack::recover_stack_variables(instructions)
}

fn remove_unused_labels(stmts: &mut Vec<HlilStmt>) {
    // 1. Collect used labels
    let mut used = HashSet::new();
    collect_used_labels(stmts, &mut used);

    // 2. Remove unused labels
    stmts.retain(|stmt| {
        if let HlilStmt::Label(addr) = stmt {
            used.contains(addr)
        } else {
            true
        }
    });

    // Recurse
    for stmt in stmts {
        match stmt {
            HlilStmt::If {
                then_body,
                else_body,
                ..
            } => {
                remove_unused_labels(then_body);
                remove_unused_labels(else_body);
            }
            HlilStmt::While { body, .. }
            | HlilStmt::DoWhile { body, .. }
            | HlilStmt::For { body, .. } => {
                remove_unused_labels(body);
            }
            HlilStmt::Block(inner) => remove_unused_labels(inner),
            HlilStmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    remove_unused_labels(body);
                }
                remove_unused_labels(default);
            }
            _ => {}
        }
    }
}

fn collect_used_labels(stmts: &[HlilStmt], used: &mut HashSet<u64>) {
    for stmt in stmts {
        match stmt {
            HlilStmt::Goto(addr) => {
                used.insert(*addr);
            }
            HlilStmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_used_labels(then_body, used);
                collect_used_labels(else_body, used);
            }
            HlilStmt::While { body, .. }
            | HlilStmt::DoWhile { body, .. }
            | HlilStmt::For { body, .. } => {
                collect_used_labels(body, used);
            }
            HlilStmt::Block(inner) => collect_used_labels(inner, used),
            HlilStmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    collect_used_labels(body, used);
                }
                collect_used_labels(default, used);
            }
            _ => {}
        }
    }
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
            HlilStmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    fold_return_values(body);
                }
                fold_return_values(default);
            }
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
            HlilStmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    detect_for_loops(body);
                }
                detect_for_loops(default);
            }
            _ => {}
        }
    }
}

/// Replace stack pointer dereferences with named local variables.
fn lift_stack_refs(stmts: &mut [HlilStmt], stack_map: &HashMap<i64, StackVariable>) {
    for stmt in stmts {
        lift_stack_refs_in_stmt(stmt, stack_map);
    }
}

fn lift_stack_refs_in_stmt(stmt: &mut HlilStmt, stack_map: &HashMap<i64, StackVariable>) {
    match stmt {
        HlilStmt::Assign { dest, src } => {
            lift_stack_refs_in_expr(dest, stack_map);
            lift_stack_refs_in_expr(src, stack_map);
        }
        HlilStmt::Store { addr, value } => {
            // First, process sub-expressions normally
            lift_stack_refs_in_expr(addr, stack_map);
            lift_stack_refs_in_expr(value, stack_map);

            // Check if addr became &var (from sp+offset replacement)
            if let HlilExpr::AddrOf(inner) = addr
                && let HlilExpr::Var(name) = &**inner
            {
                *stmt = HlilStmt::Assign {
                    dest: HlilExpr::Var(name.clone()),
                    src: value.clone(),
                };
                return;
            }

            // Fallback: check raw offset (unlikely if expr lifting worked, but for completeness)
            if let Some(offset) = extract_stack_offset(addr)
                && let Some(var) = stack_map.get(&offset)
            {
                *stmt = HlilStmt::Assign {
                    dest: HlilExpr::Var(var.name.clone()),
                    src: value.clone(),
                };
            }
        }
        HlilStmt::Expr(e) => lift_stack_refs_in_expr(e, stack_map),
        HlilStmt::Return(opt) => {
            if let Some(e) = opt {
                lift_stack_refs_in_expr(e, stack_map);
            }
        }
        HlilStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            lift_stack_refs_in_expr(cond, stack_map);
            lift_stack_refs(then_body, stack_map);
            lift_stack_refs(else_body, stack_map);
        }
        HlilStmt::While { cond, body } => {
            lift_stack_refs_in_expr(cond, stack_map);
            lift_stack_refs(body, stack_map);
        }
        HlilStmt::DoWhile { body, cond } => {
            lift_stack_refs(body, stack_map);
            lift_stack_refs_in_expr(cond, stack_map);
        }
        HlilStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            lift_stack_refs_in_stmt(init, stack_map);
            lift_stack_refs_in_expr(cond, stack_map);
            lift_stack_refs_in_stmt(update, stack_map);
            lift_stack_refs(body, stack_map);
        }
        HlilStmt::Block(stmts) => lift_stack_refs(stmts, stack_map),
        HlilStmt::Switch {
            cond,
            cases,
            default,
        } => {
            lift_stack_refs_in_expr(cond, stack_map);
            for (_, body) in cases {
                lift_stack_refs(body, stack_map);
            }
            lift_stack_refs(default, stack_map);
        }
        HlilStmt::Break
        | HlilStmt::Continue
        | HlilStmt::Label(_)
        | HlilStmt::Goto(_)
        | HlilStmt::Comment(_) => {}
    }
}

fn lift_stack_refs_in_expr(expr: &mut HlilExpr, stack_map: &HashMap<i64, StackVariable>) {
    // Top-down or bottom-up?
    // If we have `*(sp + 8)`, that is a Deref.
    // If we have `sp + 8`, that is a pointer calculation.

    // If matches `Deref(addr, size)`:
    if let HlilExpr::Deref { addr, .. } = expr
        && let Some(offset) = extract_stack_offset(addr)
        && let Some(var) = stack_map.get(&offset)
    {
        // Replace `*(sp + off)` with `var`
        *expr = HlilExpr::Var(var.name.clone());
        return;
    }

    // If matches `sp + offset` (without deref), it might be `&var`.
    // We can replace it with `AddrOf(Var)`?
    // HlilExpr has AddrOf.
    if let Some(offset) = extract_stack_offset(expr)
        && let Some(var) = stack_map.get(&offset)
    {
        *expr = HlilExpr::AddrOf(Box::new(HlilExpr::Var(var.name.clone())));
        return;
    }

    // Recurse
    match expr {
        HlilExpr::Deref { addr, .. } => lift_stack_refs_in_expr(addr, stack_map),
        HlilExpr::BinOp { left, right, .. } => {
            lift_stack_refs_in_expr(left, stack_map);
            lift_stack_refs_in_expr(right, stack_map);
        }
        HlilExpr::UnaryOp { operand, .. } => lift_stack_refs_in_expr(operand, stack_map),
        HlilExpr::Call { target, args } => {
            lift_stack_refs_in_expr(target, stack_map);
            for arg in args {
                lift_stack_refs_in_expr(arg, stack_map);
            }
        }
        HlilExpr::AddrOf(inner) => lift_stack_refs_in_expr(inner, stack_map),
        HlilExpr::VectorOp { operands, .. } => {
            for op in operands {
                lift_stack_refs_in_expr(op, stack_map);
            }
        }
        HlilExpr::FieldAccess { base, .. } => {
            lift_stack_refs_in_expr(base, stack_map);
        }
        HlilExpr::ArrayAccess { base, index } => {
            lift_stack_refs_in_expr(base, stack_map);
            lift_stack_refs_in_expr(index, stack_map);
        }
        HlilExpr::Var(_) | HlilExpr::Global(..) | HlilExpr::Const(_) => {}
    }
}

fn resolve_symbols(stmts: &mut [HlilStmt], symbols: &HashMap<u64, String>) {
    for stmt in stmts {
        resolve_symbols_in_stmt(stmt, symbols);
    }
}

fn resolve_symbols_in_stmt(stmt: &mut HlilStmt, symbols: &HashMap<u64, String>) {
    match stmt {
        HlilStmt::Assign { dest, src } => {
            resolve_symbols_in_expr(dest, symbols);
            resolve_symbols_in_expr(src, symbols);
        }
        HlilStmt::Store { addr, value } => {
            resolve_symbols_in_expr(addr, symbols);
            resolve_symbols_in_expr(value, symbols);
        }
        HlilStmt::Expr(e) => resolve_symbols_in_expr(e, symbols),
        HlilStmt::Return(opt) => {
            if let Some(e) = opt {
                resolve_symbols_in_expr(e, symbols);
            }
        }
        HlilStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            resolve_symbols_in_expr(cond, symbols);
            resolve_symbols(then_body, symbols);
            resolve_symbols(else_body, symbols);
        }
        HlilStmt::While { cond, body } => {
            resolve_symbols_in_expr(cond, symbols);
            resolve_symbols(body, symbols);
        }
        HlilStmt::DoWhile { body, cond } => {
            resolve_symbols(body, symbols);
            resolve_symbols_in_expr(cond, symbols);
        }
        HlilStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            resolve_symbols_in_stmt(init, symbols);
            resolve_symbols_in_expr(cond, symbols);
            resolve_symbols_in_stmt(update, symbols);
            resolve_symbols(body, symbols);
        }
        HlilStmt::Block(stmts) => resolve_symbols(stmts, symbols),
        HlilStmt::Switch {
            cond,
            cases,
            default,
        } => {
            resolve_symbols_in_expr(cond, symbols);
            for (_, body) in cases {
                resolve_symbols(body, symbols);
            }
            resolve_symbols(default, symbols);
        }
        HlilStmt::Break
        | HlilStmt::Continue
        | HlilStmt::Label(_)
        | HlilStmt::Goto(_)
        | HlilStmt::Comment(_) => {}
    }
}

fn resolve_symbols_in_expr(expr: &mut HlilExpr, symbols: &HashMap<u64, String>) {
    match expr {
        HlilExpr::Const(val) => {
            if let Some(name) = symbols.get(val) {
                *expr = HlilExpr::Global(*val, name.clone());
            }
        }
        HlilExpr::Deref { addr, .. } => resolve_symbols_in_expr(addr, symbols),
        HlilExpr::BinOp { left, right, .. } => {
            resolve_symbols_in_expr(left, symbols);
            resolve_symbols_in_expr(right, symbols);
        }
        HlilExpr::UnaryOp { operand, .. } => resolve_symbols_in_expr(operand, symbols),
        HlilExpr::Call { target, args } => {
            resolve_symbols_in_expr(target, symbols);
            for arg in args {
                resolve_symbols_in_expr(arg, symbols);
            }
        }
        HlilExpr::AddrOf(inner) => resolve_symbols_in_expr(inner, symbols),
        HlilExpr::VectorOp { operands, .. } => {
            for op in operands {
                resolve_symbols_in_expr(op, symbols);
            }
        }
        HlilExpr::FieldAccess { base, .. } => {
            resolve_symbols_in_expr(base, symbols);
        }
        HlilExpr::ArrayAccess { base, index } => {
            resolve_symbols_in_expr(base, symbols);
            resolve_symbols_in_expr(index, symbols);
        }
        HlilExpr::Var(_) | HlilExpr::Global(..) => {}
    }
}

// ---- Global Variable Resolution ----

fn resolve_globals(stmts: &mut [HlilStmt], types: &TypeManager) {
    for stmt in stmts {
        resolve_globals_in_stmt(stmt, types);
    }
}

fn resolve_globals_in_stmt(stmt: &mut HlilStmt, types: &TypeManager) {
    match stmt {
        HlilStmt::Store { addr, value } => {
            resolve_globals_in_expr(addr, types);
            resolve_globals_in_expr(value, types);
        }
        HlilStmt::Assign { dest, src } => {
            resolve_globals_in_expr(dest, types);
            resolve_globals_in_expr(src, types);
        }
        HlilStmt::Expr(e) => resolve_globals_in_expr(e, types),
        HlilStmt::Return(opt) => {
            if let Some(e) = opt {
                resolve_globals_in_expr(e, types);
            }
        }
        HlilStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            resolve_globals_in_expr(cond, types);
            resolve_globals(then_body, types);
            resolve_globals(else_body, types);
        }
        HlilStmt::While { cond, body } => {
            resolve_globals_in_expr(cond, types);
            resolve_globals(body, types);
        }
        HlilStmt::DoWhile { body, cond } => {
            resolve_globals(body, types);
            resolve_globals_in_expr(cond, types);
        }
        HlilStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            resolve_globals_in_stmt(init, types);
            resolve_globals_in_expr(cond, types);
            resolve_globals_in_stmt(update, types);
            resolve_globals(body, types);
        }
        HlilStmt::Block(inner) => resolve_globals(inner, types),
        HlilStmt::Switch {
            cond,
            cases,
            default,
        } => {
            resolve_globals_in_expr(cond, types);
            for (_, body) in cases {
                resolve_globals(body, types);
            }
            resolve_globals(default, types);
        }
        HlilStmt::Break
        | HlilStmt::Continue
        | HlilStmt::Label(_)
        | HlilStmt::Goto(_)
        | HlilStmt::Comment(_) => {}
    }

    // Post-pass: convert Store to Assign when address is a known global variable
    let replace_with = match &*stmt {
        HlilStmt::Store { addr, value } => {
            if let HlilExpr::Global(addr_val, name) = addr {
                if types.global_variables.contains_key(addr_val) {
                    Some(HlilStmt::Assign {
                        dest: HlilExpr::Global(*addr_val, name.clone()),
                        src: value.clone(),
                    })
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    };
    if let Some(new_stmt) = replace_with {
        *stmt = new_stmt;
    }
}

fn resolve_globals_in_expr(expr: &mut HlilExpr, types: &TypeManager) {
    match expr {
        HlilExpr::Const(val) => {
            if let Some(var) = types.global_variables.get(val) {
                *expr = HlilExpr::Global(*val, var.name.clone());
            }
        }
        HlilExpr::Global(addr, name) => {
            // Prefer global variable name over symbol name
            if let Some(var) = types.global_variables.get(addr) {
                *name = var.name.clone();
            }
        }
        HlilExpr::Deref { addr, .. } => {
            resolve_globals_in_expr(addr, types);
            // Fold: *(global_var_addr) → global_var
            let resolved = match &**addr {
                HlilExpr::Global(addr_val, name)
                    if types.global_variables.contains_key(addr_val) =>
                {
                    Some(HlilExpr::Global(*addr_val, name.clone()))
                }
                HlilExpr::Const(val) if types.global_variables.contains_key(val) => {
                    let var = &types.global_variables[val];
                    Some(HlilExpr::Global(*val, var.name.clone()))
                }
                _ => None,
            };
            if let Some(g) = resolved {
                *expr = g;
            }
        }
        HlilExpr::BinOp { left, right, .. } => {
            resolve_globals_in_expr(left, types);
            resolve_globals_in_expr(right, types);
        }
        HlilExpr::UnaryOp { operand, .. } => resolve_globals_in_expr(operand, types),
        HlilExpr::Call { target, args } => {
            resolve_globals_in_expr(target, types);
            for arg in args {
                resolve_globals_in_expr(arg, types);
            }
        }
        HlilExpr::AddrOf(inner) => resolve_globals_in_expr(inner, types),
        HlilExpr::FieldAccess { base, .. } => resolve_globals_in_expr(base, types),
        HlilExpr::ArrayAccess { base, index } => {
            resolve_globals_in_expr(base, types);
            resolve_globals_in_expr(index, types);
        }
        HlilExpr::VectorOp { operands, .. } => {
            for op in operands {
                resolve_globals_in_expr(op, types);
            }
        }
        HlilExpr::Var(_) => {}
    }
}

/// Try to extract a stack offset from an expression.
/// Matches: `sp`, `sp + C`, `sp - C`.
fn extract_stack_offset(expr: &HlilExpr) -> Option<i64> {
    match expr {
        HlilExpr::Var(name) if is_stack_pointer(name) => Some(0),
        HlilExpr::BinOp {
            op: crate::il::llil::BinOp::Add,
            left,
            right,
        } => {
            if let HlilExpr::Var(name) = &**left
                && is_stack_pointer(name)
                && let HlilExpr::Const(c) = &**right
            {
                Some(*c as i64)
            } else if let HlilExpr::Var(name) = &**right
                && is_stack_pointer(name)
                && let HlilExpr::Const(c) = &**left
            {
                Some(*c as i64)
            } else {
                None
            }
        }
        HlilExpr::BinOp {
            op: crate::il::llil::BinOp::Sub,
            left,
            right,
        } => {
            if let HlilExpr::Var(name) = &**left
                && is_stack_pointer(name)
                && let HlilExpr::Const(c) = &**right
            {
                Some(-(*c as i64))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_stack_pointer(name: &str) -> bool {
    matches!(
        name,
        "sp" | "rsp" | "esp" | "rbp" | "ebp" | "x29" | "fp" | "frame"
    )
}

/// Collect all SSA variables used in the HLIL that are not already declared
/// as parameters or locals.
fn collect_ssa_vars_in_hlil(
    stmts: &[HlilStmt],
    known_vars: &HashSet<&str>,
    type_info: Option<&FunctionTypeInfo>,
    inferred_types: &HashMap<String, TypeRef>,
) -> Vec<(String, String)> {
    let mut found = HashSet::new();
    collect_ssa_vars_stmts(stmts, &mut found);

    let mut result = Vec::new();
    for name in found {
        if !known_vars.contains(name.as_str()) && !is_stack_pointer(&name) {
            let ty = inferred_types
                .get(&name)
                .map(|t| t.display_name())
                .or_else(|| {
                    type_info
                        .and_then(|ti| ti.var_types.get(&name))
                        .map(|t| t.display_name())
                })
                .unwrap_or_else(|| "int64_t".to_string());
            result.push((ty, name));
        }
    }
    // Sort for stability
    result.sort();
    result
}

fn infer_local_types(
    stmts: &[HlilStmt],
    inferred_types: &mut HashMap<String, TypeRef>,
    types: &TypeManager,
) {
    for stmt in stmts {
        infer_types_in_stmt(stmt, inferred_types, types);
    }
}

fn infer_types_in_stmt(
    stmt: &HlilStmt,
    inferred_types: &mut HashMap<String, TypeRef>,
    types: &TypeManager,
) {
    match stmt {
        HlilStmt::Assign { dest, src } => {
            // Propagate type from src to dest
            if let HlilExpr::Var(name) = dest
                && let Some(ty) = get_expr_type(src, inferred_types, types)
            {
                inferred_types.insert(name.clone(), ty);
            }
            infer_types_in_expr(dest, inferred_types, types);
            infer_types_in_expr(src, inferred_types, types);
        }
        HlilStmt::Store { addr, value } => {
            if let HlilExpr::Var(name) = addr {
                inferred_types.entry(name.clone()).or_insert_with(|| {
                    TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::Void)))
                });
            }
            infer_types_in_expr(addr, inferred_types, types);
            infer_types_in_expr(value, inferred_types, types);
        }
        HlilStmt::Expr(e) => infer_types_in_expr(e, inferred_types, types),
        HlilStmt::Return(opt) => {
            if let Some(e) = opt {
                infer_types_in_expr(e, inferred_types, types);
            }
        }
        HlilStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            infer_types_in_expr(cond, inferred_types, types);
            infer_local_types(then_body, inferred_types, types);
            infer_local_types(else_body, inferred_types, types);
        }
        HlilStmt::While { cond, body } => {
            infer_types_in_expr(cond, inferred_types, types);
            infer_local_types(body, inferred_types, types);
        }
        HlilStmt::DoWhile { body, cond } => {
            infer_local_types(body, inferred_types, types);
            infer_types_in_expr(cond, inferred_types, types);
        }
        HlilStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            infer_types_in_stmt(init, inferred_types, types);
            infer_types_in_expr(cond, inferred_types, types);
            infer_types_in_stmt(update, inferred_types, types);
            infer_local_types(body, inferred_types, types);
        }
        HlilStmt::Block(inner) => infer_local_types(inner, inferred_types, types),
        HlilStmt::Switch {
            cond,
            cases,
            default,
        } => {
            infer_types_in_expr(cond, inferred_types, types);
            for (_, body) in cases {
                infer_local_types(body, inferred_types, types);
            }
            infer_local_types(default, inferred_types, types);
        }
        HlilStmt::Break
        | HlilStmt::Continue
        | HlilStmt::Label(_)
        | HlilStmt::Goto(_)
        | HlilStmt::Comment(_) => {}
    }
}

fn infer_types_in_expr(
    expr: &HlilExpr,
    inferred_types: &mut HashMap<String, TypeRef>,
    types: &TypeManager,
) {
    match expr {
        HlilExpr::Deref { addr, size } => {
            if let HlilExpr::Var(name) = &**addr {
                let inner = match *size {
                    1 => PrimitiveType::U8,
                    2 => PrimitiveType::U16,
                    4 => PrimitiveType::U32,
                    8 => PrimitiveType::U64,
                    _ => PrimitiveType::Void,
                };
                inferred_types
                    .entry(name.clone())
                    .or_insert_with(|| TypeRef::Pointer(Box::new(TypeRef::Primitive(inner))));
            }
            infer_types_in_expr(addr, inferred_types, types);
        }
        HlilExpr::Call { target, args } => {
            // Try to resolve target signature from TypeManager
            let sig = if let HlilExpr::Global(addr, _) = &**target {
                types.function_signatures.get(addr)
            } else {
                None
            };

            if let Some(sig) = sig {
                // Propagate parameter types to argument variables
                for (i, arg) in args.iter().enumerate() {
                    if i < sig.parameters.len() {
                        let param_type = &sig.parameters[i].type_ref;
                        if let HlilExpr::Var(arg_name) = arg {
                            inferred_types.insert(arg_name.clone(), param_type.clone());
                        }
                    }
                }
            } else {
                // Fallback: infer target is a function pointer if it's a variable
                if let HlilExpr::Var(name) = &**target {
                    inferred_types.entry(name.clone()).or_insert_with(|| {
                        TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::Void)))
                    });
                }
            }

            infer_types_in_expr(target, inferred_types, types);
            for arg in args {
                infer_types_in_expr(arg, inferred_types, types);
            }
        }
        HlilExpr::BinOp { left, right, .. } => {
            infer_types_in_expr(left, inferred_types, types);
            infer_types_in_expr(right, inferred_types, types);
        }
        HlilExpr::UnaryOp { operand, .. } => infer_types_in_expr(operand, inferred_types, types),
        HlilExpr::AddrOf(inner) => infer_types_in_expr(inner, inferred_types, types),
        HlilExpr::VectorOp { operands, .. } => {
            for op in operands {
                infer_types_in_expr(op, inferred_types, types);
            }
        }
        HlilExpr::FieldAccess { base, .. } => {
            infer_types_in_expr(base, inferred_types, types);
        }
        HlilExpr::ArrayAccess { base, index } => {
            infer_types_in_expr(base, inferred_types, types);
            infer_types_in_expr(index, inferred_types, types);
        }
        HlilExpr::Var(_) | HlilExpr::Global(..) | HlilExpr::Const(_) => {}
    }
}

fn collect_ssa_vars_stmts(stmts: &[HlilStmt], found: &mut HashSet<String>) {
    for stmt in stmts {
        match stmt {
            HlilStmt::Assign { dest, src } => {
                collect_ssa_vars_expr(dest, found);
                collect_ssa_vars_expr(src, found);
            }
            HlilStmt::Store { addr, value } => {
                collect_ssa_vars_expr(addr, found);
                collect_ssa_vars_expr(value, found);
            }
            HlilStmt::Expr(e) => collect_ssa_vars_expr(e, found),
            HlilStmt::Return(opt) => {
                if let Some(e) = opt {
                    collect_ssa_vars_expr(e, found);
                }
            }
            HlilStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_ssa_vars_expr(cond, found);
                collect_ssa_vars_stmts(then_body, found);
                collect_ssa_vars_stmts(else_body, found);
            }
            HlilStmt::While { cond, body } => {
                collect_ssa_vars_expr(cond, found);
                collect_ssa_vars_stmts(body, found);
            }
            HlilStmt::DoWhile { body, cond } => {
                collect_ssa_vars_stmts(body, found);
                collect_ssa_vars_expr(cond, found);
            }
            HlilStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                collect_ssa_vars_stmts(&[*init.clone()], found); // Box deref clone
                collect_ssa_vars_expr(cond, found);
                collect_ssa_vars_stmts(&[*update.clone()], found);
                collect_ssa_vars_stmts(body, found);
            }
            HlilStmt::Block(inner) => collect_ssa_vars_stmts(inner, found),
            HlilStmt::Switch {
                cond,
                cases,
                default,
            } => {
                collect_ssa_vars_expr(cond, found);
                for (_, body) in cases {
                    collect_ssa_vars_stmts(body, found);
                }
                collect_ssa_vars_stmts(default, found);
            }
            HlilStmt::Break
            | HlilStmt::Continue
            | HlilStmt::Label(_)
            | HlilStmt::Goto(_)
            | HlilStmt::Comment(_) => {}
        }
    }
}

fn collect_ssa_vars_expr(expr: &HlilExpr, found: &mut HashSet<String>) {
    match expr {
        HlilExpr::Var(name) => {
            found.insert(name.clone());
        }
        HlilExpr::Deref { addr, .. } => collect_ssa_vars_expr(addr, found),
        HlilExpr::BinOp { left, right, .. } => {
            collect_ssa_vars_expr(left, found);
            collect_ssa_vars_expr(right, found);
        }
        HlilExpr::UnaryOp { operand, .. } => collect_ssa_vars_expr(operand, found),
        HlilExpr::Call { target, args } => {
            collect_ssa_vars_expr(target, found);
            for arg in args {
                collect_ssa_vars_expr(arg, found);
            }
        }
        HlilExpr::AddrOf(inner) => collect_ssa_vars_expr(inner, found),
        HlilExpr::VectorOp { operands, .. } => {
            for op in operands {
                collect_ssa_vars_expr(op, found);
            }
        }
        HlilExpr::FieldAccess { base, .. } => {
            collect_ssa_vars_expr(base, found);
        }
        HlilExpr::ArrayAccess { base, index } => {
            collect_ssa_vars_expr(base, found);
            collect_ssa_vars_expr(index, found);
        }
        HlilExpr::Const(_) | HlilExpr::Global(..) => {}
    }
}

/// Convert an MLIL function into structured HLIL statements.
pub fn structure_function(
    func: &MlilFunction,
    memory: &crate::memory::MemoryMap,
    arch: crate::arch::Architecture,
) -> Vec<HlilStmt> {
    let mut jump_targets = HashSet::new();
    for inst in &func.instructions {
        for stmt in &inst.stmts {
            if let MlilStmt::Jump {
                target: MlilExpr::Const(addr),
            } = stmt
            {
                jump_targets.insert(*addr);
            }
            if let MlilStmt::BranchIf {
                target: MlilExpr::Const(addr),
                ..
            } = stmt
            {
                jump_targets.insert(*addr);
            }
        }
    }

    let mut stmts = structure_range(
        &func.instructions,
        &ControlFlowContext::default(),
        &jump_targets,
        memory,
        arch,
    );
    remove_unused_labels(&mut stmts);
    stmts
}

fn structure_range(
    insts: &[crate::il::mlil::MlilInst],
    ctx: &ControlFlowContext,
    jump_targets: &HashSet<u64>,
    memory: &crate::memory::MemoryMap,
    arch: crate::arch::Architecture,
) -> Vec<HlilStmt> {
    let mut stmts = Vec::new();
    let mut i = 0;

    while i < insts.len() {
        let inst = &insts[i];

        // Emit label if this address is a jump target
        if jump_targets.contains(&inst.address) {
            stmts.push(HlilStmt::Label(inst.address));
        }

        // Check for do-while loop: look ahead for a BranchIf that targets the current
        // instruction's address (back edge), indicating this is the loop head.
        if let Some(back_branch) = find_do_while_back_edge(insts, i) {
            // Loop head is current instruction.
            // Loop exit is the instruction following the back branch.
            let head_addr = insts[i].address;
            let exit_addr = if back_branch.branch_idx + 1 < insts.len() {
                Some(insts[back_branch.branch_idx + 1].address)
            } else {
                None
            };

            let loop_ctx = ControlFlowContext {
                loop_head: Some(head_addr),
                loop_exit: exit_addr,
            };

            let body = structure_range(
                &insts[i..back_branch.branch_idx],
                &loop_ctx,
                jump_targets,
                memory,
                arch,
            );
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

            let loop_ctx = ControlFlowContext {
                loop_head: Some(insts[i].address),
                loop_exit: Some(*exit_addr),
            };

            let body = structure_range(
                &insts[i + 1..eidx - 1],
                &loop_ctx,
                jump_targets,
                memory,
                arch,
            );
            stmts.push(HlilStmt::While { cond, body });
            i = eidx;
            continue;
        }

        // Check for if-pattern: BranchIf followed by linear blocks
        if let Some(branch_stmt) = find_branch_if(&inst.stmts)
            && let Some((then_end, else_end)) = find_if_else_bounds(insts, i, &branch_stmt)
        {
            let cond = hlil::mlil_to_hlil_expr(&branch_stmt.0);
            let then_body =
                structure_range(&insts[i + 1..then_end], ctx, jump_targets, memory, arch);
            let else_body = if else_end > then_end {
                structure_range(&insts[then_end..else_end], ctx, jump_targets, memory, arch)
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
        stmts.extend(lower_mlil_stmts(&inst.stmts, ctx, memory, arch));
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

fn recover_switch(
    target: &MlilExpr,
    memory: &crate::memory::MemoryMap,
    arch: crate::arch::Architecture,
) -> Option<HlilStmt> {
    // Pattern: Jump(Load(base + index * scale))
    if let MlilExpr::Load { addr, size } = target
        && let MlilExpr::BinOp {
            op: crate::il::llil::BinOp::Add,
            left,
            right,
        } = &**addr
    {
        let (base, offset) = if let MlilExpr::Const(c) = &**left {
            (*c, &**right)
        } else if let MlilExpr::Const(c) = &**right {
            (*c, &**left)
        } else {
            return None;
        };

        // Offset might be index * scale or just index (if scale is 1)
        let (index_expr, scale) = if let MlilExpr::BinOp {
            op: crate::il::llil::BinOp::Mul,
            left,
            right,
        } = offset
        {
            if let MlilExpr::Const(s) = &**left {
                (&**right, *s)
            } else if let MlilExpr::Const(s) = &**right {
                (&**left, *s)
            } else {
                (offset, 1)
            }
        } else {
            (offset, 1)
        };

        // Validate scale matches pointer size
        if scale != *size as u64 {
            return None;
        }

        // Heuristic: Read pointers from base until invalid
        let mut cases = Vec::new();
        let mut cursor = base;
        let mut idx = 0;
        let endian = arch.default_endianness();

        // Limit to reasonable number of cases
        while cases.len() < 256 {
            let ptr = if *size == 8 {
                match memory.read_u64(cursor, endian) {
                    Some(p) => p,
                    None => break,
                }
            } else {
                match memory.read_u32(cursor, endian) {
                    Some(p) => p as u64,
                    None => break,
                }
            };

            // Validate pointer points to executable code or is 0 (if sparse)
            if ptr == 0 {
                break;
            }

            cases.push((idx, vec![HlilStmt::Goto(ptr)]));
            cursor += *size as u64;
            idx += 1;
        }

        if !cases.is_empty() {
            return Some(HlilStmt::Switch {
                cond: hlil::mlil_to_hlil_expr(index_expr),
                cases,
                default: vec![], // Unknown default from just the jump
            });
        }
    }
    None
}

fn get_expr_type(
    expr: &HlilExpr,
    inferred_types: &HashMap<String, TypeRef>,
    types: &TypeManager,
) -> Option<TypeRef> {
    match expr {
        HlilExpr::Const(_) => Some(TypeRef::Primitive(PrimitiveType::U64)),
        HlilExpr::Var(name) => inferred_types.get(name).cloned(),
        HlilExpr::Global(addr, _) => types
            .global_variables
            .get(addr)
            .map(|var| var.type_ref.clone()),
        HlilExpr::Call { target, .. } => {
            if let HlilExpr::Global(addr, _) = &**target {
                types
                    .function_signatures
                    .get(addr)
                    .map(|s| s.return_type.clone())
            } else if let HlilExpr::Var(name) = &**target {
                if let Some(TypeRef::FunctionPointer { return_type, .. }) = inferred_types.get(name)
                {
                    Some(*return_type.clone())
                } else {
                    None
                }
            } else {
                None
            }
        }
        HlilExpr::Deref { size, .. } => Some(TypeRef::Primitive(match size {
            1 => PrimitiveType::U8,
            2 => PrimitiveType::U16,
            4 => PrimitiveType::U32,
            8 => PrimitiveType::U64,
            _ => PrimitiveType::Void,
        })),
        HlilExpr::FieldAccess {
            base,
            field_name,
            is_ptr,
        } => {
            let base_type = get_expr_type(base, inferred_types, types)?;
            let struct_type = if *is_ptr {
                if let TypeRef::Pointer(inner) = base_type {
                    *inner
                } else {
                    return None;
                }
            } else {
                base_type
            };

            if let TypeRef::Named(name) = struct_type
                && let Some(
                    crate::types::CompoundType::Struct { fields, .. }
                    | crate::types::CompoundType::Union { fields, .. },
                ) = types.get_type(&name)
            {
                return fields
                    .iter()
                    .find(|f| f.name == *field_name)
                    .map(|f| f.type_ref.clone());
            }
            None
        }
        HlilExpr::ArrayAccess { base, .. } => {
            let base_type = get_expr_type(base, inferred_types, types)?;
            if let TypeRef::Array { element, .. } = base_type {
                Some(*element)
            } else if let TypeRef::Pointer(inner) = base_type {
                Some(*inner)
            } else {
                None
            }
        }
        _ => None,
    }
}

// ---- Struct/Array Access Helpers ----

/// Get the type of an expression, combining inferred types and external type info.
fn expr_type(
    expr: &HlilExpr,
    type_info: Option<&FunctionTypeInfo>,
    inferred_types: &HashMap<String, TypeRef>,
    types: &TypeManager,
) -> Option<TypeRef> {
    get_expr_type(expr, inferred_types, types).or_else(|| {
        if let HlilExpr::Var(name) = expr {
            type_info.and_then(|ti| ti.var_types.get(name)).cloned()
        } else {
            None
        }
    })
}

/// Try to resolve `*(base + offset)` as a struct field access.
fn try_struct_field_access(
    base: &HlilExpr,
    offset: u64,
    type_info: Option<&FunctionTypeInfo>,
    inferred_types: &HashMap<String, TypeRef>,
    types: &TypeManager,
) -> Option<HlilExpr> {
    let base_type = expr_type(base, type_info, inferred_types, types)?;

    // Pointer-to-struct: base->field
    if let TypeRef::Pointer(inner) = &base_type
        && let Some(result) = resolve_struct_field(base, offset, true, inner, types)
    {
        return Some(result);
    }

    // Direct struct (e.g. stack-allocated or embedded): base.field
    if matches!(&base_type, TypeRef::Named(_))
        && let Some(result) = resolve_struct_field(base, offset, false, &base_type, types)
    {
        return Some(result);
    }

    None
}

/// Recursively resolve a struct field at a given byte offset, handling nested structs
/// and arrays of structs.
fn resolve_struct_field(
    base: &HlilExpr,
    offset: u64,
    is_ptr: bool,
    struct_type_ref: &TypeRef,
    types: &TypeManager,
) -> Option<HlilExpr> {
    let (fields, struct_size) = resolve_to_struct_fields(struct_type_ref, types)?;

    // Direct field match
    if let Some(field) = fields.iter().find(|f| f.offset == offset as usize) {
        return Some(HlilExpr::FieldAccess {
            base: Box::new(base.clone()),
            field_name: field.name.clone(),
            is_ptr,
        });
    }

    // Nested struct: find the containing field and recurse
    for field in fields {
        // Embedded struct
        if let Some((_, nested_size)) = resolve_to_struct_info(&field.type_ref, types)
            && offset as usize >= field.offset
            && (offset as usize) < field.offset + nested_size
        {
            let inner_offset = offset - field.offset as u64;
            let field_access = HlilExpr::FieldAccess {
                base: Box::new(base.clone()),
                field_name: field.name.clone(),
                is_ptr,
            };
            return resolve_struct_field(
                &field_access,
                inner_offset,
                false, // nested access is always direct (embedded struct)
                &field.type_ref,
                types,
            );
        }

        // Array of structs
        if let TypeRef::Array { element, count } = &field.type_ref
            && let Some((_, elem_size)) = resolve_to_struct_info(element, types)
            && elem_size > 0
        {
            let array_end = field.offset + elem_size * count;
            if offset as usize >= field.offset && (offset as usize) < array_end {
                let array_offset = offset as usize - field.offset;
                let index = array_offset / elem_size;
                let inner_offset = (array_offset % elem_size) as u64;

                let field_access = HlilExpr::FieldAccess {
                    base: Box::new(base.clone()),
                    field_name: field.name.clone(),
                    is_ptr,
                };
                let array_access = HlilExpr::ArrayAccess {
                    base: Box::new(field_access),
                    index: Box::new(HlilExpr::Const(index as u64)),
                };

                if inner_offset == 0 {
                    return Some(array_access);
                } else {
                    return resolve_struct_field(
                        &array_access,
                        inner_offset,
                        false,
                        element,
                        types,
                    );
                }
            }
        }
    }

    // Check if offset is still within the struct but between known fields
    // (padding or unknown field) — don't resolve
    if (offset as usize) < struct_size {
        return None;
    }

    None
}

/// Resolve a TypeRef to its struct/union fields, following typedefs.
fn resolve_to_struct_fields<'a>(
    type_ref: &TypeRef,
    types: &'a TypeManager,
) -> Option<(&'a [crate::types::StructField], usize)> {
    match type_ref {
        TypeRef::Named(name) => {
            let ct = types.get_type(name)?;
            match ct {
                crate::types::CompoundType::Struct { fields, size, .. }
                | crate::types::CompoundType::Union { fields, size, .. } => {
                    Some((fields.as_slice(), *size))
                }
                crate::types::CompoundType::Typedef { target, .. } => {
                    resolve_to_struct_fields(target, types)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Resolve a TypeRef to struct name and size, following typedefs.
fn resolve_to_struct_info<'a>(
    type_ref: &TypeRef,
    types: &'a TypeManager,
) -> Option<(&'a str, usize)> {
    match type_ref {
        TypeRef::Named(name) => {
            let ct = types.get_type(name)?;
            match ct {
                crate::types::CompoundType::Struct { name, size, .. }
                | crate::types::CompoundType::Union { name, size, .. } => {
                    Some((name.as_str(), *size))
                }
                crate::types::CompoundType::Typedef { target, .. } => {
                    resolve_to_struct_info(target, types)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Try to match an array access pattern: `*(base + index * elem_size)`.
fn try_array_access(
    base: &HlilExpr,
    index_expr: &HlilExpr,
    type_info: Option<&FunctionTypeInfo>,
    inferred_types: &HashMap<String, TypeRef>,
    types: &TypeManager,
) -> Option<HlilExpr> {
    let base_type = expr_type(base, type_info, inferred_types, types)?;
    let expected_elem_size = match &base_type {
        TypeRef::Pointer(inner) | TypeRef::Array { element: inner, .. } => types.size_of(inner),
        _ => return None,
    };
    if expected_elem_size == 0 {
        return None;
    }

    match index_expr {
        // base + index * elem_size
        HlilExpr::BinOp {
            op,
            left: mul_left,
            right: mul_right,
        } if *op == crate::il::llil::BinOp::Mul => {
            if let HlilExpr::Const(size) = &**mul_right
                && *size == expected_elem_size as u64
            {
                return Some(HlilExpr::ArrayAccess {
                    base: Box::new(base.clone()),
                    index: mul_left.clone(),
                });
            }
            // elem_size * index (commutative)
            if let HlilExpr::Const(size) = &**mul_left
                && *size == expected_elem_size as u64
            {
                return Some(HlilExpr::ArrayAccess {
                    base: Box::new(base.clone()),
                    index: mul_right.clone(),
                });
            }
            None
        }
        // base + index << log2(elem_size)
        HlilExpr::BinOp {
            op,
            left: shl_left,
            right: shl_right,
        } if *op == crate::il::llil::BinOp::Shl => {
            if let HlilExpr::Const(shift) = &**shl_right
                && expected_elem_size.is_power_of_two()
                && (1usize << shift) == expected_elem_size
            {
                return Some(HlilExpr::ArrayAccess {
                    base: Box::new(base.clone()),
                    index: shl_left.clone(),
                });
            }
            None
        }
        // base + index (element size 1, e.g. byte array / char*)
        _ => {
            if expected_elem_size == 1 {
                Some(HlilExpr::ArrayAccess {
                    base: Box::new(base.clone()),
                    index: Box::new(index_expr.clone()),
                })
            } else {
                None
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ControlFlowContext {
    loop_head: Option<u64>,
    loop_exit: Option<u64>,
}

/// Lower MLIL statements into HLIL statements.
fn lower_mlil_stmts(
    stmts: &[MlilStmt],
    ctx: &ControlFlowContext,
    memory: &crate::memory::MemoryMap,
    arch: crate::arch::Architecture,
) -> Vec<HlilStmt> {
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
            MlilStmt::Jump { target } => {
                if let MlilExpr::Const(addr) = target {
                    if Some(*addr) == ctx.loop_head {
                        result.push(HlilStmt::Continue);
                    } else if Some(*addr) == ctx.loop_exit {
                        result.push(HlilStmt::Break);
                    } else {
                        result.push(HlilStmt::Goto(*addr));
                    }
                } else if let Some(switch_stmt) = recover_switch(target, memory, arch) {
                    result.push(switch_stmt);
                } else {
                    // Indirect jump (computed goto)
                    // Fallback to evaluating the target
                    result.push(HlilStmt::Expr(hlil::mlil_to_hlil_expr(target)));
                }
            }
            MlilStmt::BranchIf { cond, target } => {
                if let MlilExpr::Const(addr) = target {
                    // If we are here, it means this branch wasn't structured into an If/Loop.
                    // We emit: if (cond) goto target;
                    result.push(HlilStmt::If {
                        cond: hlil::mlil_to_hlil_expr(cond),
                        then_body: vec![HlilStmt::Goto(*addr)],
                        else_body: vec![],
                    });
                }
            }
            MlilStmt::Nop => {}
        }
    }
    result
}

/// Full decompilation pipeline: LLIL → MLIL → SSA → fold → structure → pseudocode.
pub fn decompile(
    name: &str,
    instructions: &[crate::disasm::Instruction],
    arch: crate::arch::Architecture,
    symbols: &HashMap<u64, String>,
    type_info: Option<&FunctionTypeInfo>,
    types: &TypeManager,
    memory: &crate::memory::MemoryMap,
) -> hlil::DecompiledCode {
    if instructions.is_empty() {
        return hlil::DecompiledCode {
            text: format!("// {}: empty function\n", name),
            annotations: Vec::new(),
        };
    }
    let llil = match arch {
        crate::arch::Architecture::Arm64 => {
            crate::il::lifter_arm64::lift_function(name, instructions[0].address, instructions)
        }
        crate::arch::Architecture::Mips | crate::arch::Architecture::Mips64 => {
            crate::il::lifter_mips::lift_function(name, instructions[0].address, instructions)
        }
        crate::arch::Architecture::RiscV32 | crate::arch::Architecture::RiscV64 => {
            crate::il::lifter_riscv::lift_function(name, instructions[0].address, instructions)
        }
        _ => crate::il::lifter_x86::lift_function(name, instructions[0].address, instructions),
    };
    let mut mlil = crate::il::mlil::lower_to_mlil(&llil);
    crate::il::mlil::apply_ssa(&mut mlil);
    crate::il::mlil::eliminate_dead_stores(&mut mlil);

    let (mut info, stack_map) =
        analyze_function_signature(&mlil, instructions, arch, symbols, type_info, types);
    let mut hlil_stmts = structure_function(&mlil, memory, arch);
    detect_for_loops(&mut hlil_stmts);
    fold_return_values(&mut hlil_stmts);

    // Phase 1 Improvements:
    // 1. Lift stack references to named variables
    lift_stack_refs(&mut hlil_stmts, &stack_map);

    // 2. Resolve symbols (Phase 2)
    resolve_symbols(&mut hlil_stmts, symbols);

    // 2b. Resolve global variables from TypeManager
    resolve_globals(&mut hlil_stmts, types);

    // 3. Infer local types (Phase 3)
    let mut inferred_types = HashMap::new();
    infer_local_types(&hlil_stmts, &mut inferred_types, types);

    // Phase 4: Field Access Recovery
    fold_field_accesses(&mut hlil_stmts, type_info, &inferred_types, types);

    // Phase 2 (Roadmap): Combine nested if statements
    combine_nested_if_statements(&mut hlil_stmts);

    // 4. Collect remaining SSA variables and declare them
    let mut known_vars: HashSet<&str> = HashSet::new();
    for (_, name) in &info.params {
        known_vars.insert(name);
    }
    for (_, name) in &info.locals {
        known_vars.insert(name);
    }

    let ssa_locals = collect_ssa_vars_in_hlil(&hlil_stmts, &known_vars, type_info, &inferred_types);
    for (_ty, name) in &ssa_locals {
        // Also track types from SSA locals
        if let Some(tref) = type_info.and_then(|ti| ti.var_types.get(name)) {
            collect_required_types(tref, &mut info.required_types);
        }
    }
    info.locals.extend(ssa_locals);

    hlil::render_pseudocode_with_info(name, &hlil_stmts, &info, types)
}

fn fold_field_accesses(
    stmts: &mut [HlilStmt],
    type_info: Option<&FunctionTypeInfo>,
    inferred_types: &HashMap<String, TypeRef>,
    types: &TypeManager,
) {
    for stmt in stmts {
        fold_field_accesses_stmt(stmt, type_info, inferred_types, types);
    }
}

fn fold_field_accesses_stmt(
    stmt: &mut HlilStmt,
    type_info: Option<&FunctionTypeInfo>,
    inferred_types: &HashMap<String, TypeRef>,
    types: &TypeManager,
) {
    match stmt {
        HlilStmt::Assign { dest, src } => {
            fold_field_accesses_expr(dest, type_info, inferred_types, types);
            fold_field_accesses_expr(src, type_info, inferred_types, types);
        }
        HlilStmt::Store { addr, value } => {
            fold_field_accesses_expr(addr, type_info, inferred_types, types);
            fold_field_accesses_expr(value, type_info, inferred_types, types);
        }
        HlilStmt::Expr(e) => fold_field_accesses_expr(e, type_info, inferred_types, types),
        HlilStmt::Return(opt) => {
            if let Some(e) = opt {
                fold_field_accesses_expr(e, type_info, inferred_types, types);
            }
        }
        HlilStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            fold_field_accesses_expr(cond, type_info, inferred_types, types);
            fold_field_accesses(then_body, type_info, inferred_types, types);
            fold_field_accesses(else_body, type_info, inferred_types, types);
        }
        HlilStmt::While { cond, body } => {
            fold_field_accesses_expr(cond, type_info, inferred_types, types);
            fold_field_accesses(body, type_info, inferred_types, types);
        }
        HlilStmt::DoWhile { body, cond } => {
            fold_field_accesses(body, type_info, inferred_types, types);
            fold_field_accesses_expr(cond, type_info, inferred_types, types);
        }
        HlilStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            fold_field_accesses_stmt(init, type_info, inferred_types, types);
            fold_field_accesses_expr(cond, type_info, inferred_types, types);
            fold_field_accesses_stmt(update, type_info, inferred_types, types);
            fold_field_accesses(body, type_info, inferred_types, types);
        }
        HlilStmt::Block(inner) => fold_field_accesses(inner, type_info, inferred_types, types),
        HlilStmt::Switch {
            cond,
            cases,
            default,
        } => {
            fold_field_accesses_expr(cond, type_info, inferred_types, types);
            for (_, body) in cases {
                fold_field_accesses(body, type_info, inferred_types, types);
            }
            fold_field_accesses(default, type_info, inferred_types, types);
        }
        HlilStmt::Break
        | HlilStmt::Continue
        | HlilStmt::Label(_)
        | HlilStmt::Goto(_)
        | HlilStmt::Comment(_) => {}
    }
}

fn fold_field_accesses_expr(
    expr: &mut HlilExpr,
    type_info: Option<&FunctionTypeInfo>,
    inferred_types: &HashMap<String, TypeRef>,
    types: &TypeManager,
) {
    // Post-order traversal
    match expr {
        HlilExpr::Deref { addr, .. } => {
            fold_field_accesses_expr(addr, type_info, inferred_types, types);

            if let HlilExpr::BinOp { op, left, right } = &**addr
                && *op == crate::il::llil::BinOp::Add
            {
                // Pattern 1: *(base + const_offset) → struct field access
                if let HlilExpr::Const(offset) = &**right
                    && let Some(result) =
                        try_struct_field_access(left, *offset, type_info, inferred_types, types)
                {
                    *expr = result;
                    return;
                }
                // Reversed operands: *(const_offset + base)
                if let HlilExpr::Const(offset) = &**left
                    && let Some(result) =
                        try_struct_field_access(right, *offset, type_info, inferred_types, types)
                {
                    *expr = result;
                    return;
                }

                // Pattern 2: *(base + index * elem_size) → array access
                if let Some(result) =
                    try_array_access(left, right, type_info, inferred_types, types)
                {
                    *expr = result;
                }
            }
        }
        HlilExpr::BinOp { left, right, .. } => {
            fold_field_accesses_expr(left, type_info, inferred_types, types);
            fold_field_accesses_expr(right, type_info, inferred_types, types);
        }
        HlilExpr::UnaryOp { operand, .. } => {
            fold_field_accesses_expr(operand, type_info, inferred_types, types);
        }
        HlilExpr::Call { target, args } => {
            fold_field_accesses_expr(target, type_info, inferred_types, types);
            for arg in args {
                fold_field_accesses_expr(arg, type_info, inferred_types, types);
            }
        }
        HlilExpr::AddrOf(inner) => {
            fold_field_accesses_expr(inner, type_info, inferred_types, types);
        }
        HlilExpr::FieldAccess { base, .. } => {
            fold_field_accesses_expr(base, type_info, inferred_types, types);
        }
        HlilExpr::ArrayAccess { base, index } => {
            fold_field_accesses_expr(base, type_info, inferred_types, types);
            fold_field_accesses_expr(index, type_info, inferred_types, types);
        }
        HlilExpr::VectorOp { operands, .. } => {
            for op in operands {
                fold_field_accesses_expr(op, type_info, inferred_types, types);
            }
        }
        _ => {}
    }
}

fn combine_nested_if_statements(stmts: &mut [HlilStmt]) {
    let mut i = 0;
    while i < stmts.len() {
        if let HlilStmt::If {
            cond,
            then_body,
            else_body,
        } = &mut stmts[i]
        {
            combine_nested_if_statements(then_body);
            combine_nested_if_statements(else_body);

            // Pattern: if (a) { if (b) { body } } -> if (a && b) { body }
            if then_body.len() == 1
                && else_body.is_empty()
                && let HlilStmt::If {
                    cond: inner_cond,
                    then_body: inner_then,
                    else_body: inner_else,
                } = &then_body[0]
                && inner_else.is_empty()
            {
                let combined_cond = HlilExpr::BinOp {
                    op: crate::il::llil::BinOp::LogicalAnd,
                    left: Box::new(cond.clone()),
                    right: Box::new(inner_cond.clone()),
                };
                let new_then = inner_then.clone();
                *stmts[i].as_if_mut().unwrap().0 = combined_cond;
                *stmts[i].as_if_mut().unwrap().1 = new_then;
                // Don't increment i, try to combine again if there's another level
                continue;
            }
        }
        i += 1;
    }
}

impl HlilStmt {
    fn as_if_mut(&mut self) -> Option<(&mut HlilExpr, &mut Vec<HlilStmt>, &mut Vec<HlilStmt>)> {
        match self {
            HlilStmt::If {
                cond,
                then_body,
                else_body,
            } => Some((cond, then_body, else_body)),
            _ => None,
        }
    }
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
        let symbols = HashMap::new();
        let code = decompile(
            "simple_func",
            &insns,
            crate::arch::Architecture::X86_64,
            &symbols,
            None,
            &TypeManager::default(),
            &crate::memory::MemoryMap::default(),
        );
        // xor eax,eax is the "return 0" idiom — detected as void.
        assert!(
            code.text.contains("void simple_func(void)"),
            "expected void signature, got: {}",
            code
        );
        // xor eax,eax folded: result = 0 + return → return 0
        assert!(
            code.text.contains("return"),
            "expected return, got: {}",
            code
        );
    }

    #[test]
    fn decompile_with_call() {
        let insns = vec![
            make_insn(0x1000, "push", "rbp"),
            make_insn(0x1001, "call", "0x2000"),
            make_insn(0x1006, "pop", "rbp"),
            make_insn(0x1007, "ret", ""),
        ];
        let symbols = HashMap::new();
        let code = decompile(
            "caller",
            &insns,
            crate::arch::Architecture::X86_64,
            &symbols,
            None,
            &TypeManager::default(),
            &crate::memory::MemoryMap::default(),
        );
        assert!(code.text.contains("0x2000()"));
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
        let symbols = HashMap::new();
        let code = decompile(
            "test_func",
            &insns,
            crate::arch::Architecture::X86_64,
            &symbols,
            None,
            &TypeManager::default(),
            &crate::memory::MemoryMap::default(),
        );
        // Stack/frame operations should be filtered out; meaningful value is
        // folded into the return statement (result_1 = 42 + return → return 42).
        assert!(
            code.text.contains("return")
                && !code.text.contains("rsp")
                && !code.text.contains("rbp"),
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

        let stmts = structure_function(
            &func,
            &crate::memory::MemoryMap::default(),
            crate::arch::Architecture::X86_64,
        );
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

        let stmts = structure_function(
            &func,
            &crate::memory::MemoryMap::default(),
            crate::arch::Architecture::X86_64,
        );
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

        let mut stmts = structure_function(
            &func,
            &crate::memory::MemoryMap::default(),
            crate::arch::Architecture::X86_64,
        );
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
        let symbols = HashMap::new();
        let code = decompile(
            "get_arg",
            &insns,
            crate::arch::Architecture::X86_64,
            &symbols,
            None,
            &TypeManager::default(),
            &crate::memory::MemoryMap::default(),
        );
        // Should detect edi (mapped from rdi) as param and eax assignment as return.
        assert!(
            code.text.contains("get_arg("),
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
        let symbols = HashMap::new();
        let code = decompile(
            "with_locals",
            &insns,
            crate::arch::Architecture::X86_64,
            &symbols,
            None,
            &TypeManager::default(),
            &crate::memory::MemoryMap::default(),
        );
        // Should have local variable declarations.
        assert!(
            code.text.contains("var_"),
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
            required_types: HashSet::new(),
            includes: HashSet::new(),
        };
        let stmts = vec![HlilStmt::Return(Some(HlilExpr::Const(0)))];
        let code =
            hlil::render_pseudocode_with_info("add_func", &stmts, &info, &TypeManager::default());
        assert!(
            code.text
                .contains("int64_t add_func(int64_t arg1, int64_t arg2)"),
            "wrong signature: {}",
            code
        );
        assert!(
            code.text.contains("int32_t var_1;"),
            "missing local decl: {}",
            code
        );
        assert!(code.text.contains("return 0;"), "missing return: {}", code);
    }

    #[test]
    fn render_pseudocode_with_info_void_no_params() {
        let info = DecompileInfo {
            return_type: "void".to_string(),
            params: vec![],
            locals: vec![],
            required_types: HashSet::new(),
            includes: HashSet::new(),
        };
        let stmts = vec![HlilStmt::Return(None)];
        let code =
            hlil::render_pseudocode_with_info("noop", &stmts, &info, &TypeManager::default());
        assert!(
            code.text.contains("void noop(void)"),
            "wrong void signature: {}",
            code
        );
    }

    // ---- Tests for Global Variable Resolution ----

    #[test]
    fn resolve_globals_deref_const() {
        // *(0x404000) where 0x404000 is a known global → g_counter
        let mut types = TypeManager::default();
        types.global_variables.insert(
            0x404000,
            crate::types::VariableInfo {
                name: "g_counter".to_string(),
                type_ref: TypeRef::Primitive(PrimitiveType::I32),
                location: crate::types::VariableLocation::Address(0x404000),
            },
        );

        let mut stmts = vec![HlilStmt::Assign {
            dest: HlilExpr::Var("result_1".into()),
            src: HlilExpr::Deref {
                addr: Box::new(HlilExpr::Const(0x404000)),
                size: 4,
            },
        }];

        resolve_globals(&mut stmts, &types);

        if let HlilStmt::Assign { src, .. } = &stmts[0] {
            assert!(
                matches!(src, HlilExpr::Global(0x404000, name) if name == "g_counter"),
                "expected Global(0x404000, g_counter), got {:?}",
                src
            );
        } else {
            panic!("expected Assign, got {:?}", stmts[0]);
        }
    }

    #[test]
    fn resolve_globals_store_to_assign() {
        // Store { addr: Const(0x404000), value: 42 } → Assign { dest: Global, src: 42 }
        let mut types = TypeManager::default();
        types.global_variables.insert(
            0x404000,
            crate::types::VariableInfo {
                name: "g_counter".to_string(),
                type_ref: TypeRef::Primitive(PrimitiveType::I32),
                location: crate::types::VariableLocation::Address(0x404000),
            },
        );

        let mut stmts = vec![HlilStmt::Store {
            addr: HlilExpr::Const(0x404000),
            value: HlilExpr::Const(42),
        }];

        resolve_globals(&mut stmts, &types);

        assert!(
            matches!(
                &stmts[0],
                HlilStmt::Assign {
                    dest: HlilExpr::Global(0x404000, _),
                    src: HlilExpr::Const(42),
                }
            ),
            "expected Assign to global, got {:?}",
            stmts[0]
        );
    }

    #[test]
    fn resolve_globals_prefers_variable_name_over_symbol() {
        // If symbol was already resolved as Global("sym_name"), but global_variables
        // has a user-defined name, the user name wins.
        let mut types = TypeManager::default();
        types.global_variables.insert(
            0x404000,
            crate::types::VariableInfo {
                name: "g_my_var".to_string(),
                type_ref: TypeRef::Primitive(PrimitiveType::I32),
                location: crate::types::VariableLocation::Address(0x404000),
            },
        );

        let mut stmts = vec![HlilStmt::Expr(HlilExpr::Global(
            0x404000,
            "data_404000".to_string(),
        ))];

        resolve_globals(&mut stmts, &types);

        if let HlilStmt::Expr(HlilExpr::Global(_, name)) = &stmts[0] {
            assert_eq!(name, "g_my_var", "expected user-defined name");
        } else {
            panic!("expected Global expr");
        }
    }

    // ---- Tests for Struct/Array Propagation ----

    fn make_test_types_with_structs() -> TypeManager {
        let mut types = TypeManager::default();
        types.arch = crate::arch::Architecture::X86_64;

        // struct Point { int32_t x; int32_t y; } — size 8
        types.add_type(crate::types::CompoundType::Struct {
            name: "Point".to_string(),
            fields: vec![
                crate::types::StructField {
                    name: "x".to_string(),
                    type_ref: TypeRef::Primitive(PrimitiveType::I32),
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                },
                crate::types::StructField {
                    name: "y".to_string(),
                    type_ref: TypeRef::Primitive(PrimitiveType::I32),
                    offset: 4,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
            size: 8,
        });

        // struct Rect { Point origin; Point size; } — size 16
        types.add_type(crate::types::CompoundType::Struct {
            name: "Rect".to_string(),
            fields: vec![
                crate::types::StructField {
                    name: "origin".to_string(),
                    type_ref: TypeRef::Named("Point".to_string()),
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                },
                crate::types::StructField {
                    name: "size".to_string(),
                    type_ref: TypeRef::Named("Point".to_string()),
                    offset: 8,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
            size: 16,
        });

        types
    }

    #[test]
    fn fold_field_access_any_base() {
        // *(Global(0x404000, "g_point") + 4) where g_point is Point* → g_point->y
        let mut types = make_test_types_with_structs();
        types.global_variables.insert(
            0x404000,
            crate::types::VariableInfo {
                name: "g_point".to_string(),
                type_ref: TypeRef::Pointer(Box::new(TypeRef::Named("Point".to_string()))),
                location: crate::types::VariableLocation::Address(0x404000),
            },
        );
        let inferred = HashMap::new();

        let mut expr = HlilExpr::Deref {
            addr: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Global(0x404000, "g_point".to_string())),
                right: Box::new(HlilExpr::Const(4)),
            }),
            size: 4,
        };

        fold_field_accesses_expr(&mut expr, None, &inferred, &types);

        assert!(
            matches!(&expr, HlilExpr::FieldAccess { field_name, is_ptr: true, .. } if field_name == "y"),
            "expected ->y field access, got {:?}",
            expr
        );
    }

    #[test]
    fn fold_nested_struct_access() {
        // *(rect_ptr + 12) where rect_ptr: Rect* → rect_ptr->size.y
        // Rect.size is at offset 8, Point.y is at offset 4 → total offset 12
        let types = make_test_types_with_structs();
        let mut inferred = HashMap::new();
        inferred.insert(
            "rect_ptr".to_string(),
            TypeRef::Pointer(Box::new(TypeRef::Named("Rect".to_string()))),
        );

        let mut expr = HlilExpr::Deref {
            addr: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Var("rect_ptr".to_string())),
                right: Box::new(HlilExpr::Const(12)),
            }),
            size: 4,
        };

        fold_field_accesses_expr(&mut expr, None, &inferred, &types);

        // Should be rect_ptr->size.y
        if let HlilExpr::FieldAccess {
            base,
            field_name,
            is_ptr: false,
        } = &expr
        {
            assert_eq!(field_name, "y", "inner field should be y");
            if let HlilExpr::FieldAccess {
                field_name: outer_name,
                is_ptr: true,
                ..
            } = &**base
            {
                assert_eq!(outer_name, "size", "outer field should be size");
            } else {
                panic!("expected outer FieldAccess, got {:?}", base);
            }
        } else {
            panic!("expected nested FieldAccess, got {:?}", expr);
        }
    }

    #[test]
    fn fold_array_access_mul_pattern() {
        // *(arr_ptr + index * 4) where arr_ptr: int32_t* → arr_ptr[index]
        let types = TypeManager {
            arch: crate::arch::Architecture::X86_64,
            ..TypeManager::default()
        };
        let mut inferred = HashMap::new();
        inferred.insert(
            "arr_ptr".to_string(),
            TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::I32))),
        );

        let mut expr = HlilExpr::Deref {
            addr: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Var("arr_ptr".to_string())),
                right: Box::new(HlilExpr::BinOp {
                    op: BinOp::Mul,
                    left: Box::new(HlilExpr::Var("index".to_string())),
                    right: Box::new(HlilExpr::Const(4)),
                }),
            }),
            size: 4,
        };

        fold_field_accesses_expr(&mut expr, None, &inferred, &types);

        assert!(
            matches!(&expr, HlilExpr::ArrayAccess { .. }),
            "expected ArrayAccess, got {:?}",
            expr
        );
    }

    #[test]
    fn fold_array_access_shl_pattern() {
        // *(arr_ptr + index << 3) where arr_ptr: int64_t* → arr_ptr[index]
        let types = TypeManager {
            arch: crate::arch::Architecture::X86_64,
            ..TypeManager::default()
        };
        let mut inferred = HashMap::new();
        inferred.insert(
            "arr_ptr".to_string(),
            TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::I64))),
        );

        let mut expr = HlilExpr::Deref {
            addr: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Var("arr_ptr".to_string())),
                right: Box::new(HlilExpr::BinOp {
                    op: BinOp::Shl,
                    left: Box::new(HlilExpr::Var("index".to_string())),
                    right: Box::new(HlilExpr::Const(3)),
                }),
            }),
            size: 8,
        };

        fold_field_accesses_expr(&mut expr, None, &inferred, &types);

        assert!(
            matches!(&expr, HlilExpr::ArrayAccess { .. }),
            "expected ArrayAccess, got {:?}",
            expr
        );
    }

    #[test]
    fn fold_byte_array_access() {
        // *(buf + index) where buf: uint8_t* → buf[index]
        let types = TypeManager {
            arch: crate::arch::Architecture::X86_64,
            ..TypeManager::default()
        };
        let mut inferred = HashMap::new();
        inferred.insert(
            "buf".to_string(),
            TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::U8))),
        );

        let mut expr = HlilExpr::Deref {
            addr: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Var("buf".to_string())),
                right: Box::new(HlilExpr::Var("index".to_string())),
            }),
            size: 1,
        };

        fold_field_accesses_expr(&mut expr, None, &inferred, &types);

        assert!(
            matches!(&expr, HlilExpr::ArrayAccess { .. }),
            "expected ArrayAccess, got {:?}",
            expr
        );
    }

    #[test]
    fn fold_direct_struct_access() {
        // *(stack_var + 4) where stack_var has type Named("Point") → stack_var.y
        let types = make_test_types_with_structs();
        let mut inferred = HashMap::new();
        inferred.insert(
            "local_point".to_string(),
            TypeRef::Named("Point".to_string()),
        );

        let mut expr = HlilExpr::Deref {
            addr: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Var("local_point".to_string())),
                right: Box::new(HlilExpr::Const(4)),
            }),
            size: 4,
        };

        fold_field_accesses_expr(&mut expr, None, &inferred, &types);

        assert!(
            matches!(&expr, HlilExpr::FieldAccess { field_name, is_ptr: false, .. } if field_name == "y"),
            "expected .y field access, got {:?}",
            expr
        );
    }
}
