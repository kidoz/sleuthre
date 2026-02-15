//! High-Level Intermediate Language (HLIL)
//!
//! Structured representation with if/else, while, for, switch constructs.
//! Generates C-like pseudocode.

use crate::il::llil::{BinOp, VectorElementType, VectorOpKind};
use crate::il::mlil::{MlilExpr, SsaVar};
use std::fmt;

/// A high-level expression used in pseudocode.
#[derive(Debug, Clone)]
pub enum HlilExpr {
    Var(String),
    Const(u64),
    Deref {
        addr: Box<HlilExpr>,
        size: u8,
    },
    BinOp {
        op: BinOp,
        left: Box<HlilExpr>,
        right: Box<HlilExpr>,
    },
    UnaryOp {
        op: crate::il::llil::UnaryOp,
        operand: Box<HlilExpr>,
    },
    Call {
        target: Box<HlilExpr>,
        args: Vec<HlilExpr>,
    },
    AddrOf(Box<HlilExpr>),
    /// SIMD vector operation rendered as C code.
    VectorOp {
        kind: VectorOpKind,
        element_type: VectorElementType,
        width: u16,
        operands: Vec<HlilExpr>,
    },
}

/// A high-level statement.
#[derive(Debug, Clone)]
pub enum HlilStmt {
    Assign {
        dest: HlilExpr,
        src: HlilExpr,
    },
    Store {
        addr: HlilExpr,
        value: HlilExpr,
    },
    Expr(HlilExpr),
    Return(Option<HlilExpr>),
    If {
        cond: HlilExpr,
        then_body: Vec<HlilStmt>,
        else_body: Vec<HlilStmt>,
    },
    While {
        cond: HlilExpr,
        body: Vec<HlilStmt>,
    },
    DoWhile {
        body: Vec<HlilStmt>,
        cond: HlilExpr,
    },
    For {
        init: Box<HlilStmt>,
        cond: HlilExpr,
        update: Box<HlilStmt>,
        body: Vec<HlilStmt>,
    },
    Block(Vec<HlilStmt>),
    Comment(String),
}

/// Convert an MLIL expression to HLIL (strip SSA versions, simplify names).
pub fn mlil_to_hlil_expr(expr: &MlilExpr) -> HlilExpr {
    match expr {
        MlilExpr::Var(ssa) => HlilExpr::Var(pretty_var_name(ssa)),
        MlilExpr::Const(v) => HlilExpr::Const(*v),
        MlilExpr::Load { addr, size } => HlilExpr::Deref {
            addr: Box::new(mlil_to_hlil_expr(addr)),
            size: *size,
        },
        MlilExpr::BinOp { op, left, right } => HlilExpr::BinOp {
            op: *op,
            left: Box::new(mlil_to_hlil_expr(left)),
            right: Box::new(mlil_to_hlil_expr(right)),
        },
        MlilExpr::UnaryOp { op, operand } => HlilExpr::UnaryOp {
            op: *op,
            operand: Box::new(mlil_to_hlil_expr(operand)),
        },
        MlilExpr::Phi(vars) => {
            if let Some(first) = vars.first() {
                HlilExpr::Var(pretty_var_name(first))
            } else {
                HlilExpr::Var("??".into())
            }
        }
        MlilExpr::Call { target, args } => HlilExpr::Call {
            target: Box::new(mlil_to_hlil_expr(target)),
            args: args.iter().map(mlil_to_hlil_expr).collect(),
        },
        MlilExpr::VectorOp {
            kind,
            element_type,
            width,
            operands,
        } => HlilExpr::VectorOp {
            kind: kind.clone(),
            element_type: *element_type,
            width: *width,
            operands: operands.iter().map(mlil_to_hlil_expr).collect(),
        },
    }
}

/// Assign friendly names to registers.
fn pretty_var_name(ssa: &SsaVar) -> String {
    let base = match ssa.name.as_str() {
        "rax" | "eax" | "ax" | "al" => "result",
        "rcx" | "ecx" | "cx" | "cl" => "counter",
        "rdx" | "edx" | "dx" | "dl" => "data",
        "rbx" | "ebx" | "bx" | "bl" => "var_bx",
        "rsi" | "esi" | "si" => "src",
        "rdi" | "edi" | "di" => "dst",
        "rbp" | "ebp" | "bp" => "frame",
        "rsp" | "esp" | "sp" => "sp",
        name if name.starts_with("__") => return name.to_string(),
        name => name,
    };
    if ssa.version > 0 {
        format!("{}_{}", base, ssa.version)
    } else {
        base.to_string()
    }
}

/// Render HLIL as C-like pseudocode.
pub fn render_pseudocode(name: &str, stmts: &[HlilStmt]) -> String {
    let mut out = String::new();
    out.push_str("// Decompiled with Sleuthre\n\n");
    out.push_str(&format!("void {}() {{\n", name));
    for stmt in stmts {
        render_stmt(&mut out, stmt, 1);
    }
    out.push_str("}\n");
    out
}

/// Render HLIL as C-like pseudocode with function signature information
/// (return type, parameters, and local variable declarations).
pub fn render_pseudocode_with_info(
    name: &str,
    stmts: &[HlilStmt],
    info: &crate::il::structuring::DecompileInfo,
) -> String {
    let mut out = String::new();
    out.push_str("// Decompiled with Sleuthre\n\n");

    // Function signature with return type and params
    let params_str = if info.params.is_empty() {
        "void".to_string()
    } else {
        info.params
            .iter()
            .map(|(ty, pname)| format!("{} {}", ty, pname))
            .collect::<Vec<_>>()
            .join(", ")
    };
    out.push_str(&format!(
        "{} {}({}) {{\n",
        info.return_type, name, params_str
    ));

    // Local variable declarations
    for (ty, lname) in &info.locals {
        out.push_str(&format!("    {} {};\n", ty, lname));
    }
    if !info.locals.is_empty() {
        out.push('\n');
    }

    // Body
    for stmt in stmts {
        render_stmt(&mut out, stmt, 1);
    }
    out.push_str("}\n");
    out
}

fn render_stmt(out: &mut String, stmt: &HlilStmt, indent: usize) {
    let pad: String = "    ".repeat(indent);
    match stmt {
        HlilStmt::Assign { dest, src } => {
            out.push_str(&format!("{}{} = {};\n", pad, fmt_expr(dest), fmt_expr(src)));
        }
        HlilStmt::Store { addr, value } => {
            out.push_str(&format!(
                "{}*{} = {};\n",
                pad,
                fmt_expr(addr),
                fmt_expr(value)
            ));
        }
        HlilStmt::Expr(e) => {
            out.push_str(&format!("{}{};\n", pad, fmt_expr(e)));
        }
        HlilStmt::Return(val) => {
            if let Some(v) = val {
                out.push_str(&format!("{}return {};\n", pad, fmt_expr(v)));
            } else {
                out.push_str(&format!("{}return;\n", pad));
            }
        }
        HlilStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            out.push_str(&format!("{}if ({}) {{\n", pad, fmt_expr(cond)));
            for s in then_body {
                render_stmt(out, s, indent + 1);
            }
            if !else_body.is_empty() {
                out.push_str(&format!("{}}} else {{\n", pad));
                for s in else_body {
                    render_stmt(out, s, indent + 1);
                }
            }
            out.push_str(&format!("{}}}\n", pad));
        }
        HlilStmt::While { cond, body } => {
            out.push_str(&format!("{}while ({}) {{\n", pad, fmt_expr(cond)));
            for s in body {
                render_stmt(out, s, indent + 1);
            }
            out.push_str(&format!("{}}}\n", pad));
        }
        HlilStmt::DoWhile { body, cond } => {
            out.push_str(&format!("{}do {{\n", pad));
            for s in body {
                render_stmt(out, s, indent + 1);
            }
            out.push_str(&format!("{}}} while ({});\n", pad, fmt_expr(cond)));
        }
        HlilStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            let init_str = fmt_stmt_inline(init);
            let update_str = fmt_stmt_inline(update);
            out.push_str(&format!(
                "{}for ({}; {}; {}) {{\n",
                pad,
                init_str,
                fmt_expr(cond),
                update_str
            ));
            for s in body {
                render_stmt(out, s, indent + 1);
            }
            out.push_str(&format!("{}}}\n", pad));
        }
        HlilStmt::Block(stmts) => {
            for s in stmts {
                render_stmt(out, s, indent);
            }
        }
        HlilStmt::Comment(text) => {
            out.push_str(&format!("{}// {}\n", pad, text));
        }
    }
}

/// Return the precedence level for a binary operator.
/// Higher values bind more tightly.
fn op_precedence(op: &BinOp) -> u8 {
    match op {
        BinOp::Mul | BinOp::UDiv | BinOp::SDiv | BinOp::UMod | BinOp::SMod => 5,
        BinOp::Add | BinOp::Sub => 4,
        BinOp::Shl | BinOp::Shr | BinOp::Sar => 3,
        BinOp::And => 2,
        BinOp::Xor => 1,
        BinOp::Or => 0,
    }
}

/// Render a statement inline (without trailing semicolon/newline) for use in
/// for-loop headers.
fn fmt_stmt_inline(stmt: &HlilStmt) -> String {
    match stmt {
        HlilStmt::Assign { dest, src } => format!("{} = {}", fmt_expr(dest), fmt_expr(src)),
        HlilStmt::Expr(e) => fmt_expr(e),
        _ => String::new(),
    }
}

fn fmt_expr(expr: &HlilExpr) -> String {
    fmt_expr_prec(expr, 0)
}

/// Format an expression, adding parentheses only when the expression's
/// precedence is lower than the parent context requires.
fn fmt_expr_prec(expr: &HlilExpr, parent_prec: u8) -> String {
    match expr {
        HlilExpr::Var(name) => name.clone(),
        HlilExpr::Const(v) => {
            if *v > 9 {
                format!("0x{:x}", v)
            } else {
                format!("{}", v)
            }
        }
        HlilExpr::Deref { addr, .. } => format!("*({})", fmt_expr(addr)),
        HlilExpr::BinOp { op, left, right } => {
            let prec = op_precedence(op);
            // Right operand uses prec + 1 for left-associativity:
            // `a - b - c` stays as `a - b - c` (not `a - (b - c)`)
            let s = format!(
                "{} {} {}",
                fmt_expr_prec(left, prec),
                op,
                fmt_expr_prec(right, prec + 1)
            );
            if prec < parent_prec {
                format!("({})", s)
            } else {
                s
            }
        }
        HlilExpr::UnaryOp { op, operand } => {
            let prefix = match op {
                crate::il::llil::UnaryOp::Not => "~",
                crate::il::llil::UnaryOp::Neg => "-",
            };
            // Use high precedence (10) so complex sub-expressions always get wrapped
            format!("{}{}", prefix, fmt_expr_prec(operand, 10))
        }
        HlilExpr::Call { target, args } => {
            let args_str: Vec<String> = args.iter().map(fmt_expr).collect();
            format!("{}({})", fmt_expr(target), args_str.join(", "))
        }
        HlilExpr::AddrOf(inner) => format!("&{}", fmt_expr(inner)),
        HlilExpr::VectorOp {
            kind,
            element_type,
            width,
            operands,
        } => fmt_vector_op(kind, *element_type, *width, operands),
    }
}

/// Render a SIMD vector operation as architecture-agnostic C code.
///
/// Produces element-wise loop expansions for simple ops and intrinsic-style
/// function calls for complex ones.
fn fmt_vector_op(
    kind: &VectorOpKind,
    elem: VectorElementType,
    width: u16,
    operands: &[HlilExpr],
) -> String {
    let count = elem.count_in(width);
    let ty = elem.c_type();

    // Helper: format operand names
    let op = |i: usize| -> String { operands.get(i).map(fmt_expr).unwrap_or_else(|| "?".into()) };

    match kind {
        // Element-wise binary: a[i] OP b[i]
        VectorOpKind::Add | VectorOpKind::Sub | VectorOpKind::Mul | VectorOpKind::Div => {
            let c_op = match kind {
                VectorOpKind::Add => "+",
                VectorOpKind::Sub => "-",
                VectorOpKind::Mul => "*",
                VectorOpKind::Div => "/",
                _ => unreachable!(),
            };
            format!(
                "/* {ty}[{count}] */ {dst} = {a} {op} {b}",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                op = c_op,
                b = op(1),
            )
        }
        // Saturating arithmetic
        VectorOpKind::AddSaturate => {
            format!(
                "/* {ty}[{count}] saturating */ {kind}({a}, {b})",
                ty = ty,
                count = count,
                kind = kind,
                a = op(0),
                b = op(1)
            )
        }
        VectorOpKind::SubSaturate => {
            format!(
                "/* {ty}[{count}] saturating */ {kind}({a}, {b})",
                ty = ty,
                count = count,
                kind = kind,
                a = op(0),
                b = op(1)
            )
        }
        // Bitwise
        VectorOpKind::And | VectorOpKind::Or | VectorOpKind::Xor => {
            let c_op = match kind {
                VectorOpKind::And => "&",
                VectorOpKind::Or => "|",
                VectorOpKind::Xor => "^",
                _ => unreachable!(),
            };
            format!(
                "/* {width}-bit */ {dst} = {a} {op} {b}",
                width = width,
                dst = op(0),
                a = op(0),
                op = c_op,
                b = op(1),
            )
        }
        VectorOpKind::AndNot => {
            format!(
                "/* {width}-bit */ {dst} = ~{a} & {b}",
                width = width,
                dst = op(0),
                a = op(0),
                b = op(1),
            )
        }
        // Shifts
        VectorOpKind::ShiftLeft | VectorOpKind::ShiftRight | VectorOpKind::ShiftRightArith => {
            let c_op = match kind {
                VectorOpKind::ShiftLeft => "<<",
                _ => ">>",
            };
            format!(
                "/* {ty}[{count}] */ {dst} = {a} {op} {b}",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                op = c_op,
                b = op(1),
            )
        }
        // Compare
        VectorOpKind::CompareEq | VectorOpKind::CompareGt | VectorOpKind::CompareLt => {
            let c_op = match kind {
                VectorOpKind::CompareEq => "==",
                VectorOpKind::CompareGt => ">",
                VectorOpKind::CompareLt => "<",
                _ => unreachable!(),
            };
            format!(
                "/* {ty}[{count}] mask */ {dst} = ({a} {op} {b}) ? 0xFF..F : 0",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                op = c_op,
                b = op(1),
            )
        }
        // Shuffle
        VectorOpKind::Shuffle { mask } => {
            format!(
                "/* {ty}[{count}] */ {dst} = shuffle({src}, 0x{mask:02x})",
                ty = ty,
                count = count,
                dst = op(0),
                src = op(1),
                mask = mask,
            )
        }
        VectorOpKind::ShuffleBytes => {
            format!(
                "/* byte shuffle */ {dst} = pshufb({a}, {b})",
                dst = op(0),
                a = op(0),
                b = op(1),
            )
        }
        // Unpack
        VectorOpKind::UnpackLow => {
            format!(
                "/* {ty} interleave low */ {dst} = unpack_lo({a}, {b})",
                ty = ty,
                dst = op(0),
                a = op(0),
                b = op(1),
            )
        }
        VectorOpKind::UnpackHigh => {
            format!(
                "/* {ty} interleave high */ {dst} = unpack_hi({a}, {b})",
                ty = ty,
                dst = op(0),
                a = op(0),
                b = op(1),
            )
        }
        // Pack
        VectorOpKind::PackSigned | VectorOpKind::PackUnsigned => {
            let sat = if *kind == VectorOpKind::PackSigned {
                "signed"
            } else {
                "unsigned"
            };
            format!(
                "/* {sat} pack {ty} */ {dst} = pack({a}, {b})",
                sat = sat,
                ty = ty,
                dst = op(0),
                a = op(0),
                b = op(1),
            )
        }
        // Blend
        VectorOpKind::Blend { mask } => {
            format!(
                "/* {ty}[{count}] */ {dst} = blend({a}, {b}, 0x{mask:02x})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                b = op(1),
                mask = mask,
            )
        }
        VectorOpKind::BlendVar => {
            format!(
                "/* {ty}[{count}] */ {dst} = blendv({a}, {b}, {mask})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                b = op(1),
                mask = operands
                    .get(2)
                    .map(fmt_expr)
                    .unwrap_or_else(|| "mask".into()),
            )
        }
        // Horizontal
        VectorOpKind::HorizontalAdd => {
            format!(
                "/* {ty} hadd */ {dst} = hadd({a}, {b})",
                ty = ty,
                dst = op(0),
                a = op(0),
                b = op(1),
            )
        }
        VectorOpKind::HorizontalSub => {
            format!(
                "/* {ty} hsub */ {dst} = hsub({a}, {b})",
                ty = ty,
                dst = op(0),
                a = op(0),
                b = op(1),
            )
        }
        // Insert / Extract
        VectorOpKind::Insert { index } => {
            format!(
                "/* {ty} */ {dst}[{idx}] = {val}",
                ty = ty,
                dst = op(0),
                idx = index,
                val = op(1),
            )
        }
        VectorOpKind::Extract { index } => {
            format!(
                "/* {ty} */ {val} = {src}[{idx}]",
                ty = ty,
                val = op(0),
                src = op(0),
                idx = index,
            )
        }
        // Convert
        VectorOpKind::ConvertIntToFloat => {
            format!(
                "/* int→float */ {dst} = cvt_i2f({src})",
                dst = op(0),
                src = op(0)
            )
        }
        VectorOpKind::ConvertFloatToInt => {
            format!(
                "/* float→int */ {dst} = cvt_f2i({src})",
                dst = op(0),
                src = op(0)
            )
        }
        VectorOpKind::ConvertWiden => {
            format!(
                "/* widen {ty} */ {dst} = widen({src})",
                ty = ty,
                dst = op(0),
                src = op(0)
            )
        }
        VectorOpKind::ConvertNarrow => {
            format!(
                "/* narrow {ty} */ {dst} = narrow({src})",
                ty = ty,
                dst = op(0),
                src = op(0)
            )
        }
        // FMA
        VectorOpKind::FusedMulAdd => {
            format!(
                "/* {ty}[{count}] */ {dst} = {a} * {b} + {c}",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                b = op(1),
                c = op(2),
            )
        }
        VectorOpKind::FusedMulSub => {
            format!(
                "/* {ty}[{count}] */ {dst} = {a} * {b} - {c}",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                b = op(1),
                c = op(2),
            )
        }
        // Move
        VectorOpKind::Move | VectorOpKind::MoveAligned | VectorOpKind::MoveUnaligned => {
            format!("{dst} = {src}", dst = op(0), src = op(1))
        }
        VectorOpKind::Broadcast => {
            format!(
                "/* {ty}[{count}] broadcast */ {dst} = {{ {val}, ... }}",
                ty = ty,
                count = count,
                dst = op(0),
                val = op(1),
            )
        }
        // Math
        VectorOpKind::Sqrt => {
            format!(
                "/* {ty}[{count}] */ {dst} = sqrt({src})",
                ty = ty,
                count = count,
                dst = op(0),
                src = op(0)
            )
        }
        VectorOpKind::Reciprocal => {
            format!(
                "/* {ty}[{count}] */ {dst} = 1.0 / {src}",
                ty = ty,
                count = count,
                dst = op(0),
                src = op(0)
            )
        }
        VectorOpKind::ReciprocalSqrt => {
            format!(
                "/* {ty}[{count}] */ {dst} = 1.0 / sqrt({src})",
                ty = ty,
                count = count,
                dst = op(0),
                src = op(0)
            )
        }
        VectorOpKind::Round => {
            format!(
                "/* {ty}[{count}] */ {dst} = round({src})",
                ty = ty,
                count = count,
                dst = op(0),
                src = op(0)
            )
        }
        // Mask
        VectorOpKind::MoveMask => {
            format!(
                "/* extract sign bits */ {dst} = movemask({src})",
                dst = op(0),
                src = op(0)
            )
        }
        VectorOpKind::TestAllZeros => {
            format!(
                "/* test all zeros */ ({a} & {b}) == 0",
                a = op(0),
                b = op(1)
            )
        }
        // Min/Max/Abs/Avg
        VectorOpKind::Min => {
            format!(
                "/* {ty}[{count}] */ {dst} = min({a}, {b})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                b = op(1)
            )
        }
        VectorOpKind::Max => {
            format!(
                "/* {ty}[{count}] */ {dst} = max({a}, {b})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                b = op(1)
            )
        }
        VectorOpKind::Abs => {
            format!(
                "/* {ty}[{count}] */ {dst} = abs({src})",
                ty = ty,
                count = count,
                dst = op(0),
                src = op(0)
            )
        }
        VectorOpKind::Avg => {
            format!(
                "/* {ty}[{count}] */ {dst} = avg({a}, {b})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                b = op(1)
            )
        }
        VectorOpKind::MulHigh => {
            format!(
                "/* {ty}[{count}] high */ {dst} = mulhi({a}, {b})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                b = op(1)
            )
        }
        // String compare
        VectorOpKind::StringCompare => {
            format!(
                "/* string compare */ strcmp_simd({a}, {b})",
                a = op(0),
                b = op(1)
            )
        }
        // Zero
        VectorOpKind::Zero => {
            format!(
                "/* {width}-bit zero */ {dst} = 0",
                width = width,
                dst = op(0)
            )
        }
        // Intrinsic fallback
        VectorOpKind::Intrinsic(name) => {
            let args: Vec<String> = operands.iter().map(fmt_expr).collect();
            format!("{}({})", name, args.join(", "))
        }
    }
}

impl fmt::Display for HlilExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", fmt_expr(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_simple_function() {
        let stmts = vec![
            HlilStmt::Assign {
                dest: HlilExpr::Var("result".into()),
                src: HlilExpr::Const(0),
            },
            HlilStmt::Assign {
                dest: HlilExpr::Var("result".into()),
                src: HlilExpr::BinOp {
                    op: BinOp::Add,
                    left: Box::new(HlilExpr::Var("result".into())),
                    right: Box::new(HlilExpr::Const(42)),
                },
            },
            HlilStmt::Return(Some(HlilExpr::Var("result".into()))),
        ];
        let code = render_pseudocode("my_func", &stmts);
        assert!(code.contains("void my_func()"));
        assert!(code.contains("result = 0;"));
        assert!(code.contains("result = result + 0x2a;"));
        assert!(code.contains("return result;"));
    }

    #[test]
    fn render_if_else() {
        let stmts = vec![HlilStmt::If {
            cond: HlilExpr::Var("flag".into()),
            then_body: vec![HlilStmt::Return(Some(HlilExpr::Const(1)))],
            else_body: vec![HlilStmt::Return(Some(HlilExpr::Const(0)))],
        }];
        let code = render_pseudocode("test", &stmts);
        assert!(code.contains("if (flag)"));
        assert!(code.contains("} else {"));
    }

    #[test]
    fn render_while_loop() {
        let stmts = vec![HlilStmt::While {
            cond: HlilExpr::Var("counter".into()),
            body: vec![HlilStmt::Assign {
                dest: HlilExpr::Var("counter".into()),
                src: HlilExpr::BinOp {
                    op: BinOp::Sub,
                    left: Box::new(HlilExpr::Var("counter".into())),
                    right: Box::new(HlilExpr::Const(1)),
                },
            }],
        }];
        let code = render_pseudocode("loop_func", &stmts);
        assert!(code.contains("while (counter)"));
    }

    #[test]
    fn precedence_mul_add_no_extra_parens() {
        // a * b + c  — mul has higher precedence, no parens needed around a * b
        let expr = HlilExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(HlilExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(HlilExpr::Var("a".into())),
                right: Box::new(HlilExpr::Var("b".into())),
            }),
            right: Box::new(HlilExpr::Var("c".into())),
        };
        assert_eq!(fmt_expr(&expr), "a * b + c");
    }

    #[test]
    fn precedence_add_mul_no_parens_needed() {
        // a + b * c  — mul binds tighter so no parens needed
        let expr = HlilExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(HlilExpr::Var("a".into())),
            right: Box::new(HlilExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(HlilExpr::Var("b".into())),
                right: Box::new(HlilExpr::Var("c".into())),
            }),
        };
        assert_eq!(fmt_expr(&expr), "a + b * c");
    }

    #[test]
    fn precedence_add_in_mul_needs_parens() {
        // (a + b) * c  — add has lower precedence, needs parens
        let expr = HlilExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Var("a".into())),
                right: Box::new(HlilExpr::Var("b".into())),
            }),
            right: Box::new(HlilExpr::Var("c".into())),
        };
        assert_eq!(fmt_expr(&expr), "(a + b) * c");
    }

    #[test]
    fn precedence_left_associative_sub() {
        // a - b - c should stay as "a - b - c" (left-associative, no extra parens)
        let expr = HlilExpr::BinOp {
            op: BinOp::Sub,
            left: Box::new(HlilExpr::BinOp {
                op: BinOp::Sub,
                left: Box::new(HlilExpr::Var("a".into())),
                right: Box::new(HlilExpr::Var("b".into())),
            }),
            right: Box::new(HlilExpr::Var("c".into())),
        };
        assert_eq!(fmt_expr(&expr), "a - b - c");
    }

    #[test]
    fn precedence_right_sub_needs_parens() {
        // a - (b - c) — right-nested sub needs parens for correctness
        let expr = HlilExpr::BinOp {
            op: BinOp::Sub,
            left: Box::new(HlilExpr::Var("a".into())),
            right: Box::new(HlilExpr::BinOp {
                op: BinOp::Sub,
                left: Box::new(HlilExpr::Var("b".into())),
                right: Box::new(HlilExpr::Var("c".into())),
            }),
        };
        assert_eq!(fmt_expr(&expr), "a - (b - c)");
    }

    #[test]
    fn unary_not_renders() {
        let expr = HlilExpr::UnaryOp {
            op: crate::il::llil::UnaryOp::Not,
            operand: Box::new(HlilExpr::Var("x".into())),
        };
        assert_eq!(fmt_expr(&expr), "~x");
    }

    #[test]
    fn unary_neg_renders() {
        let expr = HlilExpr::UnaryOp {
            op: crate::il::llil::UnaryOp::Neg,
            operand: Box::new(HlilExpr::Var("x".into())),
        };
        assert_eq!(fmt_expr(&expr), "-x");
    }

    #[test]
    fn unary_of_complex_expr_wraps() {
        // ~(a + b) — complex sub-expression gets wrapped
        let expr = HlilExpr::UnaryOp {
            op: crate::il::llil::UnaryOp::Not,
            operand: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Var("a".into())),
                right: Box::new(HlilExpr::Var("b".into())),
            }),
        };
        assert_eq!(fmt_expr(&expr), "~(a + b)");
    }

    #[test]
    fn render_for_loop() {
        let stmts = vec![HlilStmt::For {
            init: Box::new(HlilStmt::Assign {
                dest: HlilExpr::Var("i".into()),
                src: HlilExpr::Const(0),
            }),
            cond: HlilExpr::BinOp {
                op: BinOp::Sub,
                left: Box::new(HlilExpr::Var("i".into())),
                right: Box::new(HlilExpr::Const(10)),
            },
            update: Box::new(HlilStmt::Assign {
                dest: HlilExpr::Var("i".into()),
                src: HlilExpr::BinOp {
                    op: BinOp::Add,
                    left: Box::new(HlilExpr::Var("i".into())),
                    right: Box::new(HlilExpr::Const(1)),
                },
            }),
            body: vec![HlilStmt::Expr(HlilExpr::Call {
                target: Box::new(HlilExpr::Const(0x2000)),
                args: vec![],
            })],
        }];
        let code = render_pseudocode("loop_test", &stmts);
        assert!(code.contains("for ("), "expected 'for (' in:\n{}", code);
        assert!(code.contains("i = 0"), "expected 'i = 0' in:\n{}", code);
        assert!(
            code.contains("i = i + 1"),
            "expected 'i = i + 1' in:\n{}",
            code
        );
        assert!(
            code.contains("0x2000()"),
            "expected '0x2000()' in:\n{}",
            code
        );
    }
}
