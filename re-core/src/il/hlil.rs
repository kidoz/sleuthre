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
    Global(u64, String),
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
    FieldAccess {
        base: Box<HlilExpr>,
        field_name: String,
        is_ptr: bool,
    },
    ArrayAccess {
        base: Box<HlilExpr>,
        index: Box<HlilExpr>,
    },
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
    Switch {
        cond: HlilExpr,
        cases: Vec<(u64, Vec<HlilStmt>)>,
        default: Vec<HlilStmt>,
    },
    Break,
    Continue,
    Label(u64),
    Goto(u64),
    Block(Vec<HlilStmt>),
    Comment(String),
}

/// Information about a specific range of characters in the decompiled output.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceAnnotation {
    pub start: usize,
    pub end: usize,
    pub kind: AnnotationKind,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AnnotationKind {
    /// Jump to a function address.
    Function(u64),
    /// Jump to a global variable address.
    Global(u64),
    /// Reference to a local variable name.
    Local(String),
    /// Reference to a type name.
    Type(String),
}

/// The result of decompilation, including the text and navigation metadata.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DecompiledCode {
    pub text: String,
    pub annotations: Vec<SourceAnnotation>,
}

/// Internal helper for building annotated source code.
struct SourceWriter {
    code: DecompiledCode,
    current_indent: usize,
}

impl SourceWriter {
    fn new() -> Self {
        Self {
            code: DecompiledCode::default(),
            current_indent: 0,
        }
    }

    fn write(&mut self, s: &str) {
        self.code.text.push_str(s);
    }

    fn write_indent(&mut self) {
        for _ in 0..self.current_indent {
            self.code.text.push_str("    ");
        }
    }

    fn write_annotated(&mut self, s: &str, kind: AnnotationKind) {
        let start = self.code.text.len();
        self.code.text.push_str(s);
        let end = self.code.text.len();
        self.code
            .annotations
            .push(SourceAnnotation { start, end, kind });
    }

    fn newline(&mut self) {
        self.code.text.push('\n');
    }

    fn indent(&mut self) {
        self.current_indent += 1;
    }

    fn unindent(&mut self) {
        self.current_indent = self.current_indent.saturating_sub(1);
    }

    fn finish(self) -> DecompiledCode {
        self.code
    }
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

/// Render HLIL as structured C-like pseudocode.
pub fn render_pseudocode(name: &str, stmts: &[HlilStmt]) -> DecompiledCode {
    let mut w = SourceWriter::new();
    w.write("// Decompiled with Sleuthre\n\n");
    w.write("void ");
    w.write(name);
    w.write("() {\n");
    w.indent();
    for stmt in stmts {
        write_stmt(&mut w, stmt);
    }
    w.unindent();
    w.write("}\n");
    w.finish()
}

/// Render HLIL as structured C-like pseudocode with function signature information.
pub fn render_pseudocode_with_info(
    name: &str,
    stmts: &[HlilStmt],
    info: &crate::il::structuring::DecompileInfo,
    types: &crate::types::TypeManager,
) -> DecompiledCode {
    let mut w = SourceWriter::new();
    w.write("// Decompiled with Sleuthre\n\n");

    // Includes
    let mut includes: Vec<_> = info.includes.iter().collect();
    includes.sort();
    for inc in includes {
        w.write("#include <");
        w.write(inc);
        w.write(">\n");
    }
    if !info.includes.is_empty() {
        w.newline();
    }

    // Type definitions
    if !info.required_types.is_empty() {
        let mut sorted_types: Vec<_> = info.required_types.iter().collect();
        sorted_types.sort();
        for type_name in sorted_types {
            if let Some(cty) = types.get_type(type_name) {
                write_type_definition(&mut w, cty);
                w.newline();
            }
        }
        w.newline();
    }

    // Function signature
    w.write_annotated(
        &info.return_type,
        AnnotationKind::Type(info.return_type.clone()),
    );
    w.write(" ");
    w.write(name);
    w.write("(");
    if info.params.is_empty() {
        w.write("void");
    } else {
        for (i, (ty, pname)) in info.params.iter().enumerate() {
            if i > 0 {
                w.write(", ");
            }
            w.write_annotated(ty, AnnotationKind::Type(ty.clone()));
            w.write(" ");
            w.write_annotated(pname, AnnotationKind::Local(pname.clone()));
        }
    }
    w.write(") {\n");
    w.indent();

    // Local variable declarations
    for (ty, lname) in &info.locals {
        w.write_indent();
        w.write_annotated(ty, AnnotationKind::Type(ty.clone()));
        w.write(" ");
        w.write_annotated(lname, AnnotationKind::Local(lname.clone()));
        w.write(";\n");
    }
    if !info.locals.is_empty() {
        w.newline();
    }

    // Body
    for stmt in stmts {
        write_stmt(&mut w, stmt);
    }
    w.unindent();
    w.write("}\n");
    w.finish()
}

fn write_type_definition(w: &mut SourceWriter, cty: &crate::types::CompoundType) {
    use crate::types::CompoundType;
    match cty {
        CompoundType::Struct { name, fields, .. } | CompoundType::Union { name, fields, .. } => {
            let kind = if matches!(cty, CompoundType::Struct { .. }) {
                "struct"
            } else {
                "union"
            };
            w.write(kind);
            w.write(" ");
            w.write(name);
            w.write(" {\n");
            w.indent();
            for field in fields {
                w.write_indent();
                w.write_annotated(
                    &field.type_ref.display_name(),
                    AnnotationKind::Type(field.type_ref.display_name()),
                );
                w.write(" ");
                w.write(&field.name);
                w.write(";\n");
            }
            w.unindent();
            w.write("};\n");
        }
        CompoundType::Enum { name, variants, .. } => {
            w.write("enum ");
            w.write(name);
            w.write(" {\n");
            w.indent();
            for (vname, val) in variants {
                w.write_indent();
                w.write(vname);
                w.write(" = ");
                w.write(&val.to_string());
                w.write(",\n");
            }
            w.unindent();
            w.write("};\n");
        }
        CompoundType::Typedef { name, target } => {
            w.write("typedef ");
            w.write_annotated(
                &target.display_name(),
                AnnotationKind::Type(target.display_name()),
            );
            w.write(" ");
            w.write(name);
            w.write(";\n");
        }
    }
}

fn write_stmt(w: &mut SourceWriter, stmt: &HlilStmt) {
    w.write_indent();
    match stmt {
        HlilStmt::Assign { dest, src } => {
            write_expr(w, dest);
            w.write(" = ");
            write_expr(w, src);
            w.write(";\n");
        }
        HlilStmt::Store { addr, value } => {
            w.write("*");
            write_expr_prec(w, addr, 10);
            w.write(" = ");
            write_expr(w, value);
            w.write(";\n");
        }
        HlilStmt::Expr(e) => {
            write_expr(w, e);
            w.write(";\n");
        }
        HlilStmt::Return(opt) => {
            w.write("return");
            if let Some(e) = opt {
                w.write(" ");
                write_expr(w, e);
            }
            w.write(";\n");
        }
        HlilStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            w.write("if (");
            write_expr(w, cond);
            w.write(") {\n");
            w.indent();
            for s in then_body {
                write_stmt(w, s);
            }
            w.unindent();
            w.write_indent();
            w.write("}");
            if !else_body.is_empty() {
                w.write(" else {\n");
                w.indent();
                for s in else_body {
                    write_stmt(w, s);
                }
                w.unindent();
                w.write_indent();
                w.write("}");
            }
            w.newline();
        }
        HlilStmt::While { cond, body } => {
            w.write("while (");
            write_expr(w, cond);
            w.write(") {\n");
            w.indent();
            for s in body {
                write_stmt(w, s);
            }
            w.unindent();
            w.write_indent();
            w.write("}\n");
        }
        HlilStmt::DoWhile { body, cond } => {
            w.write("do {\n");
            w.indent();
            for s in body {
                write_stmt(w, s);
            }
            w.unindent();
            w.write_indent();
            w.write("} while (");
            write_expr(w, cond);
            w.write(");\n");
        }
        HlilStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            w.write("for (");
            write_stmt_inline(w, init);
            w.write("; ");
            write_expr(w, cond);
            w.write("; ");
            write_stmt_inline(w, update);
            w.write(") {\n");
            w.indent();
            for s in body {
                write_stmt(w, s);
            }
            w.unindent();
            w.write_indent();
            w.write("}\n");
        }
        HlilStmt::Switch {
            cond,
            cases,
            default,
        } => {
            w.write("switch (");
            write_expr(w, cond);
            w.write(") {\n");
            w.indent();
            for (val, body) in cases {
                w.write_indent();
                w.write(&format!("case 0x{:x}:\n", val));
                w.indent();
                for s in body {
                    write_stmt(w, s);
                }
                w.write_indent();
                w.write("break;\n");
                w.unindent();
            }
            if !default.is_empty() {
                w.write_indent();
                w.write("default:\n");
                w.indent();
                for s in default {
                    write_stmt(w, s);
                }
                w.unindent();
            }
            w.unindent();
            w.write_indent();
            w.write("}\n");
        }
        HlilStmt::Break => {
            w.write("break;\n");
        }
        HlilStmt::Continue => {
            w.write("continue;\n");
        }
        HlilStmt::Label(addr) => {
            w.unindent();
            w.write_indent();
            w.write(&format!("label_{:x}:\n", addr));
            w.indent();
        }
        HlilStmt::Goto(addr) => {
            w.write(&format!("goto label_{:x};\n", addr));
        }
        HlilStmt::Block(stmts) => {
            for s in stmts {
                write_stmt(w, s);
            }
        }
        HlilStmt::Comment(text) => {
            w.write("// ");
            w.write(text);
            w.newline();
        }
    }
}

fn write_stmt_inline(w: &mut SourceWriter, stmt: &HlilStmt) {
    match stmt {
        HlilStmt::Assign { dest, src } => {
            write_expr(w, dest);
            w.write(" = ");
            write_expr(w, src);
        }
        HlilStmt::Expr(e) => write_expr(w, e),
        _ => {}
    }
}

fn write_expr(w: &mut SourceWriter, expr: &HlilExpr) {
    write_expr_prec(w, expr, 0);
}

fn write_expr_prec(w: &mut SourceWriter, expr: &HlilExpr, parent_prec: u8) {
    match expr {
        HlilExpr::Var(name) => {
            w.write_annotated(name, AnnotationKind::Local(name.clone()));
        }
        HlilExpr::Global(addr, name) => {
            w.write_annotated(name, AnnotationKind::Global(*addr));
        }
        HlilExpr::Const(v) => {
            if *v > 9 {
                w.write(&format!("0x{:x}", v));
            } else {
                w.write(&format!("{}", v));
            }
        }
        HlilExpr::Deref { addr, .. } => {
            w.write("*");
            write_expr_prec(w, addr, 10);
        }
        HlilExpr::BinOp { op, left, right } => {
            let prec = op_precedence(op);
            if prec < parent_prec {
                w.write("(");
            }
            write_expr_prec(w, left, prec);
            w.write(" ");
            w.write(&op.to_string());
            w.write(" ");
            write_expr_prec(w, right, prec + 1);
            if prec < parent_prec {
                w.write(")");
            }
        }
        HlilExpr::UnaryOp { op, operand } => {
            let prefix = match op {
                crate::il::llil::UnaryOp::Not => "~",
                crate::il::llil::UnaryOp::Neg => "-",
            };
            w.write(prefix);
            write_expr_prec(w, operand, 10);
        }
        HlilExpr::Call { target, args } => {
            match &**target {
                HlilExpr::Const(addr) => {
                    w.write_annotated(&format!("0x{:x}", addr), AnnotationKind::Function(*addr))
                }
                HlilExpr::Global(addr, name) => {
                    w.write_annotated(name, AnnotationKind::Function(*addr));
                }
                _ => write_expr_prec(w, target, 11),
            }
            w.write("(");
            for (i, arg) in args.iter().enumerate() {
                if i > 0 {
                    w.write(", ");
                }
                write_expr(w, arg);
            }
            w.write(")");
        }
        HlilExpr::AddrOf(inner) => {
            w.write("&");
            write_expr_prec(w, inner, 10);
        }
        HlilExpr::FieldAccess {
            base,
            field_name,
            is_ptr,
        } => {
            write_expr_prec(w, base, 11);
            w.write(if *is_ptr { "->" } else { "." });
            w.write(field_name);
        }
        HlilExpr::ArrayAccess { base, index } => {
            write_expr_prec(w, base, 11);
            w.write("[");
            write_expr(w, index);
            w.write("]");
        }
        HlilExpr::VectorOp {
            kind,
            element_type,
            width,
            operands,
        } => {
            let s = fmt_vector_op(kind, *element_type, *width, operands);
            w.write(&s);
        }
    }
}

/// Return the precedence level for a binary operator.
/// Higher values bind more tightly.
fn op_precedence(op: &BinOp) -> u8 {
    match op {
        BinOp::Mul
        | BinOp::UDiv
        | BinOp::SDiv
        | BinOp::UMod
        | BinOp::SMod
        | BinOp::FMul
        | BinOp::FDiv => 10,
        BinOp::Add | BinOp::Sub | BinOp::FAdd | BinOp::FSub => 9,
        BinOp::Shl | BinOp::Shr | BinOp::Sar => 8,
        BinOp::CmpEq
        | BinOp::CmpNe
        | BinOp::CmpLt
        | BinOp::CmpLe
        | BinOp::CmpGt
        | BinOp::CmpGe
        | BinOp::CmpUlt
        | BinOp::CmpUle
        | BinOp::CmpUgt
        | BinOp::CmpUge => 7,
        BinOp::And => 6,
        BinOp::Xor => 5,
        BinOp::Or => 4,
        BinOp::LogicalAnd => 2,
        BinOp::LogicalOr => 1,
    }
}

fn fmt_vector_op(
    kind: &VectorOpKind,
    elem: VectorElementType,
    width: u16,
    operands: &[HlilExpr],
) -> String {
    let count = elem.count_in(width);
    let ty = elem.c_type();

    let fmt_expr_local = |expr: &HlilExpr| match expr {
        HlilExpr::Var(n) => n.clone(),
        HlilExpr::Const(v) => format!("0x{:x}", v),
        _ => "?".into(),
    };

    let op = |i: usize| -> String {
        operands
            .get(i)
            .map(fmt_expr_local)
            .unwrap_or_else(|| "?".into())
    };

    match kind {
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
        VectorOpKind::AddSaturate | VectorOpKind::SubSaturate => {
            format!(
                "/* {ty}[{count}] saturating */ {dst} = {kind}({a}, {b})",
                ty = ty,
                count = count,
                dst = op(0),
                kind = kind,
                a = op(0),
                b = op(1)
            )
        }
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
        VectorOpKind::Abs | VectorOpKind::Min | VectorOpKind::Max | VectorOpKind::Avg => {
            format!(
                "/* {ty}[{count}] */ {dst} = {kind}({a})",
                ty = ty,
                count = count,
                dst = op(0),
                kind = kind,
                a = op(0)
            )
        }
        VectorOpKind::CompareEq | VectorOpKind::CompareGt | VectorOpKind::CompareLt => {
            let c_op = match kind {
                VectorOpKind::CompareEq => "==",
                VectorOpKind::CompareGt => ">",
                VectorOpKind::CompareLt => "<",
                _ => unreachable!(),
            };
            format!(
                "/* {ty}[{count}] cmp */ {dst} = ({a} {op} {b})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                op = c_op,
                b = op(1)
            )
        }
        VectorOpKind::ShiftLeft | VectorOpKind::ShiftRight | VectorOpKind::ShiftRightArith => {
            let c_op = match kind {
                VectorOpKind::ShiftLeft => "<<",
                _ => ">>",
            };
            format!(
                "/* {ty}[{count}] shift */ {dst} = {a} {op} {b}",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(0),
                op = c_op,
                b = op(1)
            )
        }
        VectorOpKind::Broadcast => {
            format!(
                "/* {ty}[{count}] broadcast */ {dst} = [{a}; {count}]",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(1)
            )
        }
        VectorOpKind::Shuffle { mask } => {
            format!(
                "/* {ty}[{count}] shuffle */ {dst} = shuffle({a}, 0x{mask:x})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(1),
                mask = mask
            )
        }
        VectorOpKind::ShuffleBytes => {
            format!(
                "/* {ty}[{count}] shuffle_bytes */ {dst} = shuffle_bytes({a}, {mask})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(1),
                mask = op(2)
            )
        }
        VectorOpKind::UnpackLow | VectorOpKind::UnpackHigh => {
            format!(
                "/* {ty}[{count}] unpack */ {dst} = {kind}({a}, {b})",
                ty = ty,
                count = count,
                dst = op(0),
                kind = kind,
                a = op(1),
                b = op(2)
            )
        }
        VectorOpKind::PackSigned | VectorOpKind::PackUnsigned => {
            format!(
                "/* {ty}[{count}] pack */ {dst} = {kind}({a}, {b})",
                ty = ty,
                count = count,
                dst = op(0),
                kind = kind,
                a = op(1),
                b = op(2)
            )
        }
        VectorOpKind::Blend { mask } => {
            format!(
                "/* {ty}[{count}] blend */ {dst} = blend({a}, {b}, 0x{mask:x})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(1),
                b = op(2),
                mask = mask
            )
        }
        VectorOpKind::BlendVar => {
            format!(
                "/* {ty}[{count}] blend */ {dst} = blend({a}, {b}, {mask})",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(1),
                b = op(2),
                mask = op(3)
            )
        }
        VectorOpKind::HorizontalAdd | VectorOpKind::HorizontalSub => {
            format!(
                "/* {ty}[{count}] horizontal */ {dst} = {kind}({a}, {b})",
                ty = ty,
                count = count,
                dst = op(0),
                kind = kind,
                a = op(1),
                b = op(2)
            )
        }
        VectorOpKind::Insert { index } => {
            format!(
                "/* {ty}[{count}] */ {dst}[{idx}] = {val}",
                ty = ty,
                count = count,
                dst = op(0),
                idx = index,
                val = op(1)
            )
        }
        VectorOpKind::Extract { index } => {
            format!(
                "/* {ty} */ {dst} = {src}[{idx}]",
                ty = ty,
                dst = op(0),
                src = op(1),
                idx = index
            )
        }
        VectorOpKind::ConvertIntToFloat
        | VectorOpKind::ConvertFloatToInt
        | VectorOpKind::ConvertWiden
        | VectorOpKind::ConvertNarrow => {
            format!(
                "/* vector convert */ {dst} = ({kind}) {src}",
                dst = op(0),
                kind = kind,
                src = op(1)
            )
        }
        VectorOpKind::FusedMulAdd => {
            format!(
                "/* {ty}[{count}] */ {dst} = ({a} * {b}) + {c}",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(1),
                b = op(2),
                c = op(3)
            )
        }
        VectorOpKind::FusedMulSub => {
            format!(
                "/* {ty}[{count}] */ {dst} = ({a} * {b}) - {c}",
                ty = ty,
                count = count,
                dst = op(0),
                a = op(1),
                b = op(2),
                c = op(3)
            )
        }
        VectorOpKind::MoveMask => {
            format!(
                "/* {ty}[{count}] */ {dst} = move_mask({src})",
                ty = ty,
                count = count,
                dst = op(0),
                src = op(1)
            )
        }
        VectorOpKind::Zero => {
            format!(
                "/* {ty}[{count}] */ {dst} = 0",
                ty = ty,
                count = count,
                dst = op(0)
            )
        }
        _ => format!("/* vector {kind} */ {}(...)", kind),
    }
}

impl fmt::Display for DecompiledCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

impl fmt::Display for HlilExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut w = SourceWriter::new();
        write_expr(&mut w, self);
        write!(f, "{}", w.finish().text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_simple_function() {
        let stmts = vec![HlilStmt::Return(Some(HlilExpr::Const(42)))];
        let code = render_pseudocode("test", &stmts);
        assert!(code.text.contains("void test() {"));
        assert!(code.text.contains("return 0x2a;"));
    }

    #[test]
    fn render_if_else() {
        let stmts = vec![HlilStmt::If {
            cond: HlilExpr::Var("flag".into()),
            then_body: vec![HlilStmt::Return(Some(HlilExpr::Const(1)))],
            else_body: vec![HlilStmt::Return(Some(HlilExpr::Const(0)))],
        }];
        let code = render_pseudocode("test", &stmts);
        assert!(code.text.contains("if (flag)"));
        assert!(code.text.contains("else {"));
    }

    #[test]
    fn render_while_loop() {
        let stmts = vec![HlilStmt::While {
            cond: HlilExpr::Var("flag".into()),
            body: vec![HlilStmt::Expr(HlilExpr::Var("nop".into()))],
        }];
        let code = render_pseudocode("test", &stmts);
        assert!(code.text.contains("while (flag)"));
    }

    #[test]
    fn render_for_loop() {
        let stmts = vec![HlilStmt::For {
            init: Box::new(HlilStmt::Assign {
                dest: HlilExpr::Var("i".into()),
                src: HlilExpr::Const(0),
            }),
            cond: HlilExpr::Var("flag".into()),
            update: Box::new(HlilStmt::Assign {
                dest: HlilExpr::Var("i".into()),
                src: HlilExpr::Const(1),
            }),
            body: vec![],
        }];
        let code = render_pseudocode("test", &stmts);
        assert!(code.text.contains("for (i = 0; flag; i = 1)"));
    }

    #[test]
    fn precedence_add_mul_no_parens_needed() {
        // `a + b * c` -> no parens around mul
        let expr = HlilExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(HlilExpr::Var("a".into())),
            right: Box::new(HlilExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(HlilExpr::Var("b".into())),
                right: Box::new(HlilExpr::Var("c".into())),
            }),
        };
        let mut w = SourceWriter::new();
        write_expr(&mut w, &expr);
        assert_eq!(w.finish().text, "a + b * c");
    }

    #[test]
    fn precedence_add_in_mul_needs_parens() {
        // `(a + b) * c` -> parens around add
        let expr = HlilExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Var("a".into())),
                right: Box::new(HlilExpr::Var("b".into())),
            }),
            right: Box::new(HlilExpr::Var("c".into())),
        };
        let mut w = SourceWriter::new();
        write_expr(&mut w, &expr);
        assert_eq!(w.finish().text, "(a + b) * c");
    }

    #[test]
    fn precedence_left_associative_sub() {
        // `a - b - c` -> `(a - b) - c` -> no parens
        let expr = HlilExpr::BinOp {
            op: BinOp::Sub,
            left: Box::new(HlilExpr::BinOp {
                op: BinOp::Sub,
                left: Box::new(HlilExpr::Var("a".into())),
                right: Box::new(HlilExpr::Var("b".into())),
            }),
            right: Box::new(HlilExpr::Var("c".into())),
        };
        let mut w = SourceWriter::new();
        write_expr(&mut w, &expr);
        assert_eq!(w.finish().text, "a - b - c");
    }

    #[test]
    fn precedence_right_sub_needs_parens() {
        // `a - (b - c)` -> parens around right sub
        let expr = HlilExpr::BinOp {
            op: BinOp::Sub,
            left: Box::new(HlilExpr::Var("a".into())),
            right: Box::new(HlilExpr::BinOp {
                op: BinOp::Sub,
                left: Box::new(HlilExpr::Var("b".into())),
                right: Box::new(HlilExpr::Var("c".into())),
            }),
        };
        let mut w = SourceWriter::new();
        write_expr(&mut w, &expr);
        assert_eq!(w.finish().text, "a - (b - c)");
    }

    #[test]
    fn precedence_mul_add_no_extra_parens() {
        // `a * b + c` -> no parens
        let expr = HlilExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(HlilExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(HlilExpr::Var("a".into())),
                right: Box::new(HlilExpr::Var("b".into())),
            }),
            right: Box::new(HlilExpr::Var("c".into())),
        };
        let mut w = SourceWriter::new();
        write_expr(&mut w, &expr);
        assert_eq!(w.finish().text, "a * b + c");
    }

    #[test]
    fn unary_neg_renders() {
        let expr = HlilExpr::UnaryOp {
            op: crate::il::llil::UnaryOp::Neg,
            operand: Box::new(HlilExpr::Var("x".into())),
        };
        let mut w = SourceWriter::new();
        write_expr(&mut w, &expr);
        assert_eq!(w.finish().text, "-x");
    }

    #[test]
    fn unary_not_renders() {
        let expr = HlilExpr::UnaryOp {
            op: crate::il::llil::UnaryOp::Not,
            operand: Box::new(HlilExpr::Var("x".into())),
        };
        let mut w = SourceWriter::new();
        write_expr(&mut w, &expr);
        assert_eq!(w.finish().text, "~x");
    }

    #[test]
    fn unary_of_complex_expr_wraps() {
        let expr = HlilExpr::UnaryOp {
            op: crate::il::llil::UnaryOp::Neg,
            operand: Box::new(HlilExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(HlilExpr::Var("a".into())),
                right: Box::new(HlilExpr::Var("b".into())),
            }),
        };
        let mut w = SourceWriter::new();
        write_expr(&mut w, &expr);
        assert_eq!(w.finish().text, "-(a + b)");
    }
}
