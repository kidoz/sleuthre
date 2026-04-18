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
                HlilExpr::Var("phi_undef".into())
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

/// Assign friendly names to registers for common architectures so the output
/// reads like C rather than disassembly. Unknown register names pass through
/// verbatim (they are already valid C identifiers).
fn pretty_var_name(ssa: &SsaVar) -> String {
    let base: &str = match ssa.name.as_str() {
        // x86 / x86-64 general-purpose: GAS-style low halves map to the same alias.
        "rax" | "eax" | "ax" | "al" | "ah" => "result",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "counter",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "data",
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "base",
        "rsi" | "esi" | "si" | "sil" => "src",
        "rdi" | "edi" | "di" | "dil" => "dst",
        "rbp" | "ebp" | "bp" | "bpl" => "frame",
        "rsp" | "esp" | "sp" | "spl" => "sp",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        "rip" | "eip" | "ip" => "pc",

        // ARM64 general-purpose: x0–x30 and w0–w30 share aliases.
        "x0" | "w0" => "arg0",
        "x1" | "w1" => "arg1",
        "x2" | "w2" => "arg2",
        "x3" | "w3" => "arg3",
        "x4" | "w4" => "arg4",
        "x5" | "w5" => "arg5",
        "x6" | "w6" => "arg6",
        "x7" | "w7" => "arg7",
        "x29" | "w29" | "fp" => "frame",
        "x30" | "w30" | "lr" => "return_address",

        // 32-bit ARM common aliases.
        "r0" => "arg0",
        "r1" => "arg1",
        "r2" => "arg2",
        "r3" => "arg3",
        "r4" => "r4",
        "r5" => "r5",
        "r6" => "r6",
        "r7" => "r7",

        // MIPS argument/temporary/saved registers.
        "a0" | "$a0" => "arg0",
        "a1" | "$a1" => "arg1",
        "a2" | "$a2" => "arg2",
        "a3" | "$a3" => "arg3",
        "v0" | "$v0" => "result",
        "v1" | "$v1" => "result_hi",
        "t0" | "$t0" => "tmp0",
        "t1" | "$t1" => "tmp1",
        "t2" | "$t2" => "tmp2",
        "t3" | "$t3" => "tmp3",

        // RISC-V ABI names — avoid the raw `x10..x13` form which collides
        // with ARM64's x-registers.
        "a4" | "$a4" => "arg4",
        "a5" | "$a5" => "arg5",
        "a6" | "$a6" => "arg6",
        "a7" | "$a7" => "arg7",

        // Synthetic / internal pseudo-registers pass through unchanged.
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
///
/// This fallback path emits a best-effort signature (`int name(void)`) plus the
/// minimum includes required for the typed dereferences and bool operators
/// produced by the formatter. It is intended to be syntactically valid C so
/// that the output can be piped into a compiler for sanity-checking.
pub fn render_pseudocode(name: &str, stmts: &[HlilStmt]) -> DecompiledCode {
    let mut w = SourceWriter::new();
    w.write("// Decompiled with Sleuthre\n");
    w.write("#include <stdint.h>\n");
    w.write("#include <stdbool.h>\n\n");
    w.write("int ");
    w.write(name);
    w.write("(void) {\n");
    w.indent();
    for stmt in stmts {
        write_stmt(&mut w, stmt);
    }
    // Emit a safe fall-through return so gcc -Wreturn-type stays quiet when
    // the recovered body has no explicit terminator.
    if !stmt_list_terminates(stmts) {
        w.write_indent();
        w.write("return 0;\n");
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

    // Includes. Entries prefixed with `<GUARDED>` are wrapped in a
    // preprocessor guard so that SIMD intrinsic headers do not break builds
    // on non-x86 targets.
    let mut includes: Vec<_> = info.includes.iter().collect();
    includes.sort();
    for inc in includes {
        if let Some(rest) = inc.strip_prefix("<GUARDED>") {
            w.write("#if defined(__x86_64__) || defined(__i386__)\n");
            w.write("#include <");
            w.write(rest);
            w.write(">\n");
            w.write("#endif\n");
        } else {
            w.write("#include <");
            w.write(inc);
            w.write(">\n");
        }
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

/// Format an integer constant as an unambiguous C literal.
///
/// Small positive values are emitted in decimal so boolean-looking conditions
/// read naturally (`if (x == 0)`). Larger values are hex. A suffix is attached
/// whenever the magnitude forces the literal out of `int` range:
/// - fits in `int32_t` → no suffix
/// - fits in `uint32_t` → `u` (unsigned int)
/// - fits in `int64_t` → `LL` (long long)
/// - otherwise → `ULL` (unsigned long long)
fn format_c_integer_literal(v: u64) -> String {
    let suffix = if v <= i32::MAX as u64 {
        ""
    } else if v <= u32::MAX as u64 {
        "u"
    } else if v <= i64::MAX as u64 {
        "LL"
    } else {
        "ULL"
    };
    if v <= 9 {
        format!("{}{}", v, suffix)
    } else {
        format!("0x{:x}{}", v, suffix)
    }
}

fn stmt_list_terminates(stmts: &[HlilStmt]) -> bool {
    matches!(
        stmts.last(),
        Some(HlilStmt::Return(_))
            | Some(HlilStmt::Break)
            | Some(HlilStmt::Continue)
            | Some(HlilStmt::Goto(_))
    )
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
                // Match every case arm: emit `break;` unless the body already ends
                // in a terminator. Keeping this symmetric prevents unintended
                // fall-through when the output is compiled.
                if !stmt_list_terminates(default) {
                    w.write_indent();
                    w.write("break;\n");
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
            w.write(&format_c_integer_literal(*v));
        }
        HlilExpr::Deref { addr, size } => {
            // Emit a typed C dereference: *((T*)(addr)). This compiles under
            // <stdint.h> because the size-to-type map uses standard exact-width types.
            let cast = match size {
                1 => "uint8_t",
                2 => "uint16_t",
                4 => "uint32_t",
                8 => "uint64_t",
                _ => "uint8_t",
            };
            w.write(&format!("*(({} *)(", cast));
            write_expr_prec(w, addr, 0);
            w.write("))");
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
                    // Raw address call: cast through a function pointer so the expression
                    // parses as C — `((void (*)(void))0x401000)()`.
                    w.write("((void (*)(void))");
                    w.write_annotated(&format!("0x{:x}", addr), AnnotationKind::Function(*addr));
                    w.write(")");
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

/// Format a SIMD vector operation as a compilable C expression.
///
/// Emits Intel-style intrinsics (`<immintrin.h>`) when the element type and
/// width map onto one; otherwise emits a best-effort placeholder call wrapped
/// in a C block comment so the containing line still parses. The destination
/// operand (operand 0 in MLIL) is NOT rendered here — the surrounding `Assign`
/// is responsible for the `dst = ...` binding.
fn fmt_vector_op(
    kind: &VectorOpKind,
    elem: VectorElementType,
    width: u16,
    operands: &[HlilExpr],
) -> String {
    let fmt_expr_local = |expr: &HlilExpr| match expr {
        HlilExpr::Var(n) => n.clone(),
        HlilExpr::Const(v) => format!("0x{:x}", v),
        _ => "0".into(),
    };
    let op = |i: usize| -> String {
        operands
            .get(i)
            .map(fmt_expr_local)
            .unwrap_or_else(|| "0".into())
    };
    // Operand 0 is the destination in MLIL; sources start at index 0 again in
    // most binary x86 SSE ops (dst == src1). We therefore use op(0) for the
    // first source and op(1) for the second source to match x86 semantics.
    let (s1, s2) = (op(0), op(1));
    let suf = simd_suffix(elem);

    let intrinsic =
        |name: &str, args: &[&str]| -> String { format!("{}({})", name, args.join(", ")) };

    match kind {
        VectorOpKind::Add => intrinsic(&format!("_mm_add_{}", suf), &[&s1, &s2]),
        VectorOpKind::Sub => intrinsic(&format!("_mm_sub_{}", suf), &[&s1, &s2]),
        VectorOpKind::Mul => intrinsic(&format!("_mm_mul_{}", suf), &[&s1, &s2]),
        VectorOpKind::Div => intrinsic(&format!("_mm_div_{}", suf), &[&s1, &s2]),
        VectorOpKind::AddSaturate => intrinsic(&format!("_mm_adds_{}", suf), &[&s1, &s2]),
        VectorOpKind::SubSaturate => intrinsic(&format!("_mm_subs_{}", suf), &[&s1, &s2]),
        VectorOpKind::And => intrinsic("_mm_and_si128", &[&s1, &s2]),
        VectorOpKind::Or => intrinsic("_mm_or_si128", &[&s1, &s2]),
        VectorOpKind::Xor => intrinsic("_mm_xor_si128", &[&s1, &s2]),
        VectorOpKind::Abs => intrinsic(&format!("_mm_abs_{}", suf), &[&s1]),
        VectorOpKind::Min => intrinsic(&format!("_mm_min_{}", suf), &[&s1, &s2]),
        VectorOpKind::Max => intrinsic(&format!("_mm_max_{}", suf), &[&s1, &s2]),
        VectorOpKind::Avg => intrinsic(&format!("_mm_avg_{}", suf), &[&s1, &s2]),
        VectorOpKind::CompareEq => intrinsic(&format!("_mm_cmpeq_{}", suf), &[&s1, &s2]),
        VectorOpKind::CompareGt => intrinsic(&format!("_mm_cmpgt_{}", suf), &[&s1, &s2]),
        VectorOpKind::CompareLt => intrinsic(&format!("_mm_cmplt_{}", suf), &[&s1, &s2]),
        VectorOpKind::ShiftLeft => intrinsic(&format!("_mm_slli_{}", suf), &[&s1, &s2]),
        VectorOpKind::ShiftRight => intrinsic(&format!("_mm_srli_{}", suf), &[&s1, &s2]),
        VectorOpKind::ShiftRightArith => intrinsic(&format!("_mm_srai_{}", suf), &[&s1, &s2]),
        VectorOpKind::Broadcast => intrinsic(&format!("_mm_set1_{}", suf), &[&op(1)]),
        VectorOpKind::Shuffle { mask } => intrinsic(
            &format!("_mm_shuffle_{}", suf),
            &[&op(1), &format!("0x{:x}", mask)],
        ),
        VectorOpKind::ShuffleBytes => intrinsic("_mm_shuffle_epi8", &[&op(1), &op(2)]),
        VectorOpKind::UnpackLow => intrinsic(&format!("_mm_unpacklo_{}", suf), &[&op(1), &op(2)]),
        VectorOpKind::UnpackHigh => intrinsic(&format!("_mm_unpackhi_{}", suf), &[&op(1), &op(2)]),
        VectorOpKind::PackSigned => intrinsic(&format!("_mm_packs_{}", suf), &[&op(1), &op(2)]),
        VectorOpKind::PackUnsigned => intrinsic(&format!("_mm_packus_{}", suf), &[&op(1), &op(2)]),
        VectorOpKind::Blend { mask } => intrinsic(
            &format!("_mm_blend_{}", suf),
            &[&op(1), &op(2), &format!("0x{:x}", mask)],
        ),
        VectorOpKind::BlendVar => {
            intrinsic(&format!("_mm_blendv_{}", suf), &[&op(1), &op(2), &op(3)])
        }
        VectorOpKind::HorizontalAdd => intrinsic(&format!("_mm_hadd_{}", suf), &[&op(1), &op(2)]),
        VectorOpKind::HorizontalSub => intrinsic(&format!("_mm_hsub_{}", suf), &[&op(1), &op(2)]),
        VectorOpKind::Insert { index } => intrinsic(
            &format!("_mm_insert_{}", suf),
            &[&s1, &op(1), &format!("{}", index)],
        ),
        VectorOpKind::Extract { index } => intrinsic(
            &format!("_mm_extract_{}", suf),
            &[&op(1), &format!("{}", index)],
        ),
        VectorOpKind::ConvertIntToFloat => intrinsic("_mm_cvtepi32_ps", &[&op(1)]),
        VectorOpKind::ConvertFloatToInt => intrinsic("_mm_cvtps_epi32", &[&op(1)]),
        VectorOpKind::ConvertWiden => intrinsic("_mm_cvtepi16_epi32", &[&op(1)]),
        VectorOpKind::ConvertNarrow => intrinsic("_mm_packs_epi32", &[&op(1), &op(1)]),
        VectorOpKind::FusedMulAdd => {
            intrinsic(&format!("_mm_fmadd_{}", suf), &[&op(1), &op(2), &op(3)])
        }
        VectorOpKind::FusedMulSub => {
            intrinsic(&format!("_mm_fmsub_{}", suf), &[&op(1), &op(2), &op(3)])
        }
        VectorOpKind::MoveMask => intrinsic(&format!("_mm_movemask_{}", suf), &[&op(1)]),
        VectorOpKind::Zero => intrinsic(&format!("_mm_setzero_{}", suf), &[]),
        _ => {
            let _ = width;
            format!("/* simd {:?} */ 0", kind)
        }
    }
}

/// Map a vector element type to the Intel intrinsic suffix (e.g. `ps`, `epi32`).
fn simd_suffix(elem: VectorElementType) -> &'static str {
    match elem {
        VectorElementType::Int8 => "epi8",
        VectorElementType::Int16 => "epi16",
        VectorElementType::Int32 => "epi32",
        VectorElementType::Int64 => "epi64",
        VectorElementType::Float32 => "ps",
        VectorElementType::Float64 => "pd",
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
        assert!(code.text.contains("#include <stdint.h>"));
        assert!(code.text.contains("int test(void) {"));
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

    #[test]
    fn literal_suffixes_by_magnitude() {
        // int32_t range — no suffix.
        assert_eq!(format_c_integer_literal(5), "5");
        assert_eq!(format_c_integer_literal(0x7fff_ffff), "0x7fffffff");
        // uint32_t range — u suffix.
        assert_eq!(format_c_integer_literal(0xffff_ffff), "0xffffffffu");
        // int64_t range — LL suffix.
        assert_eq!(format_c_integer_literal(0x1_0000_0000), "0x100000000LL");
        // uint64_t beyond i64 — ULL.
        assert_eq!(
            format_c_integer_literal(0xffff_ffff_ffff_ffff),
            "0xffffffffffffffffULL"
        );
    }

    #[test]
    fn generated_c_is_compilable() {
        // Build a non-trivial HLIL function and verify that the emitted text
        // compiles with a real C toolchain (syntax-only). Skipped silently if
        // no compiler is on PATH so CI hosts without one still pass.
        let Some(cc) = find_c_compiler() else {
            return;
        };

        let stmts = vec![
            HlilStmt::Assign {
                dest: HlilExpr::Var("i".into()),
                src: HlilExpr::Const(0),
            },
            HlilStmt::While {
                cond: HlilExpr::BinOp {
                    op: BinOp::CmpLt,
                    left: Box::new(HlilExpr::Var("i".into())),
                    right: Box::new(HlilExpr::Const(10)),
                },
                body: vec![
                    HlilStmt::If {
                        cond: HlilExpr::BinOp {
                            op: BinOp::CmpEq,
                            left: Box::new(HlilExpr::Var("i".into())),
                            right: Box::new(HlilExpr::Const(5)),
                        },
                        then_body: vec![HlilStmt::Break],
                        else_body: vec![],
                    },
                    HlilStmt::Assign {
                        dest: HlilExpr::Var("i".into()),
                        src: HlilExpr::BinOp {
                            op: BinOp::Add,
                            left: Box::new(HlilExpr::Var("i".into())),
                            right: Box::new(HlilExpr::Const(1)),
                        },
                    },
                ],
            },
            HlilStmt::Switch {
                cond: HlilExpr::Var("i".into()),
                cases: vec![
                    (0, vec![HlilStmt::Return(Some(HlilExpr::Const(1)))]),
                    (1, vec![]),
                ],
                default: vec![HlilStmt::Assign {
                    dest: HlilExpr::Var("i".into()),
                    src: HlilExpr::Const(0xdeadbeef),
                }],
            },
            HlilStmt::Return(Some(HlilExpr::Deref {
                addr: Box::new(HlilExpr::BinOp {
                    op: BinOp::Add,
                    left: Box::new(HlilExpr::Var("i".into())),
                    right: Box::new(HlilExpr::Const(0x10)),
                }),
                size: 4,
            })),
        ];

        // Manually declare `i` so the generated body has the expected local
        // (render_pseudocode itself doesn't infer locals).
        let mut source = String::new();
        source.push_str("#include <stdint.h>\n#include <stdbool.h>\n");
        source.push_str("int sample_fn(void) {\n");
        source.push_str("    int64_t i;\n");
        let body = render_pseudocode("sample_fn", &stmts).text;
        // Strip the auto-generated header/signature from render_pseudocode and
        // splice the body into our harness so the `i` declaration is in scope.
        if let Some(start) = body.find("int sample_fn(void) {\n") {
            let body_start = start + "int sample_fn(void) {\n".len();
            let body_end = body.rfind('}').unwrap_or(body.len());
            source.push_str(&body[body_start..body_end]);
        }
        source.push_str("}\n");

        let tmp =
            std::env::temp_dir().join(format!("sleuthre_decompile_{}.c", uuid::Uuid::new_v4()));
        std::fs::write(&tmp, source.as_bytes()).unwrap();
        let output = std::process::Command::new(&cc)
            .args([
                "-std=c11",
                "-fsyntax-only",
                "-Werror=implicit-function-declaration",
            ])
            .arg(&tmp)
            .output()
            .expect("failed to spawn C compiler");
        let _ = std::fs::remove_file(&tmp);
        assert!(
            output.status.success(),
            "generated C failed to compile:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn find_c_compiler() -> Option<std::path::PathBuf> {
        for candidate in ["cc", "gcc", "clang"] {
            if let Ok(output) = std::process::Command::new("which").arg(candidate).output()
                && output.status.success()
            {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(std::path::PathBuf::from(path));
                }
            }
        }
        None
    }
}
