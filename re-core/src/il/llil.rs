//! Low-Level Intermediate Language (LLIL)
//!
//! A register-transfer-level representation that normalizes x86/ARM/MIPS
//! instructions into a uniform format. Each native instruction maps to one
//! or more LLIL statements.

use std::fmt;

/// An index into the expression pool of an `LlilFunction`.
pub type ExprId = usize;

/// An expression in the LLIL expression tree.
#[derive(Debug, Clone, PartialEq)]
pub enum LlilExpr {
    /// A named register (e.g. "rax", "eflags").
    Reg(String),
    /// An integer constant.
    Const(u64),
    /// Memory load: `[addr]` with byte size.
    Load { addr: ExprId, size: u8 },
    /// Binary arithmetic / logic operation.
    BinOp {
        op: BinOp,
        left: ExprId,
        right: ExprId,
    },
    /// Unary operation (not, neg).
    UnaryOp { op: UnaryOp, operand: ExprId },
    /// Zero-extend to `bits` width.
    Zx { bits: u8, operand: ExprId },
    /// Sign-extend to `bits` width.
    Sx { bits: u8, operand: ExprId },
    /// A flag condition (e.g. result of a comparison).
    Flag(FlagCondition),
    /// SIMD vector operation.
    VectorOp {
        kind: VectorOpKind,
        element_type: VectorElementType,
        /// Vector width in bits (64, 128, 256, 512).
        width: u16,
        operands: Vec<ExprId>,
    },
}

/// SIMD vector element type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorElementType {
    Int8,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
}

impl VectorElementType {
    /// Number of elements that fit in a vector of `width` bits.
    pub fn count_in(self, width: u16) -> u16 {
        width / (self.bit_width() as u16)
    }

    pub fn bit_width(self) -> u8 {
        match self {
            VectorElementType::Int8 => 8,
            VectorElementType::Int16 => 16,
            VectorElementType::Int32 => 32,
            VectorElementType::Int64 => 64,
            VectorElementType::Float32 => 32,
            VectorElementType::Float64 => 64,
        }
    }

    /// C type name for this element type.
    pub fn c_type(self) -> &'static str {
        match self {
            VectorElementType::Int8 => "int8_t",
            VectorElementType::Int16 => "int16_t",
            VectorElementType::Int32 => "int32_t",
            VectorElementType::Int64 => "int64_t",
            VectorElementType::Float32 => "float",
            VectorElementType::Float64 => "double",
        }
    }
}

impl fmt::Display for VectorElementType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.c_type())
    }
}

/// SIMD vector operation kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VectorOpKind {
    // Element-wise arithmetic
    Add,
    Sub,
    Mul,
    MulHigh,
    Div,
    Abs,
    Min,
    Max,
    Avg,
    // Saturating arithmetic
    AddSaturate,
    SubSaturate,
    // Bitwise
    And,
    Or,
    Xor,
    AndNot,
    // Shifts
    ShiftLeft,
    ShiftRight,
    ShiftRightArith,
    // Compare
    CompareEq,
    CompareGt,
    CompareLt,
    // Shuffle / permute
    Shuffle {
        mask: u8,
    },
    ShuffleBytes,
    UnpackLow,
    UnpackHigh,
    // Pack
    PackSigned,
    PackUnsigned,
    // Blend
    Blend {
        mask: u8,
    },
    BlendVar,
    // Horizontal
    HorizontalAdd,
    HorizontalSub,
    // Insert / Extract
    Insert {
        index: u8,
    },
    Extract {
        index: u8,
    },
    // Convert
    ConvertIntToFloat,
    ConvertFloatToInt,
    ConvertWiden,
    ConvertNarrow,
    // FMA
    FusedMulAdd,
    FusedMulSub,
    // Move / Load / Store
    Move,
    MoveAligned,
    MoveUnaligned,
    Broadcast,
    // Math
    Sqrt,
    Reciprocal,
    ReciprocalSqrt,
    Round,
    // Mask / test
    MoveMask,
    TestAllZeros,
    // String ops (SSE4.2)
    StringCompare,
    // Zero
    Zero,
    /// Fallback: raw intrinsic name.
    Intrinsic(String),
}

impl fmt::Display for VectorOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            VectorOpKind::Add => "vadd",
            VectorOpKind::Sub => "vsub",
            VectorOpKind::Mul => "vmul",
            VectorOpKind::MulHigh => "vmulhi",
            VectorOpKind::Div => "vdiv",
            VectorOpKind::Abs => "vabs",
            VectorOpKind::Min => "vmin",
            VectorOpKind::Max => "vmax",
            VectorOpKind::Avg => "vavg",
            VectorOpKind::AddSaturate => "vadds",
            VectorOpKind::SubSaturate => "vsubs",
            VectorOpKind::And => "vand",
            VectorOpKind::Or => "vor",
            VectorOpKind::Xor => "vxor",
            VectorOpKind::AndNot => "vandn",
            VectorOpKind::ShiftLeft => "vshl",
            VectorOpKind::ShiftRight => "vshr",
            VectorOpKind::ShiftRightArith => "vsar",
            VectorOpKind::CompareEq => "vcmpeq",
            VectorOpKind::CompareGt => "vcmpgt",
            VectorOpKind::CompareLt => "vcmplt",
            VectorOpKind::Shuffle { mask } => return write!(f, "vshuffle<0x{:02x}>", mask),
            VectorOpKind::ShuffleBytes => "vshufb",
            VectorOpKind::UnpackLow => "vunpacklo",
            VectorOpKind::UnpackHigh => "vunpackhi",
            VectorOpKind::PackSigned => "vpackss",
            VectorOpKind::PackUnsigned => "vpackus",
            VectorOpKind::Blend { mask } => return write!(f, "vblend<0x{:02x}>", mask),
            VectorOpKind::BlendVar => "vblendv",
            VectorOpKind::HorizontalAdd => "vhadd",
            VectorOpKind::HorizontalSub => "vhsub",
            VectorOpKind::Insert { index } => return write!(f, "vinsert<{}>", index),
            VectorOpKind::Extract { index } => return write!(f, "vextract<{}>", index),
            VectorOpKind::ConvertIntToFloat => "vcvti2f",
            VectorOpKind::ConvertFloatToInt => "vcvtf2i",
            VectorOpKind::ConvertWiden => "vwiden",
            VectorOpKind::ConvertNarrow => "vnarrow",
            VectorOpKind::FusedMulAdd => "vfmadd",
            VectorOpKind::FusedMulSub => "vfmsub",
            VectorOpKind::Move => "vmov",
            VectorOpKind::MoveAligned => "vmova",
            VectorOpKind::MoveUnaligned => "vmovu",
            VectorOpKind::Broadcast => "vbroadcast",
            VectorOpKind::Sqrt => "vsqrt",
            VectorOpKind::Reciprocal => "vrcp",
            VectorOpKind::ReciprocalSqrt => "vrsqrt",
            VectorOpKind::Round => "vround",
            VectorOpKind::MoveMask => "vmovmsk",
            VectorOpKind::TestAllZeros => "vtestz",
            VectorOpKind::StringCompare => "vstrcmp",
            VectorOpKind::Zero => "vzero",
            VectorOpKind::Intrinsic(name) => return write!(f, "{}", name),
        };
        write!(f, "{}", s)
    }
}

/// Binary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    UMod,
    SMod,
    FAdd,
    FSub,
    FMul,
    FDiv,
    And,
    Or,
    Xor,
    LogicalAnd,
    LogicalOr,
    Shl,
    Shr,
    Sar,
    CmpEq,
    CmpNe,
    CmpLt,
    CmpLe,
    CmpGt,
    CmpGe,
    CmpUlt,
    CmpUle,
    CmpUgt,
    CmpUge,
}

/// Unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

/// CPU flag conditions used for conditional branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagCondition {
    /// Equal / zero flag set
    E,
    /// Not equal / zero flag clear
    Ne,
    /// Unsigned less than (carry flag)
    Ult,
    /// Unsigned less or equal
    Ule,
    /// Unsigned greater or equal
    Uge,
    /// Unsigned greater than
    Ugt,
    /// Signed less than
    Slt,
    /// Signed less or equal
    Sle,
    /// Signed greater or equal
    Sge,
    /// Signed greater than
    Sgt,
    /// Sign flag set
    Neg,
    /// Overflow flag set
    Overflow,
}

/// An LLIL statement — the unit of execution.
#[derive(Debug, Clone, PartialEq)]
pub enum LlilStmt {
    /// Assign an expression result to a register.
    SetReg { dest: String, src: ExprId },
    /// Store a value to memory: `[addr] = value`.
    Store {
        addr: ExprId,
        value: ExprId,
        size: u8,
    },
    /// Unconditional branch to address.
    Jump { target: ExprId },
    /// Conditional branch: if cond goto true_target.
    BranchIf { cond: ExprId, target: ExprId },
    /// Function call.
    Call { target: ExprId },
    /// Return from function.
    Return,
    /// No operation (alignment padding, etc.).
    Nop,
    /// An instruction we couldn't lift (preserves the original text).
    Unimplemented { mnemonic: String, op_str: String },
}

/// An LLIL instruction with source location.
#[derive(Debug, Clone)]
pub struct LlilInst {
    pub address: u64,
    pub stmts: Vec<LlilStmt>,
}

/// A lifted function represented in LLIL.
#[derive(Debug, Clone)]
pub struct LlilFunction {
    pub name: String,
    pub entry: u64,
    pub exprs: Vec<LlilExpr>,
    pub instructions: Vec<LlilInst>,
}

impl LlilFunction {
    pub fn new(name: String, entry: u64) -> Self {
        Self {
            name,
            entry,
            exprs: Vec::new(),
            instructions: Vec::new(),
        }
    }

    /// Add an expression to the pool and return its index.
    pub fn add_expr(&mut self, expr: LlilExpr) -> ExprId {
        let id = self.exprs.len();
        self.exprs.push(expr);
        id
    }

    /// Add an instruction.
    pub fn add_inst(&mut self, inst: LlilInst) {
        self.instructions.push(inst);
    }

    /// Helper: create a register expression.
    pub fn reg(&mut self, name: &str) -> ExprId {
        self.add_expr(LlilExpr::Reg(name.to_string()))
    }

    /// Helper: create a constant expression.
    pub fn const_val(&mut self, val: u64) -> ExprId {
        self.add_expr(LlilExpr::Const(val))
    }

    /// Helper: create a binary operation expression.
    pub fn binop(&mut self, op: BinOp, left: ExprId, right: ExprId) -> ExprId {
        self.add_expr(LlilExpr::BinOp { op, left, right })
    }

    /// Helper: create a memory load expression.
    pub fn load(&mut self, addr: ExprId, size: u8) -> ExprId {
        self.add_expr(LlilExpr::Load { addr, size })
    }

    /// Helper: create a SIMD vector operation expression.
    pub fn vector_op(
        &mut self,
        kind: VectorOpKind,
        element_type: VectorElementType,
        width: u16,
        operands: Vec<ExprId>,
    ) -> ExprId {
        self.add_expr(LlilExpr::VectorOp {
            kind,
            element_type,
            width,
            operands,
        })
    }
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::UDiv | BinOp::SDiv => "/",
            BinOp::UMod | BinOp::SMod => "%",
            BinOp::FAdd => "+",
            BinOp::FSub => "-",
            BinOp::FMul => "*",
            BinOp::FDiv => "/",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Xor => "^",
            BinOp::LogicalAnd => "&&",
            BinOp::LogicalOr => "||",
            BinOp::Shl => "<<",
            BinOp::Shr | BinOp::Sar => ">>",
            BinOp::CmpEq => "==",
            BinOp::CmpNe => "!=",
            BinOp::CmpLt | BinOp::CmpUlt => "<",
            BinOp::CmpLe | BinOp::CmpUle => "<=",
            BinOp::CmpGt | BinOp::CmpUgt => ">",
            BinOp::CmpGe | BinOp::CmpUge => ">=",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for FlagCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            FlagCondition::E => "==",
            FlagCondition::Ne => "!=",
            FlagCondition::Ult => "<u",
            FlagCondition::Ule => "<=u",
            FlagCondition::Uge => ">=u",
            FlagCondition::Ugt => ">u",
            FlagCondition::Slt => "<",
            FlagCondition::Sle => "<=",
            FlagCondition::Sge => ">=",
            FlagCondition::Sgt => ">",
            FlagCondition::Neg => "neg",
            FlagCondition::Overflow => "overflow",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_simple_function() {
        let mut func = LlilFunction::new("test".into(), 0x1000);
        let rax = func.reg("rax");
        let c42 = func.const_val(42);
        func.add_inst(LlilInst {
            address: 0x1000,
            stmts: vec![LlilStmt::SetReg {
                dest: "rax".into(),
                src: c42,
            }],
        });
        let sum = func.binop(BinOp::Add, rax, c42);
        func.add_inst(LlilInst {
            address: 0x1004,
            stmts: vec![LlilStmt::SetReg {
                dest: "rax".into(),
                src: sum,
            }],
        });

        assert_eq!(func.instructions.len(), 2);
        // Exprs: rax(0), 42(1), add(rax,42)(2) = 3 total
        assert_eq!(func.exprs.len(), 3);
    }

    #[test]
    fn expr_pool_indexing() {
        let mut func = LlilFunction::new("test".into(), 0);
        let a = func.reg("rax");
        let b = func.const_val(10);
        let c = func.binop(BinOp::Add, a, b);
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(c, 2);
        assert_eq!(
            func.exprs[c],
            LlilExpr::BinOp {
                op: BinOp::Add,
                left: 0,
                right: 1,
            }
        );
    }

    #[test]
    fn display_binop() {
        assert_eq!(format!("{}", BinOp::Add), "+");
        assert_eq!(format!("{}", BinOp::Xor), "^");
        assert_eq!(format!("{}", BinOp::Shl), "<<");
    }
}
