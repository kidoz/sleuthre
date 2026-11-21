# IL and decompiler

The decompiler is a multi-stage pipeline that lifts machine instructions into progressively
higher-level representations. Each stage exists so the next one can reason about a smaller,
more regular language.

```text
machine code
   │  Capstone
   ▼
disassembly
   │  per-architecture lifter
   ▼
LLIL   low-level IL: registers, memory, flags, calls
   │  canonicalization and lowering
   ▼
MLIL   medium-level IL: sub-registers widened, flags folded into expressions
   │  use versioning and dataflow
   ▼
SSA    definition/use chains
   │  structuring, typing, folding
   ▼
HLIL / pseudocode
```

## LLIL

LLIL represents each instruction as explicit reads, writes, memory operations, arithmetic, and
control flow. Architecture-specific lifters (`lifter_x86`, `lifter_arm`, `lifter_arm64`,
`lifter_mips`, `lifter_riscv`) translate Capstone mnemonics and operands into this form.

## MLIL

MLIL normalizes the machine-specific noise:

- Sub-registers are canonicalized to their widest alias (`eax` → `rax`, `cl` → `rcx`) so a
  definition in one width is visible to a use in another.
- Condition flags are folded into relational expressions, so `cmp a, b; jl` becomes `a < b`
  rather than an opaque flag pseudo-variable.
- Zero- and sign-extension operations become explicit casts.
- Register-passed call arguments are recovered according to the ABI.

## SSA and dataflow

Uses are versioned to their reaching definitions. This enables:

- Constant and copy propagation with folding.
- Dead-store elimination that understands mixed-width def/use chains.
- Recovering parameters from registers that are read before being written.
- Pruning unreachable code after returns and unconditional jumps.

Stack simulation reconstructs pushes and pops, elides callee-saved save/restore boilerplate, and
turns stack-passed arguments into call arguments.

## Structuring and typing

The HLIL stage rebuilds structured control flow (if/else, loops, switch) and renders C-like
expressions. Type information comes from several places:

- Debug information: function signatures, locals, globals, and source types.
- Bundled type libraries for Win32, DirectX, and libc.
- Inferred signatures from call-flow analysis.
- Struct-pointer inference: repeated accesses at stable offsets produce `base->field_<offset>`
  candidates with recorded evidence.
- User-defined structs and overlays.

Virtual dispatch resolution runs before field folding. If field folding ran first, it would rewrite
the vtable load into a synthetic field access and the resolver would no longer recognize the
pattern.

## Cache invalidation

Decompiled functions are cached in the project. The cache tracks dependencies between annotations
(renames, types, comments) and functions, so an edit invalidates only the functions that depend on
it. The cache version is stored in project metadata; changing the decompiler output format bumps
the version and discards incompatible entries on load.

## Recompile-diff

`diff_against_source` closes a different loop: it writes the decompiled C for a function to a
temporary `.c` file, compiles it with the system C compiler, disassembles the resulting object,
and compares instruction-category histograms with the original function.

The result includes:

- Original and recompiled histograms (call, branch, return, memory, arithmetic, move, compare,
  other).
- Per-category deltas and an L1 norm.
- A divergence ratio normalized by the original function size.
- The artifact path and compiler stderr.

This measures instruction mix, not semantic equivalence. A zero divergence is encouraging; a
nonzero value locates where the recompiled code differs in shape. It requires `cc` on `PATH`.

## Known limits

- Unsupported instructions may lower to opaque IL and render as placeholders.
- Unresolved indirect jumps can shorten a recovered function; unreachable code after them may be
  pruned.
- High-level structuring is heuristic; complex switch/loop shapes can produce gotos.
- Type inference is evidence-based and can leave variables at word-sized defaults.

## Related

- [Analysis pipeline](analysis-pipeline.md)
- [Use debug symbols](../how-to/use-debug-symbols.md)
- [MCP server](../reference/mcp-server.md)
