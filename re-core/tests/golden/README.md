# Golden decompiler output

Each `*.txt` file here is the exact pseudocode that `re_core::il::structuring::decompile()`
produces for one hand-assembled x86-64 function. The inputs live in
`re-core/tests/golden_decompile.rs`: small machine-code byte arrays with the
intended assembly written next to them, placed in a `MemoryMap` segment,
disassembled with the real capstone-backed `Disassembler`, then run through the
full decompilation pipeline. There are no fixture binaries — everything is
in-memory and reproducible from the repository alone.

## Cases

| Case | What it pins down |
| --- | --- |
| `arith_return` | straight-line arithmetic on register parameters plus return-value folding |
| `branch_select` | `if`/`else` recovery from a compare-and-branch pair (relational folding) |
| `loop_sum` | back-edge detection and loop structuring |
| `call_args` | call-argument recovery from ABI registers, plus symbol resolution of the callee |
| `field_access` | typeless struct-pointer folding to `base->field_<offset>` at two distinct offsets |
| `stack_locals` | frame-relative local recovery, location-based naming, and stack-slot lifting |

## Running

```sh
cargo test -p re-core --test golden_decompile
```

## Updating

When a decompiler change intentionally alters the output:

```sh
UPDATE_GOLDEN=1 cargo test -p re-core --test golden_decompile
```

This rewrites every golden file with the current output and passes. Review the
resulting `git diff` before committing.

## C compiler gate

`golden_output_is_compilable_c` feeds the golden output (minus `field_access`,
whose synthetic `base->field_<offset>` members stand in for an unrecovered
struct type) to `cc -fsyntax-only`. It skips when no compiler is on `PATH`, so
local runs stay usable, but CI sets `SLEUTHRE_REQUIRE_CC=1`, which turns a
missing compiler into a hard failure. The same switch guards
`il::hlil::tests::generated_c_is_compilable` and
`analysis::recompile_diff::tests::recompile_roundtrips_real_c`, so none of the
three compiler-backed gates can quietly stop running.

## Review policy

**A golden diff in a pull request is a behavior change, not a chore.** These
files are the record of what the decompiler actually emits, so any diff must be
read line by line and justified in the PR description:

- Is the new output *better* pseudocode, or just different?
- Did a case lose a recovered parameter, local, loop, or field access?
- Did previously valid C stop being valid C?

Regenerating with `UPDATE_GOLDEN=1` to make a red test go green, without reading
the diff, defeats the entire purpose of these files. If a diff is unexpected,
the change under review is the suspect — not the golden.

Determinism matters here: the pipeline must emit byte-identical text across
processes, so no output may derive its order from `HashMap`/`HashSet` iteration.
`decompile_is_deterministic_in_process` guards the in-process half of that; the
goldens themselves guard the cross-process half, since every CI run starts with
a fresh hash seed.
