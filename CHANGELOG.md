# Changelog

## [Unreleased]

### Fixed

- **ARM64 lifting depth (deep-review follow-ups, part 3).** Pre/post-index
  addressing (`stp x29, x30, [sp, #-16]!`, `ldp x29, x30, [sp], #16`) now
  writes the base register back, so ARM64 prologue/epilogue stack tracking is
  correct; the rewritten memory-operand parser also removes a latent slice
  panic on malformed operand text. Flag-setting ALU forms (`adds`/`subs`/
  `ands`) define the shared flags register, so `subs x2, x0, #1; b.ne` folds
  into a relational expression like `cmp` does — and the fold now invalidates
  itself when a pending flag source's operand is redefined (or a call
  intervenes), so `subs x0, x0, #1; b.ne` falls back to the opaque flag
  variable instead of folding a stale value. `movz` applies its `lsl` shift
  (previously wrong by up to 2^48), and PC-relative literal `ldr` loads the
  value at the printed address instead of the address itself. Zero/sign
  extension is now modeled end-to-end: x86 `movzx`/`movsx`/`movsxd` and ARM64
  `ldrsw` lower to a new MLIL `Cast` expression that survives all dataflow
  passes, folds on constants, and renders as a C cast (`(int8_t)x`).

- **Multi-arch analysis correctness (deep-review follow-ups, part 2).**
  ARM32 conditional branches now lift as real conditional branches with their
  condition mapped to the shared flag vocabulary (they were flattened to
  unconditional jumps), direct branch targets parse capstone's `#0x…` form
  (they previously collapsed to 0), cmp/cmn/tst define the `__flags` register
  MLIL folds on, and `push`/`pop` track the stack pointer with one slot per
  register (`pop {…, pc}` is a return). CFG construction classifies
  ARM/ARM64/RISC-V branch/call/return mnemonics correctly instead of treating
  everything non-x86 as conditional, and indirect unconditional branches no
  longer get a fabricated fall-through edge. MLIL canonicalizes sub-registers
  to their widest alias (`eax`→`rax`, `cl`→`rcx`, `w3`→`x3`) so dead-store
  elimination sees through mixed-width def/use chains and SysV argument
  recovery matches the dominant `mov edi, imm` staging form. ARM64
  shifted-register ALU forms (`add x0, x1, x2, lsl #2`) lift as shift
  expressions instead of disappearing, and all remaining silent instruction
  skips (zero-statement lifts, 1-operand `imul`, unknown ALU arities) become
  explicit `Unimplemented` barriers. Re-analysis no longer overwrites the
  lowest-address function with a fresh `entry_point` stub (user renames and
  detected conventions survive), the x86 stdcall heuristic only considers the
  function's own first `ret` (a neighbor's `ret imm` inside the flat decode
  window no longer reclassifies it), the thiscall/fastcall heuristic ignores
  `push ecx` stack-slot reservations and register zeroing/initialization, and
  the xref scan continues past early returns in multi-exit functions.

- **Untrusted-input and soundness hardening (deep-review follow-ups).**
  Crafted ELF (`p_filesz > p_memsz`) and Mach-O (`filesize > vmsize`) segment
  headers could panic the loader on open; the copies are now clamped to the
  allocation, with adversarial fixtures pinning both. A panic in a background
  analysis worker no longer destroys the open project or wedges the loading
  state (workers catch unwinds and the polls handle a dead worker). The MLIL
  optimization passes are now sound: uses with no known reaching definition
  carry a sentinel version, so dead-store elimination keeps branch-side
  assignments feeding a join and value propagation can no longer rewrite a
  use with a definition that follows it; unlifted instructions survive as an
  `Unimplemented` dataflow barrier (rendered as a pseudocode comment) instead
  of being erased to `Nop`, and the DSE return-register allowlist covers
  ARM32/MIPS/RISC-V/ARM64-w. Rhai script execution is bounded (operation and
  data-size caps) so a runaway console script or plugin can't hang or OOM the
  app. DWARF/PDB type resolution is depth-capped against crafted deep type
  chains (stack-overflow abort), a 9-byte SLEB128 no longer overflows in
  debug builds, and the fuzz-smoke harness now exercises debug-info
  extraction. MCP `save_project` writes are confined to the opened binary's
  workspace and the `.slre` extension.

- **GDB Remote debugger hardening (review follow-ups to 0.6).** A hostile or
  buggy stub could crash the GUI with a char-boundary panic via a non-ASCII
  marker byte in the `qXfer` module-list reply. Resume waits (`c`/`s`) no
  longer inherit the 5-second socket read timeout, so a continue that runs
  longer than that no longer fails spuriously and desynchronizes the protocol
  (the Stop button's unframed `0x03` remains the escape hatch, and the UI now
  polls for the stop reply instead of waiting for an input event). `Z`/`z`
  breakpoint packets send architecture-correct kinds (4 for ARM/AArch64/
  MIPS/RISC-V instead of a hardcoded x86 `1`, which gdbserver rejects).
  Watchpoints can now be removed from the breakpoint list (removal previously
  only tried the execute kinds, leaving `Z2..Z4` armed in the stub). Thread
  enumeration and the backtrace are cached per stop instead of issuing RSP
  round-trips on every rendered frame. A scripted RSP-stub test now covers the
  handshake, breakpoint wire format, and resume replies over a real socket.

### Changed

- **Decompiler quality on 32-bit x86.** Conditional branches are folded back into
  relational expressions (`cmp a,b; jl` → `a < b`; `test eax,eax; je` → `eax == 0`)
  instead of leaking opaque `flag_*` pseudo-variables. Registers, parameters, and
  return values are typed by the target word size (`int32_t` on 32-bit) rather
  than always `int64_t`, and a bare integer literal no longer forces `uint64_t`.
  A LIFO stack simulation reconstructs stack operations: callee-saved
  save/restore boilerplate is elided (removing the `*(sp - 8) = ...` prologue
  noise and its uninitialized reads), `push x; pop reg` materialization folds to
  `reg = x`, and stack-passed (cdecl/stdcall) call arguments are recovered so
  calls render as `f(a, b, c)` instead of orphaned `push` statements. Uses are
  versioned to their reaching definition (a redefined register reads its current
  value, not the stale incoming one); constant/copy propagation with constant
  folding and version-aware dead-store elimination collapse register churn; and
  unreachable code after a `return`/`goto` is pruned. Register-passed call
  arguments are recovered for x86-64 (SysV) and ARM64 (AAPCS), so calls render
  as `f(a, b)` from the argument registers; x86 `thiscall`/`fastcall` callees get
  their implicit `ecx` (`this`) / `ecx`,`edx` arguments recovered from the
  detected calling convention.

## [0.6.0] - 2026-05-31

### Added

- **GDB Remote debugger (roadmap 0.6).** Register and memory writes (`P`/`M`,
  honouring per-register width), shared-library/module enumeration
  (`qXfer:libraries-svr4`), Step Into / Step Over (call-aware) / Step Out, and a
  Stop button that interrupts a running inferior via a socket-sharing handle even
  while a blocking continue runs on a worker thread. Attach-to-PID, local launch
  (spawns and owns a `gdbserver` child on Linux), clickable backtrace frames, and
  a `file:line` source readout at the PC. Per-project saved debug profiles
  (sensitive launch args optionally kept off disk; attach PIDs never persisted).
  RSP reply decoding handles run-length encoding and `}`-escapes.
- **Backward (interprocedural) type inference.** Recovers untyped functions'
  return and parameter types by following values across calls — built on a new IL
  substrate (arch-dispatched lifting, an ABI register model, MLIL call-effect
  modelling, and a def-use index) — iterated to a fixpoint across call chains.
  Inferred signatures are provenance-tagged and shown as lower-confidence in the
  decompiler.
- **CFG switch/jump-table recovery:** indirect `jmp [reg*scale + base]` now yields
  `Switch` edges to recovered (executable) case targets.
- **x86 calling-convention detection** in the pipeline (stdcall via callee
  stack-cleanup; Microsoft x64 vs SysV by binary format), persisted per function.
- **RISC-V (rv32/rv64) ELF loading.**
- Background re-analysis with a cancel button, quick/normal/deep mode presets, and
  command-palette actions.
- A deterministic no-panic fuzz-smoke harness for the untrusted-input parsers.

### Changed

- **Dependency upgrades with API migrations:** egui/eframe 0.33 → 0.34 and
  egui_dock 0.18 → 0.19 (unified `Panel` API, `App::ui` replacing `App::update`);
  gimli 0.31 → 0.33; rusqlite 0.33 → 0.40 (explicit `u64 <-> i64` at the DB
  boundary); plus goblin 0.10, capstone 0.14, object 0.39, petgraph 0.8, rfd 0.17.
- Project files now persist the binary architecture/format, image base, and each
  function's calling convention and stack-frame size; a stamped schema version is
  checked on load and newer files are rejected.
- Removed the legacy mock-debugger UI surfaces; the menu opens the real debugger
  panel. Removed orphaned source files. The CFG is rebuilt with leader-based basic
  blocks so mid-block branch targets split correctly.

### Fixed

- **Decompiler dropped live code:** dead-store elimination keyed on SSA versions
  the (definition-only) SSA pass never matched; it is now name-based.
- **Reopened projects decoded as x86_64:** the architecture/format were not
  persisted.
- PDB symbol addresses were section-relative offsets; they are now mapped to
  virtual addresses via the PDB address map + image base.
- Lifters silently dropped unhandled instructions (MIPS, RISC-V) — now surfaced as
  `Unimplemented`. MIPS `addi`/`addiu` and negative immediates now lift (stack
  prologues), and ARM `movs`/`muls`/`bics`/`lsls` are no longer mangled away.
- Jump-table recovery is restricted to executable targets, and backward type
  inference requires straight-line flow to avoid branch-induced mis-links.
- The `cargo clippy -- -D warnings` gate is green.

### Security

- Hardened untrusted-input parsing (the project's primary safety rule):
  - Fixed an RSP stop-reply char-boundary panic and a PCX out-of-bounds index on
    malformed input.
  - Capped image (`width * height * 4`) and binary-segment allocations, and bounded
    RSP packet size and thread-enumeration rounds against a hostile stub.
  - Validated TGA bit-depth/pixel bounds and segment ordering on load; capped the
    MCP `get_disasm` request count.

## [0.4.0] - 2026-04-20

### Added

- GDB Remote Serial Protocol debugger backend with software/hardware breakpoints, read/write/access watchpoints, multi-thread support, interrupt, and stop-reply parsing
- Debugger panel in the GUI with async continue/step, run-to-cursor, per-thread BP scope, disassembly context menu, and auto-jump to PC on stop
- DWARF `.eh_frame` + `.debug_frame` stack unwinder with frame-pointer fallback, source-line stepping, and per-thread breakpoints
- DWARF location expression evaluator exposed for `.debug_loc` consumers
- Watchpoint stop replies expose the faulting data address and auto-scroll the hex view
- `WatchpointHit` and `StopReason::Watchpoint` in the public debugger API
- Live collaboration broadcaster over TCP with bidirectional `UndoCommand` streaming
- 3-way JSONL merge for git-friendly project collaboration
- JSON-Lines project export for git-friendly diffs
- Rhai plugin discovery, hot-reload, and async runner so scripts never block the UI
- Bundled Rhai example plugins (`rename_alloc_funcs`, `find_xor_loops`) with plugin API README
- Rhai archive, bytecode, and symbol import APIs (`open_archive`, `archive_entries`, `archive_extract`, `disassemble_bytecode`, `import_symbols`)
- FLIRT PAT signature importer
- ARM / Thumb-2 lifter (minimum viable)
- C++ vtable resolution for indirect calls, with `ClassInfo` persisted in SQLite and auto-linked to declared classes
- MSVC pattern recognition analysis pass
- Struct overlay persistence
- Compilable C output from the decompiler, with FP arithmetic rendered using C operators and indirect calls rendered as function-pointer casts
- Recompile-diff harness to verify decompiler semantics
- Cache dependency graph for surgical decomp invalidation
- MCP tools for MLIL, SSA form, IL rewrite, variable uses, source diff, and JSONL merge
- Decompilation cache reused through the MCP `get_decompilation` path
- Data inspector, source compare, and tabular views in the GUI
- Binary Ninja `.bndb` symbol / function rename / comment importer
- Auto-detect PDB sidecar files for PE binaries (embedded path, sibling directory, basename fallback)
- Multi-binary `Workspace` scaffolding (library-only API) with cross-binary symbol and import resolution
- Criterion benchmark harness for analysis hot paths
- Linux and Windows release jobs plus `bench-compile` in CI

### Changed

- `parse_type_str` promoted into `re-core` so scripting and MCP share one parser
- `formats`, `import`, and `vtable` modules wired through the `re-core` public surface
- Class metadata now lives in `TypeManager` alongside other type definitions

### Fixed

- Temporary breakpoints cleared automatically once the debugger stops
- Disassembly view jumps to the current PC when the inferior reports a stop

## [0.3.0] - 2026-03-26

### Added

- Struct inference pass that promotes pointer-to-blob arguments into named structs
- Bundled Win32 and DirectX struct type definitions for better Windows analysis
- `BinaryFile` scripting API exposing raw bytes, sections, and memory ranges to Rhai
- x86 `thiscall` / `fastcall` calling-convention detection
- x87 FPU instruction support in the x86 disassembler and lifter
- macOS ARM64 release job in CI

### Fixed

- Save path consistency across project open/save; the write is now wrapped in a single SQLite transaction
- `cargo fmt` drift across the workspace
- Functions panel layout glitches
- CI tag trigger and release asset upload

### Changed

- Added initial integration tests for `re-gui` and `re-mcp`

## [0.2.0] - 2026-03-23

### Added

- RISC-V architecture support (disassembly + function discovery)
- Global-variable resolution pass that names data references
- Binary diff view and entropy visualization
- Screenshot in README and release badge
- `justfile` with common dev shortcuts

### Changed

- Binary loading moved into a shared pipeline so GUI and CLI share one analysis path
- UI responsiveness improvements (background work off the main thread)
- Analysis performance improvements on the function-discovery hot path
- Graph view refresh

### Fixed

- Disassembler handling of empty/zero-length instruction streams

## [0.1.0-alpha] - 2026-02-17

### Added

- Binary format support: ELF, PE, Mach-O, and raw binaries
- Multi-architecture disassembly: x86, x86_64, ARM, ARM64, MIPS, MIPS64 (via Capstone)
- Function discovery with prologue pattern matching and recursive descent
- Control flow graph construction with basic block identification
- Cross-reference indexing: call, jump, data read/write with bidirectional lookup
- String extraction: ASCII, UTF-16LE, UTF-16BE with configurable minimum length
- Constant detection: CRC32 tables, AES S-boxes, pointer tables
- Basic decompiler with pseudo-C output
- FLIRT-like byte pattern signature matching
- SQLite-backed project persistence (save/load analysis state)
- Desktop GUI (`re-gui`) with egui/eframe:
  - Disassembly, graph, hex, strings, decompiler, imports, exports, structures, call graph views
  - Command bar with fuzzy search (Ctrl+G)
  - Navigation band with visual memory map
  - Function renaming, comments, bookmarks
  - Hex patching
  - Undo/redo
  - Dark/light theme
- MCP server (`re-mcp`) for AI agent integration:
  - 20 tools for binary analysis, annotation, and project management
  - 7 resource endpoints for project state queries
  - AI approval queue for rename suggestions
- CLI tool (`re-cli`) for headless batch analysis
