# Changelog

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
