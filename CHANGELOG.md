# Changelog

## [0.4.0] - 2026-04-20

### Added

- Auto-detect PDB sidecar files for PE binaries (embedded path, sibling `.pdb`, basename fallback)
- Per-thread breakpoint scope toggle in the debugger panel
- Run-to-cursor from the decompiler and disassembly views
- Watchpoint stop replies expose the faulting data address and auto-scroll the hex view
- `WatchpointHit` and `StopReason::Watchpoint` in the public debugger API
- Bundled Rhai example plugins (`rename_alloc_funcs`, `find_xor_loops`) with plugin API README
- Binary Ninja `.bndb` symbol / function rename / comment importer
- DWARF location expression evaluator exposed for `.debug_loc` consumers
- Multi-binary `Workspace` scaffolding (library-only API) with cross-binary symbol and import resolution

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
