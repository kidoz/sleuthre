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
