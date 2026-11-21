# sleuthre

[![GitHub release](https://img.shields.io/github/v/release/kidoz/sleuthre)](https://github.com/kidoz/sleuthre/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

An open-source reverse engineering desktop application built in Rust.

![sleuthre](docs/screenshots/main.png)

## Features

### Analysis engine
- **Loaders** — ELF, PE, Mach-O (single + fat), raw binary; archive/image/bytecode plugin formats
- **Architectures** — x86, x86-64, ARM, ARM64, ARM Thumb-2, MIPS, MIPS64, RISC-V (RV32/RV64) via Capstone
- **Function discovery** — entry-point + recursive descent + prologue heuristics
- **Control flow graphs** — basic-block recovery, switch-table reconstruction, layered layout
- **Cross-references** — bidirectional indexes for calls/jumps/data/string refs
- **Strings + constants** — ASCII / UTF-16LE / UTF-16BE; CRC32 / AES S-box / pointer tables
- **MSVC pattern recognition** — SEH frame setup, FPO prologues, inline `rep movs/stos`
- **VTable recovery** — auto-link discovered vtables to declared C++ classes; resolve `obj->Method()` in decompiled output
- **Type intelligence** — DWARF + PDB parsers, Win32 / DirectX / libc type libraries, struct inference

### Decompiler
- **Compilable C output** — typed dereferences, function-pointer casts on indirect calls, SSE/AVX intrinsic calls instead of placeholders, switch-default `break;`, return-type fall-through guard. The emitted text passes `cc -fsyntax-only -std=c11` (verified by integration test).
- **Recompile-diff** — `analysis::recompile_diff` writes the decomp output to a temp `.c`, runs `cc -c`, disassembles the result, and reports per-category instruction divergence vs. the original. Closes the loop on "did the decompilation preserve semantics?" — no commercial RE tool ships this.
- **Surgical cache invalidation** — annotation-driven dependency graph invalidates only the affected functions on a rename or type edit; full clears are gone.

### Collaboration & automation
- **Live broadcast collab** — TCP listener publishes every `UndoCommand` as line-delimited JSON; viewers can also send events back (bidirectional). Tools menu exposes start/stop.
- **Git-friendly project format** — `Project::export_jsonl` emits deterministic JSON-Lines for renames/comments/bookmarks/tags/overlays/types; `merge_jsonl_3way` performs a semantic 3-way merge with conflict markers for async PR-based RE.
- **Three-way JSONL merge** — open **File → Review JSONL merge…** and select the common ancestor and incoming exports. The open project is the current branch. Inspect automatic changes, choose a branch for each conflict, then apply or cancel. Save the project to keep the merged edits.
- **MCP server** — first-party Model Context Protocol implementation with 26 typed tools (triage reports, disasm, decomp, MLIL/SSA dumps, IL rewrite, recompile-diff, JSONL merge, signature scans, …) and 7 resources for AI agent integration.
- **Plugins** — Rhai scripts hot-reloaded from `~/.sleuthre/plugins/`; async worker thread runs scripts without blocking the UI; FLIRT PAT importer for community signature corpora.
- **GDB Remote Serial Protocol debugger** — connects to gdbserver / QEMU-gdbstub / LLDB platform via `GdbRemoteDebugger`; attach / step / continue / read registers + memory.
- **Review changes** — review incoming peer renames, comments, and local type suggestions alongside proposals from MCP and local analysis. The project retains accepted and rejected decisions.

### Project persistence
- SQLite-backed (`*.slre`) with full round-trip for functions, comments, xrefs, strings, types, classes, struct overlays, bookmarks, tags, and decompilation cache.

## Documentation

The user documentation is in [`docs/`](docs/README.md) and is organized by what you need:

- **Tutorials** — guided lessons, starting with [Your first analysis](docs/tutorials/first-analysis.md)
- **How-to guides** — task recipes for analysis, collaboration, plugins, and debugging
- **Reference** — CLI commands, MCP tools, GUI shortcuts, project formats, and supported architectures
- **Explanation** — architecture, the analysis pipeline, the decompiler, and the review model

## Architecture

The project is a Cargo workspace with four crates:

| Crate | Description |
|-------|-------------|
| **re-core** | Analysis engine — binary loaders, disassembly, CFG, cross-references, string/constant detection, decompiler, SQLite project database |
| **re-gui** | Desktop UI built with egui/eframe — disassembly, graph, hex, strings, and pseudocode views |
| **re-mcp** | Headless MCP server (JSON-RPC over stdio) for AI agent integration |
| **re-cli** | Headless CLI tool for batch binary analysis |

## Building

```sh
cargo build
```

## Running

```sh
# Desktop GUI
cargo run -p re-gui

# MCP server (JSON-RPC over stdio)
cargo run -p re-mcp

# CLI batch analysis
cargo run -p re-cli -- --help

# Export a repeatable JSON report for an executable
cargo run -p re-cli -- triage path/to/binary > report.json
cargo run -p re-cli -- triage path/to/binary --format markdown > report.md

# Map two file slices and inspect the layout without decoding instructions
cargo run -p re-cli -- raw re-core/tests/fixtures/two-regions.raw --arch mips \
  --region low:0:4:0x1000 --region high:4:4:0x8000 --byte-order little --entry 0x8001 --count 0

# Export the same raw mapping as Markdown (omit --format for JSON)
cargo run -p re-cli -- triage re-core/tests/fixtures/two-regions.raw --arch mips \
  --region low:0:4:0x1000 --region high:4:4:0x8000 --byte-order little --entry 0x8001 --format markdown
```

## Testing

```sh
cargo test
```

## Linting & Formatting

```sh
cargo clippy -- -D warnings
cargo fmt --check
```

## GUI

The desktop UI provides:

- **Disassembly view** — address, bytes, mnemonic, operands with inline comments
- **Graph view** — control flow graph with Bezier curve edges and back-edge highlighting
- **Triage** — open an executable, choose **Windows → Triage**, and select a finding to highlight its bytes in Hex View. Export JSON or Markdown from this tab. The report describes the original executable at load time.
- **Hex view** — traditional hex dump with ASCII column
- **Strings view** — filterable string table with encoding and length info
- **Pseudocode view** — decompiled C-style output
- **Functions panel** — searchable function list with jump-to navigation
- **Navigation band** — visual memory map with color-coded segments

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `F5` | Decompile current function |
| `Space` | Show control flow graph |
| `N` | Rename symbol at cursor |
| `;` | Add/edit comment at cursor |
| `X` | Show cross-references |

## MCP Server

The MCP server exposes tools for AI agents to interact with a loaded binary:

| Tool | Description |
|------|-------------|
| `open_binary` | Open an ELF, PE, or Mach-O file by path. Supply `raw` to map a raw image. |
| `get_triage_report` | Return the opened binary’s report as text. The optional `format` accepts `json` (default) or `markdown`. The MCP response supports reports up to 8 MiB. |
| `get_disasm` | Get disassembly listing at an address |
| `get_xrefs` | Get cross-references (to/from/both) |
| `get_cfg` | Get control flow graph for a function |
| `get_strings` | Get discovered strings (with filter) |
| `submit_rename` | Propose a function rename (requires approval) |
| `add_comment` | Propose adding or removing a comment |
| `rewrite_il` | Propose a local variable type |
| `save_project` | Save the analysis and pending proposals to a project file |

For a raw image, pass `open_binary` arguments like the following. Offsets and lengths are in bytes. Omitting `byte_order` uses the architecture’s default. Omitting `entry_point` uses the first supplied region’s virtual start.

```json
{
  "path": "re-core/tests/fixtures/two-regions.raw",
  "raw": {
    "arch": "mips",
    "byte_order": "little",
    "entry_point": 32769,
    "regions": [
      {"name": "low", "file_offset": 0, "length": 4, "start": 4096},
      {"name": "high", "file_offset": 4, "length": 4, "start": 32768}
    ]
  }
}
```

To review MCP proposals, call `save_project` with a new `.slre` filename and open that file in the GUI. Approve or reject each edit in the review window, then save the project. Use **File → Review changes…** to see pending proposals and the saved decision history.

Resources are available at `sleuthre://project/{functions,strings,xrefs,comments,imports,exports,bookmarks}`.

## License

Licensed under the [MIT License](LICENSE).
