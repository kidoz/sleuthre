# sleuthre

[![GitHub release](https://img.shields.io/github/v/release/kidoz/sleuthre?include_prereleases)](https://github.com/kidoz/sleuthre/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

An open-source reverse engineering desktop application built in Rust.

![sleuthre](docs/screenshots/main.png)

## Features

- **Binary format support** — ELF and PE loaders with automatic format detection
- **Multi-architecture disassembly** — x86, x86_64, ARM, ARM64, MIPS, MIPS64 (via Capstone)
- **Function discovery** — entry point analysis and heuristic-based detection (prologue patterns)
- **Control flow graphs** — basic block identification, CFG construction, layered graph layout
- **Cross-references** — call, jump, data read, and data write xrefs with bidirectional indexing
- **String extraction** — ASCII and UTF-16LE with configurable minimum length
- **Constant detection** — CRC32 tables, AES S-boxes, pointer tables
- **Basic decompiler** — pseudo-C code generation from disassembly
- **Project persistence** — SQLite-backed database for saving/loading analysis state
- **MCP server** — headless JSON-RPC interface for AI agent integration
- **AI approval queue** — review and approve AI-suggested renames and comments

## Architecture

The project is a Cargo workspace with three crates:

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
| `open_binary` | Load an ELF/PE binary for analysis |
| `get_disasm` | Get disassembly listing at an address |
| `get_xrefs` | Get cross-references (to/from/both) |
| `get_cfg` | Get control flow graph for a function |
| `get_strings` | Get discovered strings (with filter) |
| `submit_rename` | Propose a function rename (requires approval) |
| `add_comment` | Add or remove a comment at an address |
| `save_project` | Save the current project to a file |

Resources are available at `sleuthre://project/{functions,strings,xrefs,comments}`.

## License

Licensed under the [MIT License](LICENSE).
