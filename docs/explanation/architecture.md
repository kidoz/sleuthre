# Architecture

sleuthre is a Cargo workspace with a single analysis engine and three front ends.

```text
re-gui ─┐
re-mcp ─┼──> re-core
re-cli ─┘
```

| Crate | Role | Error style |
|---|---|---|
| `re-core` | Loaders, memory map, disassembly, analysis, IL, decompiler, project database, collaboration, debugger transport | `thiserror` |
| `re-gui` | egui/eframe desktop application | `anyhow` at application boundaries |
| `re-mcp` | JSON-RPC over stdio for MCP clients | `anyhow` at application boundaries |
| `re-cli` | Batch analysis commands | `anyhow` at application boundaries |

The dependency direction is deliberate: `re-core` never depends on a front end, so every engine
feature is testable headlessly and available to all three interfaces.

## Inside `re-core`

| Module | Responsibility |
|---|---|
| `loader` | Detect and map ELF, PE, Mach-O, and raw images into a `MemoryMap` |
| `memory` | Segments, permissions, address lookup, bounded byte search |
| `disasm` | Capstone-backed decoding, endianness, architecture traits |
| `analysis` | Function discovery, CFG, xrefs, strings, constants, vtables, entropy, triage, pipeline |
| `il` | LLIL, MLIL, SSA, HLIL, structuring, per-architecture lifters |
| `project` | Project state, annotations, undo/redo, proposals, review history, JSONL, merge |
| `db` | SQLite persistence for projects |
| `types`, `typelib`, `debuginfo` | Compound types, bundled type libraries, DWARF/PDB extraction |
| `signatures` | FLIRT-style signature database and matching |
| `plugin`, `scripting` | Analysis pass registry, Rhai engine, plugin discovery, worker runner |
| `collab` | Local TCP broadcast of project events |
| `debuggers` | GDB Remote Serial Protocol client |
| `formats` | Archive, image, and bytecode format helpers |

## The project as the center of gravity

Every front end manipulates a `Project`. It owns:

- The memory map and extracted evidence (functions, xrefs, strings, constants, imports, exports).
- Analyst state (names, comments, bookmarks, tags, types, overlays, candidates).
- The undo/redo stacks.
- Pending proposals and review history.
- The saved triage report and the project database handle.

The project database stores the memory map bytes as well as analysis, which is why a `.slre` file
can be reopened without the original executable. It also means a project is a snapshot: reopening
it shows the analysis and annotations that were saved, not a fresh interpretation of the binary.
Use **Re-Analyze** when you want the pipeline to run again.

## Threading model

GUI analysis runs on a background worker so the UI stays responsive. Capstone handles are not
`Send`, so worker code creates its own disassembler instead of sharing one across threads. Per-function IL
lifting and the xref scan use worker threads with per-thread Capstone handles and merge results in
range order to keep output deterministic.

MCP and CLI run analysis synchronously in their own process. The MCP server keeps one project in
memory and processes requests one line at a time.

## Why four crates

Splitting the front ends from the engine keeps binary parsing and analysis free of UI and protocol
dependencies, makes the engine usable in tests and scripts, and lets the CLI and MCP server share
exactly the same loaders, analysis pipeline, and project format as the GUI. The cost is a larger
workspace and a project model that must satisfy all three consumers; the model stays in `re-core`
rather than leaking into each front end.

## Related

- [Analysis pipeline](analysis-pipeline.md)
- [IL and decompiler](il-and-decompiler.md)
- [MCP and trust boundaries](mcp-and-trust.md)
