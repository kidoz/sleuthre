# MCP server

`re-mcp` is a headless Model Context Protocol server. It speaks JSON-RPC 2.0 over stdin/stdout,
one JSON object per line, and keeps a single analyzed project in memory.

```sh
cargo run -p re-mcp
```

The server does not open a network port. Configure your MCP client to launch the command and
exchange line-delimited messages on its standard streams.

## Protocol

| Method | Behavior |
|---|---|
| `initialize` | Returns protocol version `2024-11-05`, tool and resource capabilities, and server name `sleuthre-core` |
| `notifications/initialized` | Ignored |
| `tools/list` | Returns the 26 tools below with JSON schemas |
| `tools/call` | Invokes a tool by name |
| `resources/list` | Returns the seven project resources |
| `resources/read` | Reads one resource by URI |

Unknown methods return JSON-RPC error `-32601`. Malformed JSON returns `-32700`.

A minimal exchange:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_binary","arguments":{"path":"/absolute/path/to/sample.exe"}}}
```

## Tools

Address and count parameters are JSON numbers. Except where noted, a tool returns a JSON result in
a text content block; tools that produce text return that text directly.

### Loading and saving

| Tool | Parameters | Behavior |
|---|---|---|
| `open_binary` | `path` (required), `raw` (optional) | Loads ELF, PE, Mach-O, or a raw image and runs normal analysis. Replaces any previously open project. |
| `save_project` | `path` (required) | Saves the project. The path must end in `.slre` and resolve inside the opened binary's directory. |
| `get_triage_report` | `format` (`json` or `markdown`, default `json`) | Returns the original report captured at load time. Reports over 8 MiB are rejected. |

The raw mapping object accepted by `open_binary` is:

```json
{
  "arch": "mips",
  "byte_order": "little",
  "entry_point": 32769,
  "regions": [
    {"name": "low", "file_offset": 0, "length": 4, "start": 4096},
    {"name": "high", "file_offset": 4, "length": 4, "start": 32768}
  ]
}
```

`arch` and at least one region are required. `byte_order` defaults to the architecture's order;
`entry_point` defaults to the first region's virtual start.

### Disassembly and control flow

| Tool | Parameters | Returns |
|---|---|---|
| `get_disasm` | `address`, `count` (default 10, max 1000) | Instruction listing at the address |
| `get_cfg` | `address` | `{"blocks":[{"start","end","instruction_count"}],"edge_count":N}` for the function starting at the address |
| `get_decompilation` | `address` | C-like pseudocode text for the function starting at the address |
| `get_microcode` | `address`, `tier` (`llil` or `mlil`, default `mlil`) | Textual IL for the function starting at the address |
| `get_ssa_form` | `address` | Array of SSA variables (`name`, `version`) used by the function starting at the address |
| `get_variable_uses` | `address`, `variable`, `version` (optional) | SSA variables filtered by name and optional version |

`get_cfg` builds blocks starting at `address` and returns `-32002` if construction fails.
`get_decompilation`, `get_microcode`, `get_ssa_form`, and `get_variable_uses` look up the function
by its start address and return `-32004` when no function starts there.

### Analysis data

| Tool | Parameters | Returns |
|---|---|---|
| `get_xrefs` | `address`, `direction` (`to`, `from`, `both`; default `both`) | Array of `{from,to,type,direction}` |
| `get_strings` | `filter` (substring), `limit` (default 100) | Discovered strings |
| `get_imports` | `filter` (substring) | Imported functions |
| `get_exports` | `filter` (substring) | Exported functions |
| `search_memory` | `pattern` (hex bytes with `??` wildcards), `limit` (default 50, max 1000) | Array of matching addresses |
| `detect_patterns` | none | Runs built-in x86-64 signatures and applies matching names |
| `run_analysis_passes` | none | Runs the built-in suspicious-name pass and returns findings |
| `get_bookmarks` | none | Array of `{address,note}` |
| `add_bookmark` | `address`, `note` (optional) | Adds or replaces a bookmark in memory |
| `get_function_signature` | `address` | Typed signature when debug info or a type library provides one |
| `get_source_line` | `address` | Source file and line when line info is loaded |

`detect_patterns` and `load_pdb` modify the in-memory project directly; they are not reviewable
proposals. `add_bookmark` is also direct. Everything else in the mutation group below is queued
for review.

### Symbol and debug information

| Tool | Parameters | Behavior |
|---|---|---|
| `load_pdb` | `path` | Loads a PDB, adds its types, signatures, globals, and locals, and renames functions that still have `sub_` names |
| `get_source_line` | `address` | Returns source file/line information if present |
| `get_function_signature` | `address` | Returns the typed signature if present |

`load_pdb` uses the opened image's architecture and load base. A mismatched PDB loads mostly
nothing rather than failing.

### Proposals (require GUI approval)

| Tool | Parameters | Proposal |
|---|---|---|
| `submit_rename` | `address`, `name`, `rationale` (default `AI Suggestion`) | Rename a function |
| `add_comment` | `address`, `text` | Add or replace a comment; empty text removes it |
| `rewrite_il` | `function`, `variable`, `type` | Set a local variable's type |

Each successful call queues a pending action and returns a message telling the caller to save the
project and review it in the GUI. The queue holds up to 1024 pending actions.

### Verification and merge

| Tool | Parameters | Returns |
|---|---|---|
| `diff_against_source` | `address` | Recompiles the decompiled C with the system C compiler and returns original/recompiled instruction-category histograms, per-category deltas, `l1_norm`, `divergence_ratio`, the artifact path, and compiler stderr |
| `merge_jsonl_3way` | `base`, `left`, `right` (JSONL strings) | `{"merged","conflicts","left_adds","right_adds","shared_changes"}` |

`diff_against_source` requires a C compiler on `PATH` (it looks for `cc`). It measures instruction
mix, not semantic equivalence.

`merge_jsonl_3way` does not resolve conflicts. The merged text contains `kind:"conflict"` records
for divergent edits. See [Merge project edits](../how-to/merge-project-edits.md).

## Resources

| URI | Contents |
|---|---|
| `sleuthre://project/functions` | All functions |
| `sleuthre://project/strings` | All discovered strings |
| `sleuthre://project/xrefs` | All cross-references |
| `sleuthre://project/comments` | Address-to-comment map |
| `sleuthre://project/imports` | Imported functions |
| `sleuthre://project/exports` | Exported functions |
| `sleuthre://project/bookmarks` | Address/note pairs |

Resources return `application/json` text. Missing or unopened projects return error `-32000`.

## Limits and errors

| Condition | Error code |
|---|---|
| Parse failure | `-32700` |
| Unknown method, tool, or resource | `-32601` |
| Invalid or missing parameter | `-32602` |
| No project loaded | `-32000` |
| Binary could not be opened | `-32001` |
| Internal analysis or disassembly failure | `-32002` |
| Save or proposal-queue failure | `-32003` |
| No function at the requested address | `-32004` |
| PDB load failure | `-32005` |
| Analysis pass failure | `-32006` |

Additional limits: `get_disasm` count at most 1000, `search_memory` limit at most 1000,
`get_triage_report` output at most 8 MiB, and 1024 pending proposals.

## Related

- [Review AI proposals](../how-to/review-ai-proposals.md)
- [MCP and trust boundaries](../explanation/mcp-and-trust.md)
- [Triage report](triage-report.md)
