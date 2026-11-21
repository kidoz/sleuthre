# MCP and trust boundaries

sleuthre processes hostile inputs. Binaries are untrusted, MCP clients are semi-trusted, and user
scripts are trusted. The design applies different controls to each.

## Trust levels

| Input | Trust | Control |
|---|---|---|
| Binary bytes | Untrusted | Bounds checks, size limits, panic containment in the GUI worker |
| MCP client requests | Semi-trusted | Proposals for analyst state, confined save paths, output limits |
| Live collaboration peers | Semi-trusted | Loopback-only binding, peer proposals for edits, no authentication |
| User Rhai scripts | Trusted | Execution limits only; local code with application privileges |
| PDB and symbol files | Semi-trusted | Path restrictions, bounded parsing |

## Binary handling

The loader and parsers treat every field as hostile:

- Segment and section sizes are checked against the file and against allocation limits before
  memory is reserved.
- Offsets and lengths are validated before slicing.
- Disassembly and memory searches operate on the mapped address space and stop at unmapped
  addresses.
- The GUI runs analysis on a worker and catches panics so a malformed input cannot wedge the
  interface.

This is defensive parsing, not a sandbox. The analysis engine runs in-process with the user's
privileges. A bug in a parser is still a bug; the goal is to make malformed input fail closed and
predictably.

## MCP boundaries

The MCP server has no network listener. It exchanges one JSON object per line on stdin/stdout, so
its reach is limited to the process that launched it and the files that process can read.

Mutation tools are deliberately uneven:

| Tool | Effect |
|---|---|
| `submit_rename`, `add_comment`, `rewrite_il` | Queue a proposal; requires GUI approval |
| `save_project` | Writes a `.slre` inside the opened binary's directory |
| `add_bookmark` | Changes the in-memory project directly |
| `detect_patterns`, `load_pdb` | Apply names/types directly in memory |

The proposal tools cover the edits most likely to be wrong or misleading. Bookmark and pattern
operations are lower-risk or reversible through normal project handling.

### Save path confinement

`save_project` is the only MCP tool that writes a file. It enforces two rules:

1. The target extension must be `.slre`.
2. The resolved parent directory must be inside the directory of the opened binary.

Relative paths resolve against the binary directory. The parent is canonicalized before the
containment check, which closes `..` and symlink escapes. An absolute path outside the workspace is
rejected. A misbehaving client can therefore write project files next to the sample, but not
overwrite arbitrary files the server process can reach.

### Output limits

| Limit | Value | Why |
|---|---|---|
| Triage report | 8 MiB | Prevents a tool response from exhausting client memory |
| Disassembly count | 1000 instructions | Bounds a single response |
| Memory search results | 1000 matches | Bounds a single response |
| Pending proposals | 1024 | Bounds review state growth |

Limits apply to the MCP boundary. The CLI can export a larger triage report directly to a file.

### Direct mutations

`detect_patterns` renames matching functions and `load_pdb` installs signatures and types. These
are MCP tools rather than proposals because they mirror analysis-stage behavior: they apply a
credible external source and are visible in the project immediately. If a session needs a
reviewable record of every change, save before calling them and compare the resulting project.

### PDB path handling

Automatic sibling-PDB discovery only accepts a plain file name. It refuses paths, links,
directories, and device names, then reads the candidate as a regular file. Explicit `load_pdb`
accepts a path from the client, so an MCP client can point at any PDB the server can read; the
parsed content still has to match the image's architecture and load base to be useful.

## Live collaboration exposure

The live server binds to `127.0.0.1`. It has no authentication, encryption, or authorization, and
any local process that can reach the port can connect and send events. Peer edits arrive as
proposals, but bookmark/tag events apply directly. Treat the port as a same-machine convenience,
do not proxy it, and stop the server when the session ends.

## Script exposure

The Rhai console can read arbitrary files (`open_binary`, `open_archive`, `archive_extract`,
`parse_symbol_file`, `import_symbols`) and the plugin runner can push renames and comments. Both
are intended for analyst-authored code. Only run scripts you trust.

## Operational guidance

- Open untrusted samples in the GUI or CLI, not in a privileged environment.
- Keep the MCP server scoped to the sample directory; its save confinement assumes that workspace.
- Use proposals for AI-generated edits and review them before saving.
- Do not expose the collaboration port beyond loopback.
- Prefer the plugin runner for scripts that only need the project snapshot; prefer the console only
  for trusted analysis automation.

## Related

- [Architecture](architecture.md)
- [Collaboration and review model](collaboration-and-review.md)
- [MCP server](../reference/mcp-server.md)
- [Review AI proposals](../how-to/review-ai-proposals.md)
