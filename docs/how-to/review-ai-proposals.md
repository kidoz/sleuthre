# Review AI proposals

MCP clients can suggest renames, comments, and local variable types, but they cannot apply them.
Every mutation tool queues a pending proposal. An analyst approves or rejects it in the GUI, and
the decision is retained in the project.

## What can be proposed

| MCP tool | Proposal |
|---|---|
| `submit_rename` | Rename a function at an address |
| `add_comment` | Add or replace a comment; an empty `text` proposes removal |
| `rewrite_il` | Set the type of a named local variable in a function |

Most tools are read-only. `add_bookmark`, `detect_patterns`, and `load_pdb` change the in-memory
project directly; `add_bookmark` reaches a file only when the project is saved. The three tools
below always enqueue proposals instead.

## Walkthrough

### 1. Open the binary in the MCP server

Start the server and keep its stdin and stdout connected to your MCP client:

```sh
cargo run -p re-mcp
```

Send an `open_binary` request. Use an absolute path:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_binary","arguments":{"path":"/absolute/path/to/sample.exe"}}}
```

### 2. Submit proposals

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"submit_rename","arguments":{"address":4198400,"name":"parse_header","rationale":"Matches the error string it references"}}}
```

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add_comment","arguments":{"address":4198400,"text":"Validates the file magic before parsing"}}}
```

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"rewrite_il","arguments":{"function":4198400,"variable":"var_18","type":"uint32_t"}}}
```

Each successful call returns a message saying the change was queued. The queue is capped at 1024
pending proposals; a full queue returns an error.

### 3. Save a project for review

```json
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"save_project","arguments":{"path":"sample-review.slre"}}}
```

The save path must end in `.slre` and must stay inside the directory of the opened binary. A
relative path is resolved against that directory; an absolute path is accepted only if it is under
the same directory. This keeps an MCP client from overwriting arbitrary files.

### 4. Approve or reject in the GUI

1. Choose **File → Load Project…** and open `sample-review.slre`.
2. Choose **File → Review changes…**.
3. The **Pending changes** section lists every proposal with its target, current value, proposed
   value, origin, and rationale.
4. Click **Approve** or **Reject** for each one.

Approved edits go through the normal undo stack, so they can be undone after review. Rejected
proposals never change the project. Both decisions are appended to the **Review history** section
with the value that existed before the decision and the value that was applied, if any.

### 5. Save the reviewed project

Choose **File → Save Project…** to keep the approved edits and the review history. If an external
process changed the file on disk after you loaded it, the save is refused with a message asking
you to reopen the project or save a separate copy. That revision check prevents silently
overwriting a newer project.

## Proposal origins

The review window labels where a proposal came from:

- **MCP** — queued by an MCP mutation tool.
- **Local analysis** — produced by an analysis pass.
- **Peer · name** — received from an inbound live-collaboration event.

The origin is stored with the proposal and appears in the saved review history.

## Related

- [MCP server](../reference/mcp-server.md)
- [Collaboration and review model](../explanation/collaboration-and-review.md)
- [MCP and trust boundaries](../explanation/mcp-and-trust.md)
