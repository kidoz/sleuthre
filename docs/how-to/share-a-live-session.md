# Share a live session

sleuthre can publish every project mutation over a local TCP connection. The wire format is one
JSON object per line, so a viewer can be as small as `nc`, a script, or another GUI.

## Start the server

1. Open a project.
2. Choose **Tools → Start Collab Server…**.
3. Set a port, or leave `0` to let the operating system choose a free port.
4. Click **Start**.

The server binds to `127.0.0.1` only. A toast and the **Tools** menu show the address it is
listening on, for example `127.0.0.1:54321`. Choose **Tools → Stop Collab Server** to stop
publishing.

## What is published

Every new `UndoCommand` executed by the project is published after the local edit succeeds. That
covers renames, comments, bookmarks, tags, struct candidates, and other undoable mutations. Each
event is one line:

```json
{"kind":"rename","author":"local","seq":7,"payload":{"address":"0x401000","new_name":"parse_header","old_name":"sub_401000"}}
```

| Field | Meaning |
|---|---|
| `kind` | Event type: `rename`, `comment`, `set_local_type`, `add_bookmark`, `remove_bookmark`, `add_tag`, `remove_tag`, `accept_struct_candidate`, `set_candidate_status`, `patch` |
| `author` | Originator label; the GUI publishes local edits as `local` |
| `seq` | Monotonic sequence number assigned by the broadcaster |
| `payload` | Event-specific JSON object |

## What a viewer can send back

A client may write JSON lines back to the server. sleuthre drains them and interprets them as
either proposals or direct synchronization commands:

- `rename`, `comment`, and `set_local_type` become **peer proposals**, appear in **File → Review
  changes…** with the author, and wait for analyst approval.
- Bookmark, tag, and struct-candidate events are applied directly through the undo system.
- `patch` events are published but not applied from inbound clients; there is no remote memory
  patching path in the GUI.

The connection has no authentication and no encryption. Treat it as a same-machine collaboration
channel. Do not expose the port through a proxy or bind it to a public interface.

## Reconnect behavior

The broadcaster accepts any number of viewers and fans out events to all connected clients. A
viewer that connects after an edit does not receive a replay of earlier events; start the server
before the session, or send a snapshot through your own tooling.

Conflict resolution between simultaneous editors is last-writer-wins. For asynchronous work, use
the merge workflow instead: [Merge project edits](merge-project-edits.md).

## Related

- [Collaboration and review model](../explanation/collaboration-and-review.md)
- [MCP and trust boundaries](../explanation/mcp-and-trust.md)
- [Review AI proposals](review-ai-proposals.md)
