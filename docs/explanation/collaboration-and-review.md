# Collaboration and review model

sleuthre separates evidence derived from a binary from state authored by analysts and tools. That
separation is what makes review, undo, text-based merging, and live collaboration possible without
turning every operation into a special case.

## Two kinds of state

| Evidence | Analyst state |
|---|---|
| Segments and bytes | Function renames |
| Functions and sizes | Comments |
| Cross-references | Bookmarks and tags |
| Strings and constants | Types, struct overlays, and candidates |
| Imports and exports | Review decisions |

Evidence is produced by the analysis pipeline. Analyst state is produced by the GUI, scripts, the
MCP server, or a peer session. Most mutations go through the project's undo/redo machinery; bulk
operations such as applying a merge write directly to project state.

A saved `.slre` contains both. Reopening it restores the analysis and annotations exactly; it does
not re-run the pipeline. **Re-Analyze** regenerates evidence while preserving analyst state where
the model allows it.

## Proposals

Not every producer is allowed to change analyst state directly. MCP tools that rename functions,
change comments, or set local variable types enqueue a `PendingAction` instead:

```text
id, kind, rationale, confidence, origin
```

Origin is one of:

- `Analysis` — produced by an analysis pass.
- `Mcp` — queued by an MCP mutation tool.
- `Peer(name)` — received from a live-collaboration client.
- `Unknown` — legacy or unclassified.

The review window shows the target, the current value, the proposed value, the origin, and the
rationale. Approving applies the change through the undo system; rejecting records the decision
without touching the project. Both outcomes are appended to `review_history` with the value before
the decision and the value actually applied.

This model gives an analyst a single place to inspect every external suggestion. It also means a
saved project is a complete review record: reopening it shows pending proposals and past
decisions.

The queue is bounded at 1024 pending actions. A full queue rejects new proposals instead of
growing without limit.

## Concurrent saves

A project remembers the revision UUID it loaded or last wrote. Before overwriting an existing
database, saving compares that value with the file on disk. If another process saved in between,
the save is refused with an instruction to reopen or save a copy. This is optimistic concurrency
control: it does not merge concurrent writes, it prevents one from silently destroying the other.

## Text-based collaboration

The JSONL export exists so analyst state can live in Git:

- Records are keyed and sorted deterministically.
- Only analyst-authored state is exported; binary bytes and derived evidence stay in `.slre`.
- A three-way merge understands record identity, so non-overlapping edits merge cleanly.
- Divergent edits on the same key become explicit conflicts for an analyst to resolve.

The intended workflow is asynchronous review: one analyst exports a branch, another merges the
ancestor and incoming exports, resolves conflicts in the GUI, and saves the merged project. The
current GUI can perform the merge but does not yet expose an Export JSONL command; exports are
produced through the library API until that UI path exists.

## Live collaboration

The live server broadcasts project mutations as line-delimited JSON over a loopback TCP socket.

- Outbound events describe undoable commands.
- Inbound rename, comment, and type events become peer proposals.
- Inbound bookmark, tag, and candidate events are applied directly.
- There is no replay for late joiners.
- Conflict resolution is last-writer-wins.

Live collaboration is a session channel, not a synchronization protocol. For work that must
survive disconnects or be reviewed asynchronously, use JSONL exports and the three-way merge.

## Related

- [Review AI proposals](../how-to/review-ai-proposals.md)
- [Merge project edits](../how-to/merge-project-edits.md)
- [Share a live session](../how-to/share-a-live-session.md)
- [Project file and JSONL formats](../reference/project-format.md)
