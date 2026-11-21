# Merge project edits

sleuthre projects can be merged as text. A JSONL export contains only analyst-authored state
(renames, comments, bookmarks, tags, overlays, and types), so it can live in a Git branch and be
reviewed like code. The GUI performs a semantic three-way merge: it understands record identity,
so two analysts editing different comments do not conflict.

## What you need

- An open project that represents the current branch.
- A JSONL export of the common ancestor.
- A JSONL export of the incoming branch.

The GUI reviews and applies merges, but it does not currently expose an **Export JSONL** command.
Produce the two files with the `re-core` library API (`Project::export_jsonl`) or with tooling that
already emits the format. The [project format reference](../reference/project-format.md) documents
the records and their deterministic ordering.

## Merge in the GUI

1. Open the project that contains your branch's edits.
2. Choose **File → Review JSONL merge…**.
3. Select the **common ancestor** export.
4. Select the **incoming branch** export.
5. Click **Preview merge**.
6. Review the result:
   - **Automatic changes** lists records that changed on only one side, or changed identically on
     both sides.
   - **Conflicts** counts records changed differently on each side. Step through them with
     **Previous** and **Next**, and choose **Current branch** or **Incoming branch** for each.
7. **Apply merge** becomes available when every conflict has a choice. Click it.
8. Save the project to keep the merged state.

The merge is applied directly to the in-memory project and is not added to the undo stack. The
merged state is not written to disk until you save. If you do not want the result, close the
project without saving and reopen the pre-merge project.

## What counts as a conflict

Records are identified by kind and key:

- Comments, bookmarks, and renames by address.
- Tags by address and tag text.
- Struct overlays by address and label.
- Types by type name.

The merge compares three values per key:

| Ancestor | Current | Incoming | Result |
|---|---|---|---|
| A | A | B | Take incoming |
| A | B | A | Take current |
| A | B | B | Take the shared change |
| A | B | C | Conflict |
| A | absent | B | Conflict (one side removed, one changed) |
| A | absent | absent | Remove |

The MCP tool `merge_jsonl_3way` exposes the same algorithm. It returns the merged JSONL plus
conflict counts, but it does not choose sides; the caller must resolve conflicts.

## Conflict records

When `merge_jsonl_3way` cannot resolve a record, the merged JSONL contains a record like:

```json
{"kind":"conflict","key":"comment::4198400","base":"old","left":"current","right":"incoming"}
```

Importers skip unknown record kinds, including `conflict`. The GUI does not write such records;
it applies the choice you make for each conflict.

## Related

- [Project file and JSONL formats](../reference/project-format.md)
- [Collaboration and review model](../explanation/collaboration-and-review.md)
- [MCP server](../reference/mcp-server.md)
