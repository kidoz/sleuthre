# Project file and JSONL formats

sleuthre has two persistence formats:

- `.slre` — a self-contained SQLite project database.
- JSONL — a deterministic text export of analyst-authored state, used for diffs and three-way
  merges.

## The `.slre` project

A project file is a SQLite database. It stores the mapped bytes and the analysis results, so
reopening a project does not require the original executable.

### What it contains

| Table | Contents |
|---|---|
| `metadata` | Schema version, revision guard, pending proposals, review history, decompiler cache version, last viewed address |
| `segments` | Segment names, starts, sizes, permissions, and bytes |
| `functions` | Start address, name, end address, calling convention, stack-frame size |
| `comments`, `bookmarks`, `tags` | Analyst annotations |
| `xrefs` | From/to addresses and reference kind |
| `strings`, `constants` | Extracted evidence |
| `imports`, `exports`, `symbols` | Linkage information |
| `user_types`, `type_annotations`, `classes` | Compound types, annotations, class metadata |
| `function_signatures`, `global_variables`, `local_variables`, `source_lines` | Debug-info and type information |
| `struct_overlays`, `struct_candidates` | Struct overlays and inference evidence |
| `decompilation_cache` | Cached pseudocode and its dependency metadata |
| `debug_profiles` | Saved debugger connection profiles |

The current database schema version is 1. A project written by a newer schema is rejected instead
of being partially read.

### Saving

- **Save Project…** writes the project through a single transaction: the existing data is cleared
  and reinserted, and a mid-save error leaves the previous content intact.
- A save that must not overwrite an existing file (`save_new`, used by MCP saves and autosave
  recovery files) uses `create_new` and, on Unix, mode `0600`.
- Each save writes a new revision UUID. Before overwriting an existing database, sleuthre compares
  the on-disk revision with the one it loaded. If another process changed the file, the save fails
  with a message asking you to reopen the project or save a separate copy.
- When a project has no database yet, autosave creates a recovery sidecar named
  `<stem>.recovery-<uuid>.slre` next to the input rather than replacing an existing sidecar.

MCP-initiated saves are stricter: the path must end in `.slre` and resolve inside the opened
binary's directory. See [MCP server](mcp-server.md).

## JSONL export

`Project::export_jsonl()` produces one UTF-8 JSON object per line. It contains only
analyst-authored state; it does not contain binary bytes, functions other than renames, xrefs,
strings, or constants.

### Record kinds

The first line is always metadata:

```json
{"kind":"meta","name":"sample","arch":"x86_64","format":"Pe","version":1}
```

| Kind | Fields | Meaning |
|---|---|---|
| `meta` | `name`, `arch`, `format`, `version` | Source description; not merged |
| `comment` | `address`, `text` | Comment at an address |
| `rename` | `address`, `name` | Function name that differs from `sub_<address>` |
| `bookmark` | `address`, `note` | Bookmark |
| `tag` | `address`, `tag` | One tag per record |
| `overlay` | `address`, `type_name`, `count`, `label` | Struct overlay |
| `type` | `name`, `definition` | User-defined compound type |
| `conflict` | `key`, `base`, `left`, `right` | Emitted only by a merge; ignored on import |

Addresses are strings in `0x…` form. `format` is `Elf`, `Pe`, `MachO`, or `Raw`; `version` is the
JSONL format version (currently 1).

### Ordering

The export is deterministic:

1. `meta`.
2. Comments, sorted by address.
3. Renames, sorted by function address.
4. Bookmarks, in address order.
5. Tags, in address order, with each address's tags sorted.
6. Overlays, sorted by address then label.
7. Types, alphabetically by name.

This makes two exports comparable with a plain text diff and avoids spurious ordering changes.

### Importing

`Project::import_jsonl()` applies records for `comment`, `rename`, `bookmark`, `tag`, `overlay`,
and `type`. Unknown kinds, including `conflict`, are skipped so the format can grow without
breaking older readers. Import returns counts per record kind.

The GUI does not currently expose an **Export JSONL** command. Use the library API or your own
tooling to produce the files consumed by **File → Review JSONL merge…**.

## Three-way merge

The merge treats the JSONL as a keyed record set. The key is `(kind, identifier)`:

| Kind | Identifier |
|---|---|
| `comment`, `bookmark`, `rename` | Address |
| `tag` | Address + tag text |
| `overlay` | Address + label |
| `type` | Type name |

If only one side changed a key, that change is taken. If both sides made the same change, it is
taken once. If both sides changed the same key differently, the merge emits a conflict record:

```json
{"kind":"conflict","key":"comment::4198400","base":"old","left":"current","right":"incoming"}
```

The GUI presents conflicts one at a time and applies the chosen side. The MCP tool
`merge_jsonl_3way` returns the merged text and conflict counts without choosing sides.

## Related

- [Merge project edits](../how-to/merge-project-edits.md)
- [Review AI proposals](../how-to/review-ai-proposals.md)
- [Collaboration and review model](../explanation/collaboration-and-review.md)
