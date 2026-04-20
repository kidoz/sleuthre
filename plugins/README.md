# sleuthre plugins

Rhai scripts that run inside the sleuthre plugin runner. Copy (or symlink) the
`.rhai` files here into `~/.sleuthre/plugins/` and they'll show up under
**Tools → Plugins → Run:** in the GUI. The runner polls the directory once
per frame, so edits land without restarting the app.

## Available scripts

| Script | What it does |
|---|---|
| [`rename_alloc_funcs.rhai`](rename_alloc_funcs.rhai) | Renames every function whose name contains `alloc` to a clearer `known_alloc_<addr>` label. |
| [`find_xor_loops.rhai`](find_xor_loops.rhai) | Leaves a `TODO` comment on every function whose name hints at XOR / crypto / scramble routines so they surface in the comments view. |

## Writing your own

Scripts see a snapshot of project state via these scope variables:

- `functions` — list of `{ address, name, size }` maps
- `num_functions` — count
- `arch` — architecture display name (e.g. `"x86_64"`)

And can request these actions that apply on the main thread after the
script returns:

- `rename(address, new_name)`
- `set_comment(address, text)`
- `println(message)` — streamed to the output panel
- `import_symbols(path)` — auto-detects IDA MAP / IDC / CSV / text formats
- `open_archive(path)`, `archive_entries(path)`, `archive_extract(path, name)`
- `disassemble_bytecode(blob, opcode_table)`

Scripts run on a background thread; the UI never freezes regardless of how
long your logic takes.
