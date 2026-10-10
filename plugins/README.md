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

`hex(n)` is also registered as a pure helper that formats an integer as
`0x…`; it performs no action.

The interactive console (the **Console** panel) registers a larger API —
`import_symbols(path)`, `open_archive(path)` / `archive_entries(path)` /
`archive_extract(path, name)`, `disassemble_bytecode(blob, opcode_table)`,
`parse_symbol_file(path)`, and the `BinaryFile` reader (`open_binary`,
`read_u32_le`, `read_u16_le`, `read_string`, `len`). These are
console-only: the plugin runner does not register them, so a plugin
script calling them fails with an unknown-function error.

Scripts run on a background thread; the UI never freezes regardless of how
long your logic takes.
