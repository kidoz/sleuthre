# Write a plugin

sleuthre runs user scripts written in [Rhai](https://rhai.rs/) (an embedded Rust scripting
language). Plugins are hot-reloadable files that operate on a snapshot of the open project and
return edits for the UI thread to apply.

## 1. Create the plugin file

Plugins are discovered in `~/.sleuthre/plugins/` and must use the `.rhai` extension:

```sh
mkdir -p ~/.sleuthre/plugins
```

Create `~/.sleuthre/plugins/large_functions.rhai`:

```rhai
// Rename large unnamed functions so they stand out in the function list.
let renamed = 0;

for f in functions {
    if f.name.starts_with("sub_") && f.size > 1024 {
        rename(f.address, "large_" + hex(f.address));
        renamed += 1;
    }
}

println("renamed " + renamed + " large functions");
```

## 2. Load and run it

1. Open a project.
2. Choose **Tools → Plugins → Reload from disk**. The menu reports added, updated, and removed
   plugins.
3. Choose **Tools → Plugins → Run: large_functions**.

The **Output** panel shows `renamed N large functions`. Renames are applied on the UI thread
through the normal edit path, so each one can be undone with `Ctrl+Z` (`Cmd+Z`).

The top-level **Plugins** menu is different: **Run Analysis Passes** runs the built-in Rust
analysis passes, and **Show Findings** opens their results. It does not execute Rhai files.

## What a plugin can see and do

The plugin worker receives a snapshot, not a live project. It exposes:

| Name | Kind | Meaning |
|---|---|---|
| `functions` | Array of maps | Each map has `address`, `name`, and `size` |
| `num_functions` | Integer | Number of functions in the snapshot |
| `arch` | String | Architecture display name |
| `rename(address, name)` | Action | Queue a function rename |
| `set_comment(address, text)` | Action | Queue a comment change |
| `println(message)` | Action | Write a line to the Output panel |
| `hex(number)` | Function | Format a number as `0x…` |

The plugin environment does **not** expose binary bytes, archives, the strings list, the comments
list, `goto`, or `import_symbols`. If you need those, use the console engine described in
[Plugin and console scripting](../reference/plugin-api.md#console-environment).

## Limits

Each plugin job gets:

- 10,000,000 operations.
- 1,000,000 characters per string.
- 100,000 elements per array and per map.
- 64 nested call levels.

A script that exceeds a limit fails with an error in the Output panel. The worker keeps running, so
one bad plugin does not stop the application.

## Hot reload

The registry polls `~/.sleuthre/plugins/` for changes. After editing a file, choose
**Tools → Plugins → Reload from disk**; the plugin appears under **Run:** with its file stem as the
name. Removing a file removes it from the menu on the next reload.

## Safety

Plugins execute with the same local privileges as sleuthre. Only run scripts you trust. Although
the plugin environment is restricted compared with the console, a script can still consume the
full operation budget and can propose renames or comments across the project.

## Related

- [Plugin and console scripting](../reference/plugin-api.md)
- [Analysis pipeline](../explanation/analysis-pipeline.md)
