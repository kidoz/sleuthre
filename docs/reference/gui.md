# GUI windows, menus, and shortcuts

The desktop application is built with egui/eframe. It opens one project at a time and lays out
navigation, views, and dialogs around that project.

## Windows

Open a view with **Windows → name**. Views that do not apply to the current project show an empty
state with instructions.

| Window | Purpose |
|---|---|
| **Disassembly** | Address, bytes, mnemonic, operands, and inline comments |
| **Graph** | Layered control-flow graph for the selected function; back edges are highlighted |
| **Pseudocode** | Decompiled C-like output for the selected function |
| **Hex View** | Hex and ASCII dump of mapped memory |
| **Triage** | Load-time report: digest, format, architecture, entry point, entropy, segments, imports, findings |
| **Strings** | Discovered strings with filter, encoding, and length |
| **Imports** | Imported functions grouped with their libraries |
| **Exports** | Exported functions |
| **Structures** | User-defined structs and enums, fields, and struct overlays |
| **Call Graph** | Callers and callees around the current function |
| **Cross References** | Incoming and outgoing references for the current function |
| **Entropy** | Per-region entropy visualization and interpretation |
| **Signatures** | Signature manager: list, add, and apply function signatures |
| **Binary Diff** | Compare the open binary against a second file |
| **Archives** | Browse, preview, and extract archive entries |
| **Data Inspector** | Struct overlays and data at the current address |
| **Source Compare** | Compare binary functions against a source directory |
| **Tabular** | View CSV and TSV files |
| **Images** | Preview an image file or a folder of images |
| **Bytecode** | Disassemble a bytecode blob with an opcode table |
| **Debugger** | GDB Remote connection, stepping, registers, memory, breakpoints |
| **Inference Evidence** | Struct-inference candidates with evidence; accept, reject, or reset |

The left panel contains the searchable **Functions** list, sorting controls, and the type filter
(`All`, `User`, `Lib`). The navigation band and the bottom **Output** panel sit outside the tabbed
views.

## Menus

### File

| Item | Action |
|---|---|
| **Open Binary…** | Load ELF, PE, or Mach-O and analyze it |
| **Open Raw Image…** | Choose a file, then map regions before analysis |
| **Save Project…** | Save the project as `.slre` |
| **Load Project…** | Open a saved `.slre` project |
| **Review JSONL merge…** | Three-way merge using ancestor and incoming JSONL exports |
| **Review changes…** | Approve or reject pending proposals and view decision history |
| **Import Symbols…** | Parse MAP, IDC, CSV, or text symbols, preview, and apply |
| **Quit** | Close the application |

### Edit

| Item | Shortcut | Action |
|---|---|---|
| **Rename** | `N` | Rename the function at the selected address |
| **Comment** | `;` | Add or edit a comment at the selected address |

### Jump

| Item | Shortcut | Action |
|---|---|---|
| **Go to Address** | `Ctrl+G` / `Cmd+G` | Open the command bar for an address or function name |
| **Bookmark** | `Ctrl+D` / `Cmd+D` | Add a bookmark at the selected address |

### Search

| Item | Shortcut | Action |
|---|---|---|
| **Search…** | `Ctrl+F` / `Cmd+F` | Search strings, a hex pattern, or an address |

### View

- **Pseudocode (F5)** — decompile the selected function.
- **Theme** — Dark, Light, or Solarized.
- **AI Naming Heuristics** — run the local naming heuristics.
- **Re-Analyze…** — choose pipeline stages to re-run.

### Debugger

- **Open debugger panel** — focus or open the Debugger tab.

### Plugins

- **Run Analysis Passes** — run the built-in Rust passes and show findings.
- **Show Findings** — reopen the findings window.

### Tools

- **Plugins → Reload from disk** — rescan `~/.sleuthre/plugins/` for `.rhai` files.
- **Plugins → Run: name** — execute a discovered plugin.
- **Start Collab Server…** — open the local broadcast dialog.
- **Stop Collab Server** — stop broadcasting.

### Windows

Lists every tab in the table above.

### Help

Shows the version, a short description, and the shortcut list.

## Keyboard shortcuts

Shortcuts are active only when no modal dialog is open. Plain-key shortcuts are also suppressed
while a text field has focus.

| Key | Action |
|---|---|
| `F5` | Decompile the selected function |
| `Space` | Open the Graph view for the selected function |
| `N` | Rename at the selected address |
| `;` | Comment at the selected address |
| `X` | Show cross-references to the selected address |
| `Ctrl+G` / `Cmd+G` | Go to address |
| `Ctrl+P` / `Cmd+P` | Command palette |
| `Ctrl+F` / `Cmd+F` | Search |
| `Ctrl+D` / `Cmd+D` | Bookmark |
| `Ctrl+Z` / `Cmd+Z` | Undo |
| `Ctrl+Shift+Z` / `Cmd+Shift+Z` | Redo |
| `Alt+Left` | Navigate back |
| `Alt+Right` | Navigate forward |

On macOS, egui maps the command modifier to `Cmd`; on Windows and Linux it maps to `Ctrl`.

## Command bar

`Ctrl+G` / `Cmd+G` opens the command bar. It matches function names and addresses. Prefix a query
with `>` for commands (open, save, search, decompile, toggle output, show findings) or `@` / `view`
for view names.

## Output panel and console

The bottom panel shows analysis messages, script output, and a command line. Press **Enter** to run
a command.

| Command | Action |
|---|---|
| `help` | List console commands |
| `g <addr>`, `goto <addr>` | Jump to an address, parsed as hexadecimal |
| `rename <addr> <name>` | Rename a function (the name is one token) |
| `comment <addr> <text>` | Add or replace a comment |
| `list`, `ls` | List the first 10 functions |
| `script <expr>` | Evaluate a Rhai expression |
| `run [path]`, `load [path]` | Run a Rhai script file |

The command line normalizes `(`, `)`, and `,` to spaces before parsing, so function calls with
parentheses do not work through `script`. Use **Run Script…** or `run <path>` for full Rhai source.
See [Plugin and console scripting](plugin-api.md).

## Related

- [Your first analysis](../tutorials/first-analysis.md)
- [Plugin and console scripting](plugin-api.md)
- [Connect a debugger](../how-to/connect-a-debugger.md)
