# Use debug symbols

Debug information turns addresses into names, types, and source locations. sleuthre reads DWARF
from the binary automatically, discovers sibling PDB files for PE images, and can import symbol
maps produced by other tools.

## Automatic extraction

Normal analysis runs the debug-info stage. It reads DWARF from the original file bytes when the
container carries it. For PE files it also looks for a sibling `.pdb` file named by the image's
debug directory or by a same-stem `.pdb` next to the executable. Automatic PDB discovery only
accepts a plain file name and refuses paths, links, directories, and device names.

When debug information is found, sleuthre uses it to:

- Name functions and parameters.
- Add type definitions and struct layouts.
- Apply local variable names and types to stack slots in the decompiler.
- Populate source-line information used by **Step Source** in the debugger and by
  `get_source_line`.

Quick-triage analysis skips debug-info extraction. Use **View → Re-Analyze…** with
**Extract Debug Info** enabled if a project was opened in that mode.

## Import a symbol map

1. Choose **File → Import Symbols…**.
2. Select a file with one of these extensions: `.map`, `.idc`, `.csv`, `.txt`.
3. Click **Preview**. The dialog reports the detected format and the number of parsed symbols, and
   lists up to 200 of them.
4. Click **Apply** to rename matching functions.

The parser detects these formats from their content:

| Format | Typical source |
|---|---|
| Text map | `address name` or `name address` lines |
| IDA MAP | IDA `.map` exports |
| IDA IDC | `MakeName(0x..., "name")` scripts |
| CSV | `address,name` rows |

Renames of existing functions go through the undo stack and are saved with the project. A symbol
that does not match an existing function is added to the project's symbol list instead.

## Load a PDB explicitly

The MCP tool `load_pdb` reads a PDB even when it is not next to the executable:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"load_pdb","arguments":{"path":"/absolute/path/to/symbols.pdb"}}}
```

It reports how many signatures and types were loaded and renames functions that still have
synthetic `sub_` names. The PDB must match the opened image's architecture and load base; a
mismatched file produces few or no matches rather than a hard failure.

## Query the results

| Where | What it returns |
|---|---|
| **Pseudocode** view | Source variable names and types in decompiled output |
| **Structures** view | Compound types and fields learned from debug info |
| `get_function_signature` (MCP) | Typed signature for a function address |
| `get_source_line` (MCP) | Source file and line for an address |
| Debugger **Step Source** | Steps to the next source line when line info exists |

## Related

- [MCP server](../reference/mcp-server.md)
- [Debugger how-to](connect-a-debugger.md)
- [IL and decompiler](../explanation/il-and-decompiler.md)
