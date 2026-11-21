# Plugin and console scripting

sleuthre embeds Rhai in two places. They share a language and execution limits but expose
different data:

| Environment | How to run it | Data available | Runs on |
|---|---|---|---|
| Plugin runner | **Tools → Plugins → Run: name** | Function/string/comment snapshot subset | Background worker |
| Console engine | Output panel `script` / `run`, or **Run Script…** | Full project maps, file bytes, archives, bytecode, symbol import | UI thread |

Plugins are discovered in `~/.sleuthre/plugins/*.rhai` and can be reloaded without restarting.
Console scripts are ad hoc expressions or files and are not discovered automatically.

## Execution limits

Both environments enforce:

| Limit | Value |
|---|---|
| Operations | 10,000,000 |
| String size | 1,000,000 characters |
| Array size | 100,000 elements |
| Map size | 100,000 entries |
| Call depth | 64 |

Exceeding a limit stops the script and reports an error.

## Plugin environment

The worker receives an immutable snapshot and returns actions to the UI thread.

### Globals

| Name | Type | Contents |
|---|---|---|
| `functions` | Array of maps | `address` (integer), `name` (string), `size` (integer) |
| `num_functions` | Integer | Function count |
| `arch` | String | Architecture display name |

### Functions

| Function | Effect |
|---|---|
| `rename(address, name)` | Queue a rename action |
| `set_comment(address, text)` | Queue a comment action |
| `println(message)` | Append a line to the Output panel |
| `hex(number)` | Return `0x…` formatting |

The plugin snapshot does not include binary bytes, strings, comments, `goto`, or
`import_symbols`. Those are console-only.

Example:

```rhai
for f in functions {
    if f.name.starts_with("sub_") && f.size > 1024 {
        rename(f.address, "large_" + hex(f.address));
    }
}
```

## Console environment

The console evaluates against the live project. `script <expr>` evaluates one expression;
`run <path>` and **Run Script…** execute a full source file.

### Globals

| Name | Type | Contents |
|---|---|---|
| `functions` | Array of maps | `address`, `name`, `size` |
| `strings` | Array of maps | `address`, `value`, `encoding` |
| `comments` | Array of maps | `address`, `text` |
| `arch` | String | Architecture display name |
| `num_functions` | Integer | Function count |
| `num_strings` | Integer | String count |

### Functions and actions

| Function | Returns / effect |
|---|---|
| `hex(number)` | `0x…` string |
| `open_binary(path)` | `BinaryFile`; methods `read_u32_le(offset)`, `read_u16_le(offset)`, `read_string(offset, len)`, `len()` |
| `open_archive(path)` | Map with `path`, `format`, `count` |
| `archive_entries(path)` | Array of maps with `name`, `offset`, `size`, `compressed_size`, `is_compressed`; `size` is the decompressed size |
| `archive_extract(path, entry_name)` | Blob of the extracted entry |
| `disassemble_bytecode(data, opcodes)` | Array of decoded instructions |
| `parse_symbol_file(path)` | Integer count of parsed symbols |
| `rename(address, name)` | Queue a rename |
| `set_comment(address, text)` | Queue a comment change |
| `goto(address)` | Navigate the disassembly view |
| `println(message)` | Write to the Output panel |
| `import_symbols(path)` | Parse and apply a symbol file |

`BinaryFile` reads are bounds-checked and return a script error on an invalid offset or length.
`read_string` stops at the first NUL byte.

### Bytecode opcode tables

`disassemble_bytecode` accepts an array of maps:

```rhai
let blob = archive_extract("game.pak", "script.bin");
let ops = [
    #{ opcode: 0x01, mnemonic: "push", operands: ["u8"] },
    #{ opcode: 0x02, mnemonic: "call", operands: ["u32"] },
    #{ opcode: 0x03, mnemonic: "print", operands: ["cstr"] },
];
let insns = disassemble_bytecode(blob, ops);
```

Operand types are `u8`, `u16`, `u32`, `i8`, `i16`, `i32`, `str:N` (fixed-length string of `N`
bytes), and `cstr` (NUL-terminated string). Each decoded entry has `offset`, `opcode`, `mnemonic`,
`length`, and `operands`.

### Console command syntax

The command line is not a Rhai parser. It splits on whitespace after replacing `(`, `)`, and `,`
with spaces. Use `script` for simple expressions, and `run <path>` or **Run Script…** for any
script that contains function-call syntax, commas, or multiple statements.

## Safety

Both environments run local code with the application's privileges. `open_binary`, `open_archive`,
`archive_extract`, and `import_symbols` read arbitrary paths. Only run trusted scripts, and prefer
the plugin runner when a script only needs the project snapshot.

## Related

- [Write a plugin](../how-to/write-a-plugin.md)
- [GUI reference](gui.md)
- [MCP and trust boundaries](../explanation/mcp-and-trust.md)
