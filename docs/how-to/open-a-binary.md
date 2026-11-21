# Open a binary

Use this guide when you have an executable or a raw image and want it analyzed in the GUI, the
CLI, or the MCP server.

## What the main loader accepts

The `Open Binary` path detects the container from its bytes:

| Container | Notes |
|---|---|
| ELF | 32-bit and 64-bit; architecture from `e_machine` |
| PE | PE32 and PE32+; architecture from the COFF header |
| Mach-O | Single-architecture and fat binaries; fat binaries use the first usable architecture |
| Raw | Explicit mapping only: supply an architecture, regions, and optional byte order |

Other file kinds have separate entry points. Use **Windows → Archives** and **Open Archive…** to
browse archive containers, and use **File → Open Raw Image…** for arbitrary byte images. The main
`Open Binary` loader rejects anything that is not ELF, PE, or Mach-O.

## In the GUI

1. Choose **File → Open Binary…**.
2. Select the file.
3. Wait for the load and analysis stages to finish. Analysis runs on a background worker, so the
   window stays responsive.

When it finishes, the function list, disassembly, strings, imports, exports, and triage views are
populated. A small or stripped file may legitimately have no strings or very few named functions;
those views are then empty or show only synthetic `sub_<address>` names.

If you have a raw file, follow [Map a raw image](../tutorials/raw-image.md) instead.

## From the CLI

`info` loads the container and prints architecture, endianness, entry point, pointer size, and
segments without running full analysis:

```sh
cargo run -p re-cli -- info path/to/binary
cargo run -p re-cli -- info path/to/binary --json
```

`analyze` runs the full pipeline and prints counts plus linked libraries:

```sh
cargo run -p re-cli -- analyze path/to/binary
```

See [CLI commands](../reference/cli.md) for the complete list.

## From the MCP server

Start the server:

```sh
cargo run -p re-mcp
```

Then send a JSON-RPC request on stdin:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_binary","arguments":{"path":"/absolute/path/to/binary"}}}
```

`open_binary` runs normal analysis and keeps the project in memory. To map a raw image instead,
include the `raw` object described in [MCP server](../reference/mcp-server.md#loading-and-saving).

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `Unsupported binary format` | The file is not ELF, PE, or Mach-O | Use **Open Raw Image** with an explicit architecture and regions |
| `Unsupported ELF architecture` / `Unsupported PE architecture` | The container is valid but its machine type is not supported | Map a slice as a raw image with a supported architecture |
| `Empty input` | The selected file is zero bytes | Check the file, or map another input |
| Raw load fails with a bounds or overlap error | A region extends past the end of the file, or two regions overlap in virtual space | Correct the region's file offset, length, or virtual start |
| A function is missing from the list | Discovery did not reach it from the entry point, direct calls, signatures, or exception tables | Use **View → Re-Analyze…** with the relevant stages enabled, or navigate to the address directly |

## Related

- [Supported formats and architectures](../reference/supported-formats.md)
- [Triage a sample](triage-a-sample.md)
- [Analysis pipeline](../explanation/analysis-pipeline.md)
