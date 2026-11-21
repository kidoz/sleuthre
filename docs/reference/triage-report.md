# Triage report

A triage report is a reproducible snapshot of the original input bytes. It is produced when a file
is loaded and can be exported as JSON or Markdown. It is not updated by later analysis or analyst
edits.

## What triage does

Triage loads the container (or applies a raw mapping), computes a whole-file SHA-256 and Shannon
entropy, scans strings and constants, and records segments and imports. It does **not** discover
functions or build cross-references. For those, run full analysis (`re-cli analyze`, opening a
binary in the GUI, or `open_binary` over MCP).

The report is stored in a saved project, so a `.slre` opened later still describes the file as it
was at load time.

## JSON layout

```json
{
  "schema_version": 1,
  "sha256": "9ac2197d9258257b1ae8463e4214e4cd0a578bc1517f2415928b91be4283fc48",
  "format": "Raw",
  "architecture": "MIPS",
  "byte_order": "Little",
  "entry_point": "0x8001",
  "entropy": 3.0,
  "segments": [
    {
      "name": "low",
      "start": "0x1000",
      "size": 4,
      "file_offset": 0,
      "permissions": "READ | WRITE | EXECUTE"
    },
    {
      "name": "high",
      "start": "0x8000",
      "size": 4,
      "file_offset": 4,
      "permissions": "READ | WRITE | EXECUTE"
    }
  ],
  "imports": [],
  "findings": []
}
```

### Fields

| Field | Type | Notes |
|---|---|---|
| `schema_version` | integer | Current version is 1 |
| `sha256` | string | Lowercase hex SHA-256 of the complete input bytes |
| `format` | string | `Elf`, `Pe`, `MachO`, or `Raw` |
| `architecture` | string | Display name such as `x86_64`, `ARM64`, `MIPS`, `RISC-V64` |
| `byte_order` | string or absent | `Little`/`Big`; present only for raw mappings |
| `entry_point` | string | `0x`-prefixed address |
| `entropy` | number | Bits per byte, rounded to six decimals |
| `segments` | array | Mapped ranges |
| `imports` | array | `name`, `library`, and `address` (`null` when unresolved) |
| `findings` | array | Tagged string/constant evidence, sorted by address |

Segment fields are `name`, `start`, `size`, optional `file_offset`, and `permissions`.
`file_offset` is present for raw mappings. Permissions render as a `|`-separated list such as
`READ | EXECUTE`.

Findings use a `kind` tag:

```json
{"kind":"string","address":"0x402000","encoding":"Ascii","value":"sleuthre triage fixture"}
{"kind":"constant","address":"0x402018","description":"CRC32 lookup table (polynomial 0xEDB88320)","value":"00000000"}
```

All virtual addresses in the report are strings in `0x…` form. This avoids precision loss in
JavaScript consumers.

## Markdown layout

`--format markdown` emits:

1. `# Triage report`.
2. A header list with report version, SHA-256, format, architecture, optional byte order, entry
   point, and entropy.
3. `## Segments (N)` with one indented line per segment, including permissions and file offset.
4. `## Imports (N)` with resolved or `unresolved` addresses.
5. `## Findings (N)` with address, kind, and debug-quoted values.

String values are debug-quoted so embedded newlines cannot break the report structure.

## Producing a report

| Interface | How |
|---|---|
| GUI | **Windows → Triage**, then **Export JSON…** or **Export Markdown…** |
| CLI | `re-cli triage <file> [--format json\|markdown]` |
| MCP | `get_triage_report` with optional `format` |

The GUI writes exports atomically through a temporary file. The CLI writes to stdout. The MCP tool
rejects reports larger than 8 MiB; use the CLI for larger samples.

## Reproducibility

Two reports describe the same input only when their `sha256` values match. The digest covers the
whole file, including bytes outside any mapped region. Entropy is computed over the whole file as
well. Segment layout and findings then describe how sleuthre interpreted that snapshot.

## Related

- [Triage a sample](../how-to/triage-a-sample.md)
- [CLI commands](cli.md)
- [MCP server](mcp-server.md)
