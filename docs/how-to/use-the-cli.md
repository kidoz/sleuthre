# Analyze a binary from the CLI

`re-cli` runs the analysis engine without a GUI. It is useful for batch processing, CI checks, and
piping results into other tools.

## Build and invoke

```sh
cargo build -p re-cli
./target/debug/re-cli --help
```

During development, `cargo run -p re-cli -- <args>` is equivalent. Every subcommand accepts
`--help` for its exact flags.

Progress messages from the analysis pipeline are written to stderr. Primary output goes to stdout,
so redirection and pipelines stay clean.

## Common jobs

### Classify a file

```sh
re-cli triage sample.bin --format markdown
```

Triage loads the container and scans strings and constants. It does not build the function graph.
Use it when you need a fast, reproducible fingerprint.

### Summarize a full analysis

```sh
re-cli analyze sample.bin
re-cli analyze sample.bin --json
```

The JSON object contains architecture, entry point, function/string/import/export counts, and
linked libraries.

### List functions, strings, imports, or exports

```sh
re-cli functions sample.bin
re-cli functions sample.bin --json
re-cli strings sample.bin --json
re-cli imports sample.bin --json
re-cli exports sample.bin --json
```

The JSON output is a JSON array. Pipe it through `jq` for filtering:

```sh
re-cli functions sample.bin --json | jq -r '.[] | select(.name | startswith("sub_")) | .address'
```

### Disassemble an address

```sh
re-cli disasm sample.bin --address 0x401000 --count 32
re-cli disasm sample.bin --address 0x401000 --count 32 --json
```

`disasm` loads the container and disassembles from the requested address; it does not need a full
analysis run. The default count is 16.

### Decompile a function

```sh
re-cli decompile sample.bin --address 0x401000
```

`decompile` runs the full pipeline first, finds the function whose start address is the requested
address, and prints its pseudocode. If no function starts there, it prints
`No function found at address …`.

### Print binary layout

```sh
re-cli info sample.bin
re-cli info sample.bin --json
```

This reports architecture, endianness, entry point, pointer size, and every segment with its
permissions.

### Run built-in analysis passes

```sh
re-cli plugins sample.bin
re-cli plugins sample.bin --json
```

This runs the built-in suspicious-name and struct-inference passes. It does not load user Rhai
scripts; those run in the GUI.

## Raw images

Map raw bytes with `--region NAME:FILE_OFFSET:LENGTH:START`. Numbers accept decimal or `0x`-prefixed
hexadecimal.

```sh
re-cli raw firmware.bin --arch arm64 \
  --region code:0:0x4000:0x8000 \
  --region data:0x4000:0x2000:0x200000 \
  --entry 0x8000 \
  --count 32
```

Without `--region`, the whole file is mapped at `--base` (`0` by default). Whole-file raw
disassembly defaults to little-endian; region mappings default to the architecture's byte order.
`--byte-order little|big` overrides both. `--endian` is an alias for `--byte-order`.

## Scripting the output

`--json` output is stable enough for pipelines, but it is not a versioned interchange format.
For durable artifacts, prefer a triage report (which has `schema_version`) or a saved `.slre`
project.

```sh
# Fail a CI step when an executable imports a network API
re-cli imports sample.exe --json \
  | jq -e 'any(.[]; .name | test("WSAStartup|socket|connect"))' >/dev/null
```

## Related

- [CLI commands](../reference/cli.md) — complete option reference
- [Triage report](../reference/triage-report.md) — report schema
- [Map a raw image](../tutorials/raw-image.md) — guided raw-mapping walkthrough
