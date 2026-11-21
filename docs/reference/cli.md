# CLI commands

`re-cli` is the headless batch interface to `re-core`. It reads a file, runs the requested part of
the analysis pipeline, and writes text or JSON to stdout.

```sh
re-cli <COMMAND> [OPTIONS]
re-cli <COMMAND> --help
```

After `cargo build`, the binary is `target/debug/re-cli`. Run it directly or invoke it as
`cargo run -p re-cli -- <COMMAND> [OPTIONS]`.

## Commands

| Command | Analysis performed | Output |
|---|---|---|
| `triage` | Load the container (or raw mapping), scan strings and constants | Triage report as JSON or Markdown |
| `analyze` | Full pipeline | Counts and linked libraries as text or JSON |
| `disasm` | Load the container, disassemble from an address | Instructions as text or JSON |
| `decompile` | Full pipeline, then decompile the function at an address | C-like pseudocode text |
| `functions` | Full pipeline | Function list as text or JSON |
| `strings` | Full pipeline | String list as text or JSON |
| `imports` | Load the container | Import list as text or JSON |
| `exports` | Load the container | Export list as text or JSON |
| `info` | Load the container | Architecture, endianness, entry point, pointer size, segments |
| `raw` | Map supplied regions, disassemble from the entry point | Mapping summary and instructions |
| `plugins` | Full pipeline, then built-in analysis passes | Findings as text or JSON |

Progress messages from the full pipeline are written to stderr. Primary results are written to
stdout.

## Options shared by several commands

### `--json`

Available on `analyze`, `disasm`, `functions`, `strings`, `imports`, `exports`, `info`, `raw`, and
`plugins`. Output is pretty-printed JSON rather than the human-readable table.

### Raw mapping options

Accepted by `triage` (with `--arch`) and `raw`:

| Option | Meaning |
|---|---|
| `--arch <ARCH>` | Interpret the input as a raw image for this architecture. Required for every other raw option. |
| `--base <ADDR>` | Map the whole file at this virtual address. Default `0`. Conflicts with `--region`. |
| `--region <NAME:FILE_OFFSET:LENGTH:START>` | Map one named slice. Repeat for multiple regions. |
| `--byte-order <little\|big>` | Override the architecture default. `--endian` is an alias. |
| `--entry <ADDR>` | Entry address. Defaults to `--base`, or the virtual start of the first region. |

Numbers accept decimal or `0x`-prefixed hexadecimal. The region name must be non-empty. All regions
are validated for file bounds, length, and virtual overlap before the image is loaded.

Without `--region`, the whole file is mapped at `--base` and, unless `--byte-order` is given,
disassembly defaults to little-endian for compatibility. With regions, the default byte order is
the architecture's default (little for x86, ARM, ARM64, RISC-V; big for MIPS and MIPS64).

### Architecture names

| Accepted values | Architecture |
|---|---|
| `x86`, `i386` | x86 (32-bit) |
| `x86_64`, `x86-64`, `x64`, `amd64` | x86-64 |
| `arm`, `arm32` | ARM (32-bit) |
| `arm64`, `aarch64` | ARM64 |
| `mips`, `mips32` | MIPS |
| `mips64` | MIPS64 |
| `riscv`, `riscv32`, `rv32` | RISC-V 32 |
| `riscv64`, `rv64` | RISC-V 64 |

### Address parsing

`--address` and `--entry` accept decimal or hexadecimal. A `0x`/`0X` prefix is explicit; an
unprefixed value is parsed as decimal first and as hexadecimal if that fails.

## Command details

### `triage`

```sh
re-cli triage <BINARY> [--arch <ARCH> [raw mapping options]] [--format json|markdown]
```

Loads the file and extracts strings and constants. It does not discover functions or build
cross-references. `--format` defaults to `json`. The output is the report described in
[Triage report](triage-report.md).

### `analyze`

```sh
re-cli analyze <BINARY> [--json]
```

Runs the full pipeline and prints architecture, entry point, function count, string count, import
count, export count, and linked libraries.

### `disasm`

```sh
re-cli disasm <BINARY> --address <ADDR> [--count <N>] [--json]
```

Loads the container without a full analysis run and disassembles `N` instructions from `ADDR`.
The default is 16. Disassembly stops at the first address that cannot be decoded. JSON entries
contain `address`, `bytes`, `mnemonic`, and `operands`; bytes are space-separated lowercase hex.

### `decompile`

```sh
re-cli decompile <BINARY> --address <ADDR>
```

Runs the full pipeline, looks up the function whose start address is `ADDR`, and prints its
pseudocode. If no function starts at that address, the command prints
`No function found at address 0x…`.

### `functions`

```sh
re-cli functions <BINARY> [--json]
```

Outputs every discovered function with its start address, name, and size when known. Synthetic
names use the form `sub_<hex-address>`.

### `strings`

```sh
re-cli strings <BINARY> [--json]
```

Outputs discovered strings with address, length, encoding, section, and value. The human-readable
table truncates values longer than 80 bytes; JSON contains the complete value.

### `imports` and `exports`

```sh
re-cli imports <BINARY> [--json]
re-cli exports <BINARY> [--json]
```

These load the container only. Imports include address, name, and library; exports include address
and name. Addresses are strings in `0x…` form.

### `info`

```sh
re-cli info <BINARY> [--json]
```

Loads the container and prints architecture, endianness, entry point, pointer size, and every
segment with its name, start, size, and permissions.

### `raw`

```sh
re-cli raw <BINARY> --arch <ARCH> [--base <ADDR> | --region …] [--byte-order …] [--entry …]
  [--count <N>] [--json]
```

Maps the raw image and disassembles `N` instructions from the entry point. The default is 32.
Without `--json`, the mapping summary and instructions are written to stdout. With `--json`, the
mapping summary is written to stderr and the instruction array to stdout, so stdout remains a
single parseable JSON value.

### `plugins`

```sh
re-cli plugins <BINARY> [--json]
```

Runs full analysis and then the built-in `SuspiciousNamePass` and `StructInferencePass`. It does
not load Rhai user plugins. JSON entries contain `address`, `category`, `message`, and `severity`.

## Exit behavior

On success the process exits with status 0. A loader, analysis, or I/O error is printed to stderr
and the process exits non-zero. `cargo run` forwards the exit status of the built binary.

## Related

- [Analyze a binary from the CLI](../how-to/use-the-cli.md)
- [Supported formats and architectures](supported-formats.md)
- [Triage report](triage-report.md)
