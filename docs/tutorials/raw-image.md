# Map a raw image

Firmware, bootloader dumps, and shellcode often arrive without a container format. sleuthre can
map named slices of a raw file into one virtual address space, so instructions from different file
offsets can refer to each other. This tutorial maps a two-region fixture in the GUI and then repeats
the mapping from the CLI.

## The fixture

`re-core/tests/fixtures/two-regions.raw` is eight bytes, `ABCDEFGH`. The mapping used throughout
this tutorial places the first four bytes at virtual address `0x1000` and the last four at
`0x8000`:

| Region | File offset | Length | Virtual start |
|---|---|---|---|
| `low` | `0x0` | `4` | `0x1000` |
| `high` | `0x4` | `4` | `0x8000` |

The virtual addresses do not need to be contiguous. That is the point of the region map: it lets a
single project cover images that were flashed into separate address windows.

## Map it in the GUI

1. Choose **File → Open Raw Image…** and select
   `re-core/tests/fixtures/two-regions.raw`.
2. In the **Open Raw Image** dialog:
   - Set **Architecture** to `MIPS`. The byte order changes to `Big`, the architecture default.
   - Set **Byte order** to `Little` so it matches this fixture.
   - Set **Entry point** to `0x8001`.
3. The dialog starts with one region row. Fill it in as:
   - **Name**: `low`
   - **File offset**: `0`
   - **Length**: `4`
   - **Virtual start**: `0x1000`
4. Click **Add region** and fill the second row:
   - **Name**: `high`
   - **File offset**: `4`
   - **Length**: `4`
   - **Virtual start**: `0x8000`
5. Click **Open**.

Offsets, lengths, and addresses accept decimal or `0x`-prefixed hexadecimal. A region name is
required; overlap and bounds are validated before the file is loaded.

When the mapping loads, the **Triage** view reports `Raw`, `MIPS`, entry `0x8001`, and two
segments. Exported reports also record byte order `Little`. Use the navigation band or
**Jump → Go to Address** to move between `0x1000` and `0x8000`.

## Repeat it from the CLI

The `raw` subcommand maps the same regions and disassembles from the entry point. A count of `0`
prints only the mapping summary:

```sh
cargo run -p re-cli -- raw re-core/tests/fixtures/two-regions.raw --arch mips \
  --region low:0:4:0x1000 \
  --region high:4:4:0x8000 \
  --byte-order little \
  --entry 0x8001 \
  --count 0
```

Output:

```text
Raw binary: 8 bytes, MIPS, entry=0x8001, byte order=Little
  low: file offset 0x0, length 0x4, start 0x1000
  high: file offset 0x4, length 0x4, start 0x8000
```

The region syntax is `NAME:FILE_OFFSET:LENGTH:START`. Supply `--region` once per region. Without
regions, the whole file is mapped at `--base` (default `0`), and whole-file disassembly defaults to
little-endian for compatibility.

The `triage` subcommand accepts the same mapping arguments:

```sh
cargo run -p re-cli -- triage re-core/tests/fixtures/two-regions.raw --arch mips \
  --region low:0:4:0x1000 \
  --region high:4:4:0x8000 \
  --byte-order little \
  --entry 0x8001 \
  --format markdown
```

The Markdown report includes both regions:

```text
- Format: Raw (MIPS)
- Byte order: Little
- Entry point: `0x8001`

## Segments (2)

    0x1000  "low"  4 bytes  READ | WRITE | EXECUTE  file offset 0x0
    0x8000  "high"  4 bytes  READ | WRITE | EXECUTE  file offset 0x4
```

## What you learned

A raw mapping turns unrelated file slices into one address space, and the GUI and CLI share the
same `--region` semantics. From here:

- [Open a binary](../how-to/open-a-binary.md) covers the non-raw loaders and their failure modes.
- [CLI commands](../reference/cli.md) lists every mapping option, including `--base` and `--entry`.
- [Supported formats and architectures](../reference/supported-formats.md) lists architecture names
  and default byte orders.
