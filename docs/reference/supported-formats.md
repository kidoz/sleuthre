# Supported formats and architectures

## Containers

The main loader inspects the file bytes; extensions are not authoritative. The GUI file dialog
offers an `elf`, `exe`, `dll`, `so`, `bin`, `pe` filter, but a valid container loads regardless of
its extension.

| Container | Detection | Architectures |
|---|---|---|
| ELF | ELF magic | x86, x86-64, ARM, ARM64, MIPS, MIPS64, RISC-V 32, RISC-V 64 |
| PE | `MZ` header and PE signature | x86, x86-64, ARM, ARM64 |
| Mach-O | Mach-O magic, thin or fat | x86, x86-64, ARM, ARM64 |
| Raw | Explicit mapping | All architectures above |

Fat Mach-O binaries use the first usable architecture. PE images are mapped with their preferred
image base, so addresses shown in the UI match the loaded virtual addresses.

The main loader does not open archives, disk images, or arbitrary bytecode. Use the dedicated
**Archives** view for supported archive containers, and the **Bytecode** view or a Rhai script for
opcode-table disassembly.

## Architectures

| Display name | CLI names | Pointer size | Default byte order |
|---|---|---|---|
| x86 | `x86`, `i386` | 4 bytes | Little |
| x86_64 | `x86_64`, `x86-64`, `x64`, `amd64` | 8 bytes | Little |
| ARM | `arm`, `arm32` | 4 bytes | Little |
| ARM64 | `arm64`, `aarch64` | 8 bytes | Little |
| MIPS | `mips`, `mips32` | 4 bytes | Big |
| MIPS64 | `mips64` | 8 bytes | Big |
| RISC-V32 | `riscv`, `riscv32`, `rv32` | 4 bytes | Little |
| RISC-V64 | `riscv64`, `rv64` | 8 bytes | Little |

Container byte order comes from the file:

- ELF reads `EI_DATA`.
- PE is always little-endian.
- Mach-O reads its header byte order.
- Raw mappings use `--byte-order` if supplied, otherwise the architecture default. Whole-file raw
  disassembly defaults to little-endian for compatibility.

## Instruction support

Disassembly uses Capstone. The IL lifter and decompiler cover the x86, x86-64, ARM, ARM64, MIPS,
MIPS64, RISC-V 32, and RISC-V 64 families, with richer coverage on x86-64 and ARM64. Unsupported
instructions still appear in the disassembly listing but may lower to opaque IL or render as
placeholders in pseudocode.

## Address spaces

Addresses are virtual addresses from the loader's perspective:

- ELF and Mach-O segment addresses are used as provided by the container.
- PE addresses include the image base (`ImageBase + RVA`).
- Raw addresses come from each region's `start`.

When an address is not mapped, disassembly and memory views report that instead of reading
arbitrary bytes.

## Related

- [Open a binary](../how-to/open-a-binary.md)
- [CLI commands](cli.md)
- [Analysis pipeline](../explanation/analysis-pipeline.md)
