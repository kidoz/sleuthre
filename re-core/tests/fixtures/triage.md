# Triage report

- Report version: 1
- SHA-256: `de9aebe81736dd7d3126e3cf189d0db51ca048609ba0d30908474da681678626`
- Format: Pe (x86_64)
- Entry point: `0x140001000`
- Entropy: 1.106195 bits per byte

## Segments (3)

    0x140001000  ".text"  512 bytes  READ | EXECUTE
    0x140002000  ".rdata"  512 bytes  READ
    0x140003000  ".idata"  512 bytes  READ

## Imports (1)

    0x140003038  "KERNEL32.dll"  "OutputDebugStringA"

## Findings (4)

    0x140002000  Ascii string  "sleuthre triage fixture"
    0x140002018  Constant  "CRC32 lookup table (polynomial 0xEDB88320)"  "00000000"
    0x14000304a  Ascii string  "OutputDebugStringA"
    0x140003064  Ascii string  "KERNEL32.dll"
