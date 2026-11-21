# Analysis pipeline

Analysis turns a file on disk into a project: a memory map, a function set, cross-references,
strings, constants, and type information. The pipeline is the same in the GUI, CLI, and MCP
server; only the surrounding I/O differs.

## Stages

The pipeline runs these stages in order, skipping any disabled by the current configuration:

1. **Load the binary.** Detect the container, map segments, extract symbols, imports, exports,
   libraries, and any debug-directory path.
2. **Discover functions.** Seed from the entry point, symbols, and exported functions, then apply
   prologue heuristics. For x86-64 PE images, `.pdata` exception tables supply authoritative
   function starts and ends and remove prologue false positives.
3. **Recursive descent.** Follow direct call targets and known branches to discover reachable
   functions, including import thunks.
4. **Calling conventions and frame sizes.** Analyze each function to assign a convention and stack
   frame size. The ABI is format-aware: x86-64 PE uses the Microsoft x64 convention, other
   x86-64 targets use SysV.
5. **Strings.** Scan mapped memory for ASCII and UTF-16 strings, skipping executable segments by
   default. Mach-O `__cstring` sections inside `__TEXT` are still scanned, because that is where
   Mach-O keeps literal strings.
6. **Cross-references.** One pass over code and data records call, jump, data-read, data-write, and
   string references. Scanning strings first lets the same pass resolve string references.
7. **Constants.** Recognize known tables and constant patterns (for example CRC32 tables and AES
   S-boxes).
8. **VTables.** Find arrays of code pointers, link them to known class definitions, and record the
   virtual methods they contain.
9. **Debug information.** Extract DWARF from the binary. For PE, also look for a sibling PDB named
   by the debug directory or by a same-stem `.pdb`. Debug info adds names, types, locals, and
   source lines.
10. **Type propagation.** Infer parameter and local types using call-flow facts, debug
    information, and type libraries.
11. **Analysis passes.** Run registered passes such as suspicious-name detection and struct
    inference.
12. **Done.** The GUI also stores a triage report captured from the original bytes.

Control-flow graphs are built on demand for the selected function rather than for every function
up front. The GUI builds or refreshes a CFG when navigation changes; the MCP `get_cfg` tool builds
one per request.

## Analysis modes

| Mode | Behavior |
|---|---|
| Quick triage | Discover functions and scan strings/constants; skip recursive descent, xrefs, vtables, debug info, and type propagation |
| Normal | All stages enabled |
| Deep | Currently the same configuration as Normal |
| Custom | Chosen per stage in **View → Re-Analyze…** |

**Re-Analyze** re-runs selected stages against an open project. Use it after opening with quick
triage, after loading a PDB, or when a code change means a stale analysis should be refreshed.

## What discovery can and cannot see

Function discovery is evidence-driven:

- Direct calls, entry points, exports, symbols, exception tables, and prologue shapes are strong
  evidence.
- Indirect calls and computed jumps are resolved only when a switch table or vtable pattern is
  recognized. An unresolved indirect target is not followed.
- Recursive descent only reaches code reachable from known roots. Code that is never called
  directly and never appears in a symbol table can remain undiscovered.

Those limits are intentional: guessing broadly produces false functions that pollute xrefs and
decompilation. When a function is missing, navigate to its address directly or add a symbol.

## Naming

Discovered functions start as `sub_<hex-address>`. Names can be improved by:

- Symbols and exports in the container.
- Import-thunk naming: a body that is a single imported call takes the import's name.
- Debug information and imported symbol maps.
- Signature matching.
- Analyst renames and MCP proposals.

## Determinism

Given the same input bytes and configuration, the pipeline aims to produce the same functions,
xrefs, strings, and ordering. Per-thread work is merged in range order, exports are sorted, and
golden tests pin decompiler output. This matters for triage reports, JSONL diffs, and regression
testing.

## Related

- [Architecture](architecture.md)
- [IL and decompiler](il-and-decompiler.md)
- [Triage report](../reference/triage-report.md)
