# sleuthre documentation

sleuthre is an open-source reverse engineering desktop application written in Rust. It ships as
four Cargo workspace crates: an analysis engine (`re-core`), a desktop GUI (`re-gui`), a headless
MCP server (`re-mcp`), and a headless CLI (`re-cli`).

These pages cover the user-facing behavior of the GUI, CLI, and MCP server, plus the project
formats and analysis pipeline they share.

## How these docs are organized

The documentation is split into four sections based on what you need at the moment:

| You want to... | Read | What it contains |
|---|---|---|
| Learn by working through a complete example | [Tutorials](tutorials/) | Guided lessons that take you from a clean checkout to a finished result |
| Accomplish a specific task | [How-to guides](how-to/) | Goal-focused steps for real jobs, with the parts that usually go wrong called out |
| Look up exact details | [Reference](reference/) | Commands, flags, tool parameters, formats, and keyboard shortcuts |
| Understand how the system works | [Explanation](explanation/) | Architecture, algorithms, rationale, and trade-offs |

The split is deliberate. A tutorial teaches by doing and should be followed in order. A how-to
guide assumes you already know the basics and just need the recipe. Reference pages are complete
rather than sequential. Explanation pages answer "why" and can be read in any order.

## Start here

- **New to sleuthre?** Follow [Your first analysis](tutorials/first-analysis.md). It opens a
  compiled binary, decompiles a function, records findings, and saves a project.
- **Working with firmware or shellcode?** Follow [Map a raw image](tutorials/raw-image.md).
- **Integrating an AI agent?** Read [Review AI proposals](how-to/review-ai-proposals.md) and the
  [MCP server reference](reference/mcp-server.md).

## Sections

### Tutorials

- [Your first analysis](tutorials/first-analysis.md)
- [Map a raw image](tutorials/raw-image.md)

### How-to guides

- [Open a binary](how-to/open-a-binary.md)
- [Triage a sample](how-to/triage-a-sample.md)
- [Analyze a binary from the CLI](how-to/use-the-cli.md)
- [Review AI proposals](how-to/review-ai-proposals.md)
- [Merge project edits](how-to/merge-project-edits.md)
- [Use debug symbols](how-to/use-debug-symbols.md)
- [Write a plugin](how-to/write-a-plugin.md)
- [Connect a debugger](how-to/connect-a-debugger.md)
- [Share a live session](how-to/share-a-live-session.md)

### Reference

- [CLI commands](reference/cli.md)
- [MCP server](reference/mcp-server.md)
- [GUI windows, menus, and shortcuts](reference/gui.md)
- [Plugin and console scripting](reference/plugin-api.md)
- [Project file and JSONL formats](reference/project-format.md)
- [Triage report](reference/triage-report.md)
- [Supported formats and architectures](reference/supported-formats.md)

### Explanation

- [Architecture](explanation/architecture.md)
- [Analysis pipeline](explanation/analysis-pipeline.md)
- [IL and decompiler](explanation/il-and-decompiler.md)
- [Collaboration and review model](explanation/collaboration-and-review.md)
- [MCP and trust boundaries](explanation/mcp-and-trust.md)

## Documentation conventions

- Commands assume you are at the repository root and have built the workspace with
  `cargo build`. Examples write `re-cli` for `target/debug/re-cli`; substitute
  `cargo run -p re-cli --` if the binary is not on your `PATH`.
- GUI navigation uses `Window → Item` for menu paths and **bold** for controls.
- Addresses are hexadecimal and written with a `0x` prefix unless a page says otherwise.
- Behavior is described for the current workspace version (0.7.x). The
  [changelog](../CHANGELOG.md) records changes between releases.
- Examples use small fixtures from `re-core/tests/fixtures/` where possible, so they can be run
  without external downloads.

If a page disagrees with the code, the code is authoritative. Please update the page rather than
working around the difference.

## Related project documents

- [README](../README.md) — project overview and crate summary
- [CHANGELOG](../CHANGELOG.md) — release-by-release changes
- [LICENSE](../LICENSE) — MIT license
