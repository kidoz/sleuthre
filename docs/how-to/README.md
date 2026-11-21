# How-to guides

How-to guides are task-oriented. They assume you can already open a binary and move around the
interface, and they focus on getting one job done.

## Analyze

- [Open a binary](open-a-binary.md) — load ELF, PE, Mach-O, or a raw image.
- [Triage a sample](triage-a-sample.md) — produce a stable JSON or Markdown snapshot of a file.
- [Analyze a binary from the CLI](use-the-cli.md) — run headless analysis and feed JSON to other
  tools.
- [Use debug symbols](use-debug-symbols.md) — import MAP, IDC, CSV, or text symbols and use PDB
  debug information.

## Collaborate

- [Review AI proposals](review-ai-proposals.md) — carry MCP-generated renames, comments, and type
  edits through a saved project and approve or reject them in the GUI.
- [Merge project edits](merge-project-edits.md) — resolve concurrent analyst work with a
  three-way merge of JSONL exports.
- [Share a live session](share-a-live-session.md) — publish project mutations over a local TCP
  connection.

## Extend and debug

- [Write a plugin](write-a-plugin.md) — add a hot-reloaded Rhai script and run it against the
  current project.
- [Connect a debugger](connect-a-debugger.md) — attach to a gdbserver-compatible stub, set
  breakpoints, and step.

[Back to the documentation index](../README.md)
