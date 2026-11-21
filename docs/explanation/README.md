# Explanation

Explanation pages are understanding-oriented. They describe how sleuthre is put together, why
particular boundaries and formats exist, and what the trade-offs are. They are not step-by-step
instructions.

- [Architecture](architecture.md) — the four crates, their dependency direction, and the data that
  flows between them.
- [Analysis pipeline](analysis-pipeline.md) — what happens between opening a file and seeing
  functions, cross-references, and strings.
- [IL and decompiler](il-and-decompiler.md) — the lifting tiers, dataflow passes, caching, and
  recompile-diff.
- [Collaboration and review model](collaboration-and-review.md) — pending proposals, review
  history, JSONL exports, three-way merges, and live broadcast.
- [MCP and trust boundaries](mcp-and-trust.md) — why MCP tools propose instead of apply, how save
  paths are confined, and what the local collaboration server does and does not protect.

[Back to the documentation index](../README.md)
