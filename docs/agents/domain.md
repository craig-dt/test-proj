# Domain docs

Single-context repo.

- `CONTEXT.md` at the root is the **glossary only** — terms, one-line definitions, aliases to avoid. No
  implementation detail, no spec, no scratch notes. `grill-with-docs` updates it inline as terms are resolved.
- `docs/adr/NNNN-slug.md` — decisions that are hard to reverse, surprising without context, and the result of a
  real tradeoff. One paragraph is enough. Skills check ADRs in the area they touch before proposing changes.
- Consumers: `tdd`, `diagnose`, `improve-codebase-architecture`, `to-issues`, `triage`, `eng-reviewer`, `zoom-out`
  use the glossary for names and respect ADRs. If the repo becomes multi-context, add `CONTEXT-MAP.md` at the
  root per the `grill-with-docs` format.
