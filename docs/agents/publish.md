# Publishing targets (used only by `/project:status publish`)

## Notion — "Projects" tracker
- Database: https://app.notion.com/p/39d2a84a523080029b10cb68145e53e6
- Data source: `collection://39d2a84a-5230-8044-94ba-000b23da3da8` (`data_source_id: 39d2a84a-5230-8044-94ba-000b23da3da8`)
- One **row per project** (never nested). Properties: `Task name` (title — clean project name), `Status`
  (Not started / In progress / Done — template-locked), `Stage` (select: Research / PRD / Eng Review / Slice /
  Build / Verify), `Description`. Optional: Priority, Effort level, Assignee, Due date.
- Body: one-line description · "GitHub: <url>" · stage table (Stage | Status ⬜/🔄/✅ | Artifact | Completed) ·
  "Last updated: <date>".
- Lifecycle: `In progress` from first publish → `Done` when the final verify pass completes.
- Note: the `Stage` select still has a `Plan` and `Scaffold` option from the old pipeline; map `Slice` → `Plan`
  until the select is edited, and never set `Scaffold`.

## Google Drive — PRDs
- PRD template Doc id: `10D1TOyjxnFat5_o1S5h5XFR35XFTncBcDSzG1pM5_Tg` (read it before assembling a PRD; it evolves).
- PRDs folder id: `1kdHw7oawKulPCvF-yXLga3kpHkV404uR`; one subfolder per project.
- Create `<Project> — PRD` via `create_file` with `contentMimeType: text/markdown` from `docs/prd.md`. Drive can't
  edit in place: on change, create `<Project> — PRD (rev N)` and update the Notion link.
- `docs/prd.md` in the repo is the source of truth; the Doc is a projection for readers who live in Drive.
