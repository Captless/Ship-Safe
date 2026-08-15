# Ship Safe — Agent Instructions

## Project

Ship Safe is a lightweight, beginner-friendly pre-launch code scanner.

Current architecture and data flow are documented in:

    DOCS/codemap.md

The current local source code is always the final source of truth.

---

## Before Planning

1. Read this file.
2. Read `DOCS/codemap.md`.
3. Identify the parts of the codebase relevant to the requested change.
4. Inspect those relevant files and their tests.
5. Do NOT scan the entire repository unless the change genuinely
   requires it or the codemap is insufficient/outdated.

Use the codemap to narrow the inspection scope, not as a replacement
for checking the actual code.

---

## Architecture Rules

- Reuse the existing architecture whenever possible.
- Modify existing files before creating new ones.
- Do not create duplicate modules, renderers, components, scanners,
  APIs, state systems, or prompt generators.
- Do not assume file paths, functions, or architecture that are not
  present.
- Keep changes focused on the requested feature.
- Avoid unnecessary dependencies or frameworks.
- Do not perform unrelated refactoring.

---

## Planning

Implementation plans must be based on the current local codebase.

Plans should document:

- actual files involved
- relevant functions/components
- current data flow
- proposed changes
- tests
- acceptance criteria
- things that must not change

The plan should contain the codebase knowledge discovered during
planning so the implementation agent does not need to repeat the
planning process.

---

## Scanner

Ship Safe's scanner is deterministic.

Unless explicitly approved:

- do not add LLM calls
- do not add AI APIs
- do not add token-consuming scan processing
- do not change scanner behavior during unrelated UI work
- do not change scoring/severity semantics without an explicit plan

---

## Security

Never expose secrets such as:

- API keys
- passwords
- tokens
- credentials
- private keys

Preserve existing redaction when displaying findings or generating
AI-fix prompts.

---

## UI

Keep the product beginner-friendly.

Prefer:

    What happened?
    Why does it matter?
    What should I do?

over technical terminology in the primary UI.

Keep technical information available through progressive disclosure
when appropriate.

Preserve accessibility and responsive behavior.

---

## Documentation

`AGENTS.md` contains stable project-wide agent rules.

`DOCS/codemap.md` contains architecture information.

Update the codemap when a change materially changes architecture,
data flow, or important file relationships.

Do not update either file for ordinary feature work unless necessary.

---

## Implementation

Follow the approved implementation plan.

Use the current local codebase.

Make the smallest appropriate change.

Run relevant tests and inspect the final diff.

Do not automatically commit.

---

## Source-of-Truth Priority

When information conflicts, use this priority:

1. Current source code
2. Current tests
3. Current implementation plan
4. `DOCS/codemap.md`
5. Older documentation/plans
6. Assumptions

Never invent architecture to fill a gap.