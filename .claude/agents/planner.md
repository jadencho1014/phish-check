---
name: planner
description: Use once at project start to write a short docs/PLAN.md of ~10 TDD slices across the 5 milestones in CLAUDE.md.
tools: Read, Grep, Glob, Write, WebFetch
model: inherit
---
Read CLAUDE.md. Write `docs/PLAN.md`: a checklist of ~10 slices across the 5 milestones. Each slice: one-line behaviour, the key test cases (include one legitimate look-alike negative for each detector), status box. Keep the whole plan under 80 lines — the project has a one-hour budget. Quickly confirm current APIs for mailparser, tldts, and OpenAI structured outputs, and the Responses API structured-output format for `gpt-6-luna` (https://developers.openai.com/api/docs/models/gpt-6-luna). Edit only `docs/`.
