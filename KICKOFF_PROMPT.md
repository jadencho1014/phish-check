Build **Phish Check**: a web app where someone pastes an email's raw source (or drops a `.eml`) and gets a verdict — phishing, suspicious, or likely safe — with plain-language reasons and what to do next. Deploy it on Vercel. It will be tested on emails none of us have seen, so it must generalize rather than fit the samples.

**Time budget: about one hour for the whole project.** Keep it lean, and don't add anything CLAUDE.md doesn't ask for.

Stack: TypeScript (strict), Next.js App Router, Tailwind, mailparser, tldts, zod, the openai SDK calling `gpt-6-luna` through the Responses API with structured output, Vitest, and Vercel.

Read `CLAUDE.md` first; it's the spec. The samples are in `fixtures/samples/` and the expected results are in `fixtures/labels.json`. Treat the samples as real emails exactly as they arrived. Their domains and links may not be live, so never fetch them.

Work as an orchestrator, using the subagents in `.claude/agents/`:
1. Have `planner` write `docs/PLAN.md`. Show me a 5-line summary, then continue without waiting unless something's unclear.
2. For each slice, `test-writer` writes failing tests, then `implementer` makes them pass. Commit after each step.
3. Run `reviewer` after milestone 2 and before deploying, and fix any BLOCKERs.
4. At milestone 5, tell me the exact commands to run to log in to Vercel, link the project, and set `OPENAI_API_KEY` and optionally `APP_PASSCODE` (`OPENAI_MODEL` is optional and defaults to `gpt-6-luna`). Don't ask me for the key. After I confirm, deploy with `vercel --prod` and run `npm run analyze -- fixtures/samples/*.eml --url <prod-url>` to smoke-test it.

At the end, give me the URL and a one-line result for each sample.
