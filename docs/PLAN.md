# PLAN — Phish Check (TDD slices)

APIs confirmed: `mailparser` → `simpleParser(source)` returns `Promise<ParsedMail>`
(`headers` Map, `text`, `html`, `attachments[]` w/ filename/contentType/size,
`from`/`to` AddressObject). `tldts` → `getDomain(host)` / `parse(host)` gives
registrable domain (`domain`, `subdomain`, `publicSuffix`). OpenAI Responses API
structured output: `text.format = { type: "json_schema", name, schema, strict }`
on `client.responses.create({ model, input, text, reasoning: { effort } })`.
`gpt-6-luna` runs on the Responses API; `reasoning.effort` accepts
`none|low|medium|high|xhigh|max` — we use `low`.

## Milestone 1 — Scaffold
- [ ] **1. Project scaffold** — Next.js (App Router, TS strict) + Tailwind + Vitest + typecheck script boot.
  Tests: `npm run typecheck` and `npm run test` pass on a trivial sanity spec; `types.ts` skeleton compiles.
- [ ] **2. `parse.ts`** — raw `.eml` string → `ParsedEmail` (ordered headers, text+html parts, `links{text,href}`, attachment metadata).
  Tests: preserves duplicate/ordered headers; extracts text and html bodies separately; pulls anchor `{text,href}` pairs from html; reads attachment filename/type/size. Negative: text-only email (no html part) parses with empty `links` and no crash.

## Milestone 2 — Rules (`signals.ts`, `brands.ts`, `analyze.ts` combine)
- [ ] **3. Auth + Reply-To signals** — `AUTH_FAIL`, `AUTH_ALIGNED_PASS`, `REPLY_TO_MISMATCH` using `tldts` + topmost `Authentication-Results`.
  Tests: spf/dkim/dmarc fail → `AUTH_FAIL`; dmarc pass aligned → `AUTH_ALIGNED_PASS`; Reply-To domain ≠ From domain → `REPLY_TO_MISMATCH`. Negative (look-alike): ESP subdomain (`em123.brand.com`) with aligned dmarc pass does **not** raise `AUTH_FAIL`; Reply-To on the same registrable domain (different subdomain) does **not** raise `REPLY_TO_MISMATCH`.
- [ ] **4. Impersonation signals** — `brands.ts` table + `LOOKALIKE_DOMAIN`, `INTERNAL_IMPERSONATION`.
  Tests: brand token in sender domain (hyphen-normalized, e.g. `docusign-notify.net`) → `LOOKALIKE_DOMAIN`; display name claims a brand from a non-brand domain → same; body footer shares a distinctive token with sender domain but different registrable domain → same. From display name contains a ≥4-char word from recipient's own domain but sender is external → `INTERNAL_IMPERSONATION`. Negative: brand's real subdomain (`em.docusign.net`) → no signal; unrelated third-party domain mentioned in body (no shared token) → no signal; internal sender whose domain *is* the recipient's own → no `INTERNAL_IMPERSONATION`.
- [ ] **5. Link/payment/attachment signals + combine()** — `LINK_MISMATCH`, `PAYMENT_CHANGE_REQUEST`, `RISKY_ATTACHMENT`, and verdict combiner.
  Tests: link text domain ≠ href registrable domain, or text/html parts disagree → `LINK_MISMATCH`; bank/wire/gift-card change language → `PAYMENT_CHANGE_REQUEST` (medium, escalates to high with `REPLY_TO_MISMATCH`); `.exe`/`.iso`/`.docm`/double-extension attachment → `RISKY_ATTACHMENT`. `combine()`: critical→phishing; ≥2 high or high+medium→phishing; 1 high or ≥2 medium→suspicious; floor never lowered. Negative: tracker link where text has no domain (e.g. "Click here") → no `LINK_MISMATCH`; invoice mentioning normal payment terms (no change requested) → no `PAYMENT_CHANGE_REQUEST`; plain `.pdf`/`.docx` attachment → no `RISKY_ATTACHMENT`.
- [ ] **6. Fixture floor test** — run rules over all `fixtures/samples/*.eml` against `labels.json`.
  Tests: every sample's `mustHave`/`mustNotHave` signals present/absent; rules-only verdict never calls a phishing sample `likely_safe`, nor a legit sample worse than `likely_safe`.
  *(→ reviewer pass #1 here: correctness/overfitting/security, per CLAUDE.md workflow.)*

## Milestone 3 — LLM + API
- [ ] **7. `llm.ts`** — Responses API call (`gpt-6-luna`, `reasoning.effort: low`) with injected client + zod-validated JSON-schema output.
  Tests (mocked client): valid structured response parses to `AnalysisResult` shape; invalid/schema-violating response → falls back to rules-only; simulated timeout → falls back to rules-only; LLM verdict can raise but never lower the rules floor.
- [ ] **8. `analyze.ts` + `route.ts`** — parse → signals → llm → combine; passcode check, body-size limit, `maxDuration = 60`.
  Tests: end-to-end with mocked LLM returns combined result; missing/no `OPENAI_API_KEY` returns rules-only with a note; `APP_PASSCODE` set → request without/with wrong passcode is rejected, correct passcode passes; oversized body (>4MB) rejected. Negative: a legit sample with passing auth and a genuine advisory-worthy notice still resolves to `likely_safe` (LLM doesn't over-escalate benign account-activity emails).

## Milestone 4 — UI + batch script
- [ ] **9. `page.tsx` + `scripts/analyze.ts`** — textarea/`.eml` picker, verdict banner, defanged non-clickable links, collapsible details; batch script hitting local `analyze()` or a deployed `--url`.
  Tests: link-defanging helper turns `https://x.com` into `hxxps://x[.]com`; page renders text only (no raw HTML injected) even when the email has an html part; "no headers provided" pasted body shows the sender-unverified notice; batch script reads multiple `.eml` files and prints a verdict per file without network calls when no `--url` given.

## Milestone 5 — Deploy
- [ ] **10. Deploy** — human runs `vercel login`, sets `OPENAI_API_KEY` (+ optional `OPENAI_MODEL`/`APP_PASSCODE`), `vercel --prod`, then `npm run analyze -- fixtures/samples/*.eml --url <prod>`.
  No new automated tests; smoke-check the batch run output against `labels.json` `acceptable` verdicts.
  *(→ reviewer pass #2 here: correctness/overfitting/security, before/at deploy.)*

## Cross-cutting (verify once, not a separate slice)
- [ ] Overfitting grep test: no fixture company/vendor/person/domain tokens appear anywhere in `src/`.
