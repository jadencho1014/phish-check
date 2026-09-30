// POST /api/analyze — see CLAUDE.md's "Files" and "Security" sections.
// Request contract (decided by route.test.ts, slice 8): JSON body
// `{ raw: string }` (the raw .eml/email source), optional passcode via the
// `x-app-passcode` header when APP_PASSCODE is configured. Response body is
// an AnalysisResult (see src/lib/types.ts) on success.
//
// Deliberately no test-only seam for injecting a fake LLM client into a real
// request: in production this route only ever constructs a real `openai`
// client when OPENAI_API_KEY is set, and passes it to analyzeEmail (see
// src/lib/analyze.ts). Route-level tests therefore cover passcode checks,
// the 4MB body limit, and the "no OPENAI_API_KEY -> rules-only" path (which
// needs no LLM mock at all, since no client is constructed); the mocked-LLM
// orchestration itself is unit-tested directly against analyzeEmail in
// src/lib/analyze.test.ts.
//
// Stub only for now (slice 8 test-writer pass) - implementer wires this up
// to analyzeEmail in the next commit.

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(_request: Request): Promise<Response> {
  throw new Error("not implemented");
}
