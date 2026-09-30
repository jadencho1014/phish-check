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

import OpenAI from "openai";
import { z } from "zod";
import { analyzeEmail } from "../../../lib/analyze";
import type { ResponsesClient } from "../../../lib/llm";

export const runtime = "nodejs";
export const maxDuration = 60;

const MAX_BODY_BYTES = 4 * 1024 * 1024;

const requestBodySchema = z.object({
  raw: z.string(),
});

export async function POST(request: Request): Promise<Response> {
  // Fast-path rejection when the transport layer reports an oversized body
  // up front (real HTTP servers set this; not relied on alone since it's
  // absent in some environments, e.g. this project's own tests).
  const contentLength = request.headers.get("content-length");
  if (contentLength && Number(contentLength) > MAX_BODY_BYTES) {
    return Response.json({ error: "Request body too large" }, { status: 413 });
  }

  const bodyText = await request.text();

  let bodyJson: unknown;
  try {
    bodyJson = JSON.parse(bodyText);
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const parsedBody = requestBodySchema.safeParse(bodyJson);
  if (!parsedBody.success) {
    return Response.json({ error: "Invalid request body" }, { status: 400 });
  }

  const { raw } = parsedBody.data;
  if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) {
    return Response.json({ error: "Request body too large" }, { status: 413 });
  }

  const passcode = process.env.APP_PASSCODE;
  if (passcode) {
    const providedPasscode = request.headers.get("x-app-passcode");
    if (providedPasscode !== passcode) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }
  }

  // The real SDK's `.responses.create` has a much more specific parameter
  // type than ResponsesClient's structural `Record<string, unknown>`, so
  // TypeScript won't accept it as a plain structural match; it satisfies the
  // interface at runtime (same shape, a superset of methods/fields), so the
  // cast here is a deliberate, narrow bridge between the real SDK type and
  // this project's minimal client interface (see llm.ts).
  const apiKey = process.env.OPENAI_API_KEY;
  const client: ResponsesClient | undefined = apiKey
    ? (new OpenAI({ apiKey }) as unknown as ResponsesClient)
    : undefined;

  const result = await analyzeEmail(raw, { client });

  return Response.json(result);
}
