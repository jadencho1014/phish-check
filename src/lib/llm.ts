// OpenAI call with an injected client. See CLAUDE.md's "LLM" paragraph:
// model gpt-6-luna via the Responses API (not Chat Completions), a
// json_schema text format for structured output, reasoning.effort "low",
// model name read from OPENAI_MODEL (default gpt-6-luna). The client is a
// constructor parameter (not built here) so tests can inject a fake object
// implementing just `.responses.create` without any network access or
// OPENAI_API_KEY. Combining the parsed AnalysisResult with the rules floor is
// analyze.ts's job (see combineWithLlm in analyze.ts), not this module's.
//
// Full request construction / parsing / zod validation lands with the
// analyze.ts + route.ts wiring (slice 8); this is the stub signature slice 7
// tests against.

import { z } from "zod";
import type { AnalysisResult, Signal } from "./types";

export const analysisResultSchema = z.object({
  verdict: z.enum(["phishing", "suspicious", "likely_safe"]),
  reasons: z.array(z.object({ title: z.string(), explanation: z.string() })),
  actions: z.array(z.string()),
  advisory: z.string().optional(),
});

export interface LlmLinkPair {
  text: string;
  href: string;
}

export interface LlmAttachment {
  filename: string;
  contentType: string;
  size: number;
}

export interface LlmInput {
  headersSummary: string;
  authResults: string;
  text: string;
  links: LlmLinkPair[];
  attachments: LlmAttachment[];
  signals: Signal[];
  recipientDomain: string;
}

// Minimal shape of the openai SDK's Responses API surface this module needs.
// Real usage: `new OpenAI().responses` satisfies this; tests inject a fake
// object literal instead.
export interface ResponsesClient {
  responses: {
    create: (params: Record<string, unknown>) => Promise<{ output_text?: string }>;
  };
}

export async function callLlm(
  _client: ResponsesClient,
  _input: LlmInput,
): Promise<AnalysisResult | null> {
  throw new Error("not implemented");
}
