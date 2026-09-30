import { describe, expect, it, vi } from "vitest";
import { callLlm } from "./llm";
import type { LlmInput, ResponsesClient } from "./llm";

// llm.ts wraps the OpenAI Responses API (gpt-6-luna) behind an injected
// client (see CLAUDE.md's "LLM" paragraph), so these tests never touch the
// network or need OPENAI_API_KEY. The fake client below is a plain object
// literal implementing only the `.responses.create` surface llm.ts uses -
// never the real 'openai' package. Names/domains here are generic synthetic
// placeholders, distinct from anything in fixtures/samples.

function fakeInput(overrides: Partial<LlmInput> = {}): LlmInput {
  return {
    headersSummary: "From: billing@northgate-supply.example\nTo: ap@rivermere-foods.example",
    authResults: "spf=pass dkim=pass dmarc=pass",
    text: "Please update our remittance account for future invoices.",
    links: [
      {
        text: "https://northgate-supply.example/pay",
        href: "https://northgate-supply.example/pay",
      },
    ],
    attachments: [],
    signals: [],
    recipientDomain: "rivermere-foods.example",
    ...overrides,
  };
}

function fakeClient(create: ReturnType<typeof vi.fn>): ResponsesClient {
  return { responses: { create } };
}

describe("callLlm", () => {
  it("parses a valid structured response into an AnalysisResult", async () => {
    const create = vi.fn().mockResolvedValue({
      output_text: JSON.stringify({
        verdict: "phishing",
        reasons: [
          { title: "Payment change request", explanation: "Asks to redirect remittance." },
        ],
        actions: ["Verify by phone before changing payment details."],
      }),
    });

    const result = await callLlm(fakeClient(create), fakeInput());

    expect(result).toEqual({
      verdict: "phishing",
      reasons: [{ title: "Payment change request", explanation: "Asks to redirect remittance." }],
      actions: ["Verify by phone before changing payment details."],
    });
  });

  it("falls back to null when the response violates the schema (bad enum, missing reasons)", async () => {
    const create = vi.fn().mockResolvedValue({
      output_text: JSON.stringify({
        verdict: "extremely_phishy", // not a valid Verdict enum value
        actions: ["do something"],
        // `reasons` is missing entirely
      }),
    });

    const result = await callLlm(fakeClient(create), fakeInput());
    expect(result).toBeNull();
  });

  it("falls back to null (never throws) when the client call rejects, e.g. a timeout", async () => {
    const create = vi.fn().mockRejectedValue(new Error("simulated timeout"));

    await expect(callLlm(fakeClient(create), fakeInput())).resolves.toBeNull();
  });

  it("calls the Responses API with gpt-6-luna, low reasoning effort, and a json_schema text format", async () => {
    const create = vi.fn().mockResolvedValue({
      output_text: JSON.stringify({ verdict: "likely_safe", reasons: [], actions: [] }),
    });

    await callLlm(fakeClient(create), fakeInput());

    expect(create).toHaveBeenCalledTimes(1);
    const args = create.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(args.model).toBe("gpt-6-luna");
    expect((args.reasoning as { effort?: string } | undefined)?.effort).toBe("low");
    const format = (args.text as { format?: { type?: string } } | undefined)?.format;
    expect(format?.type).toBe("json_schema");
  });
});
