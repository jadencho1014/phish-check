import { describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { analyzeEmail, combine, combineWithLlm } from "./analyze";
import type { ResponsesClient } from "./llm";
import type { Signal } from "./types";

// Pure combine() tests: Signal[] -> rules-floor Verdict. See CLAUDE.md's
// "Combine" rule. No fixtures/LLM involved - synthetic signals only.

function sig(id: Signal["id"], severity: Signal["severity"]): Signal {
  return { id, severity, evidence: "synthetic evidence for combine() test" };
}

describe("combine", () => {
  it("a critical signal alone -> phishing", () => {
    expect(combine([sig("LINK_MISMATCH", "critical")])).toBe("phishing");
  });

  it("two high signals -> phishing", () => {
    expect(combine([sig("AUTH_FAIL", "high"), sig("LOOKALIKE_DOMAIN", "high")])).toBe("phishing");
  });

  it("one high + one medium -> phishing", () => {
    expect(combine([sig("AUTH_FAIL", "high"), sig("REPLY_TO_MISMATCH", "medium")])).toBe("phishing");
  });

  it("exactly one high signal alone -> suspicious", () => {
    expect(combine([sig("AUTH_FAIL", "high")])).toBe("suspicious");
  });

  it("two medium signals -> suspicious", () => {
    expect(
      combine([sig("REPLY_TO_MISMATCH", "medium"), sig("INTERNAL_IMPERSONATION", "medium")]),
    ).toBe("suspicious");
  });

  it("no signals, or only a trust signal -> likely_safe", () => {
    expect(combine([])).toBe("likely_safe");
    expect(combine([sig("AUTH_ALIGNED_PASS", "trust")])).toBe("likely_safe");
  });

  it("floor never lowered: a trust signal alongside a high signal keeps the high floor", () => {
    expect(combine([sig("AUTH_ALIGNED_PASS", "trust"), sig("AUTH_FAIL", "high")])).toBe(
      "suspicious",
    );
  });
});

// combineWithLlm(): reconciling the rules-only floor with the LLM's verdict
// (or null when llm.ts falls back, per CLAUDE.md's "LLM" paragraph). The LLM
// can only raise, never lower, the floor.
describe("combineWithLlm", () => {
  it("the LLM cannot lower the rules floor (suspicious floor, likely_safe from LLM -> suspicious)", () => {
    expect(combineWithLlm("suspicious", "likely_safe")).toBe("suspicious");
  });

  it("the LLM can raise the rules floor (likely_safe floor, phishing from LLM -> phishing)", () => {
    expect(combineWithLlm("likely_safe", "phishing")).toBe("phishing");
  });

  it("a null LLM verdict (fallback: no key, invalid response, or timeout) keeps the floor as-is", () => {
    expect(combineWithLlm("suspicious", null)).toBe("suspicious");
  });
});

// analyzeEmail(): the full parse -> signals -> llm -> combine pipeline
// (slice 8, docs/PLAN.md #8). The client is injected, exactly like
// llm.test.ts's fakes - these tests never touch the network. route.test.ts
// covers the HTTP-level concerns (passcode, body-size limit, and the
// "no OPENAI_API_KEY -> rules-only" env-driven path, which needs no LLM
// mock at all); the mocked-LLM orchestration itself is tested here,
// unit-style, since route.ts has no test-only seam for injecting a fake
// client into a real request (by design - it only ever builds a real
// `openai` client from OPENAI_API_KEY in production).
function fakeClient(outputText: string): ResponsesClient {
  return {
    responses: {
      create: vi.fn().mockResolvedValue({ output_text: outputText }),
    },
  };
}

// Inline synthetic .eml source, different names/domains from both the
// fixtures and llm.test.ts's fakes, so this can't be sample-specific.
// One AUTH_FAIL signal -> rules floor "suspicious" (see combine() above).
const SUSPICIOUS_FLOOR_RAW = [
  'From: "Helpdesk" <helpdesk@south-ridge-tools.example>',
  "To: ops@driftwood-cabinetry.example",
  "Subject: Action required on your ticket",
  "Authentication-Results: mx.driftwood-cabinetry.example; spf=fail smtp.mailfrom=south-ridge-tools.example; dkim=fail; dmarc=fail",
  "MIME-Version: 1.0",
  'Content-Type: text/plain; charset="utf-8"',
  "",
  "Please review the attached ticket update at your convenience.",
  "",
].join("\r\n");

describe("analyzeEmail", () => {
  it("end-to-end with a mocked LLM: the LLM's verdict/reasons/actions raise the rules floor", async () => {
    const client = fakeClient(
      JSON.stringify({
        verdict: "phishing",
        reasons: [{ title: "Credential harvest", explanation: "Asks to review a fake ticket." }],
        actions: ["Do not click any links; report to IT."],
      }),
    );

    const result = await analyzeEmail(SUSPICIOUS_FLOOR_RAW, { client });

    expect(result.verdict).toBe("phishing");
    expect(result.reasons).toEqual([
      { title: "Credential harvest", explanation: "Asks to review a fake ticket." },
    ]);
    expect(result.actions).toEqual(["Do not click any links; report to IT."]);
  });

  it("no client available (no OPENAI_API_KEY) -> rules-only result that says so", async () => {
    const result = await analyzeEmail(SUSPICIOUS_FLOOR_RAW);

    // The rules floor alone (one AUTH_FAIL, high severity) is "suspicious";
    // with no LLM to raise it, the final verdict must equal the floor.
    expect(result.verdict).toBe("suspicious");
    expect(result.reasons.length).toBeGreaterThan(0);
    expect(result.reasons.some((r) => /rules-only/i.test(r.title))).toBe(true);
    expect(result.actions.length).toBeGreaterThan(0);
  });

  it("negative: a real legit sample with an advisory-worthy LLM verdict is not over-escalated", async () => {
    // fixtures/samples/email-18.eml: genuine GitHub SSH-key notice, aligned
    // auth, no rule signals beyond AUTH_ALIGNED_PASS (trust) -> floor is
    // likely_safe. Using a real fixture here (not synthetic) because this is
    // specifically the "genuine account-activity notice" scenario CLAUDE.md
    // and docs/PLAN.md #8 describe; reading fixtures in a test is normal
        // fixture usage (see fixtures.test.ts), not the overfitting src/ leak.

    const raw = fs.readFileSync(
      path.join(process.cwd(), "fixtures/samples/email-18.eml"),
      "utf8",
    );
    const client = fakeClient(
      JSON.stringify({
        verdict: "likely_safe",
        reasons: [{ title: "Account activity notice", explanation: "A new SSH key was added." }],
        actions: ["If this wasn't you, sign in directly and remove the key."],
        advisory: "If you did not add this key, go to github.com directly and secure your account.",
      }),
    );

    const result = await analyzeEmail(raw, { client });

    expect(result.verdict).toBe("likely_safe");
    expect(result.advisory).toBe(
      "If you did not add this key, go to github.com directly and secure your account.",
    );
  });
});
