import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { POST } from "./route";

// HTTP-level concerns only (slice 8, docs/PLAN.md #8): passcode gating, the
// 4MB body-size limit, and the "no OPENAI_API_KEY -> rules-only" path (which
// needs no LLM mock at all - route.ts never constructs a real `openai`
// client when the key is absent, so analyzeEmail runs with no client and
// naturally falls back, per CLAUDE.md's "If the LLM fails or there's no
// key, return the rules-only result and say so"). The mocked-LLM
// orchestration itself (combining a fake client's verdict with the rules
// floor, and the advisory-non-escalation negative case) is unit-tested
// directly against analyzeEmail in src/lib/analyze.test.ts instead, since
// route.ts deliberately has no test-only seam for injecting a fake client
// into a real request.
//
// Inline synthetic .eml source, different names/domains from both
// fixtures/samples and other test files, so this can't be sample-specific.
const SYNTHETIC_RAW = [
  'From: "Notices" <notices@lakeview-parts.example>',
  "To: buyer@thornfield-supply.example",
  "Subject: Your order has shipped",
  "MIME-Version: 1.0",
  'Content-Type: text/plain; charset="utf-8"',
  "",
  "Your order #4821 has shipped and will arrive in 3-5 business days.",
  "",
].join("\r\n");

function makeRequest(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/analyze", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

const ENV_KEYS = ["OPENAI_API_KEY", "APP_PASSCODE"] as const;
let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = {};
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

describe("POST /api/analyze", () => {
  it("no OPENAI_API_KEY configured -> 200 with a rules-only result that says so", async () => {
    const response = await POST(makeRequest({ raw: SYNTHETIC_RAW }));

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.verdict).toBe("likely_safe");
    expect(
      (body.reasons as { title: string }[]).some((r) => /rules-only/i.test(r.title)),
    ).toBe(true);
  });

  it("APP_PASSCODE set, no passcode header -> rejected", async () => {
    process.env.APP_PASSCODE = "sunset-harbor-42";

    const response = await POST(makeRequest({ raw: SYNTHETIC_RAW }));

    expect(response.status).toBe(401);
  });

  it("APP_PASSCODE set, wrong passcode header -> rejected", async () => {
    process.env.APP_PASSCODE = "sunset-harbor-42";

    const response = await POST(
      makeRequest({ raw: SYNTHETIC_RAW }, { "x-app-passcode": "wrong-guess" }),
    );

    expect(response.status).toBe(401);
  });

  it("APP_PASSCODE set, correct passcode header -> processed normally", async () => {
    process.env.APP_PASSCODE = "sunset-harbor-42";

    const response = await POST(
      makeRequest({ raw: SYNTHETIC_RAW }, { "x-app-passcode": "sunset-harbor-42" }),
    );

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.verdict).toBe("likely_safe");
  });

  it("oversized body (>4MB raw email string) -> rejected", async () => {
    const oversizedRaw = "a".repeat(4 * 1024 * 1024 + 1024);

    const response = await POST(makeRequest({ raw: oversizedRaw }));

    expect(response.status).toBe(413);
  });
});
