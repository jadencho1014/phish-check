import { describe, expect, it } from "vitest";
import { combine } from "./analyze";
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
