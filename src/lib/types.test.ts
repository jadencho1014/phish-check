import { describe, expect, it } from "vitest";
import type {
  AnalysisResult,
  ParsedEmail,
  Signal,
  SignalSeverity,
  Verdict,
} from "./types";

const ALLOWED_SEVERITIES: SignalSeverity[] = [
  "trust",
  "medium",
  "high",
  "critical",
];
const ALLOWED_VERDICTS: Verdict[] = ["phishing", "suspicious", "likely_safe"];

describe("types skeleton", () => {
  it("builds a ParsedEmail with ordered headers, parts, links and attachments", () => {
    const email: ParsedEmail = {
      headers: [
        { key: "From", value: "sender@example.com" },
        { key: "To", value: "recipient@example.org" },
      ],
      text: "hello",
      html: "<p>hello</p>",
      links: [{ text: "click here", href: "https://example.com" }],
      attachments: [
        { filename: "invoice.pdf", contentType: "application/pdf", size: 100 },
      ],
    };

    // headers must preserve insertion order (From before To)
    expect(email.headers.map((h) => h.key)).toEqual(["From", "To"]);
    expect(email.links).toHaveLength(1);
    expect(email.links[0]?.href).toBe("https://example.com");
    expect(email.attachments[0]?.filename).toBe("invoice.pdf");
  });

  it("only allows known signal severities", () => {
    const signal: Signal = {
      id: "AUTH_FAIL",
      severity: "high",
      evidence: "spf=fail",
    };

    expect(ALLOWED_SEVERITIES).toContain(signal.severity);
  });

  it("only allows known verdicts on an AnalysisResult", () => {
    const result: AnalysisResult = {
      verdict: "suspicious",
      reasons: [{ title: "Auth failed", explanation: "spf/dmarc failed" }],
      actions: ["Do not click any links"],
    };

    expect(ALLOWED_VERDICTS).toContain(result.verdict);
    expect(result.reasons[0]?.title).toBe("Auth failed");
  });
});
