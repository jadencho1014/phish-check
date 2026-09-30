import { describe, expect, it } from "vitest";
import { parseEmail } from "./parse";
import { detectSignals } from "./signals";

// Inline synthetic .eml sources (not fixtures/samples) so these rules can't
// be fixture-specific. Only Authentication-Results / From / Reply-To / To
// matter for this slice; bodies are minimal filler text.

function buildRaw(headers: string[], body = "Hello,\r\n\r\nJust a quick note.\r\n"): string {
  return [...headers, "MIME-Version: 1.0", 'Content-Type: text/plain; charset="utf-8"', "", body].join(
    "\r\n",
  );
}

async function signalsFor(headers: string[]) {
  const parsed = await parseEmail(buildRaw(headers));
  return detectSignals(parsed);
}

function ids(signals: { id: string }[]): string[] {
  return signals.map((s) => s.id);
}

describe("detectSignals - auth + reply-to (slice 3)", () => {
  it("spf=softfail on the topmost Authentication-Results -> AUTH_FAIL (high)", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.riverton-outfitters.example; spf=softfail smtp.mailfrom=cobalt-freight.example; dkim=pass header.d=cobalt-freight.example; dmarc=pass header.from=cobalt-freight.example",
      'From: "Cobalt Freight Billing" <billing@cobalt-freight.example>',
      "To: ops@riverton-outfitters.example",
      "Subject: Invoice #4471",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    const authFail = signals.find((s) => s.id === "AUTH_FAIL");
    expect(authFail).toBeDefined();
    expect(authFail?.severity).toBe("high");
  });

  it("dkim=fail on the topmost Authentication-Results -> AUTH_FAIL (high)", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.riverton-outfitters.example; spf=pass smtp.mailfrom=cobalt-freight.example; dkim=fail header.d=cobalt-freight.example; dmarc=pass header.from=cobalt-freight.example",
      'From: "Cobalt Freight Billing" <billing@cobalt-freight.example>',
      "To: ops@riverton-outfitters.example",
      "Subject: Invoice #4471",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    const authFail = signals.find((s) => s.id === "AUTH_FAIL");
    expect(authFail).toBeDefined();
    expect(authFail?.severity).toBe("high");
  });

  it("dmarc=fail on the topmost Authentication-Results -> AUTH_FAIL (high), no AUTH_ALIGNED_PASS", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.riverton-outfitters.example; spf=pass smtp.mailfrom=cobalt-freight.example; dkim=pass header.d=cobalt-freight.example; dmarc=fail header.from=cobalt-freight.example",
      'From: "Cobalt Freight Billing" <billing@cobalt-freight.example>',
      "To: ops@riverton-outfitters.example",
      "Subject: Invoice #4471",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    expect(ids(signals)).toContain("AUTH_FAIL");
    expect(ids(signals)).not.toContain("AUTH_ALIGNED_PASS");
    const authFail = signals.find((s) => s.id === "AUTH_FAIL");
    expect(authFail?.severity).toBe("high");
  });

  it("dmarc=pass aligned with From domain -> AUTH_ALIGNED_PASS (trust), no AUTH_FAIL", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.riverton-outfitters.example; spf=pass smtp.mailfrom=cobalt-freight.example; dkim=pass header.d=cobalt-freight.example; dmarc=pass header.from=cobalt-freight.example",
      'From: "Cobalt Freight Billing" <billing@cobalt-freight.example>',
      "To: ops@riverton-outfitters.example",
      "Subject: Invoice #4471",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    const aligned = signals.find((s) => s.id === "AUTH_ALIGNED_PASS");
    expect(aligned).toBeDefined();
    expect(aligned?.severity).toBe("trust");
    expect(ids(signals)).not.toContain("AUTH_FAIL");
  });

  it("Reply-To registrable domain != From registrable domain -> REPLY_TO_MISMATCH (medium)", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.riverton-outfitters.example; spf=pass smtp.mailfrom=cobalt-freight.example; dkim=pass header.d=cobalt-freight.example; dmarc=pass header.from=cobalt-freight.example",
      'From: "Cobalt Freight Billing" <billing@cobalt-freight.example>',
      "Reply-To: payouts@attacker-mail.example",
      "To: ops@riverton-outfitters.example",
      "Subject: Invoice #4471",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    const mismatch = signals.find((s) => s.id === "REPLY_TO_MISMATCH");
    expect(mismatch).toBeDefined();
    expect(mismatch?.severity).toBe("medium");
  });

  it("negative: ESP subdomain sender (em42.brand) with aligned dmarc pass -> AUTH_ALIGNED_PASS, no AUTH_FAIL", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.riverton-outfitters.example; spf=pass smtp.mailfrom=em42.cobalt-freight.example; dkim=pass header.d=cobalt-freight.example; dmarc=pass header.from=em42.cobalt-freight.example",
      'From: "Cobalt Freight Notifications" <notify@em42.cobalt-freight.example>',
      "To: ops@riverton-outfitters.example",
      "Subject: Your monthly statement is ready",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    expect(ids(signals)).toContain("AUTH_ALIGNED_PASS");
    expect(ids(signals)).not.toContain("AUTH_FAIL");
  });

  it("negative: Reply-To on a different subdomain of the same registrable domain -> no REPLY_TO_MISMATCH", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.riverton-outfitters.example; spf=pass smtp.mailfrom=sales.cobalt-freight.example; dkim=pass header.d=cobalt-freight.example; dmarc=pass header.from=sales.cobalt-freight.example",
      'From: "Cobalt Freight Sales" <sales@sales.cobalt-freight.example>',
      "Reply-To: support@help.cobalt-freight.example",
      "To: ops@riverton-outfitters.example",
      "Subject: Invoice #4471",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    expect(ids(signals)).not.toContain("REPLY_TO_MISMATCH");
  });

  it("only the topmost Authentication-Results header is used when there are multiple (pass then fail)", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.riverton-outfitters.example; spf=pass smtp.mailfrom=cobalt-freight.example; dkim=pass header.d=cobalt-freight.example; dmarc=pass header.from=cobalt-freight.example",
      "Authentication-Results: mx.other-relay.example; spf=fail smtp.mailfrom=cobalt-freight.example; dkim=fail header.d=cobalt-freight.example; dmarc=fail header.from=cobalt-freight.example",
      'From: "Cobalt Freight Billing" <billing@cobalt-freight.example>',
      "To: ops@riverton-outfitters.example",
      "Subject: Invoice #4471",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    expect(ids(signals)).toContain("AUTH_ALIGNED_PASS");
    expect(ids(signals)).not.toContain("AUTH_FAIL");
  });

  it("only the topmost Authentication-Results header is used when there are multiple (fail then pass)", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.riverton-outfitters.example; spf=fail smtp.mailfrom=cobalt-freight.example; dkim=fail header.d=cobalt-freight.example; dmarc=fail header.from=cobalt-freight.example",
      "Authentication-Results: mx.other-relay.example; spf=pass smtp.mailfrom=cobalt-freight.example; dkim=pass header.d=cobalt-freight.example; dmarc=pass header.from=cobalt-freight.example",
      'From: "Cobalt Freight Billing" <billing@cobalt-freight.example>',
      "To: ops@riverton-outfitters.example",
      "Subject: Invoice #4471",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    expect(ids(signals)).toContain("AUTH_FAIL");
    expect(ids(signals)).not.toContain("AUTH_ALIGNED_PASS");
  });
});
