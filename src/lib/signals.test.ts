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

async function signalsFor(headers: string[], body?: string) {
  const parsed = await parseEmail(body === undefined ? buildRaw(headers) : buildRaw(headers, body));
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

describe("detectSignals - impersonation (slice 4)", () => {
  it("brand token in sender domain, hyphen-normalized -> LOOKALIKE_DOMAIN (high)", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.unrelated-recipient.example; spf=pass smtp.mailfrom=docusign-notify.net; dkim=pass header.d=docusign-notify.net; dmarc=pass header.from=docusign-notify.net",
      'From: "DocuSign" <notify@docusign-notify.net>',
      "To: pat@unrelated-recipient.example",
      "Subject: You have a document waiting",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    const lookalike = signals.find((s) => s.id === "LOOKALIKE_DOMAIN");
    expect(lookalike).toBeDefined();
    expect(lookalike?.severity).toBe("high");
  });

  it("display name claims a brand from a non-brand domain -> LOOKALIKE_DOMAIN", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.unrelated-recipient.example; spf=pass smtp.mailfrom=unrelated-mailer.example; dkim=pass header.d=unrelated-mailer.example; dmarc=pass header.from=unrelated-mailer.example",
      'From: "DocuSign Notifications" <random@unrelated-mailer.example>',
      "To: pat@unrelated-recipient.example",
      "Subject: Document ready for signature",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    expect(ids(signals)).toContain("LOOKALIKE_DOMAIN");
  });

  it("body footer shares a distinctive token with sender's domain but a different registrable domain -> LOOKALIKE_DOMAIN", async () => {
    const signals = await signalsFor(
      [
        "Authentication-Results: mx.unrelated-recipient.example; spf=pass smtp.mailfrom=acme-docs.example; dkim=pass header.d=acme-docs.example; dmarc=pass header.from=acme-docs.example",
        'From: "Acme Docs" <notify@acme-docs.example>',
        "To: pat@unrelated-recipient.example",
        "Subject: Your document is ready to review",
        "Date: Mon, 05 Jan 2026 09:00:00 +0000",
      ],
      "Hello,\r\n\r\nYour document is ready to review.\r\n\r\nAcme Docs, Inc. | acme.example\r\n",
    );

    expect(ids(signals)).toContain("LOOKALIKE_DOMAIN");
  });

  it("negative: brand's real subdomain (notifications.docusign.net) -> no LOOKALIKE_DOMAIN", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.unrelated-recipient.example; spf=pass smtp.mailfrom=notifications.docusign.net; dkim=pass header.d=docusign.net; dmarc=pass header.from=notifications.docusign.net",
      'From: "DocuSign" <notify@notifications.docusign.net>',
      "To: pat@unrelated-recipient.example",
      "Subject: You have a document waiting",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    expect(ids(signals)).not.toContain("LOOKALIKE_DOMAIN");
  });

  it("negative: unrelated third-party domain mentioned in body with no shared token -> no LOOKALIKE_DOMAIN", async () => {
    const signals = await signalsFor(
      [
        "Authentication-Results: mx.riverton-outfitters.example; spf=pass smtp.mailfrom=cobalt-freight.example; dkim=pass header.d=cobalt-freight.example; dmarc=pass header.from=cobalt-freight.example",
        'From: "Cobalt Freight Billing" <billing@cobalt-freight.example>',
        "To: ops@riverton-outfitters.example",
        "Subject: Invoice #4471",
        "Date: Mon, 05 Jan 2026 09:00:00 +0000",
      ],
      "Hello,\r\n\r\nInvoice attached. For scheduling questions see our partner's site at totally-unrelated-service.example.\r\n",
    );

    expect(ids(signals)).not.toContain("LOOKALIKE_DOMAIN");
  });

  it("From display name contains a >=4-char word from the recipient's own domain, sender external -> INTERNAL_IMPERSONATION (medium)", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.meridianworks.example; spf=pass smtp.mailfrom=external-mailer.example; dkim=pass header.d=external-mailer.example; dmarc=pass header.from=external-mailer.example",
      'From: "Meridian Works Billing" <billing@external-mailer.example>',
      "To: ops@meridianworks.example",
      "Subject: Updated billing details",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    const internal = signals.find((s) => s.id === "INTERNAL_IMPERSONATION");
    expect(internal).toBeDefined();
    expect(internal?.severity).toBe("medium");
  });

  it("negative: sender's own domain IS the recipient's domain -> no INTERNAL_IMPERSONATION", async () => {
    const signals = await signalsFor([
      "Authentication-Results: mx.meridianworks.example; spf=pass smtp.mailfrom=meridianworks.example; dkim=pass header.d=meridianworks.example; dmarc=pass header.from=meridianworks.example",
      'From: "Meridian Works Billing" <billing@meridianworks.example>',
      "To: ops@meridianworks.example",
      "Subject: Updated billing details",
      "Date: Mon, 05 Jan 2026 09:00:00 +0000",
    ]);

    expect(ids(signals)).not.toContain("INTERNAL_IMPERSONATION");
  });
});
