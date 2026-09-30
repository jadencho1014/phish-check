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

// Multipart builder for slice 5 tests (link/attachment signals need real
// text+html parts and/or a MIME attachment, unlike the plain-text helper
// above).
function buildMultipart(
  headers: string[],
  opts: { text: string; html?: string; attachment?: { filename: string; contentType?: string } },
): string {
  const bodyPart = opts.html
    ? [
        'Content-Type: multipart/alternative; boundary="ALT"',
        "",
        "--ALT",
        'Content-Type: text/plain; charset="utf-8"',
        "",
        opts.text,
        "",
        "--ALT",
        'Content-Type: text/html; charset="utf-8"',
        "",
        opts.html,
        "",
        "--ALT--",
        "",
      ]
    : ['Content-Type: text/plain; charset="utf-8"', "", opts.text, ""];

  const attachmentPart = opts.attachment
    ? [
        "--MIXED",
        `Content-Type: ${opts.attachment.contentType ?? "application/octet-stream"}; name="${opts.attachment.filename}"`,
        `Content-Disposition: attachment; filename="${opts.attachment.filename}"`,
        "Content-Transfer-Encoding: base64",
        "",
        "ZmFrZSBjb250ZW50",
        "",
      ]
    : [];

  return [
    ...headers,
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="MIXED"',
    "",
    "--MIXED",
    ...bodyPart,
    ...attachmentPart,
    "--MIXED--",
    "",
  ].join("\r\n");
}

async function signalsForRaw(raw: string) {
  const parsed = await parseEmail(raw);
  return detectSignals(parsed);
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

describe("detectSignals - link/payment/attachment (slice 5)", () => {
  it("html anchor text names one domain but href goes elsewhere -> LINK_MISMATCH (critical)", async () => {
    const raw = buildMultipart(
      [
        "Authentication-Results: mx.summit-holdings.example; spf=pass smtp.mailfrom=granite-bank.example; dkim=pass header.d=granite-bank.example; dmarc=pass header.from=granite-bank.example",
        'From: "Granite Bank Alerts" <alerts@granite-bank.example>',
        "To: pat@summit-holdings.example",
        "Subject: Please verify your account",
        "Date: Mon, 05 Jan 2026 09:00:00 +0000",
      ],
      {
        text: "Please verify your account using the link in this email.",
        html: '<p>Please verify your account at <a href="https://secure-login-portal.example/verify">https://granite-bank.example/verify</a></p>',
      },
    );

    const signals = await signalsForRaw(raw);
    const mismatch = signals.find((s) => s.id === "LINK_MISMATCH");
    expect(mismatch).toBeDefined();
    expect(mismatch?.severity).toBe("critical");
  });

  it("text/plain part links to one domain, html part links to a different one -> LINK_MISMATCH", async () => {
    const raw = buildMultipart(
      [
        "Authentication-Results: mx.summit-holdings.example; spf=pass smtp.mailfrom=polaris-freight.example; dkim=pass header.d=polaris-freight.example; dmarc=pass header.from=polaris-freight.example",
        'From: "Polaris Freight" <dispatch@polaris-freight.example>',
        "To: pat@summit-holdings.example",
        "Subject: Your shipment is on the way",
        "Date: Mon, 05 Jan 2026 09:00:00 +0000",
      ],
      {
        text: "Track your shipment: https://tracking.polaris-freight.example/abc123",
        html: '<p>Track your shipment: <a href="https://tracking.other-carrier.example/abc123">track here</a></p>',
      },
    );

    const signals = await signalsForRaw(raw);
    expect(ids(signals)).toContain("LINK_MISMATCH");
  });

  it("negative: generic link text ('Click here') to a tracker subdomain of the sender's own domain -> no LINK_MISMATCH", async () => {
    const raw = buildMultipart(
      [
        "Authentication-Results: mx.summit-holdings.example; spf=pass smtp.mailfrom=lumen-parts.example; dkim=pass header.d=lumen-parts.example; dmarc=pass header.from=lumen-parts.example",
        'From: "Lumen Parts" <billing@lumen-parts.example>',
        "To: pat@summit-holdings.example",
        "Subject: Your statement is ready",
        "Date: Mon, 05 Jan 2026 09:00:00 +0000",
      ],
      {
        text: "Please review your statement, attached.",
        html: '<p>Please review your statement. <a href="https://click.lumen-parts.example/track?id=99">Click here</a></p>',
      },
    );

    const signals = await signalsForRaw(raw);
    expect(ids(signals)).not.toContain("LINK_MISMATCH");
  });

  it("bank/wire account-change request -> PAYMENT_CHANGE_REQUEST (medium) alone", async () => {
    const signals = await signalsFor(
      [
        "Authentication-Results: mx.summit-holdings.example; spf=pass smtp.mailfrom=vantage-components.example; dkim=pass header.d=vantage-components.example; dmarc=pass header.from=vantage-components.example",
        'From: "Vantage Components AP" <ap@vantage-components.example>',
        "To: ops@summit-holdings.example",
        "Subject: Updated remittance details",
        "Date: Mon, 05 Jan 2026 09:00:00 +0000",
      ],
      "Hello,\r\n\r\nPlease update our remittance account to the following: routing number 021000021, account number 004567890123. Kindly direct all future payments to this new account.\r\n\r\nThanks,\r\nAP Team\r\n",
    );

    const paymentChange = signals.find((s) => s.id === "PAYMENT_CHANGE_REQUEST");
    expect(paymentChange).toBeDefined();
    expect(paymentChange?.severity).toBe("medium");
    expect(ids(signals)).not.toContain("REPLY_TO_MISMATCH");
  });

  it("bank/wire account-change request + REPLY_TO_MISMATCH -> PAYMENT_CHANGE_REQUEST escalates to high", async () => {
    const signals = await signalsFor(
      [
        "Authentication-Results: mx.summit-holdings.example; spf=pass smtp.mailfrom=vantage-components.example; dkim=pass header.d=vantage-components.example; dmarc=pass header.from=vantage-components.example",
        'From: "Vantage Components AP" <ap@vantage-components.example>',
        "Reply-To: finance@offsite-collections.example",
        "To: ops@summit-holdings.example",
        "Subject: Updated remittance details",
        "Date: Mon, 05 Jan 2026 09:00:00 +0000",
      ],
      "Hello,\r\n\r\nPlease update our remittance account to the following: routing number 021000021, account number 004567890123. Kindly direct all future payments to this new account.\r\n\r\nThanks,\r\nAP Team\r\n",
    );

    expect(ids(signals)).toContain("REPLY_TO_MISMATCH");
    const paymentChange = signals.find((s) => s.id === "PAYMENT_CHANGE_REQUEST");
    expect(paymentChange).toBeDefined();
    expect(paymentChange?.severity).toBe("high");
  });

  it("negative: ordinary invoice with normal payment terms (no change requested) -> no PAYMENT_CHANGE_REQUEST", async () => {
    const signals = await signalsFor(
      [
        "Authentication-Results: mx.summit-holdings.example; spf=pass smtp.mailfrom=vantage-components.example; dkim=pass header.d=vantage-components.example; dmarc=pass header.from=vantage-components.example",
        'From: "Vantage Components AP" <ap@vantage-components.example>',
        "To: ops@summit-holdings.example",
        "Subject: Invoice #8823",
        "Date: Mon, 05 Jan 2026 09:00:00 +0000",
      ],
      "Hello,\r\n\r\nInvoice #8823 is attached. Payment terms: Net 30. Please remit payment via wire transfer to our account on file.\r\n\r\nThanks,\r\nAP Team\r\n",
    );

    expect(ids(signals)).not.toContain("PAYMENT_CHANGE_REQUEST");
  });

  it.each(["invoice.exe", "resume.docm", "invoice.pdf.exe"])(
    "risky attachment %s -> RISKY_ATTACHMENT (high)",
    async (filename) => {
      const raw = buildMultipart(
        [
          "Authentication-Results: mx.summit-holdings.example; spf=pass smtp.mailfrom=vantage-components.example; dkim=pass header.d=vantage-components.example; dmarc=pass header.from=vantage-components.example",
          'From: "Vantage Components AP" <ap@vantage-components.example>',
          "To: ops@summit-holdings.example",
          "Subject: Document attached",
          "Date: Mon, 05 Jan 2026 09:00:00 +0000",
        ],
        {
          text: "Please see the attached document.",
          attachment: { filename },
        },
      );

      const signals = await signalsForRaw(raw);
      const risky = signals.find((s) => s.id === "RISKY_ATTACHMENT");
      expect(risky).toBeDefined();
      expect(risky?.severity).toBe("high");
    },
  );

  it.each(["invoice.pdf", "contract.docx"])(
    "negative: plain %s attachment -> no RISKY_ATTACHMENT",
    async (filename) => {
      const raw = buildMultipart(
        [
          "Authentication-Results: mx.summit-holdings.example; spf=pass smtp.mailfrom=vantage-components.example; dkim=pass header.d=vantage-components.example; dmarc=pass header.from=vantage-components.example",
          'From: "Vantage Components AP" <ap@vantage-components.example>',
          "To: ops@summit-holdings.example",
          "Subject: Document attached",
          "Date: Mon, 05 Jan 2026 09:00:00 +0000",
        ],
        {
          text: "Please see the attached document.",
          attachment: { filename },
        },
      );

      const signals = await signalsForRaw(raw);
      expect(ids(signals)).not.toContain("RISKY_ATTACHMENT");
    },
  );
});
