// Pure rule detectors: ParsedEmail -> Signal[]. See CLAUDE.md's Detection
// section for the signal table. Implemented incrementally across slices 3-5
// (auth/reply-to, then impersonation, then link/payment/attachment).
//
// TODO (slice 4, implementer): LOOKALIKE_DOMAIN and INTERNAL_IMPERSONATION
// are not yet implemented here. brands.ts (well-known brand -> domains
// table) is ready to be consulted for LOOKALIKE_DOMAIN; the recipient's
// domain label for INTERNAL_IMPERSONATION should be derived from the `To`
// header already present in email.headers. See signals.test.ts's
// "impersonation (slice 4)" describe block for the expected behaviour.

import { getDomain } from "tldts";
import type { ParsedEmail, ParsedEmailHeader, Signal } from "./types";

function findHeader(headers: ParsedEmailHeader[], name: string): ParsedEmailHeader | undefined {
  const lower = name.toLowerCase();
  return headers.find((h) => h.key.toLowerCase() === lower);
}

function extractEmailAddress(headerValue: string | undefined): string | undefined {
  if (!headerValue) return undefined;
  const angleMatch = headerValue.match(/<([^>]+)>/);
  const candidate = (angleMatch?.[1] ?? headerValue).trim();
  const emailMatch = candidate.match(/[^\s<>"]+@[^\s<>",;]+/);
  return emailMatch?.[0];
}

function registrableDomainOfAddress(address: string | undefined): string | null {
  if (!address) return null;
  const atIndex = address.lastIndexOf("@");
  if (atIndex === -1) return null;
  const host = address.slice(atIndex + 1);
  return getDomain(host);
}

function extractAuthToken(authResultsValue: string, mechanism: string): string | undefined {
  const regex = new RegExp(`\\b${mechanism}\\s*=\\s*(\\w+)`, "i");
  const match = authResultsValue.match(regex);
  return match?.[1]?.toLowerCase();
}

export function detectSignals(email: ParsedEmail): Signal[] {
  const signals: Signal[] = [];

  const authResultsHeader = findHeader(email.headers, "Authentication-Results");
  if (authResultsHeader) {
    const spf = extractAuthToken(authResultsHeader.value, "spf");
    const dkim = extractAuthToken(authResultsHeader.value, "dkim");
    const dmarc = extractAuthToken(authResultsHeader.value, "dmarc");

    const spfFail = spf === "fail" || spf === "softfail";
    const dkimFail = dkim === "fail";
    const dmarcFail = dmarc === "fail";

    if (spfFail || dkimFail || dmarcFail) {
      signals.push({
        id: "AUTH_FAIL",
        severity: "high",
        evidence: authResultsHeader.value,
      });
    }

    if (dmarc === "pass") {
      signals.push({
        id: "AUTH_ALIGNED_PASS",
        severity: "trust",
        evidence: authResultsHeader.value,
      });
    }
  }

  const fromHeader = findHeader(email.headers, "From");
  const replyToHeader = findHeader(email.headers, "Reply-To");

  if (replyToHeader) {
    const fromDomain = registrableDomainOfAddress(extractEmailAddress(fromHeader?.value));
    const replyToDomain = registrableDomainOfAddress(extractEmailAddress(replyToHeader.value));

    if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
      signals.push({
        id: "REPLY_TO_MISMATCH",
        severity: "medium",
        evidence: `From: ${fromDomain}, Reply-To: ${replyToDomain}`,
      });
    }
  }

  return signals;
}
