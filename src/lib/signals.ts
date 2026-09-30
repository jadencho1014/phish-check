// Pure rule detectors: ParsedEmail -> Signal[]. See CLAUDE.md's Detection
// section for the signal table. Implemented incrementally across slices 3-5
// (auth/reply-to, then impersonation, then link/payment/attachment).

import { getDomain, getDomainWithoutSuffix } from "tldts";
import { BRANDS } from "./brands";
import type { ParsedEmail, ParsedEmailHeader, Signal } from "./types";

// Domain-like mention in free text: at least two dot-separated labels.
const DOMAIN_MENTION_REGEX =
  /\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b/g;

const MIN_TOKEN_LENGTH = 4;

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

function extractDisplayName(headerValue: string | undefined): string {
  if (!headerValue) return "";
  const angleIndex = headerValue.indexOf("<");
  const namePart = angleIndex === -1 ? "" : headerValue.slice(0, angleIndex);
  return namePart.trim().replace(/^["']|["']$/g, "").trim();
}

function normalizeToken(value: string): string {
  return value.toLowerCase().replace(/-/g, "");
}

function labelParts(label: string): string[] {
  return label
    .toLowerCase()
    .split("-")
    .filter((part) => part.length > 0);
}

function extractMentionedDomains(text: string): string[] {
  const matches = text.match(DOMAIN_MENTION_REGEX) ?? [];
  const domains = new Set<string>();
  for (const match of matches) {
    const domain = getDomain(match);
    if (domain) domains.add(domain);
  }
  return [...domains];
}

function detectLookalikeDomain(email: ParsedEmail, fromDomain: string | null): Signal | undefined {
  if (!fromDomain) return undefined;

  const senderLabel = getDomainWithoutSuffix(fromDomain) ?? "";
  const normalizedSenderLabel = normalizeToken(senderLabel);

  // A: sender domain contains a known brand token (ignoring hyphens) but
  // isn't actually that brand's domain.
  for (const brand of BRANDS) {
    if (normalizedSenderLabel.includes(brand.name) && !brand.domains.includes(fromDomain)) {
      return {
        id: "LOOKALIKE_DOMAIN",
        severity: "high",
        evidence: `Sender domain "${fromDomain}" resembles ${brand.name} but is not a known ${brand.name} domain`,
      };
    }
  }

  // B: From display name claims a known brand from a non-brand domain.
  const fromHeader = findHeader(email.headers, "From");
  const displayName = extractDisplayName(fromHeader?.value).toLowerCase();
  for (const brand of BRANDS) {
    if (displayName.includes(brand.name) && !brand.domains.includes(fromDomain)) {
      return {
        id: "LOOKALIKE_DOMAIN",
        severity: "high",
        evidence: `Display name "${extractDisplayName(fromHeader?.value)}" claims ${brand.name} but sender domain is "${fromDomain}"`,
      };
    }
  }

  // C: body mentions a domain sharing a distinctive token with the sender's
  // own domain but is a different registrable domain.
  const senderParts = labelParts(senderLabel).filter((part) => part.length >= MIN_TOKEN_LENGTH);
  if (senderParts.length > 0) {
    const mentionedDomains = extractMentionedDomains(`${email.text}\n${email.html}`);
    for (const mentioned of mentionedDomains) {
      if (mentioned === fromDomain) continue;
      const mentionedLabel = getDomainWithoutSuffix(mentioned) ?? "";
      const mentionedParts = labelParts(mentionedLabel);
      if (senderParts.some((part) => mentionedParts.includes(part))) {
        return {
          id: "LOOKALIKE_DOMAIN",
          severity: "high",
          evidence: `Body mentions "${mentioned}", which shares a distinctive token with sender domain "${fromDomain}"`,
        };
      }
    }
  }

  return undefined;
}

function detectInternalImpersonation(email: ParsedEmail, fromDomain: string | null): Signal | undefined {
  const toHeader = findHeader(email.headers, "To");
  const recipientDomain = registrableDomainOfAddress(extractEmailAddress(toHeader?.value));
  if (!recipientDomain || !fromDomain || fromDomain === recipientDomain) return undefined;

  const recipientLabel = normalizeToken(getDomainWithoutSuffix(recipientDomain) ?? "");
  if (recipientLabel.length < MIN_TOKEN_LENGTH) return undefined;

  const fromHeader = findHeader(email.headers, "From");
  const replyToHeader = findHeader(email.headers, "Reply-To");

  for (const header of [fromHeader, replyToHeader]) {
    const displayName = extractDisplayName(header?.value);
    const words = displayName
      .toLowerCase()
      .split(/[^a-z]+/)
      .filter((word) => word.length >= MIN_TOKEN_LENGTH);

    for (const word of words) {
      if (recipientLabel.includes(word)) {
        return {
          id: "INTERNAL_IMPERSONATION",
          severity: "medium",
          evidence: `Display name "${displayName}" echoes recipient domain "${recipientDomain}", but sender domain is "${fromDomain}"`,
        };
      }
    }
  }

  return undefined;
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
  const fromDomain = registrableDomainOfAddress(extractEmailAddress(fromHeader?.value));

  if (replyToHeader) {
    const replyToDomain = registrableDomainOfAddress(extractEmailAddress(replyToHeader.value));

    if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
      signals.push({
        id: "REPLY_TO_MISMATCH",
        severity: "medium",
        evidence: `From: ${fromDomain}, Reply-To: ${replyToDomain}`,
      });
    }
  }

  const lookalike = detectLookalikeDomain(email, fromDomain);
  if (lookalike) signals.push(lookalike);

  const internalImpersonation = detectInternalImpersonation(email, fromDomain);
  if (internalImpersonation) signals.push(internalImpersonation);

  return signals;
}
