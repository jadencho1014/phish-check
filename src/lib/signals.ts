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

function domainOfUrlOrHost(value: string): string | null {
  try {
    return getDomain(new URL(value).hostname);
  } catch {
    return getDomain(value);
  }
}

// Domains mentioned as explicit http(s) URLs in free text (used to compare
// text/plain vs html link targets; stricter than DOMAIN_MENTION_REGEX so
// ordinary prose mentioning unrelated domains doesn't count).
function extractUrlDomains(text: string): Set<string> {
  const matches = text.match(/https?:\/\/[^\s<>"')]+/gi) ?? [];
  const domains = new Set<string>();
  for (const url of matches) {
    const domain = domainOfUrlOrHost(url);
    if (domain) domains.add(domain);
  }
  return domains;
}

function detectLinkMismatch(email: ParsedEmail): Signal | undefined {
  // A: visible link text names a domain that differs from where the href
  // actually points.
  for (const link of email.links) {
    const textDomains = extractMentionedDomains(link.text);
    if (textDomains.length === 0) continue;

    const hrefDomain = domainOfUrlOrHost(link.href);
    if (!hrefDomain) continue;

    const mismatched = textDomains.find((domain) => domain !== hrefDomain);
    if (mismatched) {
      return {
        id: "LINK_MISMATCH",
        severity: "critical",
        evidence: `Link text "${link.text}" suggests "${mismatched}" but the link goes to "${hrefDomain}"`,
      };
    }
  }

  // B: the text/plain part and the html part link to different registrable
  // domains.
  if (email.text && email.html) {
    const textDomains = extractUrlDomains(email.text);
    const htmlDomains = new Set<string>();
    for (const link of email.links) {
      const domain = domainOfUrlOrHost(link.href);
      if (domain) htmlDomains.add(domain);
    }

    if (textDomains.size > 0 && htmlDomains.size > 0) {
      const overlaps = [...textDomains].some((domain) => htmlDomains.has(domain));
      if (!overlaps) {
        return {
          id: "LINK_MISMATCH",
          severity: "critical",
          evidence: `Text part links to ${[...textDomains].join(", ")}, but the html part links to ${[...htmlDomains].join(", ")}`,
        };
      }
    }
  }

  return undefined;
}

// Change-of-payment-details language: a verb ("update", "new", "change",
// "switch", "redirect", ...) near a payment noun ("bank", "account",
// "routing", "remittance", "wire"), in either order, plus a standalone
// gift-card mention. Kept general per CLAUDE.md - not tied to fixture wording.
const PAYMENT_VERB = "(?:update|updated|updating|new|change|changed|changing|switch|switched|switching|redirect|redirected|redirecting)";
const PAYMENT_NOUN = "(?:bank|banking|account|routing|remittance|wire)";
const PAYMENT_CHANGE_FORWARD = new RegExp(`\\b${PAYMENT_VERB}\\b[\\s\\S]{0,60}?\\b${PAYMENT_NOUN}\\b`, "i");
const PAYMENT_CHANGE_BACKWARD = new RegExp(`\\b${PAYMENT_NOUN}\\b[\\s\\S]{0,60}?\\b${PAYMENT_VERB}\\b`, "i");
const GIFT_CARD_REGEX = /\bgift cards?\b/i;

function detectPaymentChangeRequest(email: ParsedEmail, existingSignals: Signal[]): Signal | undefined {
  const body = `${email.text}\n${email.html}`;
  const matches =
    PAYMENT_CHANGE_FORWARD.test(body) || PAYMENT_CHANGE_BACKWARD.test(body) || GIFT_CARD_REGEX.test(body);
  if (!matches) return undefined;

  const hasReplyToMismatch = existingSignals.some((s) => s.id === "REPLY_TO_MISMATCH");
  return {
    id: "PAYMENT_CHANGE_REQUEST",
    severity: hasReplyToMismatch ? "high" : "medium",
    evidence: "Body requests a change to bank/payment details, or references gift cards",
  };
}

const RISKY_EXTENSIONS = new Set(["html", "htm", "iso", "exe", "js", "lnk", "docm", "xlsm"]);

function isRiskyFilename(filename: string): boolean {
  const match = filename.toLowerCase().match(/\.([a-z0-9]+)$/);
  const extension = match?.[1];
  if (!extension) return false;
  return RISKY_EXTENSIONS.has(extension);
}

function detectRiskyAttachment(email: ParsedEmail): Signal | undefined {
  const risky = email.attachments.filter((a) => isRiskyFilename(a.filename));
  if (risky.length === 0) return undefined;

  return {
    id: "RISKY_ATTACHMENT",
    severity: "high",
    evidence: `Risky attachment(s): ${risky.map((a) => a.filename).join(", ")}`,
  };
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

  const linkMismatch = detectLinkMismatch(email);
  if (linkMismatch) signals.push(linkMismatch);

  const paymentChangeRequest = detectPaymentChangeRequest(email, signals);
  if (paymentChangeRequest) signals.push(paymentChangeRequest);

  const riskyAttachment = detectRiskyAttachment(email);
  if (riskyAttachment) signals.push(riskyAttachment);

  return signals;
}
