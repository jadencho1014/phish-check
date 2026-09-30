// Skeleton types for Phish Check. Fleshed out further in later slices
// (parse.ts, signals.ts, llm.ts) per CLAUDE.md's Detection and LLM sections.

export interface ParsedEmailHeader {
  key: string;
  value: string;
}

export interface EmailLink {
  text: string;
  href: string;
}

export interface EmailAttachment {
  filename: string;
  contentType: string;
  size: number;
}

export interface ParsedEmail {
  headers: ParsedEmailHeader[];
  text: string;
  html: string;
  links: EmailLink[];
  attachments: EmailAttachment[];
}

export type SignalId =
  | "AUTH_FAIL"
  | "AUTH_ALIGNED_PASS"
  | "REPLY_TO_MISMATCH"
  | "LINK_MISMATCH"
  | "LOOKALIKE_DOMAIN"
  | "INTERNAL_IMPERSONATION"
  | "PAYMENT_CHANGE_REQUEST"
  | "RISKY_ATTACHMENT";

export type SignalSeverity = "trust" | "medium" | "high" | "critical";

export interface Signal {
  id: SignalId;
  severity: SignalSeverity;
  evidence: string;
}

export type Verdict = "phishing" | "suspicious" | "likely_safe";

export interface AnalysisReason {
  title: string;
  explanation: string;
}

export interface AnalysisResult {
  verdict: Verdict;
  reasons: AnalysisReason[];
  actions: string[];
  advisory?: string;
  // Set by analyzeEmail (slice 9+) when the submitted source had no usable
  // headers at all (e.g. a bare pasted body with no From/Authentication-
  // Results), so the sender's identity couldn't be checked. Per CLAUDE.md's
  // UI section: "If no headers were provided, say the sender couldn't be
  // verified." Optional/additive so existing callers are unaffected.
  headerless?: boolean;
  // The following are populated by analyzeEmail (slice 9) purely to feed the
  // UI's collapsible "details" section (CLAUDE.md's UI section: "auth,
  // defanged links, signals"). All optional/additive - no existing caller or
  // test constructs/compares a full AnalysisResult object, so these are safe
  // extensions (see analyze.test.ts/llm.test.ts/route.test.ts, which only
  // assert individual fields like verdict/reasons/actions).
  authSummary?: string;
  links?: EmailLink[];
  // Human-readable "title: evidence" summaries of the notable (non-trust)
  // rule signals that fired, for display only - never the raw SignalId.
  signalSummaries?: string[];
}
