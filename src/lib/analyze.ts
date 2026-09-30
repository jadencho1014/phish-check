// parse -> signals -> llm -> combine. See CLAUDE.md's Files + Detection
// sections. combine() is a pure function that reduces rule Signal[] to a
// floor Verdict, per the "Combine" rule in CLAUDE.md: critical -> phishing;
// >=2 high, or high+medium -> phishing; exactly one high, or >=2 medium ->
// suspicious; otherwise likely_safe. Trust-severity signals never count
// toward escalation, so they can't raise or lower the floor.
//
// INTERNAL_IMPERSONATION special case: this signal means a display name is
// impersonating a specific person/org the recipient trusts (CEO-fraud/BEC
// pattern), which is qualitatively stronger than an isolated medium signal
// like a lone REPLY_TO_MISMATCH or PAYMENT_CHANGE_REQUEST (routine ESP/
// helpdesk setups commonly trip those alone). So its presence floors the
// verdict at "suspicious" regardless of the other counts. This is a general
// rule about what the signal ID means, not tied to any particular sample.
//
// parseEmail/detectSignals/llm wiring for the full analyze() pipeline lands
// in later slices (7-8).

import type { AnalysisReason, AnalysisResult, Signal, SignalId, Verdict } from "./types";
import { callLlm, type LlmInput, type ResponsesClient } from "./llm";
import { parseEmail } from "./parse";
import { detectSignals, getRecipientDomain } from "./signals";

// combineWithLlm: how the LLM's verdict (or null on fallback, per llm.ts) is
// reconciled with the rules-only floor from combine() above. Per CLAUDE.md's
// "Combine" rule, "the rules set a floor; the LLM can raise the verdict but
// never lower it below the floor. If the LLM fails ... return the rules-only
// result." This lives in analyze.ts (not llm.ts) because CLAUDE.md's file
// layout assigns the final combine step to analyze.ts's
// parse -> signals -> llm -> combine pipeline; llm.ts only calls the model
// and validates its shape. Full parse->signals->llm wiring lands in slice 8.
const VERDICT_RANK: Record<Verdict, number> = {
  likely_safe: 0,
  suspicious: 1,
  phishing: 2,
};

export function combineWithLlm(floor: Verdict, llmVerdict: Verdict | null): Verdict {
  if (llmVerdict === null) return floor;
  return VERDICT_RANK[llmVerdict] > VERDICT_RANK[floor] ? llmVerdict : floor;
}

export function combine(signals: Signal[]): Verdict {
  const hasCritical = signals.some((s) => s.severity === "critical");
  if (hasCritical) return "phishing";

  const highCount = signals.filter((s) => s.severity === "high").length;
  const mediumCount = signals.filter((s) => s.severity === "medium").length;
  const hasInternalImpersonation = signals.some((s) => s.id === "INTERNAL_IMPERSONATION");

  if (highCount >= 2 || (highCount >= 1 && mediumCount >= 1)) return "phishing";
  if (highCount === 1 || mediumCount >= 2 || hasInternalImpersonation) return "suspicious";
  return "likely_safe";
}

// analyzeEmail: the full parse -> signals -> llm -> combine pipeline (slice
// 8). `client` is injected (never constructed here) so tests never touch the
// network or need OPENAI_API_KEY - route.ts decides whether a real client
// exists (OPENAI_API_KEY set) and passes it in, or omits it entirely, in
// which case this returns the rules-only result "and says so" per CLAUDE.md's
// LLM paragraph ("If the LLM fails or there's no key, return the rules-only
// result and say so"). When the LLM succeeds, its reasons/actions/advisory
// are used as-is; combineWithLlm still governs the final verdict floor.
export interface AnalyzeOptions {
  client?: ResponsesClient;
}

// Generic, human-readable title per signal ID, used only in the rules-only
// fallback below (no LLM available). Kept general/non-fixture-specific per
// CLAUDE.md's overfitting rule.
const SIGNAL_TITLES: Record<SignalId, string> = {
  AUTH_FAIL: "Sender authentication failed",
  AUTH_ALIGNED_PASS: "Sender authentication passed",
  REPLY_TO_MISMATCH: "Reply-To domain differs from sender",
  LINK_MISMATCH: "Link destination doesn't match its visible text",
  LOOKALIKE_DOMAIN: "Sender domain resembles a known brand",
  INTERNAL_IMPERSONATION: "Sender name echoes your own organization",
  PAYMENT_CHANGE_REQUEST: "Requests a payment or account-details change",
  RISKY_ATTACHMENT: "Attachment type is commonly used to deliver malware",
};

// Human-readable "title: evidence" lines for the UI's collapsible details
// section (never the raw SignalId - see AnalysisResult.signalSummaries in
// types.ts). Excludes "trust" signals, which are informational only.
function summarizeSignals(signals: Signal[]): string[] {
  return signals
    .filter((s) => s.severity !== "trust")
    .map((s) => `${SIGNAL_TITLES[s.id]}: ${s.evidence}`);
}

function rulesOnlyResult(floor: Verdict, signals: Signal[]): AnalysisResult {
  const notableSignals = signals.filter((s) => s.severity !== "trust");

  const reasons: AnalysisReason[] = [
    {
      title: "Rules-only assessment",
      explanation:
        "No AI review was available for this message, so this verdict is based only on automated rule checks.",
    },
    ...notableSignals.map((s) => ({
      title: SIGNAL_TITLES[s.id],
      explanation: s.evidence,
    })),
  ];

  return {
    verdict: floor,
    reasons,
    actions: [
      "Do not click any links, open attachments, or reply.",
      "Verify with the sender through a separate, known channel before taking any action.",
    ],
  };
}

export async function analyzeEmail(
  raw: string,
  opts: AnalyzeOptions = {},
): Promise<AnalysisResult> {
  const parsed = await parseEmail(raw);
  const signals = detectSignals(parsed);
  const recipientDomain = getRecipientDomain(parsed) ?? "";
  const floor = combine(signals);

  const authResultsHeader = parsed.headers.find(
    (h) => h.key.toLowerCase() === "authentication-results",
  );

  // "If no headers were provided, say the sender couldn't be verified" per
  // CLAUDE.md's UI section - a bare pasted body has no headers at all, so
  // From/Authentication-Results can never be checked.
  const headerless = parsed.headers.length === 0;

  // Extra fields the UI's collapsible details section renders (auth,
  // defanged links, signals) - additive on top of whichever
  // reasons/actions/verdict/advisory come from the LLM or rules-only path.
  const uiExtras: Pick<AnalysisResult, "headerless" | "authSummary" | "links" | "signalSummaries"> = {
    headerless,
    authSummary: authResultsHeader?.value ?? "No Authentication-Results header present",
    links: parsed.links,
    signalSummaries: summarizeSignals(signals),
  };

  if (opts.client) {
    const llmInput: LlmInput = {
      headersSummary: parsed.headers.map((h) => `${h.key}: ${h.value}`).join("\n"),
      authResults: authResultsHeader?.value ?? "(none)",
      text: parsed.text,
      links: parsed.links,
      attachments: parsed.attachments,
      signals,
      recipientDomain,
    };

    const llmResult = await callLlm(opts.client, llmInput);
    if (llmResult) {
      const finalVerdict = combineWithLlm(floor, llmResult.verdict);
      return {
        verdict: finalVerdict,
        reasons: llmResult.reasons,
        actions: llmResult.actions,
        ...(llmResult.advisory !== undefined ? { advisory: llmResult.advisory } : {}),
        ...uiExtras,
      };
    }
  }

  return { ...rulesOnlyResult(floor, signals), ...uiExtras };
}
