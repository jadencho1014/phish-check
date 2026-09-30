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

import type { Signal, Verdict } from "./types";

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
  throw new Error("not implemented");
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
