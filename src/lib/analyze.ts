// parse -> signals -> llm -> combine. See CLAUDE.md's Files + Detection
// sections. combine() is a pure function that reduces rule Signal[] to a
// floor Verdict, per the "Combine" rule in CLAUDE.md: critical -> phishing;
// >=2 high, or high+medium -> phishing; 1 high or >=2 medium -> suspicious;
// otherwise likely_safe. Trust-severity signals never count toward
// escalation, so they can't raise or lower the floor.
// parseEmail/detectSignals/llm wiring for the full analyze() pipeline lands
// in later slices (7-8).

import type { Signal, Verdict } from "./types";

export function combine(signals: Signal[]): Verdict {
  const hasCritical = signals.some((s) => s.severity === "critical");
  if (hasCritical) return "phishing";

  const highCount = signals.filter((s) => s.severity === "high").length;
  const mediumCount = signals.filter((s) => s.severity === "medium").length;

  if (highCount >= 2 || (highCount >= 1 && mediumCount >= 1)) return "phishing";
  if (highCount === 1 || mediumCount >= 2) return "suspicious";
  return "likely_safe";
}
