// parse -> signals -> llm -> combine. See CLAUDE.md's Files + Detection
// sections. This slice only stubs combine(): a pure function that reduces
// rule Signal[] to a floor Verdict, per the "Combine" rule in CLAUDE.md.
// parseEmail/detectSignals/llm wiring for the full analyze() pipeline lands
// in later slices (7-8).

import type { Signal, Verdict } from "./types";

export function combine(_signals: Signal[]): Verdict {
  throw new Error("combine() not implemented yet");
}
