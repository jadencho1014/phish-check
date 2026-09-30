// Pure rule detectors: ParsedEmail -> Signal[]. See CLAUDE.md's Detection
// section for the signal table. Implemented incrementally across slices 3-5
// (auth/reply-to, then impersonation, then link/payment/attachment).

import type { ParsedEmail, Signal } from "./types";

export function detectSignals(_email: ParsedEmail): Signal[] {
  throw new Error("detectSignals: not implemented");
}
