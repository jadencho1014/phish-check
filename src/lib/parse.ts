// raw .eml string -> ParsedEmail (ordered headers, text + html parts,
// links {text, href}, attachment metadata). See CLAUDE.md's Files section.
//
// Implemented in the next slice using mailparser's simpleParser (headerLines
// preserves raw header order/duplicates; text/html parts extracted
// separately; attachments carry filename/contentType/size).

import type { ParsedEmail } from "./types";

export async function parseEmail(raw: string): Promise<ParsedEmail> {
  throw new Error("parseEmail: not implemented");
}
