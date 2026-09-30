// raw .eml string -> ParsedEmail (ordered headers, text + html parts,
// links {text, href}, attachment metadata). See CLAUDE.md's Files section.
//
// Uses mailparser's simpleParser. headerLines preserves raw header order
// and duplicates; text/html parts are extracted separately; attachments
// carry filename/contentType/size. Anchor tags are pulled out of the html
// body with a small regex (no extra HTML-parsing dependency, per
// CLAUDE.md's stack list).

import { simpleParser } from "mailparser";
import type { EmailAttachment, EmailLink, ParsedEmail, ParsedEmailHeader } from "./types";

const ANCHOR_REGEX = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
const TAG_REGEX = /<[^>]*>/g;

function decodeEntities(value: string): string {
  return value
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function extractLinks(html: string): EmailLink[] {
  if (!html) return [];

  const links: EmailLink[] = [];
  let match: RegExpExecArray | null;

  ANCHOR_REGEX.lastIndex = 0;
  while ((match = ANCHOR_REGEX.exec(html)) !== null) {
    const href = decodeEntities(match[1] ?? match[2] ?? match[3] ?? "");
    const text = decodeEntities((match[4] ?? "").replace(TAG_REGEX, "")).trim();
    links.push({ text, href });
  }

  return links;
}

export async function parseEmail(raw: string): Promise<ParsedEmail> {
  const parsed = await simpleParser(raw);

  const headers: ParsedEmailHeader[] = parsed.headerLines.map(({ key, line }) => {
    const colonIndex = line.indexOf(":");
    const displayKey = colonIndex === -1 ? key : line.slice(0, colonIndex).trim();
    const rawValue = colonIndex === -1 ? "" : line.slice(colonIndex + 1);
    const value = rawValue.replace(/\r\n[ \t]+/g, " ").trim();
    return { key: displayKey, value };
  });

  const html = typeof parsed.html === "string" ? parsed.html : "";
  const text = parsed.text ?? "";

  const attachments: EmailAttachment[] = (parsed.attachments ?? []).map((attachment) => ({
    filename: attachment.filename ?? "",
    contentType: attachment.contentType ?? "",
    size: attachment.size ?? 0,
  }));

  return {
    headers,
    text,
    html,
    links: extractLinks(html),
    attachments,
  };
}
