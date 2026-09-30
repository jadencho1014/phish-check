import { describe, expect, it } from "vitest";
import { parseEmail } from "./parse";

// Inline synthetic .eml sources (different names/domains than fixtures/samples,
// so parse.ts logic can't be fixture-specific).

const RAW_MULTIPART = [
  'From: "Ada Lovelace" <ada@northwind-labs.example>',
  'To: "Ben Rivers" <ben@fern-industries.example>',
  "Subject: Weekly sync notes",
  "Date: Wed, 01 Jan 2025 10:00:00 +0000",
  "Received: from mail1.relay.example by mail2.relay.example; Wed, 01 Jan 2025 09:59:00 +0000",
  "Received: from mail2.relay.example by mail3.relay.example; Wed, 01 Jan 2025 09:59:30 +0000",
  "Message-ID: <abc123@northwind-labs.example>",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="MIXED"',
  "",
  "--MIXED",
  'Content-Type: multipart/alternative; boundary="ALT"',
  "",
  "--ALT",
  'Content-Type: text/plain; charset="utf-8"',
  "",
  "Hi Ben,",
  "",
  "Here are the notes from our sync: https://notes.fern-industries.example/weekly",
  "",
  "Thanks,",
  "Ada",
  "",
  "--ALT",
  'Content-Type: text/html; charset="utf-8"',
  "",
  '<p>Hi Ben,</p><p>Here are the notes from our sync: <a href="https://notes.fern-industries.example/weekly">weekly notes</a></p><p>Thanks,<br>Ada</p>',
  "",
  "--ALT--",
  "",
  "--MIXED",
  'Content-Type: application/pdf; name="notes.pdf"',
  'Content-Disposition: attachment; filename="notes.pdf"',
  "Content-Transfer-Encoding: base64",
  "",
  "JVBERi0xLjQKJSBmYWtlIHBkZg==",
  "",
  "--MIXED--",
  "",
].join("\r\n");

const RAW_TEXT_ONLY = [
  'From: "Cara Diaz" <cara@lockhart-supply.example>',
  'To: "Drew Malone" <drew@haventree.example>',
  "Subject: Quick question",
  "Date: Thu, 02 Jan 2025 12:00:00 +0000",
  'Content-Type: text/plain; charset="utf-8"',
  "",
  "Hey Drew, just checking in - are we still on for Friday?",
  "",
  "Thanks,",
  "Cara",
  "",
].join("\r\n");

describe("parseEmail", () => {
  it("preserves headers in order, including duplicates", async () => {
    const parsed = await parseEmail(RAW_MULTIPART);

    const keys = parsed.headers.map((h) => h.key.toLowerCase());
    expect(keys).toEqual([
      "from",
      "to",
      "subject",
      "date",
      "received",
      "received",
      "message-id",
      "mime-version",
      "content-type",
    ]);

    const receivedValues = parsed.headers
      .filter((h) => h.key.toLowerCase() === "received")
      .map((h) => h.value);
    expect(receivedValues).toHaveLength(2);
    expect(receivedValues[0]).toContain("mail1.relay.example");
    expect(receivedValues[1]).toContain("mail2.relay.example");
  });

  it("extracts text and html parts separately", async () => {
    const parsed = await parseEmail(RAW_MULTIPART);

    expect(parsed.text).toContain("Here are the notes from our sync:");
    expect(parsed.text).not.toContain("<a href");
    expect(parsed.html).toContain("<a href");
    expect(parsed.html).toContain("weekly notes");
  });

  it("pulls anchor {text, href} pairs out of the html part", async () => {
    const parsed = await parseEmail(RAW_MULTIPART);

    expect(parsed.links).toHaveLength(1);
    expect(parsed.links[0]).toEqual({
      text: "weekly notes",
      href: "https://notes.fern-industries.example/weekly",
    });
  });

  it("reads attachment filename/contentType/size", async () => {
    const parsed = await parseEmail(RAW_MULTIPART);

    expect(parsed.attachments).toHaveLength(1);
    expect(parsed.attachments[0]).toEqual({
      filename: "notes.pdf",
      contentType: "application/pdf",
      size: 19,
    });
  });

  it("parses a text-only email with no html part without crashing, links empty", async () => {
    const parsed = await parseEmail(RAW_TEXT_ONLY);

    expect(parsed.text).toContain("still on for Friday?");
    expect(parsed.html).toBe("");
    expect(parsed.links).toEqual([]);
    expect(parsed.attachments).toEqual([]);
  });
});
