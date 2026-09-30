import { describe, expect, it, vi, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { main } from "./analyze";

// Batch script tests (slice 9). Synthetic .eml content written to a temp
// dir - not fixtures/samples. No --url given, so main() must never touch
// the network: fetch is mocked and asserted never called.

function writeTempEml(dir: string, name: string, from: string, to: string): string {
  const raw = [
    `From: ${from}`,
    `To: ${to}`,
    "Subject: Synthetic test message",
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="utf-8"',
    "",
    "Just a plain synthetic message body for a script test.",
    "",
  ].join("\r\n");
  const filePath = path.join(dir, name);
  fs.writeFileSync(filePath, raw, "utf8");
  return filePath;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("scripts/analyze.ts main()", () => {
  it("prints one verdict line per file and never calls fetch when --url is omitted", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "phish-check-analyze-"));
    const fileA = writeTempEml(dir, "one.eml", "alice@northwind-example.test", "bob@acme-example.test");
    const fileB = writeTempEml(dir, "two.eml", "carol@northwind-example.test", "bob@acme-example.test");

    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await main([fileA, fileB]);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledTimes(2);

    const printedLines = logSpy.mock.calls.map((call) => String(call[0]));
    expect(printedLines.some((line) => line.includes("one.eml"))).toBe(true);
    expect(printedLines.some((line) => line.includes("two.eml"))).toBe(true);

    fs.rmSync(dir, { recursive: true, force: true });
  });
});
