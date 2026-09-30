// Batch-check .eml files: `npm run analyze -- <files...> [--url <url>]`.
// No --url: analyze each file in-process via analyzeEmail() (no network
// calls at all). With --url: POST the raw source to `<url>/api/analyze`
// instead. Either way, print one verdict line per file. See CLAUDE.md's
// Commands section and scripts/analyze.test.ts.
//
// main() is exported (rather than only running as top-level side effects)
// so scripts/analyze.test.ts can call it directly without spawning a
// process; the block at the bottom is the thin, real entry point used by
// `npm run analyze`.

import fs from "node:fs";
import path from "node:path";
import OpenAI from "openai";
import { analyzeEmail } from "../src/lib/analyze";
import type { ResponsesClient } from "../src/lib/llm";
import type { AnalysisResult } from "../src/lib/types";

interface CliArgs {
  files: string[];
  url?: string;
}

function parseArgs(argv: string[]): CliArgs {
  const files: string[] = [];
  let url: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--url") {
      url = argv[i + 1];
      i++;
    } else if (arg !== undefined) {
      files.push(arg);
    }
  }

  return { files, url };
}

async function analyzeViaUrl(url: string, raw: string): Promise<AnalysisResult> {
  const response = await fetch(`${url}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw }),
  });
  return (await response.json()) as AnalysisResult;
}

export async function main(argv: string[]): Promise<void> {
  const { files, url } = parseArgs(argv);

  // Same pattern as route.ts: only construct a real client when a key is
  // configured, and never when hitting a remote --url (that server builds
  // its own client).
  const apiKey = process.env.OPENAI_API_KEY;
  const client: ResponsesClient | undefined =
    !url && apiKey ? (new OpenAI({ apiKey }) as unknown as ResponsesClient) : undefined;

  for (const file of files) {
    const raw = fs.readFileSync(file, "utf8");
    const filename = path.basename(file);

    const result = url ? await analyzeViaUrl(url, raw) : await analyzeEmail(raw, { client });

    const topReason = result.reasons[0]?.title;
    console.log(`${filename}: ${result.verdict}${topReason ? ` - ${topReason}` : ""}`);
  }
}

const invokedDirectly =
  typeof process.argv[1] === "string" &&
  path.resolve(process.argv[1]) === path.resolve(__filename);

if (invokedDirectly) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}
