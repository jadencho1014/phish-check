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

import path from "node:path";

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

export async function main(argv: string[]): Promise<void> {
  const { files } = parseArgs(argv);

  // TODO(implementer): for each file, fs.readFileSync it, then either
  // - no `url`: call analyzeEmail(raw) locally (import from
  //   "../src/lib/analyze") - must not touch the network.
  // - `url` set: fetch(`${url}/api/analyze`, { method: "POST", ... }) with
  //   the raw source, per --url in CLAUDE.md's Commands section.
  // Print one line per file either way, e.g. `${filename}: ${verdict}`. See
  // scripts/analyze.test.ts for the no-network contract when --url is
  // omitted.
  void files;
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
