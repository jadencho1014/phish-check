import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";

// Cross-cutting guard (CLAUDE.md "No overfitting"): nothing from
// fixtures/samples or fixtures/labels.json (company, vendors, fictional
// services/mail providers, people) may appear anywhere in src/. Real brand
// names (Microsoft, Google, DocuSign, GitHub...) are fine - they belong in
// brands.ts.

const SRC_DIR = path.resolve(__dirname, "../../src");
const SELF_FILE = path.resolve(__dirname, "leakage.test.ts");

// Fixture-specific tokens pulled from fixtures/samples/*.eml and labels.json:
// the recipient org and its people, and the fictional vendors/services/mail
// providers the samples invent (as opposed to real brands like DocuSign).
const FORBIDDEN_TOKENS = [
  "halvorsenmachining",
  "halvorsen",
  "dana ortiz",
  "dana.ortiz",
  "brightlinemetals",
  "brightline metals",
  "keystoneit",
  "keystone it",
  "mailboxpro",
  "signflow",
  "mail-secure-notify",
  "sprs-dod-support",
  "cloudvault",
  "carbidedirect",
  "carbide direct",
  "docu-sign-secure",
  "renee walsh",
  "rwalsh",
];

function collectFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(full));
    } else if (/\.(ts|tsx|js|jsx|css)$/.test(entry.name)) {
      files.push(full);
    }
  }
  return files;
}

describe("no fixture leakage", () => {
  it("never mentions fixture-specific company/vendor/person names in src/", () => {
    const files = collectFiles(SRC_DIR).filter((f) => f !== SELF_FILE);
    const offenders: string[] = [];

    for (const file of files) {
      const content = fs.readFileSync(file, "utf8").toLowerCase();
      for (const token of FORBIDDEN_TOKENS) {
        if (content.includes(token)) {
          offenders.push(`${path.relative(SRC_DIR, file)}: "${token}"`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});
