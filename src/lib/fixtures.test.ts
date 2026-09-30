import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { parseEmail } from "./parse";
import { detectSignals } from "./signals";
import { combine } from "./analyze";
import type { SignalId } from "./types";

// Slice 6 (docs/PLAN.md #6): run the rules pipeline over every real sample in
// fixtures/samples/ against the ground truth in fixtures/labels.json. This is
// the "floor" test from CLAUDE.md's Milestone 2: rules-only must never call a
// phishing sample likely_safe, nor a legitimate sample worse than
// likely_safe, and every mustHave/mustNotHave signal must line up.
//
// Reading fixtures/samples/*.eml and fixtures/labels.json here is normal test
// fixture usage, not overfitting - the no-overfitting rule (see
// leakage.test.ts) is about fixture-specific names/domains leaking into
// src/lib/*.ts production logic, not about test files reading test fixtures.

const SAMPLES_DIR = path.join(process.cwd(), "fixtures/samples");
const LABELS_PATH = path.join(process.cwd(), "fixtures/labels.json");

interface SampleLabel {
  label: "phishing" | "legitimate";
  acceptable: string[];
  mustHave: SignalId[];
  mustNotHave: SignalId[];
  rationale: string;
  expectAdvisory?: boolean;
}

interface LabelsFile {
  samples: Record<string, SampleLabel>;
}

const labelsFile: LabelsFile = JSON.parse(fs.readFileSync(LABELS_PATH, "utf8"));
const sampleNames = Object.keys(labelsFile.samples);

describe("fixture floor test", () => {
  it("has a labels.json entry for every sample and vice versa", () => {
    const filesOnDisk = fs.readdirSync(SAMPLES_DIR).filter((f) => f.endsWith(".eml"));
    expect(new Set(filesOnDisk)).toEqual(new Set(sampleNames));
  });

  for (const [filename, meta] of Object.entries(labelsFile.samples)) {
    it(`${filename}: mustHave/mustNotHave signals and rules-only verdict floor`, async () => {
      const raw = fs.readFileSync(path.join(SAMPLES_DIR, filename), "utf8");
      const email = await parseEmail(raw);
      const signals = detectSignals(email);
      const ids = signals.map((s) => s.id);
      const verdict = combine(signals);

      for (const required of meta.mustHave) {
        expect(ids, `${filename} expected to have ${required}; got [${ids.join(", ")}]`).toContain(required);
      }

      for (const forbidden of meta.mustNotHave) {
        expect(ids, `${filename} expected NOT to have ${forbidden}; got [${ids.join(", ")}]`).not.toContain(
          forbidden,
        );
      }

      if (meta.label === "phishing") {
        expect(verdict, `${filename} is phishing; rules-only verdict must not be likely_safe`).not.toBe(
          "likely_safe",
        );
      } else {
        expect(
          verdict,
          `${filename} is legitimate; rules-only verdict must be exactly likely_safe, got "${verdict}"`,
        ).toBe("likely_safe");
      }
    });
  }
});
