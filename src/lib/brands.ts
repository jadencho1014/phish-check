// Well-known real brands -> their legit registrable domains. Used by
// signals.ts for LOOKALIKE_DOMAIN detection (CLAUDE.md's Files + Detection
// sections). Static spec'd data, not fixture-derived — real brand names are
// fine here per the no-overfitting rule.

export interface Brand {
  name: string;
  domains: string[];
}

export const BRANDS: Brand[] = [
  { name: "microsoft", domains: ["microsoft.com"] },
  { name: "google", domains: ["google.com"] },
  { name: "docusign", domains: ["docusign.com", "docusign.net"] },
  { name: "github", domains: ["github.com"] },
  { name: "paypal", domains: ["paypal.com"] },
  { name: "amazon", domains: ["amazon.com"] },
  { name: "apple", domains: ["apple.com"] },
  { name: "chase", domains: ["chase.com"] },
  { name: "bank of america", domains: ["bankofamerica.com"] },
  { name: "wells fargo", domains: ["wellsfargo.com"] },
  { name: "usps", domains: ["usps.com"] },
  { name: "fedex", domains: ["fedex.com"] },
  { name: "ups", domains: ["ups.com"] },
];
