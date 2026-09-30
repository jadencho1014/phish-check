import { describe, expect, it } from "vitest";
import { defang } from "./defang";

// Pure helper: only the scheme and the hostname's dots get bracketed, per
// CLAUDE.md's exact example "hxxps://x[.]com". Path/query/hash stay normal
// so a reviewer can still read the destination. Synthetic domains only.

describe("defang", () => {
  it("turns https://x.com into hxxps://x[.]com", () => {
    expect(defang("https://x.com")).toBe("hxxps://x[.]com");
  });

  it("defangs http scheme and hostname dots, but leaves the path/query intact", () => {
    expect(defang("http://sub.example.com/path?a=1")).toBe(
      "hxxp://sub[.]example[.]com/path?a=1",
    );
  });

  it("defangs a hostname with many labels and a trailing slash", () => {
    expect(defang("https://login.accounts-verify.co.uk/")).toBe(
      "hxxps://login[.]accounts-verify[.]co[.]uk/",
    );
  });

  it("passes a non-URL string through unchanged (no-op contract)", () => {
    expect(defang("not a url at all")).toBe("not a url at all");
    expect(defang("")).toBe("");
  });
});
