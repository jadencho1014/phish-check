// Defang a URL for safe display, per CLAUDE.md's Security section: "Show
// links defanged (hxxps://x[.]com), not clickable." Only the scheme
// ("http"/"https" -> "hxxp"/"hxxps") and the dots inside the *hostname* are
// altered; the rest of the URL (path, query, hash, port) is left as-is so
// the destination is still legible for a human reviewer. Non-URL input
// (anything `new URL()` can't parse, e.g. a bare word or already-defanged
// text) is a no-op: returned unchanged.
//
// Stub only for now (slice 9 test-writer pass) - implementer fills this in
// against src/lib/defang.test.ts.

export function defang(url: string): string {
  // TODO(implementer): parse `url`, replace "http(s)" with "hxxp(s)" in the
  // scheme, and replace "." with "[.]" only within the hostname. Leave
  // non-URL strings unchanged.
  return url;
}
