// Defang a URL for safe display, per CLAUDE.md's Security section: "Show
// links defanged (hxxps://x[.]com), not clickable." Only the scheme
// ("http"/"https" -> "hxxp"/"hxxps") and the dots inside the *hostname* are
// altered; the rest of the URL (path, query, hash, port) is left as-is so
// the destination is still legible for a human reviewer. Non-URL input
// (anything `new URL()` can't parse, e.g. a bare word or already-defanged
// text) is a no-op: returned unchanged.
//
// Matches "http://" or "https://" followed by the host (everything up to
// the first "/", "?" or "#") and captures the rest of the URL untouched.
// A plain regex (rather than the `URL` constructor) is used deliberately:
// `new URL("https://x.com")` normalizes the pathname to "/", which would
// add a trailing slash the input never had - this regex only rewrites what
// CLAUDE.md asks for and leaves everything else byte-for-byte as given.
const URL_REGEX = /^(https?):\/\/([^/?#]+)([\s\S]*)$/i;

export function defang(url: string): string {
  const match = url.match(URL_REGEX);
  if (!match) return url;

  const [, scheme = "", host = "", rest = ""] = match;
  const defangedScheme = scheme.toLowerCase() === "https" ? "hxxps" : "hxxp";
  const defangedHost = host.replace(/\./g, "[.]");
  return `${defangedScheme}://${defangedHost}${rest}`;
}
