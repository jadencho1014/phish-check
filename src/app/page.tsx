"use client";

import { useState } from "react";
import type { AnalysisResult, Verdict } from "../lib/types";
import { defang } from "../lib/defang";

const VERDICT_STYLES: Record<Verdict, { label: string; className: string }> = {
  phishing: { label: "Phishing", className: "bg-red-100 border-red-600 text-red-900" },
  suspicious: {
    label: "Suspicious",
    className: "bg-amber-100 border-amber-600 text-amber-900",
  },
  likely_safe: {
    label: "Likely safe",
    className: "bg-green-100 border-green-600 text-green-900",
  },
};

// One page: textarea + .eml drop/picker, a short tip on getting full source,
// and (once implemented) a verdict banner, reasons, actions, and collapsible
// details. Per CLAUDE.md's Security section: never render email HTML, show
// links defanged and non-clickable, never fetch URLs from emails. This
// component only ever renders AnalysisResult fields as plain React text
// children (never dangerouslySetInnerHTML) - see page.test.tsx.

export default function Home() {
  const [raw, setRaw] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw }),
      });
      if (!response.ok) {
        setError("Analysis failed. Please try again.");
        return;
      }
      const data = (await response.json()) as AnalysisResult;
      setResult(data);
    } catch {
      setError("Analysis failed. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  function handleFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setRaw(String(reader.result ?? ""));
    reader.readAsText(file);
  }

  return (
    <main>
      <h1>Phish Check</h1>
      <p>
        Paste the email&apos;s full raw source below (not just the visible
        text) or upload a <code>.eml</code> file. To get the full source -
        Gmail: open the message, click the three-dot menu, &quot;Show
        original&quot;. Outlook: open the message, &quot;View message
        source&quot;. Apple Mail: select the message, Message menu &rarr;
        &quot;Raw Source&quot;.
      </p>
      <form onSubmit={handleSubmit}>
        <label htmlFor="raw-email">Paste raw email source</label>
        <textarea
          id="raw-email"
          value={raw}
          onChange={(event) => setRaw(event.target.value)}
        />
        <label htmlFor="eml-file">Or upload a .eml file</label>
        <input id="eml-file" type="file" accept=".eml" onChange={handleFile} />
        <button type="submit" disabled={loading || raw.trim().length === 0}>
          {loading ? "Checking..." : "Check email"}
        </button>
      </form>
      {error && <p role="alert">{error}</p>}

      {result && (
        <section aria-label="Analysis result">
          <div className={`border-2 rounded p-4 ${VERDICT_STYLES[result.verdict].className}`}>
            <strong>{VERDICT_STYLES[result.verdict].label}</strong>
          </div>

          {result.headerless && (
            <p role="status">
              No headers were provided, so the sender couldn&apos;t be verified.
            </p>
          )}

          {result.advisory && <p>{result.advisory}</p>}

          <h2>Reasons</h2>
          <ul>
            {result.reasons.map((reason, index) => (
              <li key={index}>
                <strong>{reason.title}</strong>
                {": "}
                {reason.explanation}
              </li>
            ))}
          </ul>

          <h2>What to do</h2>
          <ul>
            {result.actions.map((action, index) => (
              <li key={index}>{action}</li>
            ))}
          </ul>

          <details>
            <summary>Details</summary>

            <h3>Authentication</h3>
            <p>{result.authSummary ?? "No authentication information available."}</p>

            <h3>Links</h3>
            {result.links && result.links.length > 0 ? (
              <ul>
                {result.links.map((link, index) => (
                  <li key={index}>
                    {link.text ? `${link.text} -> ` : ""}
                    {defang(link.href)}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No links found.</p>
            )}

            <h3>Signals</h3>
            {result.signalSummaries && result.signalSummaries.length > 0 ? (
              <ul>
                {result.signalSummaries.map((summary, index) => (
                  <li key={index}>{summary}</li>
                ))}
              </ul>
            ) : (
              <p>No notable rule signals.</p>
            )}
          </details>
        </section>
      )}
    </main>
  );
}
