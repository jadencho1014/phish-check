"use client";

import { useState } from "react";
import type { AnalysisResult } from "../lib/types";

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
      {/*
        TODO(implementer): render `result` here per CLAUDE.md's UI section:
        - verdict banner (color + text)
        - summary + top reasons with evidence (result.reasons)
        - what to do (result.actions)
        - if result.headerless, a notice that the sender couldn't be
          verified (no headers were provided)
        - collapsible details: auth results, defanged links (use
          src/lib/defang.ts - never render raw hrefs as clickable <a>), and
          rule signals
        Always render these as plain text (JSX text children), never via
        dangerouslySetInnerHTML - see page.test.tsx.
      */}
    </main>
  );
}
