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
    <main className="mx-auto max-w-2xl px-4 py-10">
      <h1 className="text-2xl font-bold text-gray-900">Phish Check</h1>
      <p className="mt-2 text-sm text-gray-600">
        Paste the email&apos;s full raw source below (not just the visible
        text) or upload a <code className="rounded bg-gray-100 px-1">.eml</code> file. To
        get the full source - Gmail: open the message, click the three-dot
        menu, &quot;Show original&quot;. Outlook: open the message, &quot;View
        message source&quot;. Apple Mail: select the message, Message menu
        &rarr; &quot;Raw Source&quot;.
      </p>
      <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-3">
        <label htmlFor="raw-email" className="text-sm font-medium text-gray-700">
          Paste raw email source
        </label>
        <textarea
          id="raw-email"
          value={raw}
          onChange={(event) => setRaw(event.target.value)}
          rows={10}
          className="w-full rounded border border-gray-300 p-3 font-mono text-sm focus:border-gray-500 focus:outline-none"
        />
        <label htmlFor="eml-file" className="text-sm font-medium text-gray-700">
          Or upload a .eml file
        </label>
        <input
          id="eml-file"
          type="file"
          accept=".eml"
          onChange={handleFile}
          className="text-sm"
        />
        <button
          type="submit"
          disabled={loading || raw.trim().length === 0}
          className="mt-2 self-start rounded bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-700 disabled:cursor-not-allowed disabled:bg-gray-300"
        >
          {loading ? "Checking..." : "Check email"}
        </button>
      </form>
      {error && (
        <p role="alert" className="mt-4 text-sm text-red-700">
          {error}
        </p>
      )}

      {result && (
        <section aria-label="Analysis result" className="mt-8 flex flex-col gap-4">
          <div
            className={`rounded border-2 p-4 text-lg font-semibold ${VERDICT_STYLES[result.verdict].className}`}
          >
            {VERDICT_STYLES[result.verdict].label}
          </div>

          {result.headerless && (
            <p role="status" className="rounded bg-amber-50 p-3 text-sm text-amber-900">
              No headers were provided, so the sender couldn&apos;t be verified.
            </p>
          )}

          {result.advisory && (
            <p className="rounded bg-blue-50 p-3 text-sm text-blue-900">{result.advisory}</p>
          )}

          <div>
            <h2 className="text-base font-semibold text-gray-900">Reasons</h2>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-gray-700">
              {result.reasons.map((reason, index) => (
                <li key={index}>
                  <strong>{reason.title}</strong>
                  {": "}
                  {reason.explanation}
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h2 className="text-base font-semibold text-gray-900">What to do</h2>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-gray-700">
              {result.actions.map((action, index) => (
                <li key={index}>{action}</li>
              ))}
            </ul>
          </div>

          <details className="rounded border border-gray-200 p-3 text-sm">
            <summary className="cursor-pointer font-medium text-gray-900">Details</summary>

            <h3 className="mt-3 font-medium text-gray-800">Authentication</h3>
            <p className="mt-1 text-gray-600">
              {result.authSummary ?? "No authentication information available."}
            </p>

            <h3 className="mt-3 font-medium text-gray-800">Links</h3>
            {result.links && result.links.length > 0 ? (
              <ul className="mt-1 list-disc space-y-1 pl-5 text-gray-600">
                {result.links.map((link, index) => (
                  <li key={index}>
                    {link.text ? `${link.text} -> ` : ""}
                    {defang(link.href)}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-1 text-gray-600">No links found.</p>
            )}

            <h3 className="mt-3 font-medium text-gray-800">Signals</h3>
            {result.signalSummaries && result.signalSummaries.length > 0 ? (
              <ul className="mt-1 list-disc space-y-1 pl-5 text-gray-600">
                {result.signalSummaries.map((summary, index) => (
                  <li key={index}>{summary}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-1 text-gray-600">No notable rule signals.</p>
            )}
          </details>
        </section>
      )}
    </main>
  );
}
