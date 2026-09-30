// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import Home from "./page";
import type { AnalysisResult } from "../lib/types";

// Component-level UI tests for slice 9. Synthetic data only (no fixtures).
// fetch is always mocked here - no network calls in tests.

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function mockFetchOnce(result: AnalysisResult) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => result,
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function submitEmail(raw: string) {
  const textarea = screen.getByLabelText(/paste raw email source/i);
  fireEvent.change(textarea, { target: { value: raw } });
  const button = screen.getByRole("button", { name: /check email/i });
  fireEvent.click(button);
}

describe("page - result rendering never injects raw HTML", () => {
  it("renders reasons/actions as plain text, never as live <img>/<script> DOM nodes", async () => {
    const dangerousExplanation =
      'Visible link text contained <img src=x onerror="alert(document.cookie)"> before a lookalike href.';

    const fakeResult: AnalysisResult = {
      verdict: "phishing",
      reasons: [
        {
          title: "Link destination doesn't match its visible text",
          explanation: dangerousExplanation,
        },
      ],
      actions: ["Do not click any links, open attachments, or reply."],
    };

    mockFetchOnce(fakeResult);
    render(<Home />);
    await submitEmail("From: a@example.com\r\nTo: b@example.org\r\n\r\nhi");

    // The explanation text must actually reach the screen (as text)...
    await waitFor(() => {
      expect(screen.getByText(/onerror/i)).toBeInTheDocument();
    });

    // ...but never as parsed HTML elements.
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
    // And no element's innerHTML should have been set via
    // dangerouslySetInnerHTML with the raw markup baked in as tags.
    expect(document.body.innerHTML).not.toContain("<img src=x");
  });
});

describe("page - sender-unverified notice", () => {
  it("shows a 'sender couldn't be verified' notice when the result is headerless", async () => {
    const fakeResult: AnalysisResult = {
      verdict: "suspicious",
      reasons: [{ title: "No headers", explanation: "No headers were present." }],
      actions: ["Ask the sender to forward the original message with full headers."],
      headerless: true,
    };

    mockFetchOnce(fakeResult);
    render(<Home />);
    await submitEmail("Just a plain pasted body with no headers at all.");

    await waitFor(() => {
      expect(screen.getByText(/sender couldn't be verified/i)).toBeInTheDocument();
    });
  });

  it("does not show the notice when headers were present", async () => {
    const fakeResult: AnalysisResult = {
      verdict: "likely_safe",
      reasons: [{ title: "Looks fine", explanation: "No notable signals." }],
      actions: ["No action needed."],
    };

    mockFetchOnce(fakeResult);
    render(<Home />);
    await submitEmail("From: a@example.com\r\nTo: b@example.org\r\n\r\nhi");

    await waitFor(() => {
      expect(screen.getByText(/no notable signals/i)).toBeInTheDocument();
    });
    expect(screen.queryByText(/sender couldn't be verified/i)).not.toBeInTheDocument();
  });
});
