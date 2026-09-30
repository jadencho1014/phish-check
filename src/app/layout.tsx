import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Phish Check",
  description: "Paste an email's raw source and get a phishing verdict.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
