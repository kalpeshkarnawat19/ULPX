import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ULPF-X — Universal Log Parsing Framework",
  description:
    "A lightweight, secure and extensible framework for collecting, parsing and normalizing log data.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}