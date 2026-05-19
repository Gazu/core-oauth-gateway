import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "core-oauth-gateway",
  description: "OAuth2 service compatible with Passport-style endpoints"
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}
