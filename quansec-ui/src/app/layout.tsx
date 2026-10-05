import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth-context";
import { DEFAULT_THEME, THEME_BOOT_SCRIPT, THEME_COLOR } from "@/lib/theme-script";

export const metadata: Metadata = {
  title: "QUANSEC — IPsec Security Console",
  description: "Post-quantum IPsec monitoring and policy management",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    // The boot script may change data-theme before hydration, so the
    // server-rendered attribute is allowed to differ.
    <html lang="en" data-theme={DEFAULT_THEME} className="h-full antialiased" suppressHydrationWarning>
      <head>
        <meta name="theme-color" content={THEME_COLOR[DEFAULT_THEME]} />
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
      </head>
      <body className="min-h-full">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
