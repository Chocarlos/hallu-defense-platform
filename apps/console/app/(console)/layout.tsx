import type { Metadata } from "next";

import "../globals.css";

export const metadata: Metadata = {
  metadataBase: new URL(
    process.env.HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN ?? "http://localhost:3000"
  ),
  title: "Hallu Defense Console",
  description: "Consola operativa autenticada de Hallu Defense",
  robots: {
    index: false,
    follow: false,
    nocache: true
  }
};

export default function ConsoleRootLayout({
  children
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="es">
      <body>
        <a className="skip-link" href="#main-content">
          Saltar al contenido principal
        </a>
        {children}
      </body>
    </html>
  );
}
