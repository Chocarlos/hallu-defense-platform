import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Hallu Defense Console",
  description: "Operational console for hallucination defense runs"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
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

