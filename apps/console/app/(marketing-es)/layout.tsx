import type { ReactNode } from "react";

import { MarketingRoot } from "../../components/marketing/marketing-root";

export default function SpanishMarketingLayout({ children }: Readonly<{ children: ReactNode }>) {
  return <MarketingRoot locale="es">{children}</MarketingRoot>;
}
