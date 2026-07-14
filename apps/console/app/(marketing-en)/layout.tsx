import type { ReactNode } from "react";

import { MarketingRoot } from "../../components/marketing/marketing-root";

export default function EnglishMarketingLayout({ children }: Readonly<{ children: ReactNode }>) {
  return <MarketingRoot locale="en">{children}</MarketingRoot>;
}
