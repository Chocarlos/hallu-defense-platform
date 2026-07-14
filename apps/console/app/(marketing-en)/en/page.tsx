import type { Metadata } from "next";

import { MarketingPage } from "../../../components/marketing/marketing-page";
import { loadMarketingPublicConfig } from "../../../lib/marketing/config";
import { buildLandingMetadata } from "../../../lib/marketing/seo";

export function generateMetadata(): Metadata {
  const config = loadMarketingPublicConfig();
  return buildLandingMetadata("en", config.siteOrigin);
}

export default function EnglishLandingPage() {
  const config = loadMarketingPublicConfig();
  return <MarketingPage locale="en" demoRequestsEnabled={config.demoRequestsEnabled} siteOrigin={config.siteOrigin} />;
}
