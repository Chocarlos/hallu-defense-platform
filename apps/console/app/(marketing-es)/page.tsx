import type { Metadata } from "next";

import { MarketingPage } from "../../components/marketing/marketing-page";
import { loadMarketingPublicConfig } from "../../lib/marketing/config";
import { buildLandingMetadata } from "../../lib/marketing/seo";

export function generateMetadata(): Metadata {
  const config = loadMarketingPublicConfig();
  return buildLandingMetadata("es", config.siteOrigin);
}

export default function SpanishLandingPage() {
  const config = loadMarketingPublicConfig();
  return <MarketingPage locale="es" demoRequestsEnabled={config.demoRequestsEnabled} siteOrigin={config.siteOrigin} />;
}
