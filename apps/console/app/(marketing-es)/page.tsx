import type { Metadata } from "next";

import { MarketingPage } from "../../components/marketing/marketing-page";
import { loadRuntimeMarketingPublicConfig } from "../../lib/marketing/runtime-config";
import { buildLandingMetadata } from "../../lib/marketing/seo";

export async function generateMetadata(): Promise<Metadata> {
  const config = await loadRuntimeMarketingPublicConfig();
  return buildLandingMetadata("es", config.siteOrigin);
}

export default async function SpanishLandingPage() {
  const config = await loadRuntimeMarketingPublicConfig();
  return <MarketingPage locale="es" demoRequestsEnabled={config.demoRequestsEnabled} siteOrigin={config.siteOrigin} />;
}
