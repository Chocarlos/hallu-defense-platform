import type { Metadata } from "next";

import { MarketingPage } from "../../../components/marketing/marketing-page";
import { loadRuntimeMarketingPublicConfig } from "../../../lib/marketing/runtime-config";
import { buildLandingMetadata } from "../../../lib/marketing/seo";

export async function generateMetadata(): Promise<Metadata> {
  const config = await loadRuntimeMarketingPublicConfig();
  return buildLandingMetadata("en", config.siteOrigin);
}

export default async function EnglishLandingPage() {
  const config = await loadRuntimeMarketingPublicConfig();
  return <MarketingPage locale="en" demoRequestsEnabled={config.demoRequestsEnabled} siteOrigin={config.siteOrigin} />;
}
