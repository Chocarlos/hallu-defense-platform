import type { Metadata } from "next";

import { PrivacyPage } from "../../../components/marketing/privacy-page";
import { loadRuntimeMarketingPublicConfig } from "../../../lib/marketing/runtime-config";
import { buildPrivacyMetadata } from "../../../lib/marketing/seo";

export async function generateMetadata(): Promise<Metadata> {
  const config = await loadRuntimeMarketingPublicConfig();
  return buildPrivacyMetadata("es", config.siteOrigin);
}

export default async function SpanishPrivacyPage() {
  const config = await loadRuntimeMarketingPublicConfig();
  return <PrivacyPage locale="es" contactEmail={config.privacyContactEmail} />;
}
