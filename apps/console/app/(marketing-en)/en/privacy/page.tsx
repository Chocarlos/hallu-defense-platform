import type { Metadata } from "next";

import { PrivacyPage } from "../../../../components/marketing/privacy-page";
import { loadRuntimeMarketingPublicConfig } from "../../../../lib/marketing/runtime-config";
import { buildPrivacyMetadata } from "../../../../lib/marketing/seo";

export async function generateMetadata(): Promise<Metadata> {
  const config = await loadRuntimeMarketingPublicConfig();
  return buildPrivacyMetadata("en", config.siteOrigin);
}

export default async function EnglishPrivacyPage() {
  const config = await loadRuntimeMarketingPublicConfig();
  return <PrivacyPage locale="en" contactEmail={config.privacyContactEmail} />;
}
