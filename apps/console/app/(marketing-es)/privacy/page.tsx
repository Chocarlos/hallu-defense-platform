import type { Metadata } from "next";

import { PrivacyPage } from "../../../components/marketing/privacy-page";
import { loadMarketingPublicConfig } from "../../../lib/marketing/config";
import { buildPrivacyMetadata } from "../../../lib/marketing/seo";

export function generateMetadata(): Metadata {
  const config = loadMarketingPublicConfig();
  return buildPrivacyMetadata("es", config.siteOrigin);
}

export default function SpanishPrivacyPage() {
  const config = loadMarketingPublicConfig();
  return <PrivacyPage locale="es" contactEmail={config.privacyContactEmail} />;
}
