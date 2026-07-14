import type { MetadataRoute } from "next";

import { loadRuntimeMarketingPublicConfig } from "../lib/marketing/runtime-config";
import { buildMarketingSitemap } from "../lib/marketing/seo";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  return buildMarketingSitemap(
    (await loadRuntimeMarketingPublicConfig()).siteOrigin
  );
}
