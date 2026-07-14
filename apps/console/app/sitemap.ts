import type { MetadataRoute } from "next";

import { loadMarketingPublicConfig } from "../lib/marketing/config";
import { buildMarketingSitemap } from "../lib/marketing/seo";

export default function sitemap(): MetadataRoute.Sitemap {
  return buildMarketingSitemap(loadMarketingPublicConfig().siteOrigin);
}
