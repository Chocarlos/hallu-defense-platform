import type { MetadataRoute } from "next";

import { loadRuntimeMarketingPublicConfig } from "../lib/marketing/runtime-config";
import { buildMarketingRobots } from "../lib/marketing/seo";

export default async function robots(): Promise<MetadataRoute.Robots> {
  return buildMarketingRobots(
    (await loadRuntimeMarketingPublicConfig()).siteOrigin
  );
}
