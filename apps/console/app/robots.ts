import type { MetadataRoute } from "next";

import { loadMarketingPublicConfig } from "../lib/marketing/config";
import { buildMarketingRobots } from "../lib/marketing/seo";

export default function robots(): MetadataRoute.Robots {
  return buildMarketingRobots(loadMarketingPublicConfig().siteOrigin);
}
