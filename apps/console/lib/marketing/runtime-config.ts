import "server-only";

import { connection } from "next/server";

import { loadMarketingPublicConfig, type MarketingPublicConfig } from "./config";

export async function loadRuntimeMarketingPublicConfig(): Promise<MarketingPublicConfig> {
  await connection();
  return loadMarketingPublicConfig();
}
