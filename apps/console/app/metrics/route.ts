import { createDemoMetricsHandler } from "../../lib/demo-request/metrics-route";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const handleMetrics = createDemoMetricsHandler();

export function GET(request: Request): Response {
  return handleMetrics(request);
}
