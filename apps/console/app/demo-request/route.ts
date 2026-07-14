import { createDemoRequestHandler } from "../../lib/demo-request/service";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Constructing the handler validates enabled production configuration when
// this route module is loaded. The root instrumentation hook may call the same
// loader to make the check process-start eager across deployment modes.
const handleDemoRequest = createDemoRequestHandler();

export async function POST(request: Request): Promise<Response> {
  return handleDemoRequest(request);
}
