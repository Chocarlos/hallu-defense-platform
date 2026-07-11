import type { NextRequest } from "next/server";

import { forwardConsoleApiRequest } from "../../../lib/console-bff";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  context: { readonly params: Promise<{ readonly path: readonly string[] }> }
) {
  const { path } = await context.params;
  return forwardConsoleApiRequest(request, path);
}
