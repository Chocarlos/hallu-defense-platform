import { connection } from "next/server";

import { RunConsole } from "../../run-console";
import {
  browserRuntimeConfig,
  loadConsoleRuntimeConfig
} from "../../../lib/runtime-config";

export const dynamic = "force-dynamic";

export default async function ConsolePage() {
  await connection();
  const consoleRuntimeConfig = loadConsoleRuntimeConfig();
  const runtimeConfig = browserRuntimeConfig(consoleRuntimeConfig);
  return <RunConsole runtimeConfig={runtimeConfig} />;
}
