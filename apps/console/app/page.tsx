import { connection } from "next/server";

import { RunConsole } from "./run-console";
import { loadInitialVerificationRun } from "../lib/initial-run";
import {
  browserRuntimeConfig,
  loadConsoleRuntimeConfig
} from "../lib/runtime-config";

export const dynamic = "force-dynamic";

export default async function Page() {
  await connection();
  const consoleRuntimeConfig = loadConsoleRuntimeConfig();
  const runtimeConfig = browserRuntimeConfig(consoleRuntimeConfig);
  const initialRun = await loadInitialVerificationRun(consoleRuntimeConfig);
  return <RunConsole runtimeConfig={runtimeConfig} initialRun={initialRun} />;
}
