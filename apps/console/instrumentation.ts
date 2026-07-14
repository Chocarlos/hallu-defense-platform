export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { validateServerStartup } = await import("./instrumentation-node");
    validateServerStartup();
  }
}
