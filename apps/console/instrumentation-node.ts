import {
  loadDemoRuntimeConfig,
  type EnvironmentSource
} from "./lib/demo-request/config";

/**
 * Validate file-backed intake settings before a Node server becomes ready.
 * Disabled intake remains a valid launch state; enabled production intake is
 * rejected unless every HTTPS, Redis TLS, secret, and metrics precondition is
 * present and readable.
 */
export function validateServerStartup(
  env: EnvironmentSource = process.env
): void {
  loadDemoRuntimeConfig(env);
}
