import { HalluDefenseClient } from "@hallu-defense/sdk";

import type { BrowserAuthenticatedSession } from "./browser-session";

export type ConsoleApiClientFactory = (signal?: AbortSignal) => HalluDefenseClient;

export function createConsoleApiClient(
  session: BrowserAuthenticatedSession
): ConsoleApiClientFactory {
  return (externalSignal?: AbortSignal) =>
    new HalluDefenseClient({
      baseUrl: "/api",
      timeoutMs: 15_000,
      fetchImpl: async (input, init = {}) => {
        const target = new URL(requestUrl(input), globalThis.location.origin);
        if (
          target.origin !== globalThis.location.origin ||
          !target.pathname.startsWith("/api/")
        ) {
          throw new TypeError("Console API request escaped the same-origin BFF.");
        }
        const headers = new Headers(init.headers);
        headers.set("x-console-csrf", session.csrfToken);
        return fetch(target, {
          ...init,
          headers,
          credentials: "same-origin",
          mode: "same-origin",
          redirect: "error",
          cache: "no-store",
          signal: combinedSignal(init.signal, externalSignal) ?? null
        });
      }
    });
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") {
    return input;
  }
  return input instanceof URL ? input.toString() : input.url;
}

function combinedSignal(
  requestSignal: AbortSignal | null | undefined,
  externalSignal: AbortSignal | undefined
): AbortSignal | undefined {
  const signals = [requestSignal, externalSignal].filter(
    (signal): signal is AbortSignal => signal !== null && signal !== undefined
  );
  if (signals.length === 0) {
    return undefined;
  }
  if (signals.length === 1) {
    return signals[0];
  }
  return AbortSignal.any(signals);
}
