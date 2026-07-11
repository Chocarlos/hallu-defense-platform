import { describe, expect, it, vi } from "vitest";
import { safeConsoleApiError } from "./api-error";

describe("safe Console API errors", () => {
  it.each([
    [403, "permiso"],
    [429, "Demasiadas"],
    [500, "temporalmente"],
    [503, "temporalmente"]
  ])("maps status %i without exposing the upstream body", (status, expected) => {
    const result = safeConsoleApiError(
      statusError(status, "bearer secret-body"),
      "fallback"
    );
    expect(result.message).toContain(expected);
    expect(result.message).not.toContain("secret-body");
  });

  it("invalidates browser authentication on 401", () => {
    const onUnauthorized = vi.fn();
    const result = safeConsoleApiError(
      statusError(401, "token=secret"),
      "fallback",
      onUnauthorized
    );
    expect(onUnauthorized).toHaveBeenCalledOnce();
    expect(result.status).toBe(401);
    expect(result.message).not.toContain("secret");
  });
});

function statusError(status: number, message: string): Error & { readonly status: number } {
  return Object.assign(new Error(message), { status });
}
