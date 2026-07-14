import { expect, test } from "@playwright/test";

for (const path of ["/", "/en", "/privacy", "/en/privacy"] as const) {
  test(`response CSP nonce authorizes every executable script on ${path}`, async ({ page }) => {
    const response = await page.goto(path, { waitUntil: "load" });
    expect(response).not.toBeNull();
    expect(response?.status()).toBe(200);
    const policy = response?.headers()["content-security-policy"] ?? "";
    const nonceMatches = [
      ...policy.matchAll(/(?:^|;)\s*script-src\s+[^;]*'nonce-([^']+)'/gu)
    ];
    expect(nonceMatches, `CSP: ${policy}`).toHaveLength(1);
    const responseNonce = nonceMatches[0]?.[1];
    expect(responseNonce).toBeTruthy();

    const executableScripts = await page.locator("script").evaluateAll((elements) =>
      (elements as HTMLScriptElement[])
        .filter((script) => {
          const type = script.type.trim().toLowerCase();
          return !["application/json", "application/ld+json"].includes(type);
        })
        .map((script, index) => ({
          index,
          source: script.src === "" ? "<inline>" : new URL(script.src).pathname,
          type: script.type,
          nonce: script.nonce
        }))
    );
    expect(executableScripts.length).toBeGreaterThan(0);
    expect(
      executableScripts.filter(({ nonce }) => nonce !== responseNonce),
      `CSP nonce mismatch: ${JSON.stringify(executableScripts)}`
    ).toEqual([]);
  });
}
