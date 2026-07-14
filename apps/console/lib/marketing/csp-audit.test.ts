import { describe, expect, it } from "vitest";

import { auditExecutableScriptNonces } from "./csp-audit";

describe("marketing CSP response audit", () => {
  const policy = "default-src 'self'; script-src 'nonce-request-nonce' 'strict-dynamic'";

  it("requires the response nonce on every executable inline or external script", () => {
    expect(
      auditExecutableScriptNonces(
        [
          '<script nonce="request-nonce">self.__next_f.push([])</script>',
          '<script src="/_next/static/chunk.js" nonce="request-nonce"></script>',
          '<script type="module" nonce="request-nonce">import("/client.js")</script>',
          '<script type="application/ld+json">{"@context":"https://schema.org"}</script>'
        ].join(""),
        policy
      )
    ).toEqual({
      executableScriptCount: 3,
      responseNonce: "request-nonce",
      unauthorizedScriptIndexes: []
    });
  });

  it("reports missing, mismatched, or absent response nonces", () => {
    expect(
      auditExecutableScriptNonces(
        '<script></script><script nonce="stale"></script>',
        policy
      ).unauthorizedScriptIndexes
    ).toEqual([0, 1]);
    expect(
      auditExecutableScriptNonces(
        '<script nonce="request-nonce"></script>',
        "default-src 'self'"
      )
    ).toMatchObject({
      responseNonce: null,
      unauthorizedScriptIndexes: [0]
    });
  });

  it("does not confuse data-nonce with nonce and treats an empty type as executable", () => {
    expect(
      auditExecutableScriptNonces(
        '<script data-nonce="request-nonce"></script><script type=""></script>',
        policy
      )
    ).toEqual({
      executableScriptCount: 2,
      responseNonce: "request-nonce",
      unauthorizedScriptIndexes: [0, 1]
    });
  });
});
