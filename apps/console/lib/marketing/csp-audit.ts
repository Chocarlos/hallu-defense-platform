const SCRIPT_TAG = /<script\b[^>]*>/giu;
const EXECUTABLE_TYPES = new Set([
  "importmap",
  "module",
  "text/ecmascript",
  "text/javascript"
]);

export interface ExecutableScriptNonceAudit {
  readonly executableScriptCount: number;
  readonly responseNonce: string | null;
  readonly unauthorizedScriptIndexes: readonly number[];
}

export function auditExecutableScriptNonces(
  html: string,
  contentSecurityPolicy: string
): ExecutableScriptNonceAudit {
  const responseNonce = scriptNonce(contentSecurityPolicy);
  const executableTags = [...html.matchAll(SCRIPT_TAG)]
    .map(([tag]) => tag)
    .filter(isExecutableScript);
  const unauthorizedScriptIndexes = executableTags.flatMap((tag, index) =>
    responseNonce !== null && attribute(tag, "nonce") === responseNonce ? [] : [index]
  );
  return {
    executableScriptCount: executableTags.length,
    responseNonce,
    unauthorizedScriptIndexes
  };
}

function scriptNonce(policy: string): string | null {
  const directive = policy
    .split(";")
    .map((value) => value.trim())
    .find((value) => value === "script-src" || value.startsWith("script-src "));
  if (directive === undefined) {
    return null;
  }
  const match = /(?:^|\s)'nonce-([^']+)'(?:\s|$)/u.exec(directive);
  return match?.[1] ?? null;
}

function isExecutableScript(tag: string): boolean {
  const type = attribute(tag, "type")?.trim().toLowerCase();
  return (
    type === undefined ||
    type === "" ||
    EXECUTABLE_TYPES.has(type) ||
    type.includes("javascript") ||
    type.includes("ecmascript")
  );
}

function attribute(tag: string, name: "nonce" | "type"): string | undefined {
  const match = new RegExp(
    `\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\u0060]+))`,
    "iu"
  ).exec(tag);
  return match?.[1] ?? match?.[2] ?? match?.[3];
}
