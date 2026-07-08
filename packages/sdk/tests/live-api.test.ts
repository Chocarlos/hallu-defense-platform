import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { HalluDefenseClient } from "../src/index.js";

type ApiServer = {
  readonly baseUrl: string;
  readonly stop: () => Promise<void>;
};

const testDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(testDir, "../../..");

describe("HalluDefenseClient live API contract", () => {
  let server: ApiServer | undefined;

  beforeAll(async () => {
    server = await startApiServer();
  }, 20000);

  afterAll(async () => {
    await server?.stop();
  });

  it("propagates tenant and trace IDs through FastAPI and audit events", async () => {
    if (server === undefined) {
      throw new Error("API server did not start");
    }

    const tenantId = "sdk-live-contract";
    const traceId = "tr_sdk_live_contract";
    const client = new HalluDefenseClient({
      baseUrl: server.baseUrl,
      tenantId,
      traceId
    });

    const run = await client.runVerification({
      message_text: "Full-time employees receive 15 days of paid vacation per year.",
      documents: [
        {
          source_ref: "hr-manual-v7",
          content: "Full-time employees receive 15 days of paid vacation per year.",
          authority: "internal"
        }
      ]
    });

    expect(run.trace_id).toBe(traceId);
    expect(run.tenant_id).toBe(tenantId);
    expect(run.claims.length).toBeGreaterThan(0);
    expect(run.verdicts.length).toBeGreaterThan(0);

    const ingestion = await client.ingestDocuments({
      corpus_id: "hr",
      documents: [
        {
          source_ref: "hr-manual-v7",
          content: "Full-time employees receive 15 days of paid vacation per year.",
          authority: "internal"
        }
      ]
    });

    expect(ingestion.trace_id).toBe(traceId);
    expect(ingestion.tenant_id).toBe(tenantId);
    expect(ingestion.backend).toBe("local");
    expect(ingestion.indexed_count).toBe(0);
    expect(ingestion.warnings.length).toBe(1);

    const grantWriterClient = new HalluDefenseClient({
      baseUrl: server.baseUrl,
      tenantId,
      traceId: "tr_sdk_live_grant",
      subjectId: "sdk-rag-writer",
      roles: ["rag_writer"]
    });
    const grant = await grantWriterClient.upsertCorpusGrant({
      corpus_id: "hr",
      reader_roles: ["hr_reader"],
      writer_roles: ["hr_writer"],
      expected_version: 0
    });

    expect(grant.grant.tenant_id).toBe(tenantId);
    expect(grant.grant.corpus_id).toBe("hr");
    expect(grant.grant.updated_by).toBe("sdk-rag-writer");
    expect(grant.grant.version).toBe(1);

    const verifierClient = new HalluDefenseClient({
      baseUrl: server.baseUrl,
      tenantId,
      traceId: "tr_sdk_live_grant_list",
      subjectId: "sdk-verifier",
      roles: ["verifier"]
    });
    const grants = await verifierClient.listCorpusGrants({ corpus_id: "hr" });

    expect(grants.grants.map((item) => item.corpus_id)).toEqual(["hr"]);
    expect(grants.next_cursor).toBeNull();

    const disabled = await grantWriterClient.disableCorpusGrant({
      corpus_id: "hr",
      expected_version: grant.grant.version
    });
    expect(disabled.grant.disabled_by).toBe("sdk-rag-writer");
    expect(disabled.grant.version).toBe(2);

    const activeAfterDisable = await verifierClient.listCorpusGrants({ corpus_id: "hr" });
    expect(activeAfterDisable.grants).toEqual([]);
    const disabledGrants = await verifierClient.listCorpusGrants({
      corpus_id: "hr",
      include_disabled: true
    });
    expect(disabledGrants.grants[0]?.disabled_by).toBe("sdk-rag-writer");
    const history = await verifierClient.corpusGrantHistory({
      corpus_id: "hr",
      actor_id: "sdk-rag-writer"
    });
    expect(history.grants.map((item) => item.version)).toEqual([1, 2]);
    expect(history.next_cursor).toBeNull();
    const historyDiff = await verifierClient.corpusGrantHistoryDiff({
      corpus_id: "hr",
      actor_id: "sdk-rag-writer"
    });
    expect(historyDiff.diffs.map((item) => item.action)).toEqual(["create", "disable"]);
    expect(historyDiff.diffs[1]?.previous_version).toBe(1);
    expect(historyDiff.next_cursor).toBeNull();

    const auditClient = new HalluDefenseClient({
      baseUrl: server.baseUrl,
      tenantId,
      traceId: "tr_sdk_live_audit"
    });
    const audit = await auditClient.exportAudit({ tenant_id: tenantId, include_events: true });

    expect(audit.events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          tenant_id: tenantId,
          trace_id: traceId,
          path: "/verification/run",
          outcome: "success"
        }),
        expect.objectContaining({
          tenant_id: tenantId,
          trace_id: traceId,
          path: "/documents/ingest",
          outcome: "success"
        }),
        expect.objectContaining({
          tenant_id: tenantId,
          trace_id: "tr_sdk_live_grant",
          path: "/rag/corpus-grants/upsert",
          outcome: "success"
        }),
        expect.objectContaining({
          tenant_id: tenantId,
          trace_id: "tr_sdk_live_grant",
          path: "/rag/corpus-grants/disable",
          outcome: "success"
        })
      ])
    );
  });
});

async function startApiServer(): Promise<ApiServer> {
  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const python = resolvePython();
  const child = spawn(
    python,
    ["-m", "uvicorn", "hallu_defense.main:app", "--host", "127.0.0.1", "--port", String(port)],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
        HALLU_DEFENSE_ALLOWED_WORKSPACE: repoRoot
      },
      stdio: ["ignore", "pipe", "pipe"]
    }
  );

  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });

  try {
    await waitForHealth(baseUrl, 15000);
  } catch (error) {
    await stopChild(child);
    throw new Error(
      `FastAPI server failed to become healthy: ${
        error instanceof Error ? error.message : String(error)
      }\nstdout:\n${stdout}\nstderr:\n${stderr}`
    );
  }

  return {
    baseUrl,
    stop: async () => {
      await stopChild(child);
    }
  };
}

function resolvePython(): string {
  const candidate =
    process.platform === "win32"
      ? path.join(repoRoot, ".venv", "Scripts", "python.exe")
      : path.join(repoRoot, ".venv", "bin", "python");
  if (process.env.HALLU_CONTRACT_PYTHON !== undefined) {
    return process.env.HALLU_CONTRACT_PYTHON;
  }
  return existsSync(candidate) ? candidate : "python";
}

async function getFreePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Could not allocate a TCP port");
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
  return address.port;
}

async function waitForHealth(baseUrl: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(1000) });
      if (response.ok) {
        return;
      }
    } catch {
      // The server may still be booting; retry until the deadline.
    }
    await delay(150);
  }
  throw new Error(`Timed out waiting for ${baseUrl}/health`);
}

async function stopChild(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  child.kill();
  await Promise.race([
    new Promise<void>((resolve) => {
      child.once("exit", () => resolve());
    }),
    delay(2000)
  ]);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
