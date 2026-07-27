import { describe, expect, test } from "bun:test";
import { API_KEY_RECORD_RESOURCE, runIssueKey, signingSecretEnvName, databaseUrlEnvName } from "../src/cli/issue-key";
import { verifyApiKeyToken } from "../src/auth/keys";

const SIGNING = "test-signing-secret-not-a-real-credential-000";

function collectReports() {
  const reports: Array<{ error: string; details?: Record<string, unknown> }> = [];
  return {
    reports,
    report: (_o: { json?: boolean }, error: string, details?: Record<string, unknown>) => {
      reports.push({ error, ...(details ? { details } : {}) });
    },
  };
}

async function captureStdout(fn: () => Promise<void>): Promise<string> {
  const original = console.log;
  const lines: string[] = [];
  console.log = (...args: unknown[]) => void lines.push(args.map((a) => String(a)).join(" "));
  try {
    await fn();
  } finally {
    console.log = original;
  }
  return lines.join("\n");
}

describe("issue-key env name resolution", () => {
  test("default env names follow the HASNA_<APP>_ convention", () => {
    expect(signingSecretEnvName("todos")).toBe("HASNA_TODOS_API_SIGNING_KEY");
    expect(signingSecretEnvName("open-brain")).toBe("HASNA_OPEN_BRAIN_API_SIGNING_KEY");
    expect(databaseUrlEnvName("todos")).toBe("HASNA_TODOS_DATABASE_URL");
    expect(signingSecretEnvName("todos", "CUSTOM_ENV")).toBe("CUSTOM_ENV");
  });
});

describe("runIssueKey", () => {
  test("errors when --app is missing", async () => {
    const { reports, report } = collectReports();
    await runIssueKey({ json: true }, { report, env: {} });
    expect(reports[0]?.error).toContain("--app");
  });

  test("errors when scopes missing and not bootstrap", async () => {
    const { reports, report } = collectReports();
    await runIssueKey({ app: "todos", json: true }, { report, env: { HASNA_TODOS_API_SIGNING_KEY: SIGNING } });
    expect(reports[0]?.error).toContain("--scopes");
  });

  test("errors when signing secret missing", async () => {
    const { reports, report } = collectReports();
    await runIssueKey({ app: "todos", scopes: "todos:read", store: false, json: true }, { report, env: {} });
    expect(reports[0]?.error).toContain("signing secret");
  });

  test("mints and prints a JSON key (no-store) that verifies", async () => {
    const { reports, report } = collectReports();
    let out = "";
    out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read,todos:write", store: false, json: true, agent: "ci" },
        { report, env: { HASNA_TODOS_API_SIGNING_KEY: SIGNING } },
      );
    });
    expect(reports).toEqual([]);
    const parsed = JSON.parse(out);
    expect(parsed.ok).toBe(true);
    expect(parsed.stored).toBe(false);
    expect(parsed.app).toBe("todos");
    expect(parsed.scopes).toEqual(["todos:read", "todos:write"]);
    expect(parsed.token.startsWith("hasna_todos_")).toBe(true);
    const verified = verifyApiKeyToken(parsed.token, { signingSecret: SIGNING, expectedApp: "todos", requiredScopes: ["todos:write"] });
    expect(verified.ok).toBe(true);
  });

  test("bootstrap defaults scopes to <app>:* and agent bootstrap", async () => {
    const { reports, report } = collectReports();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", bootstrap: true, store: false, json: true },
        { report, env: { HASNA_API_SIGNING_KEY: SIGNING } },
      );
    });
    expect(reports).toEqual([]);
    const parsed = JSON.parse(out);
    expect(parsed.scopes).toEqual(["todos:*"]);
    expect(parsed.agent).toBe("bootstrap");
    expect(parsed.bootstrap).toBe(true);
  });

  test("falls back to HASNA_API_SIGNING_KEY when app-specific is absent", async () => {
    const { reports, report } = collectReports();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", store: false, json: true },
        { report, env: { HASNA_API_SIGNING_KEY: SIGNING } },
      );
    });
    expect(reports).toEqual([]);
    expect(JSON.parse(out).ok).toBe(true);
  });

  test("no-expiry mints a non-expiring key", async () => {
    const { reports, report } = collectReports();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", store: false, json: true, expiry: false },
        { report, env: { HASNA_TODOS_API_SIGNING_KEY: SIGNING } },
      );
    });
    expect(reports).toEqual([]);
    expect(JSON.parse(out).expiresAt).toBeNull();
  });

  test("stores through the database fallback when no API transport is configured", async () => {
    const { reports, report } = collectReports();
    const inserted: Array<{ kid: string; createdBy: string | undefined }> = [];
    let schemaEnsured = false;
    let closed = false;
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", json: true, agent: "issuer" },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_DATABASE_URL: "postgres://unused.example/unused",
          },
          connectStore: async (connectionString, table) => {
            expect(connectionString).toBe("postgres://unused.example/unused");
            expect(table).toBe("api_keys");
            return {
              store: {
                ensureSchema: async () => {
                  schemaEnsured = true;
                },
                insertMinted: async (minted, createdBy) => {
                  inserted.push({ kid: minted.kid, createdBy });
                },
              },
              close: async () => {
                closed = true;
              },
            };
          },
        },
      );
    });
    expect(reports).toEqual([]);
    const parsed = JSON.parse(out);
    expect(parsed.ok).toBe(true);
    expect(parsed.stored).toBe(true);
    expect(parsed.storeBackend).toBe("database");
    expect(schemaEnsured).toBe(true);
    expect(closed).toBe(true);
    expect(inserted).toEqual([{ kid: parsed.kid, createdBy: "issuer" }]);
  });

  test("cloud mode stores the hashed record through the API transport", async () => {
    const { reports, report } = collectReports();
    const calls: Array<{ url: string; method: string; headers: Record<string, string>; body: Record<string, unknown> }> = [];
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read,todos:write", json: true, agent: "issuer", tid: "acme-corp" },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_STORAGE_MODE: "cloud",
            HASNA_TODOS_API_URL: "https://todos.example.test/contracts",
            HASNA_TODOS_API_KEY: "operator-api-key",
          },
          transportOverrides: {
            retry: false,
            fetchImpl: async (input, init) => {
              const headers: Record<string, string> = {};
              for (const [key, value] of Object.entries(init?.headers as Record<string, string>)) {
                headers[key.toLowerCase()] = value;
              }
              calls.push({
                url: String(input),
                method: init?.method ?? "GET",
                headers,
                body: JSON.parse(String(init?.body)),
              });
              return Response.json({ ok: true }, { status: 201 });
            },
          },
        },
      );
    });
    expect(reports).toEqual([]);
    const parsed = JSON.parse(out);
    expect(parsed.ok).toBe(true);
    expect(parsed.stored).toBe(true);
    expect(parsed.storeBackend).toBe("api");
    expect(calls.length).toBe(1);
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.url).toBe(`https://todos.example.test/contracts/v1/${API_KEY_RECORD_RESOURCE}`);
    expect(calls[0]!.headers["authorization"]).toBe("Bearer operator-api-key");
    expect(calls[0]!.headers["x-api-key"]).toBe("operator-api-key");
    expect(calls[0]!.headers["idempotency-key"]).toBe(parsed.kid);
    expect(calls[0]!.body).toMatchObject({
      kid: parsed.kid,
      app: "todos",
      agent: "issuer",
      tid: "acme-corp",
      scopes: ["todos:read", "todos:write"],
      tokenHash: parsed.tokenHash,
      createdBy: "issuer",
    });
    expect(calls[0]!.body.token).toBeUndefined();
    expect(JSON.stringify(calls[0]!.body)).not.toContain(parsed.token);
  });
});
