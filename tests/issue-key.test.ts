import { describe, expect, test } from "bun:test";
import {
  API_KEY_RECORD_RESOURCE,
  databaseUrlEnvName,
  resolveStoreBackend,
  runIssueKey,
  signingSecretEnvName,
} from "../src/cli/issue-key";
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
        { app: "todos", scopes: "todos:read,todos:write", json: true, agent: "issuer", tid: "acme-corp", storeBackend: "api" },
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

/** Records every database write so a test can assert the record's real destination. */
function recordingConnectStore() {
  const writes: Array<{ connectionString: string; table: string; kid: string; createdBy: string | undefined }> = [];
  return {
    writes,
    connectStore: async (connectionString: string, table: string) => ({
      store: {
        ensureSchema: async () => {},
        insertMinted: async (minted: { kid: string }, createdBy?: string) => {
          writes.push({ connectionString, table, kid: minted.kid, createdBy });
        },
      },
      close: async () => {},
    }),
  };
}

/** A fetch that fails the test if the API transport is reached at all. */
function forbiddenFetch() {
  const calls: string[] = [];
  return {
    calls,
    fetchImpl: async (input: string) => {
      calls.push(String(input));
      return Response.json({ error: "not found" }, { status: 404 });
    },
  };
}

describe("resolveStoreBackend", () => {
  test("defaults to the database so ambient API env cannot reroute the record", () => {
    expect(resolveStoreBackend({ app: "todos" })).toEqual({ ok: true, backend: "database" });
  });

  test("accepts the explicit backends", () => {
    expect(resolveStoreBackend({ storeBackend: "api" })).toEqual({ ok: true, backend: "api" });
    expect(resolveStoreBackend({ storeBackend: "AUTO" })).toEqual({ ok: true, backend: "auto" });
    expect(resolveStoreBackend({ storeBackend: "database" })).toEqual({ ok: true, backend: "database" });
  });

  test("a supplied --database-url-env/--table pins auto to the database", () => {
    expect(resolveStoreBackend({ storeBackend: "auto", databaseUrlEnv: "MY_ADMIN_DB_URL" })).toEqual({
      ok: true,
      backend: "database",
    });
    expect(resolveStoreBackend({ storeBackend: "auto", table: "custom_api_keys" })).toEqual({
      ok: true,
      backend: "database",
    });
    // An explicit --store-backend api is the operator's most specific signal.
    expect(resolveStoreBackend({ storeBackend: "api", table: "custom_api_keys" })).toEqual({ ok: true, backend: "api" });
  });

  test("rejects an unknown backend", () => {
    const resolved = resolveStoreBackend({ storeBackend: "postgres" });
    expect(resolved.ok).toBe(false);
    expect(resolved.ok === false && resolved.error).toContain("--store-backend");
  });
});

describe("issue-key store backend selection", () => {
  test("rejects an unknown --store-backend before minting", async () => {
    const { reports, report } = collectReports();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", json: true, storeBackend: "postgres" },
        { report, env: { HASNA_TODOS_API_SIGNING_KEY: SIGNING } },
      );
    });
    expect(reports[0]?.details?.code).toBe("bad_store_backend");
    expect(out).toBe("");
  });

  test("ambient API url+key do not preempt an explicit database request", async () => {
    // The fleet env-flip writes exactly API_URL + API_KEY and no STORAGE_MODE, so
    // resolveClientTransport() infers cloud. That must not redirect a record the
    // operator explicitly pointed at Postgres.
    const { reports, report } = collectReports();
    const db = recordingConnectStore();
    const http = forbiddenFetch();
    const out = await captureStdout(async () => {
      await runIssueKey(
        {
          app: "todos",
          scopes: "todos:read",
          json: true,
          agent: "issuer",
          databaseUrlEnv: "MY_ADMIN_DB_URL",
          table: "custom_api_keys",
        },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_API_URL: "https://todos.example.test",
            HASNA_TODOS_API_KEY: "operator-api-key",
            MY_ADMIN_DB_URL: "postgres://admin.example/todos",
          },
          connectStore: db.connectStore,
          transportOverrides: { retry: false, fetchImpl: http.fetchImpl },
        },
      );
    });
    expect(reports).toEqual([]);
    expect(http.calls).toEqual([]);
    const parsed = JSON.parse(out);
    expect(parsed.storeBackend).toBe("database");
    expect(db.writes).toEqual([
      { connectionString: "postgres://admin.example/todos", table: "custom_api_keys", kid: parsed.kid, createdBy: "issuer" },
    ]);
    expect(parsed.token.startsWith("hasna_todos_")).toBe(true);
  });

  test("ambient API url+key do not preempt the default database backend", async () => {
    const { reports, report } = collectReports();
    const db = recordingConnectStore();
    const http = forbiddenFetch();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", json: true },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_API_URL: "https://todos.example.test",
            HASNA_TODOS_API_KEY: "operator-api-key",
            HASNA_TODOS_DATABASE_URL: "postgres://admin.example/todos",
          },
          connectStore: db.connectStore,
          transportOverrides: { retry: false, fetchImpl: http.fetchImpl },
        },
      );
    });
    expect(reports).toEqual([]);
    expect(http.calls).toEqual([]);
    expect(JSON.parse(out).storeBackend).toBe("database");
    expect(db.writes.length).toBe(1);
  });

  test("--store-backend auto uses the API transport when it is configured", async () => {
    const { reports, report } = collectReports();
    const db = recordingConnectStore();
    const calls: string[] = [];
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", json: true, storeBackend: "auto" },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_API_URL: "https://todos.example.test",
            HASNA_TODOS_API_KEY: "operator-api-key",
            HASNA_TODOS_DATABASE_URL: "postgres://admin.example/todos",
          },
          connectStore: db.connectStore,
          transportOverrides: {
            retry: false,
            fetchImpl: async (input) => {
              calls.push(String(input));
              return Response.json({ ok: true }, { status: 201 });
            },
          },
        },
      );
    });
    expect(reports).toEqual([]);
    expect(JSON.parse(out).storeBackend).toBe("api");
    expect(calls).toEqual([`https://todos.example.test/v1/${API_KEY_RECORD_RESOURCE}`]);
    expect(db.writes).toEqual([]);
  });

  test("--store-backend api fails loudly instead of falling back to the database", async () => {
    const { reports, report } = collectReports();
    const db = recordingConnectStore();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", json: true, storeBackend: "api" },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_DATABASE_URL: "postgres://admin.example/todos",
          },
          connectStore: db.connectStore,
        },
      );
    });
    expect(reports[0]?.details?.code).toBe("api_transport_unavailable");
    expect(db.writes).toEqual([]);
    expect(out).toBe("");
    // The secret must survive the refusal.
    const token = String(reports[0]?.details?.token);
    expect(verifyApiKeyToken(token, { signingSecret: SIGNING, expectedApp: "todos" }).ok).toBe(true);
  });
});

describe("issue-key misconfigured cloud transport", () => {
  test("cloud mode without an API key refuses to write to the local database", async () => {
    // createClientTransport() throws on this exact resolution; issue-key must not
    // quietly serve the other datastore instead.
    const { reports, report } = collectReports();
    const db = recordingConnectStore();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", json: true },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_STORAGE_MODE: "cloud",
            HASNA_TODOS_DATABASE_URL: "postgres://local/db",
          },
          connectStore: db.connectStore,
        },
      );
    });
    expect(db.writes).toEqual([]);
    expect(out).toBe("");
    expect(reports.length).toBe(1);
    expect(reports[0]?.details?.code).toBe("transport_misconfigured");
    expect(reports[0]?.error).toContain("no API key is set");
    const token = String(reports[0]?.details?.token);
    expect(verifyApiKeyToken(token, { signingSecret: SIGNING, expectedApp: "todos" }).ok).toBe(true);
  });

  test("cloud mode with an unusable API URL refuses to persist", async () => {
    const { reports, report } = collectReports();
    const db = recordingConnectStore();
    await runIssueKey(
      { app: "todos", scopes: "todos:read", json: true, storeBackend: "auto" },
      {
        report,
        env: {
          HASNA_TODOS_API_SIGNING_KEY: SIGNING,
          HASNA_TODOS_API_URL: "not-a-url",
          HASNA_TODOS_API_KEY: "operator-api-key",
          HASNA_TODOS_DATABASE_URL: "postgres://local/db",
        },
        connectStore: db.connectStore,
      },
    );
    expect(db.writes).toEqual([]);
    expect(reports[0]?.details?.code).toBe("transport_misconfigured");
  });
});

describe("issue-key never loses the minted secret", () => {
  test("a database failure still reports the token in JSON mode", async () => {
    const { reports, report } = collectReports();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", json: true },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_DATABASE_URL: "postgres://local/db",
          },
          connectStore: async () => {
            throw new Error("connection refused");
          },
        },
      );
    });
    // A single JSON document on stdout would be ambiguous alongside the error, so
    // the failure report itself carries the key material.
    expect(out).toBe("");
    expect(reports.length).toBe(1);
    expect(reports[0]?.details?.code).toBe("store_failed");
    expect(reports[0]?.details?.stored).toBe(false);
    const token = String(reports[0]?.details?.token);
    expect(token.startsWith("hasna_todos_")).toBe(true);
    expect(verifyApiKeyToken(token, { signingSecret: SIGNING, expectedApp: "todos" }).ok).toBe(true);
  });

  test("a database failure still prints the token in human mode", async () => {
    const { reports, report } = collectReports();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read" },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_DATABASE_URL: "postgres://local/db",
          },
          connectStore: async () => {
            throw new Error("connection refused");
          },
        },
      );
    });
    expect(reports[0]?.details?.code).toBe("store_failed");
    expect(out).toContain("NOT STORED");
    expect(out).toContain("connection refused");
    const token = out.split("\n").map((line) => line.trim()).find((line) => line.startsWith("hasna_todos_"));
    expect(token).toBeDefined();
    expect(verifyApiKeyToken(String(token), { signingSecret: SIGNING, expectedApp: "todos" }).ok).toBe(true);
  });

  test("an API failure still reports the token", async () => {
    const { reports, report } = collectReports();
    const out = await captureStdout(async () => {
      await runIssueKey(
        { app: "todos", scopes: "todos:read", json: true, storeBackend: "api" },
        {
          report,
          env: {
            HASNA_TODOS_API_SIGNING_KEY: SIGNING,
            HASNA_TODOS_API_URL: "https://todos.example.test",
            HASNA_TODOS_API_KEY: "operator-api-key",
          },
          transportOverrides: {
            retry: false,
            fetchImpl: async () => Response.json({ error: "not found" }, { status: 404 }),
          },
        },
      );
    });
    expect(out).toBe("");
    expect(reports[0]?.details?.code).toBe("store_failed");
    expect(reports[0]?.error).toContain("404");
    const token = String(reports[0]?.details?.token);
    expect(verifyApiKeyToken(token, { signingSecret: SIGNING, expectedApp: "todos" }).ok).toBe(true);
  });

  test("a missing database URL still reports the token", async () => {
    const { reports, report } = collectReports();
    await runIssueKey(
      { app: "todos", scopes: "todos:read", json: true },
      { report, env: { HASNA_TODOS_API_SIGNING_KEY: SIGNING } },
    );
    expect(reports[0]?.details?.code).toBe("missing_database_url");
    const token = String(reports[0]?.details?.token);
    expect(verifyApiKeyToken(token, { signingSecret: SIGNING, expectedApp: "todos" }).ok).toBe(true);
  });
});
