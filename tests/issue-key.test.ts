import { describe, expect, test } from "bun:test";
import { databaseUrlEnvName, runIssueKey, signingSecretEnvName } from "../src/cli/issue-key";
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

  test("stores the hashed record in the app's Postgres", async () => {
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
    expect(schemaEnsured).toBe(true);
    expect(closed).toBe(true);
    expect(inserted).toEqual([{ kid: parsed.kid, createdBy: "issuer" }]);
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

/** Fail the test if issue-key makes ANY network call while persisting a record. */
async function withoutNetwork<T>(fn: () => Promise<T>): Promise<{ value: T; calls: string[] }> {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = (async (input: unknown) => {
    calls.push(String(input));
    return Response.json({ ok: true }, { status: 201 });
  }) as typeof fetch;
  try {
    return { value: await fn(), calls };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

describe("issue-key persistence destination", () => {
  test("the hashed record goes to Postgres over no network at all", async () => {
    // The contract target alone is not evidence that an app implements and serves
    // it, so issue-key must never post the record anywhere yet.
    const { reports, report } = collectReports();
    const db = recordingConnectStore();
    const { value: out, calls } = await withoutNetwork(async () =>
      captureStdout(async () => {
        await runIssueKey(
          { app: "todos", scopes: "todos:read", json: true, agent: "issuer" },
          {
            report,
            env: {
              HASNA_TODOS_API_SIGNING_KEY: SIGNING,
              HASNA_TODOS_STORAGE_MODE: "cloud",
              HASNA_TODOS_API_URL: "https://todos.example.test",
              HASNA_TODOS_API_KEY: "operator-api-key",
              HASNA_TODOS_DATABASE_URL: "postgres://admin.example/todos",
            },
            connectStore: db.connectStore,
          },
        );
      }),
    );
    expect(reports).toEqual([]);
    expect(calls).toEqual([]);
    const parsed = JSON.parse(out);
    expect(parsed.stored).toBe(true);
    expect(db.writes).toEqual([
      { connectionString: "postgres://admin.example/todos", table: "api_keys", kid: parsed.kid, createdBy: "issuer" },
    ]);
  });

  test("--database-url-env/--table select the connection and table", async () => {
    const { reports, report } = collectReports();
    const db = recordingConnectStore();
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
            MY_ADMIN_DB_URL: "postgres://admin.example/todos",
          },
          connectStore: db.connectStore,
        },
      );
    });
    expect(reports).toEqual([]);
    const parsed = JSON.parse(out);
    expect(db.writes).toEqual([
      { connectionString: "postgres://admin.example/todos", table: "custom_api_keys", kid: parsed.kid, createdBy: "issuer" },
    ]);
    expect(parsed.token.startsWith("hasna_todos_")).toBe(true);
  });
});

describe("issue-key ignores client-transport configuration", () => {
  // The client transport decides where a CLI reads that app's DATA. It says
  // nothing about where this hashed record belongs, so an unusable cloud client
  // must not stop the Postgres write that worked before `--store-backend` existed.
  const cloudEnvironments: Array<{ name: string; env: Record<string, string> }> = [
    {
      name: "cloud mode with no API key",
      env: { HASNA_TODOS_STORAGE_MODE: "cloud" },
    },
    {
      name: "cloud mode with an API key but no API URL or fleet domain",
      env: { HASNA_TODOS_STORAGE_MODE: "cloud", HASNA_TODOS_API_KEY: "operator-api-key" },
    },
    {
      name: "cloud mode with an unusable API URL",
      env: {
        HASNA_TODOS_STORAGE_MODE: "cloud",
        HASNA_TODOS_API_URL: "not-a-url",
        HASNA_TODOS_API_KEY: "operator-api-key",
      },
    },
  ];

  for (const { name, env } of cloudEnvironments) {
    test(`${name} still persists the record to the database`, async () => {
      const { reports, report } = collectReports();
      const db = recordingConnectStore();
      const out = await captureStdout(async () => {
        await runIssueKey(
          { app: "todos", scopes: "todos:read", json: true, agent: "issuer" },
          {
            report,
            env: {
              HASNA_TODOS_API_SIGNING_KEY: SIGNING,
              HASNA_TODOS_DATABASE_URL: "postgres://local/db",
              ...env,
            },
            connectStore: db.connectStore,
          },
        );
      });
      expect(reports).toEqual([]);
      const parsed = JSON.parse(out);
      expect(parsed.stored).toBe(true);
      expect(db.writes).toEqual([
        { connectionString: "postgres://local/db", table: "api_keys", kid: parsed.kid, createdBy: "issuer" },
      ]);
    });
  }
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
