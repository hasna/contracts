import { describe, expect, test } from "bun:test";
import { runIssueKey, signingSecretEnvName, databaseUrlEnvName } from "../src/cli/issue-key";
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
});
