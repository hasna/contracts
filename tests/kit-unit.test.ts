import { describe, expect, test } from "bun:test";
import {
  normalizeStorageMode,
  resolveStorageMode,
  resolveDatabaseUrl,
  storageEnvKeys,
} from "../src/kit/templates/mode";
import { resolveTlsConfig, sslModeFromConnectionString } from "../src/kit/templates/tls";
import { wrapExecutor, type PgExecutor } from "../src/kit/templates/query";
import {
  checksumSql,
  defineMigration,
  MigrationLedger,
  type Migration,
} from "../src/kit/templates/migrations";
import { checkHealth, checkReady } from "../src/kit/templates/health";
import type { TypedQueryClient } from "../src/kit/templates/query";

// --- mode.ts -------------------------------------------------------------

describe("kit mode resolution", () => {
  test("normalizes canonical + deprecated aliases", () => {
    expect(normalizeStorageMode("local")).toEqual({ mode: "local", deprecatedAlias: null });
    expect(normalizeStorageMode("CLOUD")).toEqual({ mode: "cloud", deprecatedAlias: null });
    expect(normalizeStorageMode("self-hosted")).toEqual({ mode: "cloud", deprecatedAlias: "self_hosted" });
    expect(normalizeStorageMode("remote").mode).toBe("cloud");
    expect(() => normalizeStorageMode("bogus")).toThrow(/Unknown storage mode/);
  });

  test("env-key precedence and cloud warning", () => {
    const keys = storageEnvKeys("todos");
    expect(keys.modeKeys[0]).toBe("HASNA_TODOS_STORAGE_MODE");
    expect(keys.databaseUrlKeys[0]).toBe("HASNA_TODOS_DATABASE_URL");

    const def = resolveStorageMode("todos", {});
    expect(def.mode).toBe("local");
    expect(def.source).toBe("default");

    const cloudNoUrl = resolveStorageMode("todos", { HASNA_TODOS_STORAGE_MODE: "cloud" });
    expect(cloudNoUrl.mode).toBe("cloud");
    expect(cloudNoUrl.warning).toContain("cloud mode needs");

    const aliasEnv = resolveStorageMode("todos", { TODOS_STORAGE_MODE: "cloud", TODOS_DATABASE_URL: "postgres://x" });
    expect(aliasEnv.mode).toBe("cloud");
    expect(aliasEnv.databaseUrlPresent).toBe(true);
    expect(aliasEnv.warning).toContain("canonical key");
  });

  test("resolveDatabaseUrl honors alias but never logs value", () => {
    expect(resolveDatabaseUrl("todos", {})).toBeNull();
    expect(resolveDatabaseUrl("todos", { TODOS_DATABASE_URL: "postgres://user@h/db" })).toBe(
      "postgres://user@h/db",
    );
  });
});

// --- tls.ts --------------------------------------------------------------

describe("kit TLS (one correct approach)", () => {
  test("parses sslmode variants", () => {
    expect(sslModeFromConnectionString("postgres://h/db")).toBe("disable");
    expect(sslModeFromConnectionString("postgres://h/db?sslmode=require")).toBe("require");
    expect(sslModeFromConnectionString("postgres://h/db?sslmode=verify-full")).toBe("verify-full");
    expect(sslModeFromConnectionString("postgres://h/db?ssl=true")).toBe("require");
  });

  test("require encrypts without verification; verify-full needs a CA", () => {
    // Isolate from ambient PGSSLROOTCERT / NODE_EXTRA_CA_CERTS in the shell.
    const noEnv = { env: {} } as const;
    expect(resolveTlsConfig("postgres://h/db", noEnv)).toBeUndefined();
    expect(resolveTlsConfig("postgres://h/db?sslmode=require", noEnv)).toEqual({ rejectUnauthorized: false });
    expect(() => resolveTlsConfig("postgres://h/db?sslmode=verify-full", noEnv)).toThrow(/requires a CA bundle/);
    expect(resolveTlsConfig("postgres://h/db?sslmode=verify-full", { ca: "PEM", env: {} })).toEqual({
      rejectUnauthorized: true,
      ca: "PEM",
    });
    // require still pins a CA when one is available, but stays non-verifying.
    expect(resolveTlsConfig("postgres://h/db?sslmode=require", { ca: "PEM", env: {} })).toEqual({
      rejectUnauthorized: false,
      ca: "PEM",
    });
  });

  test("loads CA bundle from PGSSLROOTCERT / NODE_EXTRA_CA_CERTS env", () => {
    const config = resolveTlsConfig("postgres://h/db?sslmode=verify-full", {
      env: { NODE_EXTRA_CA_CERTS: "PATH_UNUSED" },
      ca: "INLINE_CA",
    });
    expect(config).toEqual({ rejectUnauthorized: true, ca: "INLINE_CA" });
  });
});

// --- query.ts ------------------------------------------------------------

function stubExecutor(rowsByCall: Record<string, unknown[]>): PgExecutor {
  return {
    async query<T>(sql: string): Promise<{ rows: T[]; rowCount: number | null }> {
      const rows = (rowsByCall[sql] ?? []) as T[];
      return { rows, rowCount: rows.length };
    },
  };
}

describe("kit typed query wrapper", () => {
  test("get returns first row or null (the method open-knowledge dropped)", async () => {
    const client = wrapExecutor(
      stubExecutor({ "SELECT * FROM t": [{ id: 1 }, { id: 2 }], "SELECT * FROM empty": [] }),
    );
    expect(await client.get("SELECT * FROM t")).toEqual({ id: 1 });
    expect(await client.get("SELECT * FROM empty")).toBeNull();
    expect(await client.many("SELECT * FROM t")).toHaveLength(2);
  });

  test("one throws unless exactly one row", async () => {
    const client = wrapExecutor(stubExecutor({ single: [{ id: 1 }], multi: [{ id: 1 }, { id: 2 }] }));
    expect(await client.one("single")).toEqual({ id: 1 });
    await expect(client.one("multi")).rejects.toThrow(/exactly one row/);
  });
});

// --- migrations.ts (in-memory ledger shim) -------------------------------

/**
 * Minimal in-memory TypedQueryClient that emulates the `schema_migrations`
 * ledger, so ledger logic is testable without a live Postgres (pragmatic
 * sqlite/pg-mem substitute). It interprets the exact SQL the ledger emits.
 */
function inMemoryLedgerClient(): TypedQueryClient & {
  appliedDdl: string[];
  statements: string[];
  transaction<T>(fn: (client: TypedQueryClient) => Promise<T>): Promise<T>;
} {
  const ledger = new Map<string, { id: string; checksum: string; applied_at: string }>();
  const appliedDdl: string[] = [];
  const statements: string[] = [];
  let txSnapshot: { ledger: Map<string, { id: string; checksum: string; applied_at: string }>; ddl: string[] } | null = null;
  const client: TypedQueryClient & {
    appliedDdl: string[];
    statements: string[];
    transaction<T>(fn: (client: TypedQueryClient) => Promise<T>): Promise<T>;
  } = {
    appliedDdl,
    statements,
    async transaction<T>(fn: (tx: TypedQueryClient) => Promise<T>): Promise<T> {
      statements.push("BEGIN");
      txSnapshot = { ledger: new Map(ledger), ddl: [...appliedDdl] };
      try {
        const result = await fn(client);
        statements.push("COMMIT");
        txSnapshot = null;
        return result;
      } catch (error) {
        statements.push("ROLLBACK");
        if (txSnapshot) {
          ledger.clear();
          for (const [id, row] of txSnapshot.ledger) ledger.set(id, row);
          appliedDdl.splice(0, appliedDdl.length, ...txSnapshot.ddl);
        }
        txSnapshot = null;
        throw error;
      }
    },
    async query<T>() {
      return { rows: [] as T[], rowCount: 0 };
    },
    async many<T>(sql: string): Promise<T[]> {
      statements.push(sql);
      if (/SELECT id, checksum, applied_at FROM/.test(sql)) {
        return [...ledger.values()].sort((a, b) => a.id.localeCompare(b.id)) as unknown as T[];
      }
      return [] as T[];
    },
    async get<T>() {
      return null as T | null;
    },
    async one<T>(): Promise<T> {
      throw new Error("not used");
    },
    async execute(sql: string, params?: readonly unknown[]) {
      statements.push(sql);
      if (/CREATE TABLE IF NOT EXISTS/.test(sql)) return;
      if (/pg_advisory_xact_lock/.test(sql)) return;
      if (/^INSERT INTO/.test(sql.trim()) && params) {
        const [id, checksum] = params as [string, string];
        ledger.set(id, { id, checksum, applied_at: new Date().toISOString() });
        return;
      }
      appliedDdl.push(sql);
      if (sql.includes("FAIL_AFTER_DDL")) throw new Error("simulated migration failure after DDL");
    },
  };
  return client;
}

describe("kit migration ledger", () => {
  const migrations: Migration[] = [
    defineMigration("0001_init", "CREATE TABLE demo (id int);"),
    defineMigration("0002_more", "ALTER TABLE demo ADD COLUMN name text;"),
  ];

  test("checksum is stable and content-addressed", () => {
    expect(checksumSql("SELECT 1;")).toBe(checksumSql(" SELECT 1; "));
    expect(checksumSql("A")).not.toBe(checksumSql("B"));
  });

  test("applies pending once, then is idempotent", async () => {
    const client = inMemoryLedgerClient();
    const ledger = new MigrationLedger(client, migrations);
    const first = await ledger.migrate();
    expect(first.applied.map((m) => m.id)).toEqual(["0001_init", "0002_more"]);
    expect(client.appliedDdl).toHaveLength(2);
    expect(client.statements).toContain("BEGIN");
    expect(client.statements).toContain("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))");
    expect(client.statements).toContain("COMMIT");

    const second = await ledger.migrate();
    expect(second.plan.every((p) => p.state === "already_applied")).toBe(true);
    expect(client.appliedDdl).toHaveLength(2); // no re-run
  });

  test("dry-run reports plan without applying", async () => {
    const client = inMemoryLedgerClient();
    const ledger = new MigrationLedger(client, migrations);
    const plan = await ledger.migrate({ dryRun: true });
    expect(plan.dryRun).toBe(true);
    expect(plan.plan.every((p) => p.state === "pending")).toBe(true);
    expect(client.appliedDdl).toHaveLength(0);
  });

  test("detects checksum drift after apply", async () => {
    const client = inMemoryLedgerClient();
    await new MigrationLedger(client, migrations).migrate();
    const tampered: Migration[] = [
      { ...migrations[0]!, sql: "CREATE TABLE demo (id bigint);", checksum: checksumSql("changed") },
      migrations[1]!,
    ];
    await expect(new MigrationLedger(client, tampered).migrate()).rejects.toThrow(/checksum mismatch/);
  });

  test("detects downgrade (applied migration unknown to build)", async () => {
    const client = inMemoryLedgerClient();
    await new MigrationLedger(client, migrations).migrate();
    await expect(new MigrationLedger(client, [migrations[0]!]).migrate()).rejects.toThrow(/not recognized/);
  });

  test("rejects duplicate migration ids", () => {
    expect(() => new MigrationLedger(inMemoryLedgerClient(), [migrations[0]!, migrations[0]!])).toThrow(
      /Duplicate migration id/,
    );
  });

  test("quotes ledger table names and rejects unsafe identifiers", async () => {
    const client = inMemoryLedgerClient();
    await new MigrationLedger(client, [migrations[0]!], { ledgerTable: "public.schema_migrations" }).migrate();
    expect(client.statements.some((sql) => sql.includes('"public"."schema_migrations"'))).toBe(true);
    expect(() => new MigrationLedger(inMemoryLedgerClient(), [], { ledgerTable: "schema_migrations; DROP TABLE users" })).toThrow(
      /Invalid migration ledger table/,
    );
  });

  test("rolls back migration SQL and ledger insert together on failure", async () => {
    const client = inMemoryLedgerClient();
    const failing = [defineMigration("0001_fail", "CREATE TABLE fail_marker (id int); -- FAIL_AFTER_DDL")];
    await expect(new MigrationLedger(client, failing).migrate()).rejects.toThrow(/simulated migration failure/);
    expect(client.statements).toContain("ROLLBACK");
    expect(client.appliedDdl).toHaveLength(0);
    expect(await new MigrationLedger(client, failing).listApplied()).toEqual([]);
  });

  test("refuses to apply with a non-transaction-capable client", async () => {
    const { transaction: _transaction, ...client } = inMemoryLedgerClient();
    await expect(new MigrationLedger(client, [migrations[0]!]).migrate()).rejects.toThrow(
      /transaction-capable query client/,
    );
  });
});

// --- health.ts -----------------------------------------------------------

describe("kit health/ready", () => {
  test("checkHealth ok and failure", async () => {
    const ok = await checkHealth(wrapExecutor(stubExecutor({ "SELECT 1 AS ok": [{ ok: 1 }] })));
    expect(ok.ok).toBe(true);
    const failing: TypedQueryClient = {
      ...wrapExecutor(stubExecutor({})),
      async get() {
        throw new Error("boom");
      },
    };
    const bad = await checkHealth(failing);
    expect(bad.ok).toBe(false);
    expect(bad.error).toContain("boom");
  });

  test("checkReady flags pending migrations", async () => {
    const migrations = [defineMigration("0001", "CREATE TABLE x (id int);")];
    const client = inMemoryLedgerClient();
    const before = await checkReady(client, migrations);
    expect(before.ok).toBe(false);
    expect(before.pendingMigrations).toEqual(["0001"]);
    await new MigrationLedger(client, migrations).migrate();
    const after = await checkReady(client, migrations);
    expect(after.ok).toBe(true);
    expect(after.pendingMigrations).toEqual([]);
  });
});
