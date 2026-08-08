// Prototype-pollution regression suite for the vendored storage kit templates.
//
// The kit is STAMPED INTO CONSUMER REPOSITORIES, so every one of these reads
// runs inside somebody else's process, where the sink for a polluted
// Object.prototype belongs to them. A plain `options.ca` read walks the
// prototype chain, so a polluted prototype injects configuration the caller
// never supplied.
//
// The measured effect on tls.ts, which is why this suite exists:
//   CLEAN    -> throws "sslmode=verify-full requires a CA bundle"
//   POLLUTED -> { rejectUnauthorized: true, ca: "<attacker anchor>" }
// rejectUnauthorized stays TRUE, so the connection still verifies — against a
// trust anchor the attacker supplied, and every surface that would report a
// TLS problem reports success.
//
// Every test is TWO-SIDED. The guard must FIRE under pollution and STAY SILENT
// on legitimate caller-supplied configuration: a guard that rejects valid
// config is a worse defect than the one being fixed.

import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { resolveTlsConfig } from "../src/kit/templates/tls";
import { createPgPool } from "../src/kit/templates/pool";
import { resolveServerDataBackend, resolveDatabaseUrl } from "../src/kit/templates/backend";
import { MigrationLedger, defineMigration } from "../src/kit/templates/migrations";
import type { TypedQueryClient, QueryResult } from "../src/kit/templates/query";
import type { QueryResultRow } from "pg";

const ATTACKER_CA = "-----BEGIN CERTIFICATE-----ATTACKER-TRUST-ANCHOR-----END CERTIFICATE-----";
const LEGITIMATE_CA = "-----BEGIN CERTIFICATE-----LEGITIMATE-OPERATOR-BUNDLE-----END CERTIFICATE-----";

const VERIFY_FULL = "postgres://u@h:5432/db?sslmode=verify-full";

/**
 * The three pollution ROUTES a real attacker reaches Object.prototype through.
 * Object.hasOwn is token-independent, so all three must be closed by the same
 * guard — this is what proves the fix is not a denylist of names.
 */
const ROUTES: ReadonlyArray<{ token: string; pollute: (k: string, v: unknown) => void }> = [
  { token: "__proto__", pollute: (k, v) => { ({} as any).__proto__[k] = v; } },
  { token: "constructor", pollute: (k, v) => { ({} as any).constructor.prototype[k] = v; } },
  { token: "prototype", pollute: (k, v) => { (Object as any).prototype[k] = v; } },
];

const polluted = new Set<string>();

/**
 * Run `fn` with the named variables absent from the REAL `process.env`, then
 * restore them. station01's shell exports `NODE_EXTRA_CA_CERTS` (the RDS global
 * bundle) and `HASNA_TODOS_STORAGE_MODE`, so a default-env assertion written
 * without this passes or fails according to whose shell ran it.
 */
function withoutRealEnv<T>(keys: readonly string[], fn: () => T): T {
  const saved = new Map<string, string | undefined>();
  for (const key of keys) {
    saved.set(key, Object.hasOwn(process.env, key) ? process.env[key] : undefined);
    delete process.env[key];
  }
  try {
    return fn();
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function pollute(route: (typeof ROUTES)[number], key: string, value: unknown): void {
  route.pollute(key, value);
  polluted.add(key);
}

function cleanPrototype(): void {
  for (const key of polluted) delete (Object.prototype as any)[key];
  polluted.clear();
}

afterEach(cleanPrototype);

// Confirms the pollution helper actually pollutes — without this, a suite that
// simply failed to set the property would pass every assertion below.
describe("pollution harness control", () => {
  for (const route of ROUTES) {
    test(`route '${route.token}' reaches a bare object literal`, () => {
      const probe = "hasnaKitPollutionProbe";
      expect(({} as any)[probe]).toBeUndefined();
      pollute(route, probe, "REACHED");
      expect(({} as any)[probe]).toBe("REACHED");
      cleanPrototype();
      expect(({} as any)[probe]).toBeUndefined();
    });
  }
});

// --- tls.ts --------------------------------------------------------------

describe("tls.ts loadCaBundle refuses a prototype-supplied CA", () => {
  for (const route of ROUTES) {
    test(`[${route.token}] the 'ca' arm stays fail-closed`, () => {
      pollute(route, "ca", ATTACKER_CA);
      expect(() => resolveTlsConfig(VERIFY_FULL, { env: {} })).toThrow(/requires a CA bundle/);
      // The default-options path: `options = {}` is itself polluted.
      withoutRealEnv(["PGSSLROOTCERT", "NODE_EXTRA_CA_CERTS"], () => {
        expect(() => resolveTlsConfig(VERIFY_FULL)).toThrow(/requires a CA bundle/);
        expect(() => resolveTlsConfig(VERIFY_FULL, {})).toThrow(/requires a CA bundle/);
      });
    });

    test(`[${route.token}] the 'caCertPath' arm stays fail-closed`, () => {
      const dir = mkdtempSync(join(tmpdir(), "kit-proto-"));
      const bundle = join(dir, "attacker.pem");
      writeFileSync(bundle, ATTACKER_CA, "utf8");
      try {
        pollute(route, "caCertPath", bundle);
        expect(() => resolveTlsConfig(VERIFY_FULL, { env: {} })).toThrow(/requires a CA bundle/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    test(`[${route.token}] a polluted PGSSLROOTCERT does not reach the env read`, () => {
      const dir = mkdtempSync(join(tmpdir(), "kit-proto-env-"));
      const bundle = join(dir, "attacker.pem");
      writeFileSync(bundle, ATTACKER_CA, "utf8");
      try {
        pollute(route, "PGSSLROOTCERT", bundle);
        // Caller-supplied env object.
        expect(() => resolveTlsConfig(VERIFY_FULL, { env: {} })).toThrow(/requires a CA bundle/);
        // Default env: MEASURED, process.env is prototype-pollutable on this
        // runtime — a polluted PGSSLROOTCERT reads back through process.env.
        withoutRealEnv(["PGSSLROOTCERT", "NODE_EXTRA_CA_CERTS"], () => {
          expect(() => resolveTlsConfig(VERIFY_FULL)).toThrow(/requires a CA bundle/);
        });
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    // `prefer` and `require` both reach loadCaBundle now that they resolve to a
    // verifying config, so both must refuse a prototype-supplied anchor. The
    // assertion that matters is the ABSENCE of `ca`: a pinned attacker anchor
    // would be the ONLY trust anchor for the connection.
    for (const mode of ["prefer", "require"] as const) {
      test(`[${route.token}] '${mode}' mode does not silently pin an attacker anchor`, () => {
        pollute(route, "ca", ATTACKER_CA);
        const ssl = resolveTlsConfig(`postgres://u@h/db?sslmode=${mode}`, { env: {} });
        expect(ssl).toEqual({ rejectUnauthorized: true });
      });
    }
  }

  // --- the silent half: legitimate configuration must still work ---

  test("an own 'ca' is honored", () => {
    expect(resolveTlsConfig(VERIFY_FULL, { ca: LEGITIMATE_CA })).toEqual({
      rejectUnauthorized: true,
      ca: LEGITIMATE_CA,
    });
  });

  test("an own 'caCertPath' is honored", () => {
    const dir = mkdtempSync(join(tmpdir(), "kit-ok-"));
    const bundle = join(dir, "operator.pem");
    writeFileSync(bundle, LEGITIMATE_CA, "utf8");
    try {
      expect(resolveTlsConfig(VERIFY_FULL, { caCertPath: bundle, env: {} })).toEqual({
        rejectUnauthorized: true,
        ca: LEGITIMATE_CA,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("an own PGSSLROOTCERT / NODE_EXTRA_CA_CERTS is honored", () => {
    const dir = mkdtempSync(join(tmpdir(), "kit-ok-env-"));
    const bundle = join(dir, "operator.pem");
    writeFileSync(bundle, LEGITIMATE_CA, "utf8");
    try {
      expect(resolveTlsConfig(VERIFY_FULL, { env: { PGSSLROOTCERT: bundle } })).toEqual({
        rejectUnauthorized: true,
        ca: LEGITIMATE_CA,
      });
      expect(resolveTlsConfig(VERIFY_FULL, { env: { NODE_EXTRA_CA_CERTS: bundle } })).toEqual({
        rejectUnauthorized: true,
        ca: LEGITIMATE_CA,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("an own 'ca' still wins over an own caCertPath", () => {
    expect(resolveTlsConfig(VERIFY_FULL, { ca: LEGITIMATE_CA, caCertPath: "/nonexistent.pem" })).toEqual({
      rejectUnauthorized: true,
      ca: LEGITIMATE_CA,
    });
  });

  // Consumer repos (hasna/loops, hasna/emails) deleted the non-verifying
  // `require` arm, routing MORE sslmodes into the `if (!ca) throw` branch —
  // exactly the branch pollution converts into a silent success. The guard must
  // hold for any mode that reaches loadCaBundle, not just verify-full.
  test("holds for every mode that reaches the CA read (verify-ca too)", () => {
    for (const route of ROUTES) {
      pollute(route, "ca", ATTACKER_CA);
      expect(() => resolveTlsConfig("postgres://u@h/db?sslmode=verify-ca", { env: {} })).toThrow(
        /requires a CA bundle/,
      );
      cleanPrototype();
    }
  });
});

// --- pool.ts -------------------------------------------------------------
//
// pool.ts LAUNDERS pollution: `options.ca !== undefined ? { ca: options.ca }`
// copies a prototype-supplied value into an OWN property before handing it to
// resolveTlsConfig, so guarding tls.ts alone does NOT close this path.

describe("pool.ts does not launder prototype-supplied config into pg", () => {
  for (const route of ROUTES) {
    test(`[${route.token}] a polluted 'ca' never reaches the pool ssl config`, () => {
      pollute(route, "ca", ATTACKER_CA);
      // Fail-closed all the way through the factory: with no legitimate CA the
      // pool is never constructed, rather than constructed around the
      // attacker's anchor. Before the fix this returned a live Pool whose ssl
      // config was `{"rejectUnauthorized":true,"ca":"...ATTACKER-TRUST-ANCHOR..."}`.
      expect(() => createPgPool({ connectionString: VERIFY_FULL, env: {} })).toThrow(
        /requires a CA bundle/,
      );
    });

    test(`[${route.token}] polluted tuning is not copied into the pool config`, async () => {
      pollute(route, "applicationName", "attacker-app");
      const pool = createPgPool({ connectionString: "postgres://u@h/db?sslmode=disable" });
      try {
        const opts = (pool as any).options ?? {};
        // OWN-property assertion, not `opts.application_name`: pg's own Pool
        // constructor re-reads its config through the prototype chain, so a
        // chain read here would measure pg rather than the kit. See the note
        // below on `max`.
        expect(Object.hasOwn(opts, "application_name")).toBe(false);
      } finally {
        await pool.end();
      }
    });
  }

  // KNOWN AND OUT OF THE KIT'S REACH, recorded rather than asserted away:
  // `pg`'s Pool constructor does `this.options.max = this.options.max || 10`,
  // an unguarded prototype-chain read of its own. MEASURED: with
  // `Object.prototype.max = 9999` polluted, `pool.options.max` is an OWN 9999
  // even when the kit passes no `max` at all. The kit's guarantee is that it
  // does not itself launder a prototype value into pg; closing pg's read is an
  // upstream change in `pg`.
  test("pg re-reads its own config through the prototype chain (upstream, documented)", async () => {
    (Object.prototype as any).max = 9999;
    polluted.add("max");
    const pool = createPgPool({ connectionString: "postgres://u@h/db?sslmode=disable" });
    try {
      expect((pool as any).options.max).toBe(9999);
    } finally {
      await pool.end();
    }
  });

  test("own pool options are still honored", async () => {
    const pool = createPgPool({
      connectionString: "postgres://u@h/db?sslmode=disable",
      max: 7,
      applicationName: "legit-app",
    });
    try {
      const opts = (pool as any).options ?? {};
      expect(opts.max).toBe(7);
      expect(opts.application_name).toBe("legit-app");
    } finally {
      await pool.end();
    }
  });

  test("an own 'ca' still reaches the pool ssl config", async () => {
    const pool = createPgPool({ connectionString: VERIFY_FULL, ca: LEGITIMATE_CA, env: {} });
    try {
      expect((pool as any).options?.ssl).toEqual({ rejectUnauthorized: true, ca: LEGITIMATE_CA });
    } finally {
      await pool.end();
    }
  });
});

// --- backend.ts ----------------------------------------------------------

describe("backend.ts env reads do not walk the prototype chain", () => {
  for (const route of ROUTES) {
    // A synthetic app name, because station01's real shell exports
    // HASNA_TODOS_* variables and a `todos`-named default-env assertion would
    // measure the shell rather than the code.
    test(`[${route.token}] a polluted DATABASE_URL neither flips the backend nor is returned`, () => {
      pollute(route, "HASNA_KITPROBE_DATABASE_URL", "postgres://attacker@evil.invalid/db");
      expect(resolveServerDataBackend("kitprobe", {}).backend).toBe("sqlite");
      expect(resolveDatabaseUrl("kitprobe", {})).toBeNull();
      // Default env: MEASURED, process.env is prototype-pollutable on this runtime.
      expect(resolveDatabaseUrl("kitprobe")).toBeNull();
      expect(resolveServerDataBackend("kitprobe").backend).toBe("sqlite");
    });

    test(`[${route.token}] a polluted legacy mode key does not fabricate a throw`, () => {
      pollute(route, "HASNA_KITPROBE_STORAGE_MODE", "cloud");
      expect(resolveServerDataBackend("kitprobe", {}).backend).toBe("sqlite");
      expect(resolveServerDataBackend("kitprobe").backend).toBe("sqlite");
    });
  }

  test("an own DATABASE_URL is still honored", () => {
    const env = { HASNA_TODOS_DATABASE_URL: "postgres://u@real/db" };
    expect(resolveServerDataBackend("todos", env).backend).toBe("postgresql");
    expect(resolveServerDataBackend("todos", env).databaseUrlSource).toBe("HASNA_TODOS_DATABASE_URL");
    expect(resolveDatabaseUrl("todos", env)).toBe("postgres://u@real/db");
  });

  test("an own legacy mode key still throws with migration guidance", () => {
    expect(() => resolveServerDataBackend("todos", { HASNA_TODOS_STORAGE_MODE: "cloud" })).toThrow(
      /removed.*HASNA_TODOS_DATABASE_URL/i,
    );
  });
});

// --- migrations.ts -------------------------------------------------------
//
// `ledgerTable` is interpolated straight into DDL, so a prototype-supplied
// value is SQL injection; a prototype-supplied `dryRun` silently converts an
// apply into a no-op that still reports a plan.

function recordingClient(sql: string[]): TypedQueryClient {
  const empty = async <T extends QueryResultRow>(): Promise<QueryResult<T>> => ({ rows: [], rowCount: 0 });
  return {
    async query<T extends QueryResultRow>(text: string): Promise<QueryResult<T>> {
      sql.push(text);
      return empty<T>();
    },
    async many<T extends QueryResultRow>(text: string): Promise<T[]> {
      sql.push(text);
      return [];
    },
    async get<T extends QueryResultRow>(text: string): Promise<T | null> {
      sql.push(text);
      return null;
    },
    async one<T extends QueryResultRow>(text: string): Promise<T> {
      sql.push(text);
      throw new Error("no rows");
    },
    async execute(text: string): Promise<void> {
      sql.push(text);
    },
  };
}

describe("migrations.ts options reads do not walk the prototype chain", () => {
  for (const route of ROUTES) {
    test(`[${route.token}] a polluted 'ledgerTable' never reaches emitted SQL`, async () => {
      pollute(route, "ledgerTable", "evil_ledger; DROP TABLE users; --");
      const sql: string[] = [];
      const ledger = new MigrationLedger(recordingClient(sql), []);
      await ledger.ensureLedger();
      expect(sql.join("\n")).not.toContain("evil_ledger");
      expect(sql.join("\n")).toContain("schema_migrations");
    });

    test(`[${route.token}] a polluted 'dryRun' does not silently skip migrations`, async () => {
      pollute(route, "dryRun", true);
      const sql: string[] = [];
      const ledger = new MigrationLedger(recordingClient(sql), [
        defineMigration("0001_init", "CREATE TABLE widgets (id TEXT PRIMARY KEY)"),
      ]);
      const result = await ledger.migrate();
      expect(result.dryRun).toBe(false);
      expect(sql.join("\n")).toContain("CREATE TABLE widgets");
    });
  }

  test("an own ledgerTable is still honored", async () => {
    const sql: string[] = [];
    const ledger = new MigrationLedger(recordingClient(sql), [], { ledgerTable: "app_migrations" });
    await ledger.ensureLedger();
    expect(sql.join("\n")).toContain("app_migrations");
  });

  test("an own dryRun still reports the plan without applying", async () => {
    const sql: string[] = [];
    const ledger = new MigrationLedger(recordingClient(sql), [
      defineMigration("0001_init", "CREATE TABLE widgets (id TEXT PRIMARY KEY)"),
    ]);
    const result = await ledger.migrate({ dryRun: true });
    expect(result.dryRun).toBe(true);
    expect(result.plan.map((p) => p.state)).toEqual(["pending"]);
    expect(sql.join("\n")).not.toContain("CREATE TABLE widgets");
  });
});
