import { beforeAll, afterAll, describe, expect, test } from "bun:test";
import { createPgPool } from "../src/kit/templates/pool";
import { createQueryClient, type PoolQueryClient } from "../src/kit/templates/query";
import { defineMigration, MigrationLedger, type Migration } from "../src/kit/templates/migrations";
import { checkHealth, checkReady } from "../src/kit/templates/health";

// Live Postgres integration for the kit. Runs only when a database URL is
// available (KIT_TEST_DATABASE_URL); otherwise skipped so CI without a database
// stays green. Spin one up locally, e.g.:
//   docker run --rm -e POSTGRES_PASSWORD=<throwaway> -p 5432:5432 postgres:16
//   KIT_TEST_DATABASE_URL=postgres://postgres:<throwaway>@localhost:5432/postgres bun test
const DATABASE_URL = process.env.KIT_TEST_DATABASE_URL;
const LEDGER_TABLE = `kit_test_schema_migrations`;

const migrations: Migration[] = [
  defineMigration(
    "0001_kit_probe",
    `CREATE TABLE IF NOT EXISTS kit_probe (id SERIAL PRIMARY KEY, note TEXT NOT NULL);`,
  ),
  defineMigration("0002_kit_probe_ts", `ALTER TABLE kit_probe ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;`),
];

const describeLive = DATABASE_URL ? describe : describe.skip;

describeLive("kit live Postgres", () => {
  let client: PoolQueryClient;

  beforeAll(async () => {
    const pool = createPgPool({ connectionString: DATABASE_URL!, applicationName: "contracts-kit-test" });
    client = createQueryClient(pool);
    await client.execute(`DROP TABLE IF EXISTS kit_probe`);
    await client.execute(`DROP TABLE IF EXISTS ${LEDGER_TABLE}`);
  });

  afterAll(async () => {
    if (client) {
      await client.execute(`DROP TABLE IF EXISTS kit_probe`).catch(() => {});
      await client.execute(`DROP TABLE IF EXISTS ${LEDGER_TABLE}`).catch(() => {});
      await client.close();
    }
  });

  test("health probe against real database", async () => {
    const health = await checkHealth(client);
    expect(health.ok).toBe(true);
    expect(health.latencyMs).toBeGreaterThanOrEqual(0);
  });

  test("migrate applies, is idempotent, and readiness flips", async () => {
    const ledger = new MigrationLedger(client, migrations, { ledgerTable: LEDGER_TABLE });

    const notReady = await checkReady(client, migrations, { ledgerTable: LEDGER_TABLE });
    expect(notReady.ok).toBe(false);
    expect(notReady.pendingMigrations).toEqual(["0001_kit_probe", "0002_kit_probe_ts"]);

    const first = await ledger.migrate();
    expect(first.applied.map((m) => m.id)).toEqual(["0001_kit_probe", "0002_kit_probe_ts"]);

    const ready = await checkReady(client, migrations, { ledgerTable: LEDGER_TABLE });
    expect(ready.ok).toBe(true);

    // Idempotent re-run.
    const second = await ledger.migrate();
    expect(second.plan.every((p) => p.state === "already_applied")).toBe(true);
  });

  test("typed wrapper get/one/many against real rows", async () => {
    await client.execute(`INSERT INTO kit_probe (note) VALUES ($1), ($2)`, ["a", "b"]);
    const all = await client.many<{ id: number; note: string }>(`SELECT id, note FROM kit_probe ORDER BY id`);
    expect(all.length).toBeGreaterThanOrEqual(2);
    const first = await client.get<{ note: string }>(`SELECT note FROM kit_probe ORDER BY id LIMIT 1`);
    expect(first?.note).toBe("a");
    const none = await client.get(`SELECT note FROM kit_probe WHERE note = 'zzz'`);
    expect(none).toBeNull();
    const count = await client.one<{ n: string }>(`SELECT count(*)::text AS n FROM kit_probe`);
    expect(Number(count.n)).toBeGreaterThanOrEqual(2);
  });

  test("checksum drift is rejected on a real ledger", async () => {
    const tampered: Migration[] = [
      { ...migrations[0]!, sql: `${migrations[0]!.sql} -- changed`, checksum: "sha256:deadbeef" },
      migrations[1]!,
    ];
    await expect(
      new MigrationLedger(client, tampered, { ledgerTable: LEDGER_TABLE }).migrate(),
    ).rejects.toThrow(/checksum mismatch/);
  });
});
