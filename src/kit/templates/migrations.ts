// Migration-ledger helper for the vendored Hasna storage kit.
//
// A `schema_migrations` ledger with per-migration sha256 checksums, modeled on
// open-loops' storage ledger. Guarantees:
//   - each migration runs at most once (idempotent by id),
//   - a migration whose SQL changed after being applied is detected as a
//     checksum mismatch and refuses to proceed (no silent drift),
//   - an applied migration unknown to this binary is detected (downgrade
//     guard),
//   - `dryRun` reports the plan without mutating anything.
//
// PURE REMOTE (Amendment A1): migrations run against the cloud Postgres. There
// is no local schema and no sync of ledger rows between machines.

import { createHash } from "node:crypto";
import type { TypedQueryClient } from "./query.js";

/** Default ledger table name. Override per app if a legacy name exists. */
export const DEFAULT_MIGRATION_LEDGER_TABLE = "schema_migrations";

export interface Migration {
  readonly id: string;
  readonly sql: string;
  readonly checksum: string;
}

export type MigrationState = "already_applied" | "pending";

export interface MigrationPlanItem {
  readonly migration: Migration;
  readonly state: MigrationState;
}

export interface AppliedMigration {
  readonly id: string;
  readonly checksum: string;
  readonly appliedAt: string;
}

export interface MigrationResult {
  readonly dryRun: boolean;
  readonly applied: AppliedMigration[];
  readonly plan: MigrationPlanItem[];
}

/** Stable sha256 checksum for a migration's SQL text. */
export function checksumSql(sql: string): string {
  const normalized = sql.trim().replace(/\r\n/g, "\n");
  return `sha256:${createHash("sha256").update(normalized).digest("hex")}`;
}

/** Freeze a migration definition, computing its checksum from the SQL. */
export function defineMigration(id: string, sql: string): Migration {
  return Object.freeze({ id, sql: sql.trim(), checksum: checksumSql(sql) });
}

interface LedgerRow {
  id: string;
  checksum: string;
  applied_at: string | Date;
}

export interface MigrationRunnerOptions {
  ledgerTable?: string;
}

function quoteIdentifier(identifier: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(identifier)) {
    throw new Error(`Invalid migration ledger table identifier segment: ${identifier}`);
  }
  return `"${identifier.replace(/"/g, "\"\"")}"`;
}

function quoteIdentifierPath(name: string): string {
  const parts = name.split(".");
  if (parts.length === 0 || parts.length > 2 || parts.some((part) => part.length === 0)) {
    throw new Error(`Invalid migration ledger table name: ${name}`);
  }
  return parts.map(quoteIdentifier).join(".");
}

interface TransactionCapableClient extends TypedQueryClient {
  transaction<T>(fn: (client: TypedQueryClient) => Promise<T>): Promise<T>;
}

function hasTransaction(client: TypedQueryClient): client is TransactionCapableClient {
  return typeof (client as { transaction?: unknown }).transaction === "function";
}

export class MigrationLedger {
  private readonly ledgerTable: string;
  private readonly ledgerTableName: string;

  constructor(
    private readonly client: TypedQueryClient,
    private readonly migrations: readonly Migration[],
    options: MigrationRunnerOptions = {},
  ) {
    this.ledgerTableName = options.ledgerTable ?? DEFAULT_MIGRATION_LEDGER_TABLE;
    this.ledgerTable = quoteIdentifierPath(this.ledgerTableName);
    const seen = new Set<string>();
    for (const migration of migrations) {
      if (seen.has(migration.id)) throw new Error(`Duplicate migration id: ${migration.id}`);
      seen.add(migration.id);
    }
  }

  async ensureLedger(): Promise<void> {
    await this.ensureLedgerFrom(this.client);
  }

  private async ensureLedgerFrom(client: TypedQueryClient): Promise<void> {
    await client.execute(
      `CREATE TABLE IF NOT EXISTS ${this.ledgerTable} (
         id TEXT PRIMARY KEY,
         checksum TEXT NOT NULL,
         applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
       )`,
    );
  }

  private async runTransaction<T>(fn: (client: TypedQueryClient) => Promise<T>): Promise<T> {
    if (!hasTransaction(this.client)) {
      throw new Error(
        "Migration application requires a transaction-capable query client. Use createQueryClient(pool) or pass a client with transaction().",
      );
    }
    return this.client.transaction(fn);
  }

  private async takeMigrationLock(client: TypedQueryClient): Promise<void> {
    await client.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [this.ledgerTableName]);
  }

  async listApplied(): Promise<AppliedMigration[]> {
    await this.ensureLedger();
    return this.readApplied();
  }

  private async readApplied(): Promise<AppliedMigration[]> {
    const rows = await this.client.many<LedgerRow>(
      `SELECT id, checksum, applied_at FROM ${this.ledgerTable} ORDER BY id ASC`,
    );
    return rows.map((row) => ({
      id: row.id,
      checksum: row.checksum,
      appliedAt: row.applied_at instanceof Date ? row.applied_at.toISOString() : String(row.applied_at),
    }));
  }

  /** Compute the migration plan and guard against drift/downgrade. */
  private buildPlan(applied: AppliedMigration[]): MigrationPlanItem[] {
    const known = new Set(this.migrations.map((m) => m.id));
    for (const row of applied) {
      if (!known.has(row.id)) {
        throw new Error(`Applied migration '${row.id}' is not recognized by this build (downgrade?).`);
      }
    }
    const appliedById = new Map(applied.map((row) => [row.id, row]));
    for (const migration of this.migrations) {
      const existing = appliedById.get(migration.id);
      if (existing && existing.checksum !== migration.checksum) {
        throw new Error(
          `Migration checksum mismatch for '${migration.id}': the SQL changed after it was applied.`,
        );
      }
    }
    return this.migrations.map((migration) => ({
      migration,
      state: appliedById.has(migration.id) ? "already_applied" : "pending",
    }));
  }

  /** Apply all pending migrations. With `dryRun`, report the plan only. */
  async migrate(opts: { dryRun?: boolean } = {}): Promise<MigrationResult> {
    const dryRun = opts.dryRun === true;
    if (dryRun) {
      await this.ensureLedger();
      const applied = await this.readApplied();
      const plan = this.buildPlan(applied);
      return { dryRun, applied, plan };
    }

    const plan = await this.runTransaction(async (tx) => {
      await this.takeMigrationLock(tx);
      await this.ensureLedgerFrom(tx);
      const txApplied = await this.readAppliedFrom(tx);
      const txPlan = this.buildPlan(txApplied);
      for (const item of txPlan) {
        if (item.state === "already_applied") continue;
        await tx.execute(item.migration.sql);
        await tx.execute(
          `INSERT INTO ${this.ledgerTable} (id, checksum, applied_at) VALUES ($1, $2, now())`,
          [item.migration.id, item.migration.checksum],
        );
      }
      return txPlan;
    });
    return { dryRun, applied: await this.readApplied(), plan };
  }

  private async readAppliedFrom(client: TypedQueryClient): Promise<AppliedMigration[]> {
    const rows = await client.many<LedgerRow>(
      `SELECT id, checksum, applied_at FROM ${this.ledgerTable} ORDER BY id ASC`,
    );
    return rows.map((row) => ({
      id: row.id,
      checksum: row.checksum,
      appliedAt: row.applied_at instanceof Date ? row.applied_at.toISOString() : String(row.applied_at),
    }));
  }
}

/** Convenience: build a ledger and run all pending migrations. */
export function createMigrationLedger(
  client: TypedQueryClient,
  migrations: readonly Migration[],
  options: MigrationRunnerOptions = {},
): MigrationLedger {
  return new MigrationLedger(client, migrations, options);
}
