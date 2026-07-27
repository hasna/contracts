// Persistence for Hasna API keys: hashed records + revocation list.
//
// Stores ONLY the sha256 hash of each token (never the plaintext) plus metadata
// needed for revocation and audit. Built on a minimal structural query-client
// interface so it works with the vendored storage kit's `TypedQueryClient`, a
// raw `pg.Pool` wrapper, or a lightweight test shim — no direct `pg` import.
//
// PURE REMOTE (Amendment A1): every call hits the cloud Postgres directly. There
// is no cache and no local mirror; a revocation check reads the row each time.

import type { ApiKeyClaims, MintedApiKey } from "./keys.js";
import { normalizeTenantId, ownTenantId } from "./tenant.js";

/** Minimal row shape. Compatible with `pg` QueryResultRow. */
export type Row = Record<string, unknown>;

/**
 * Structural subset of the storage kit's `TypedQueryClient`. Any object with
 * these methods (the kit client, a pool wrapper, or a test shim) works.
 */
export interface AuthQueryClient {
  many<T extends Row>(sql: string, params?: readonly unknown[]): Promise<T[]>;
  get<T extends Row>(sql: string, params?: readonly unknown[]): Promise<T | null>;
  execute(sql: string, params?: readonly unknown[]): Promise<void>;
}

export const DEFAULT_API_KEYS_TABLE = "api_keys";

export interface ApiKeyRecord {
  kid: string;
  app: string;
  agent: string | null;
  /** Tenant the key acts for; `null` for untenanted (pre-`tid`) keys. */
  tid: string | null;
  scopes: string[];
  tokenHash: string;
  issuedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
  revokedReason: string | null;
  lastUsedAt: string | null;
  createdBy: string | null;
}

export type ApiKeyStatus = "active" | "revoked" | "expired" | "unknown";

/** Migration id + SQL, feedable to the kit's `MigrationLedger`. */
export interface AuthMigration {
  readonly id: string;
  readonly sql: string;
}

function createTableSql(table: string): string {
  return `CREATE TABLE IF NOT EXISTS ${table} (
    kid TEXT PRIMARY KEY,
    app TEXT NOT NULL,
    agent TEXT,
    scopes JSONB NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    last_used_at TIMESTAMPTZ,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
}

/**
 * Ordered migrations for the api-keys table (id namespaced to avoid clashes).
 *
 * 0003 adds the tenant column, as a SEPARATE migration. 0001's SQL MUST NOT be
 * edited to include it, and not merely because a deployed ledger would not
 * re-run 0001: consumers feed these straight into a CONTENT-ADDRESSED ledger
 * (`checksumSql` in src/kit/templates/migrations.ts) that aborts the whole
 * migration run on `Migration checksum mismatch`. Editing 0001 therefore breaks
 * the upgrade AND prevents 0003 from ever running, so the column would never
 * land. `tests/auth-tenant.test.ts` pins 0001's and 0002's checksums to make
 * that mistake impossible to commit.
 *
 * The column is `TEXT NULL` with no DEFAULT — matching the contract's wire
 * type, and nullable because keys issued before the tenant claim existed are
 * untenanted, not tenant-zero.
 */
export function apiKeyMigrations(table: string = DEFAULT_API_KEYS_TABLE): AuthMigration[] {
  return [
    { id: `hasna_auth_0001_${table}`, sql: createTableSql(table) },
    {
      id: `hasna_auth_0002_${table}_indexes`,
      sql: `CREATE INDEX IF NOT EXISTS ${table}_app_idx ON ${table} (app);
            CREATE INDEX IF NOT EXISTS ${table}_token_hash_idx ON ${table} (token_hash);`,
    },
    {
      id: `hasna_auth_0003_${table}_tenant`,
      sql: `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS tid TEXT;
            CREATE INDEX IF NOT EXISTS ${table}_tid_idx ON ${table} (tid);`,
    },
  ];
}

function toIso(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  return new Date(String(value)).toISOString();
}

function parseScopes(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v));
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
    } catch {
      return [];
    }
  }
  return [];
}

function rowToRecord(row: Row): ApiKeyRecord {
  // Own-property read (see `ownTenantId`): a driver returning a row from before
  // migration 0003 has no `tid` key at all, and that absence must read as
  // untenanted rather than as whatever sits on the prototype.
  const tid = ownTenantId(row);
  return {
    kid: String(row.kid),
    app: String(row.app),
    agent: row.agent === null || row.agent === undefined ? null : String(row.agent),
    tid: tid === null || tid === undefined ? null : String(tid),
    scopes: parseScopes(row.scopes),
    tokenHash: String(row.token_hash),
    issuedAt: toIso(row.issued_at) ?? new Date(0).toISOString(),
    expiresAt: toIso(row.expires_at),
    revokedAt: toIso(row.revoked_at),
    revokedReason: row.revoked_reason === null || row.revoked_reason === undefined ? null : String(row.revoked_reason),
    lastUsedAt: toIso(row.last_used_at),
    createdBy: row.created_by === null || row.created_by === undefined ? null : String(row.created_by),
  };
}

export interface InsertKeyInput {
  kid: string;
  app: string;
  agent?: string | null;
  /**
   * Tenant the key acts for. Omit or `null` for an untenanted key. Validated
   * and canonicalized on the way in: a store that accepted ids no token could
   * carry, or that stored two spellings of one UUID, would reopen the drift
   * this claim exists to close.
   */
  tid?: string | null;
  scopes: string[];
  tokenHash: string;
  issuedAt: Date;
  expiresAt: Date | null;
  createdBy?: string | null;
}

export interface ApiKeyStoreOptions {
  table?: string;
}

/** DB-backed store for issued API keys. */
export class ApiKeyStore {
  readonly table: string;

  constructor(private readonly client: AuthQueryClient, options: ApiKeyStoreOptions = {}) {
    this.table = options.table ?? DEFAULT_API_KEYS_TABLE;
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(this.table)) {
      throw new Error(`Invalid api-keys table name '${this.table}'.`);
    }
  }

  /** Migrations for this store's table, for the kit's `MigrationLedger`. */
  migrations(): AuthMigration[] {
    return apiKeyMigrations(this.table);
  }

  /** Idempotently create the table + indexes (standalone path). */
  async ensureSchema(): Promise<void> {
    for (const migration of this.migrations()) {
      await this.client.execute(migration.sql);
    }
  }

  /** Insert a hashed key record. Throws on duplicate kid/token hash. */
  async insert(input: InsertKeyInput): Promise<void> {
    // Own-property read (see `ownTenantId`): a polluted prototype must not put
    // a tenant on a row the caller inserted without one.
    const tid = ownTenantId(input);
    await this.client.execute(
      `INSERT INTO ${this.table}
         (kid, app, agent, tid, scopes, token_hash, issued_at, expires_at, created_by)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9)`,
      [
        input.kid,
        input.app,
        input.agent ?? null,
        tid === undefined || tid === null ? null : normalizeTenantId(tid),
        JSON.stringify(input.scopes),
        input.tokenHash,
        input.issuedAt.toISOString(),
        input.expiresAt ? input.expiresAt.toISOString() : null,
        input.createdBy ?? null,
      ],
    );
  }

  /** Convenience: persist the record for a freshly minted key. */
  async insertMinted(minted: MintedApiKey, createdBy?: string): Promise<void> {
    const claims: ApiKeyClaims = minted.claims;
    await this.insert({
      kid: minted.kid,
      app: claims.app,
      agent: claims.agent ?? null,
      tid: ownTenantId(claims) ?? null,
      scopes: claims.scopes,
      tokenHash: minted.tokenHash,
      issuedAt: new Date(claims.iat * 1000),
      expiresAt: claims.exp === null ? null : new Date(claims.exp * 1000),
      createdBy: createdBy ?? null,
    });
  }

  async findByKid(kid: string): Promise<ApiKeyRecord | null> {
    const row = await this.client.get<Row>(`SELECT * FROM ${this.table} WHERE kid = $1`, [kid]);
    return row ? rowToRecord(row) : null;
  }

  async findByTokenHash(tokenHash: string): Promise<ApiKeyRecord | null> {
    const row = await this.client.get<Row>(`SELECT * FROM ${this.table} WHERE token_hash = $1`, [tokenHash]);
    return row ? rowToRecord(row) : null;
  }

  /**
   * Revocation check for the middleware. Returns `true` (deny) only when a
   * record exists AND is explicitly revoked. Unknown kids return `false` — the
   * token is cryptographically valid and simply was not persisted here. Use
   * {@link statusChecker} for strict "must be recorded and active" semantics.
   */
  isRevoked = async (kid: string): Promise<boolean> => {
    const row = await this.client.get<Row>(`SELECT revoked_at FROM ${this.table} WHERE kid = $1`, [kid]);
    if (!row) return false;
    return row.revoked_at !== null && row.revoked_at !== undefined;
  };

  /** Resolve the lifecycle status of a kid (unknown/active/revoked/expired). */
  async status(kid: string, nowMs = Date.now()): Promise<ApiKeyStatus> {
    const record = await this.findByKid(kid);
    if (!record) return "unknown";
    if (record.revokedAt) return "revoked";
    if (record.expiresAt && new Date(record.expiresAt).getTime() <= nowMs) return "expired";
    return "active";
  }

  /**
   * Strict checker for {@link import("./middleware.js")}: denies unknown OR
   * revoked kids (an unrecorded token cannot authenticate).
   */
  statusChecker(): (kid: string) => Promise<boolean> {
    return async (kid: string): Promise<boolean> => {
      const status = await this.status(kid);
      return status !== "active";
    };
  }

  /** Revoke a key by kid. Returns true if a row was affected. */
  async revoke(kid: string, reason?: string, atMs = Date.now()): Promise<boolean> {
    const row = await this.client.get<Row>(
      `UPDATE ${this.table}
          SET revoked_at = COALESCE(revoked_at, $2), revoked_reason = COALESCE(revoked_reason, $3)
        WHERE kid = $1
      RETURNING kid`,
      [kid, new Date(atMs).toISOString(), reason ?? null],
    );
    return row !== null;
  }

  /** Record last-used for a kid (best-effort telemetry). */
  async touchLastUsed(kid: string, atMs = Date.now()): Promise<void> {
    await this.client.execute(`UPDATE ${this.table} SET last_used_at = $2 WHERE kid = $1`, [
      kid,
      new Date(atMs).toISOString(),
    ]);
  }

  /**
   * List keys, optionally filtered by app and/or tenant, excluding revoked by
   * default. `tid` filters to exactly that tenant; it never falls back to
   * "all tenants" when the filter does not match, so an operator listing one
   * organization's keys cannot accidentally enumerate another's. A `tid` that
   * is present but unusable (empty, whitespace, or outside the grammar) THROWS
   * rather than listing anything.
   */
  async list(options: { app?: string; tid?: string; includeRevoked?: boolean } = {}): Promise<ApiKeyRecord[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (options.app) {
      params.push(options.app);
      clauses.push(`app = $${params.length}`);
    }
    // PRESENCE, not truthiness. `tid: ""` — a `req.params.tid` that was empty,
    // or a `String(req.query.tid ?? "")` — is a caller that MEANT to filter by
    // tenant, so dropping the clause would widen the query to every
    // organization's key records: the exact enumeration this filter exists to
    // prevent, and the opposite of what the guarantee above promises.
    // `normalizeTenantId` therefore does the work: it trims, canonicalizes so
    // that listing by the UUID an operator pasted from a `uuid` column matches
    // a row written from a `text` column and vice versa, and throws on anything
    // no token could ever carry — the same rule `insert` already applies.
    const tid = ownTenantId(options);
    if (tid !== undefined) {
      params.push(normalizeTenantId(tid));
      clauses.push(`tid = $${params.length}`);
    }
    if (!options.includeRevoked) {
      clauses.push("revoked_at IS NULL");
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows = await this.client.many<Row>(`SELECT * FROM ${this.table} ${where} ORDER BY issued_at DESC`, params);
    return rows.map(rowToRecord);
  }

  /** The set of currently-revoked kids (for building an in-memory deny-set). */
  async revokedKids(): Promise<string[]> {
    const rows = await this.client.many<Row>(`SELECT kid FROM ${this.table} WHERE revoked_at IS NOT NULL`);
    return rows.map((row) => String(row.kid));
  }
}
