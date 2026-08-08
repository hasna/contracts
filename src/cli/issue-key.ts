// `contracts issue-key` implementation.
//
// Mints a Hasna API key, persists ONLY the hashed record to the app's Postgres,
// and prints the plaintext secret exactly once (that is the command's purpose —
// it is a freshly generated secret, not the disclosure of an at-rest credential).
// The secret exists only in this process, so every exit path after minting prints
// it, including persistence failures.
//
// PERSISTENCE IS POSTGRES-ONLY, DELIBERATELY. Writing the hashed record through an
// app's cloud `/v1` API would need an `api-keys` operation that is declared in the
// operation manifest, published in the served OpenAPI document, and implemented by
// the app. None of that exists yet, so this command ships no client for it: an
// HTTP writer aimed at an undeclared route cannot report honestly whether the
// record was stored. For the same reason the client-transport env
// (`HASNA_<APP>_API_URL`, `HASNA_<APP>_API_KEY`) is not
// consulted here — it selects the transport for app data, not for this record, and
// must never block or divert the database write.

import { mintApiKey, type MintedApiKey } from "../auth/keys";
import { normalizeTenantId } from "../auth/tenant";
import { ApiKeyStore, type AuthQueryClient } from "../auth/store";

type IssueKeyStore = Pick<ApiKeyStore, "ensureSchema" | "insertMinted">;
type IssueKeyStoreHandle = { store: IssueKeyStore; close: () => Promise<void> };
type IssueKeyConnectStore = (connectionString: string, table: string) => Promise<IssueKeyStoreHandle>;

export interface IssueKeyDeps {
  report: (options: { json?: boolean }, error: string, details?: Record<string, unknown>) => void;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  connectStore?: IssueKeyConnectStore;
}

function envToken(app: string): string {
  return app.toUpperCase().replace(/-/g, "_");
}

/** Resolve the signing-secret env var name (never the value) for messages. */
export function signingSecretEnvName(app: string, override?: string): string {
  return override ?? `HASNA_${envToken(app)}_API_SIGNING_KEY`;
}

/** Resolve the database-url env var name for the record store. */
export function databaseUrlEnvName(app: string, override?: string): string {
  return override ?? `HASNA_${envToken(app)}_DATABASE_URL`;
}

/**
 * Read one option as an OWN property — the sibling of `ownAgentClaim` and
 * `ownTenantId` in `src/auth/keys.ts`, moved to the WRITE path.
 *
 * Commander omits a flag the operator did not type rather than defining it as
 * `undefined`, so the parsed options object genuinely lacks those keys while
 * still having `Object.prototype` in its chain. A bare `options.<flag>` read is
 * therefore a real prototype lookup, and a `__proto__`/`constructor.prototype`
 * write primitive anywhere else in the process decides what it returns.
 *
 * That matters more here than on the verify path. Values read in `runIssueKey`
 * are handed to `mintApiKey` and land INSIDE the HMAC-signed body, so the key
 * that comes out is cryptographically authentic and no verify-time guard can —
 * or should — reject it. `ownAgentClaim`/`ownTenantId`/`ownScopesClaim` all sit
 * downstream of the signature and cannot help. This is the only place the value
 * can be stopped.
 */
function ownOption(options: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(options, name) ? options[name] : undefined;
}

function parseScopesCsv(csv: unknown): string[] {
  if (typeof csv !== "string") return [];
  return csv
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

async function connectStore(connectionString: string, table: string): Promise<IssueKeyStoreHandle> {
  let pgModule: any;
  try {
    pgModule = await import("pg");
  } catch {
    throw new Error("Persisting the key record requires the 'pg' package. Install it, or pass --no-store.");
  }
  const Pool = pgModule.default?.Pool ?? pgModule.Pool;
  const pool = new Pool({ connectionString });
  const client: AuthQueryClient = {
    many: async (sql, params) => (await pool.query(sql, params as unknown[])).rows,
    get: async (sql, params) => (await pool.query(sql, params as unknown[])).rows[0] ?? null,
    execute: async (sql, params) => {
      await pool.query(sql, params as unknown[]);
    },
  };
  const store = new ApiKeyStore(client, { table });
  return { store, close: () => pool.end() };
}

export async function runIssueKey(options: Record<string, unknown>, deps: IssueKeyDeps): Promise<void> {
  const env = deps.env ?? process.env;

  // EVERY option is read exactly once, here, as an own property. Reading them
  // in one place is the point: a single bare `options.x` left anywhere below
  // reopens the hole for that flag alone, and a bare read is invisible at a
  // glance because it looks identical to a correct one. Past this block the
  // function sees locals, never `options`.
  const optJson = ownOption(options, "json");
  const optApp = ownOption(options, "app");
  const optBootstrap = ownOption(options, "bootstrap");
  const optScopes = ownOption(options, "scopes");
  const optAgent = ownOption(options, "agent");
  const optTid = ownOption(options, "tid");
  const optExpiry = ownOption(options, "expiry");
  const optTtlDays = ownOption(options, "ttlDays");
  const optSigningSecretEnv = ownOption(options, "signingSecretEnv") as string | undefined;
  const optDatabaseUrlEnv = ownOption(options, "databaseUrlEnv") as string | undefined;
  const optTable = ownOption(options, "table") as string | undefined;
  const optStore = ownOption(options, "store");

  const json = optJson === true;
  const app = String(optApp ?? "").trim();
  if (!app) {
    deps.report({ json }, "Missing required option --app.", { code: "missing_app" });
    return;
  }

  const bootstrap = optBootstrap === true;
  let scopes = parseScopesCsv(optScopes);
  if (scopes.length === 0) {
    if (bootstrap) {
      scopes = [`${app}:*`];
    } else {
      deps.report({ json }, "Missing --scopes. Provide e.g. --scopes 'todos:read,todos:write' or use --bootstrap.", {
        code: "missing_scopes",
      });
      return;
    }
  }

  // `optAgent` is the own-property read #80 introduced here, now taken at the
  // top of the function with every other option. Its reasoning is unchanged and
  // is recorded on `ownOption` above: downstream `ownAgentClaim` reads this back
  // as an OWN, string-valued claim and reports it as authentic, because once it
  // has been signed it genuinely is — a read-side guard cannot undo a poisoned
  // signature. `String()` coercion and the `bootstrap` fallback are preserved
  // exactly; only the prototype walk is gone.
  const agent = optAgent !== undefined ? String(optAgent) : bootstrap ? "bootstrap" : undefined;

  let tid: string | undefined;
  if (optTid !== undefined) {
    try {
      tid = normalizeTenantId(String(optTid));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      deps.report({ json }, message, { code: "bad_tid" });
      return;
    }
  }

  // TTL: --no-expiry => null; else --ttl-days (default 90).
  let ttlSeconds: number | null;
  if (optExpiry === false) {
    ttlSeconds = null;
  } else {
    const days = optTtlDays !== undefined ? Number(optTtlDays) : 90;
    if (!Number.isFinite(days) || days <= 0) {
      deps.report({ json }, "--ttl-days must be a positive number.", { code: "bad_ttl" });
      return;
    }
    ttlSeconds = Math.floor(days * 24 * 60 * 60);
  }

  const secretEnvName = signingSecretEnvName(app, optSigningSecretEnv);
  const fallbackName = optSigningSecretEnv ? undefined : "HASNA_API_SIGNING_KEY";
  const signingSecret = env[secretEnvName] ?? (fallbackName ? env[fallbackName] : undefined);
  if (!signingSecret) {
    const tried = fallbackName ? `${secretEnvName} (or ${fallbackName})` : secretEnvName;
    deps.report({ json }, `No signing secret found. Set the ${tried} env var (openssl rand -hex 32).`, {
      code: "missing_signing_secret",
      signingSecretEnv: secretEnvName,
    });
    return;
  }

  let minted: MintedApiKey;
  try {
    minted = mintApiKey({
      app,
      scopes,
      signingSecret,
      ttlSeconds,
      ...(agent !== undefined ? { agent } : {}),
      ...(tid !== undefined ? { tid } : {}),
      ...(deps.now ? { nowMs: deps.now() } : {}),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    deps.report({ json }, `Could not mint key: ${message}`, { code: "mint_failed" });
    return;
  }

  const table = optTable ?? "api_keys";
  const dbEnvName = databaseUrlEnvName(app, optDatabaseUrlEnv);
  const expiresAt = minted.claims.exp === null ? null : new Date(minted.claims.exp * 1000).toISOString();
  const issuedAt = new Date(minted.claims.iat * 1000).toISOString();

  // The plaintext token is derived at mint time and never persisted anywhere.
  // EVERY exit path after minting must hand it to the operator: a persistence
  // failure that swallows it destroys an unrecoverable credential.
  const keyMaterial = {
    app,
    kid: minted.kid,
    agent: agent ?? null,
    tid: tid ?? null,
    scopes,
    issuedAt,
    expiresAt,
    tokenHash: minted.tokenHash,
    bootstrap,
    // The secret token, shown ONCE. Store it now; it cannot be recovered.
    token: minted.token,
  };

  const printKeyBlock = (record: string, storeError: string | null): void => {
    console.log(`Issued API key for app '${app}' (kid ${minted.kid})${bootstrap ? " [bootstrap]" : ""}`);
    console.log(`  scopes:    ${scopes.join(", ")}`);
    console.log(`  agent:     ${agent ?? "-"}`);
    console.log(`  tenant:    ${tid ?? "- (untenanted)"}`);
    console.log(`  issued:    ${issuedAt}`);
    console.log(`  expires:   ${expiresAt ?? "never"}`);
    console.log(`  record:    ${record}`);
    if (storeError) console.log(`  storeError: ${storeError}`);
    console.log(`  tokenHash: ${minted.tokenHash}`);
    if (!stored) {
      console.log("");
      console.log("  WARNING: no api_keys record was stored for this key. Services that verify");
      console.log("  key status (the default: keyStatus/statusChecker) will REFUSE it with");
      console.log("  reason 'unknown_key', and it CANNOT BE REVOKED — revocation works by");
      console.log(`  writing revoked_at on the '${table}' row, and there is no row. Register it`);
      console.log("  with ApiKeyStore.insertMinted, or re-issue with the database URL set.");
    }
    if (expiresAt === null) {
      console.log("");
      console.log("  WARNING: this key NEVER EXPIRES. Fleet TTL policy is expiring keys");
      console.log("  (default 90 days); a leaked forever-key stays valid until someone");
      console.log("  notices. Prefer --ttl-days and rotate on schedule.");
    }
    console.log("");
    console.log("  API key (shown once — copy it now, it cannot be recovered):");
    console.log(`  ${minted.token}`);
  };

  /** Surface a persistence failure WITHOUT losing the already-minted secret. */
  const reportStoreFailure = (message: string, code: string, details: Record<string, unknown> = {}): void => {
    deps.report({ json }, message, { code, ...details, stored: false, ...keyMaterial });
    if (!json) printKeyBlock("NOT STORED", message);
  };

  let stored = false;
  if (optStore !== false) {
    const createdBy = agent ?? "issue-key";
    const connectionString = env[dbEnvName];
    if (!connectionString) {
      reportStoreFailure(
        `No database URL found. Set ${dbEnvName}, or pass --no-store to skip persistence.`,
        "missing_database_url",
        { databaseUrlEnv: dbEnvName },
      );
      return;
    }
    let handle: IssueKeyStoreHandle | undefined;
    try {
      const connect = deps.connectStore ?? connectStore;
      handle = await connect(connectionString, table);
      await handle.store.ensureSchema();
      await handle.store.insertMinted(minted, createdBy);
      stored = true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      reportStoreFailure(`Could not persist key record: ${message}`, "store_failed");
      return;
    } finally {
      if (handle) {
        try {
          await handle.close();
        } catch {
          // ignore pool close failure
        }
      }
    }
  }

  if (json) {
    const warnings: string[] = [];
    if (!stored) {
      warnings.push(
        "unregistered: no api_keys record stored — strict services (keyStatus/statusChecker) will refuse this key with reason 'unknown_key', and it cannot be revoked until a record exists",
      );
    }
    if (expiresAt === null) {
      warnings.push("no_expiry: this key never expires; fleet TTL policy is expiring keys (default 90 days)");
    }
    console.log(JSON.stringify({ ok: true, ...keyMaterial, stored, revocable: stored, warnings }, null, 2));
    return;
  }

  printKeyBlock(stored ? `stored (${table})` : "not stored (--no-store)", null);
}
