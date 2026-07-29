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
// (`HASNA_<APP>_STORAGE_MODE`, `HASNA_<APP>_API_URL`, `HASNA_<APP>_API_KEY`) is not
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
  const json = options.json === true;
  const app = String(options.app ?? "").trim();
  if (!app) {
    deps.report({ json }, "Missing required option --app.", { code: "missing_app" });
    return;
  }

  const bootstrap = options.bootstrap === true;
  let scopes = parseScopesCsv(options.scopes);
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

  const agent = options.agent !== undefined ? String(options.agent) : bootstrap ? "bootstrap" : undefined;

  let tid: string | undefined;
  if (options.tid !== undefined) {
    try {
      tid = normalizeTenantId(String(options.tid));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      deps.report({ json }, message, { code: "bad_tid" });
      return;
    }
  }

  // TTL: --no-expiry => null; else --ttl-days (default 90).
  let ttlSeconds: number | null;
  if (options.expiry === false) {
    ttlSeconds = null;
  } else {
    const days = options.ttlDays !== undefined ? Number(options.ttlDays) : 90;
    if (!Number.isFinite(days) || days <= 0) {
      deps.report({ json }, "--ttl-days must be a positive number.", { code: "bad_ttl" });
      return;
    }
    ttlSeconds = Math.floor(days * 24 * 60 * 60);
  }

  const secretEnvName = signingSecretEnvName(app, options.signingSecretEnv as string | undefined);
  const fallbackName = options.signingSecretEnv ? undefined : "HASNA_API_SIGNING_KEY";
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

  const table = (options.table as string | undefined) ?? "api_keys";
  const dbEnvName = databaseUrlEnvName(app, options.databaseUrlEnv as string | undefined);
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
  if (options.store !== false) {
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
    console.log(JSON.stringify({ ok: true, ...keyMaterial, stored }, null, 2));
    return;
  }

  printKeyBlock(stored ? `stored (${table})` : "not stored (--no-store)", null);
}
