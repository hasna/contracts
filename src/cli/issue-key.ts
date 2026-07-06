// `contracts issue-key` implementation.
//
// Mints a Hasna API key, persists ONLY the hashed record to the app's Postgres,
// and prints the plaintext secret exactly once (that is the command's purpose —
// it is a freshly generated secret, not the disclosure of an at-rest credential).

import { mintApiKey } from "../auth/keys";
import { ApiKeyStore, type AuthQueryClient } from "../auth/store";

export interface IssueKeyDeps {
  report: (options: { json?: boolean }, error: string, details?: Record<string, unknown>) => void;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
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

async function connectStore(connectionString: string, table: string): Promise<{ store: ApiKeyStore; close: () => Promise<void> }> {
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

  let minted;
  try {
    minted = mintApiKey({
      app,
      scopes,
      signingSecret,
      ttlSeconds,
      ...(agent !== undefined ? { agent } : {}),
      ...(deps.now ? { nowMs: deps.now() } : {}),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    deps.report({ json }, `Could not mint key: ${message}`, { code: "mint_failed" });
    return;
  }

  let stored = false;
  const table = (options.table as string | undefined) ?? "api_keys";
  if (options.store !== false) {
    const dbEnvName = databaseUrlEnvName(app, options.databaseUrlEnv as string | undefined);
    const connectionString = env[dbEnvName];
    if (!connectionString) {
      deps.report({ json }, `No database URL found. Set ${dbEnvName}, or pass --no-store to skip persistence.`, {
        code: "missing_database_url",
        databaseUrlEnv: dbEnvName,
      });
      return;
    }
    let handle: { store: ApiKeyStore; close: () => Promise<void> } | undefined;
    try {
      handle = await connectStore(connectionString, table);
      await handle.store.ensureSchema();
      await handle.store.insertMinted(minted, agent ?? "issue-key");
      stored = true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      deps.report({ json }, `Could not persist key record: ${message}`, { code: "store_failed" });
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

  const expiresAt = minted.claims.exp === null ? null : new Date(minted.claims.exp * 1000).toISOString();
  const issuedAt = new Date(minted.claims.iat * 1000).toISOString();

  if (json) {
    console.log(
      JSON.stringify(
        {
          ok: true,
          app,
          kid: minted.kid,
          agent: agent ?? null,
          scopes,
          issuedAt,
          expiresAt,
          tokenHash: minted.tokenHash,
          stored,
          bootstrap,
          // The secret token, shown ONCE. Store it now; it cannot be recovered.
          token: minted.token,
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Issued API key for app '${app}' (kid ${minted.kid})${bootstrap ? " [bootstrap]" : ""}`);
  console.log(`  scopes:    ${scopes.join(", ")}`);
  console.log(`  agent:     ${agent ?? "-"}`);
  console.log(`  issued:    ${issuedAt}`);
  console.log(`  expires:   ${expiresAt ?? "never"}`);
  console.log(`  record:    ${stored ? `stored (${table})` : "not stored (--no-store)"}`);
  console.log(`  tokenHash: ${minted.tokenHash}`);
  console.log("");
  console.log("  API key (shown once — copy it now, it cannot be recovered):");
  console.log(`  ${minted.token}`);
}
