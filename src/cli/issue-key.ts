// `contracts issue-key` implementation.
//
// Mints a Hasna API key, persists ONLY the hashed record — to the app's Postgres
// by default, or to its cloud `/v1` API when `--store-backend api|auto` selects
// that transport — and prints the plaintext secret exactly once (that is the
// command's purpose — it is a freshly generated secret, not the disclosure of an
// at-rest credential). The secret exists only in this process, so every exit path
// after minting prints it, including persistence failures.

import { mintApiKey, type MintedApiKey } from "../auth/keys";
import { normalizeTenantId } from "../auth/tenant";
import { ApiKeyStore, type AuthQueryClient } from "../auth/store";
import {
  createClientTransport,
  resolveClientTransport,
  type ClientTransportResolution,
  type HasnaHttpTransportOptions,
} from "../client/transport";

export const API_KEY_RECORD_RESOURCE = "api-keys";

/** Where the hashed record is persisted. */
export type IssueKeyStoreBackend = "api" | "database" | "auto";

const STORE_BACKENDS: readonly IssueKeyStoreBackend[] = ["api", "database", "auto"];

export interface IssueKeyRecordPayload {
  kid: string;
  app: string;
  agent: string | null;
  tid: string | null;
  scopes: string[];
  tokenHash: string;
  issuedAt: string;
  expiresAt: string | null;
  createdBy: string;
}

type IssueKeyStore = Pick<ApiKeyStore, "ensureSchema" | "insertMinted">;
type IssueKeyStoreHandle = { store: IssueKeyStore; close: () => Promise<void> };
type IssueKeyConnectStore = (connectionString: string, table: string) => Promise<IssueKeyStoreHandle>;
type IssueKeyTransportOverrides = Partial<
  Pick<HasnaHttpTransportOptions, "fetchImpl" | "headers" | "timeoutMs" | "retry" | "sleepImpl">
>;

export interface IssueKeyDeps {
  report: (options: { json?: boolean }, error: string, details?: Record<string, unknown>) => void;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  connectStore?: IssueKeyConnectStore;
  transportOverrides?: IssueKeyTransportOverrides;
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
 * Resolve which persistence backend the operator asked for.
 *
 * The default is `database`. Ambient `HASNA_<APP>_API_URL` + `HASNA_<APP>_API_KEY`
 * — exactly what the fleet env-flip writes — must NOT silently redirect a record
 * that used to land in Postgres to an HTTP route the app may not serve. `api` and
 * `auto` opt into the transport; `auto` still defers to the database when the
 * caller supplied `--database-url-env`/`--table`, since those options are a
 * database request and mean nothing to the API backend.
 */
export function resolveStoreBackend(
  options: Record<string, unknown>,
): { ok: true; backend: IssueKeyStoreBackend } | { ok: false; error: string } {
  const raw = options.storeBackend;
  const requested = raw === undefined ? "database" : String(raw).trim().toLowerCase();
  if (!STORE_BACKENDS.includes(requested as IssueKeyStoreBackend)) {
    return { ok: false, error: `--store-backend must be one of: ${STORE_BACKENDS.join(", ")} (got '${String(raw)}').` };
  }
  const backend = requested as IssueKeyStoreBackend;
  const databaseOptionsGiven = options.databaseUrlEnv !== undefined || options.table !== undefined;
  return { ok: true, backend: backend === "auto" && databaseOptionsGiven ? "database" : backend };
}

function parseScopesCsv(csv: unknown): string[] {
  if (typeof csv !== "string") return [];
  return csv
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function issueKeyRecordPayload(minted: MintedApiKey, createdBy: string): IssueKeyRecordPayload {
  const claims = minted.claims;
  return {
    kid: minted.kid,
    app: claims.app,
    agent: claims.agent ?? null,
    tid: claims.tid ?? null,
    scopes: [...claims.scopes],
    tokenHash: minted.tokenHash,
    issuedAt: new Date(claims.iat * 1000).toISOString(),
    expiresAt: claims.exp === null ? null : new Date(claims.exp * 1000).toISOString(),
    createdBy,
  };
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

async function persistKeyRecordOverHttp(
  app: string,
  minted: MintedApiKey,
  createdBy: string,
  env: NodeJS.ProcessEnv,
  overrides: IssueKeyTransportOverrides | undefined,
  resolution: ClientTransportResolution,
): Promise<boolean> {
  if (resolution.transport !== "cloud-http") {
    return false;
  }

  const wired = createClientTransport(app, env, overrides);
  if (wired.transport !== "cloud-http") {
    return false;
  }

  await wired.client.post(
    `/${API_KEY_RECORD_RESOURCE}`,
    issueKeyRecordPayload(minted, createdBy),
    { idempotencyKey: minted.kid },
  );
  return true;
}

export async function runIssueKey(options: Record<string, unknown>, deps: IssueKeyDeps): Promise<void> {
  const env = deps.env ?? process.env;
  const json = options.json === true;
  const app = String(options.app ?? "").trim();
  if (!app) {
    deps.report({ json }, "Missing required option --app.", { code: "missing_app" });
    return;
  }

  const backendChoice = resolveStoreBackend(options);
  if (!backendChoice.ok) {
    deps.report({ json }, backendChoice.error, { code: "bad_store_backend" });
    return;
  }
  const backend = backendChoice.backend;

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
  const appEnvToken = envToken(app);
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
    deps.report({ json }, message, { code, ...details, stored: false, storeBackend: "none", ...keyMaterial });
    if (!json) printKeyBlock("NOT STORED", message);
  };

  let stored = false;
  let storeBackend: "none" | "api" | "database" = "none";
  if (options.store !== false) {
    const createdBy = agent ?? "issue-key";

    // Resolve — never construct — the transport first, whatever the chosen
    // backend. `misconfigured` means the operator asked for cloud with config
    // that cannot serve it; createClientTransport() throws on exactly that state,
    // so persisting anywhere while it holds would quietly write the record to a
    // different datastore than the one that was requested.
    const resolution = resolveClientTransport(app, env);
    if (resolution.misconfigured) {
      reportStoreFailure(
        resolution.warning ?? `Client for '${app}' is misconfigured for cloud mode.`,
        "transport_misconfigured",
      );
      return;
    }

    if (backend !== "database") {
      try {
        if (await persistKeyRecordOverHttp(app, minted, createdBy, env, deps.transportOverrides, resolution)) {
          stored = true;
          storeBackend = "api";
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        reportStoreFailure(`Could not persist key record through API: ${message}`, "store_failed");
        return;
      }
      if (!stored && backend === "api") {
        reportStoreFailure(
          `--store-backend api needs the cloud transport. Set HASNA_${appEnvToken}_API_URL + HASNA_${appEnvToken}_API_KEY, or use --store-backend database.`,
          "api_transport_unavailable",
        );
        return;
      }
    }

    if (!stored) {
      const connectionString = env[dbEnvName];
      if (!connectionString) {
        reportStoreFailure(
          `No database URL found. Set ${dbEnvName}, or pass --store-backend api with HASNA_${appEnvToken}_API_URL + HASNA_${appEnvToken}_API_KEY, or pass --no-store to skip persistence.`,
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
        storeBackend = "database";
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
  }

  if (json) {
    console.log(JSON.stringify({ ok: true, ...keyMaterial, stored, storeBackend }, null, 2));
    return;
  }

  printKeyBlock(stored ? `stored (${storeBackend === "api" ? "api" : table})` : "not stored (--no-store)", null);
}
