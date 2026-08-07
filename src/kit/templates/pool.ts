// Postgres pool factory for the vendored Hasna storage kit.
//
// The single sanctioned way for a SERVER to open its PostgreSQL connection.
// TLS is resolved through `tls.ts` (one correct approach), and env resolution
// runs through `backend.ts` (the contract). A Pool is only ever built for the
// `postgresql` backend; clients never open PostgreSQL directly (sqlite-or-http).

import pg from "pg";
import type { Pool, PoolConfig } from "pg";
import { resolveServerDataBackend, resolveDatabaseUrl } from "./backend.js";
import { resolveTlsConfig, type TlsResolveOptions } from "./tls.js";
import { createQueryClient, type PoolQueryClient } from "./query.js";
import { ownProp, ownString } from "./own.js";

type KitEnv = Record<string, string | undefined>;

/**
 * The TLS + tuning fields this factory forwards, read as OWN properties only.
 *
 * Guarding `tls.ts` alone does NOT close this path: the previous
 * `options.ca !== undefined ? { ca: options.ca } : {}` spread copied a
 * prototype-supplied value into an OWN property, which `resolveTlsConfig` would
 * then correctly accept as caller-supplied. The laundering has to stop here.
 */
interface OwnPoolOptions {
  ca?: string;
  caCertPath?: string;
  env?: KitEnv;
  max?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
  applicationName?: string;
}

function ownPoolOptions(options: unknown): OwnPoolOptions {
  // NULL PROTOTYPE, deliberately. Returning a plain object literal here would
  // re-open the hole this function closes: a guarded read stored in a literal
  // is UNGUARDED AGAIN on read-back, because `own.ca` walks the same polluted
  // chain. Measured while building this fix — the first version of this
  // function guarded every read and still handed the attacker's CA to
  // `resolveTlsConfig`.
  const own = Object.create(null) as OwnPoolOptions;
  const ca = ownString(options, "ca");
  if (ca !== undefined) own.ca = ca;
  const caCertPath = ownString(options, "caCertPath");
  if (caCertPath !== undefined) own.caCertPath = caCertPath;
  const env = ownProp<KitEnv>(options, "env");
  if (env !== undefined) own.env = env;
  const max = ownProp<number>(options, "max");
  if (max !== undefined) own.max = max;
  const idleTimeoutMillis = ownProp<number>(options, "idleTimeoutMillis");
  if (idleTimeoutMillis !== undefined) own.idleTimeoutMillis = idleTimeoutMillis;
  const connectionTimeoutMillis = ownProp<number>(options, "connectionTimeoutMillis");
  if (connectionTimeoutMillis !== undefined) own.connectionTimeoutMillis = connectionTimeoutMillis;
  const applicationName = ownString(options, "applicationName");
  if (applicationName !== undefined) own.applicationName = applicationName;
  return own;
}

export interface CreatePgPoolOptions extends TlsResolveOptions {
  connectionString: string;
  /** Max clients in the pool. Defaults to pg's default (10). */
  max?: number;
  /** Idle client timeout (ms). */
  idleTimeoutMillis?: number;
  /** Connection acquisition timeout (ms). */
  connectionTimeoutMillis?: number;
  /** Application name reported to Postgres (shows in pg_stat_activity). */
  applicationName?: string;
}

/** Build a `pg.Pool` with fleet-standard TLS handling. */
export function createPgPool(options: CreatePgPoolOptions): Pool {
  // `connectionString` is guarded too: a prototype-supplied one would silently
  // redirect the whole connection, so an inherited value is refused outright
  // rather than dialed.
  const connectionString = ownString(options, "connectionString");
  if (!connectionString || !connectionString.trim()) {
    throw new Error("createPgPool requires an own `connectionString` on the options object.");
  }

  const own = ownPoolOptions(options);
  const ssl = resolveTlsConfig(connectionString, {
    ...(own.ca !== undefined ? { ca: own.ca } : {}),
    ...(own.caCertPath !== undefined ? { caCertPath: own.caCertPath } : {}),
    ...(own.env !== undefined ? { env: own.env } : {}),
  });

  const config: PoolConfig = { connectionString };
  if (ssl !== undefined) config.ssl = ssl;
  if (own.max !== undefined) config.max = own.max;
  if (own.idleTimeoutMillis !== undefined) config.idleTimeoutMillis = own.idleTimeoutMillis;
  if (own.connectionTimeoutMillis !== undefined) config.connectionTimeoutMillis = own.connectionTimeoutMillis;
  if (own.applicationName !== undefined) config.application_name = own.applicationName;

  return new pg.Pool(config);
}

export interface CreateServerPoolFromEnvOptions extends TlsResolveOptions {
  max?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
  applicationName?: string;
}

export interface ServerPoolFromEnv {
  client: PoolQueryClient;
  connectionSource: string;
}

/**
 * Resolve backend + database URL from the environment and build the server's
 * PostgreSQL pool.
 *
 * Throws when no database URL selects the `postgresql` backend. Never logs the
 * URL.
 */
export function createServerPoolFromEnv(
  appName: string,
  options: CreateServerPoolFromEnvOptions = {},
): ServerPoolFromEnv {
  const own = ownPoolOptions(options);
  const env = own.env ?? process.env;
  const resolution = resolveServerDataBackend(appName, env);
  const connectionString = resolveDatabaseUrl(appName, env);
  if (!connectionString) {
    throw new Error(
      `postgresql storage for ${appName} needs a database URL. Set ` +
        `HASNA_${appName.toUpperCase().replace(/-/g, "_")}_DATABASE_URL.`,
    );
  }
  const pool = createPgPool({
    ...own,
    connectionString,
    env,
  });
  return {
    client: createQueryClient(pool),
    connectionSource: resolution.databaseUrlSource ?? "unknown",
  };
}
