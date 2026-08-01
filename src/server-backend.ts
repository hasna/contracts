// Server data-backend resolution for the Hasna Service Contract v1.
//
// The server has exactly one technical switch: `sqlite | postgresql`.
// A configured `HASNA_<NAME>_DATABASE_URL` (or the short alias) selects
// PostgreSQL; otherwise the on-box SQLite file is authoritative. There is no
// deployment/storage mode and no client-side PostgreSQL path.

import { type ServerDataBackend } from "./schemas";
import { envToken, type Env } from "./env-token";

export { envToken };
export type { Env };

export interface ServerDataBackendEnvKeys {
  /** `HASNA_<NAME>_DATABASE_URL` then the optional `<NAME>_DATABASE_URL` alias. */
  databaseUrlKeys: string[];
}

/** Resolve the canonical environment keys for an app's server database. */
export function serverDataBackendEnvKeys(name: string): ServerDataBackendEnvKeys {
  const token = envToken(name);
  return {
    databaseUrlKeys: [`HASNA_${token}_DATABASE_URL`, `${token}_DATABASE_URL`],
  };
}

function legacyModeKeys(name: string): string[] {
  const token = envToken(name);
  return [
    `HASNA_${token}_STORAGE_MODE`,
    `HASNA_${token}_MODE`,
    `${token}_STORAGE_MODE`,
    `${token}_MODE`,
  ];
}

function firstEnv(env: Env, keys: readonly string[]): { key: string; value: string } | null {
  for (const key of keys) {
    const value = env[key]?.trim();
    if (value) return { key, value };
  }
  return null;
}

function firstDefinedEnvKey(env: Env, keys: readonly string[]): string | null {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(env, key) && env[key] !== undefined) return key;
  }
  return null;
}

/**
 * Fail closed when an old mode variable survives deployment.
 *
 * This is a bounded migration guard, not a compatibility mode: the old value
 * is never parsed or mapped. The message names the replacement configuration.
 */
export function assertNoLegacyStorageMode(name: string, env: Env = process.env): void {
  const legacyKey = firstDefinedEnvKey(env, legacyModeKeys(name));
  if (!legacyKey) return;
  const canonicalDatabaseUrl = serverDataBackendEnvKeys(name).databaseUrlKeys[0];
  throw new Error(
    `${legacyKey} was removed. Delete the storage-mode variable; ` +
      `set ${canonicalDatabaseUrl} to select the postgresql server backend, ` +
      `or leave it unset for sqlite.`,
  );
}

export interface ServerDataBackendResolution {
  backend: ServerDataBackend;
  /** Env key that selected PostgreSQL, or `"default"` for SQLite. */
  source: string;
  databaseUrlPresent: boolean;
  /** Env key the database URL came from, or `null`. */
  databaseUrlSource: string | null;
}

/**
 * Resolve the server backend from database configuration only.
 * Never returns or logs the database URL value.
 */
export function resolveServerDataBackend(
  name: string,
  env: Env = process.env,
): ServerDataBackendResolution {
  assertNoLegacyStorageMode(name, env);
  const { databaseUrlKeys } = serverDataBackendEnvKeys(name);
  const databaseUrl = firstEnv(env, databaseUrlKeys);
  if (!databaseUrl) {
    return {
      backend: "sqlite",
      source: "default",
      databaseUrlPresent: false,
      databaseUrlSource: null,
    };
  }
  return {
    backend: "postgresql",
    source: databaseUrl.key,
    databaseUrlPresent: true,
    databaseUrlSource: databaseUrl.key,
  };
}

/** Resolve the database URL without logging it. Returns `null` when unset. */
export function resolveDatabaseUrl(name: string, env: Env = process.env): string | null {
  assertNoLegacyStorageMode(name, env);
  const hit = firstEnv(env, serverDataBackendEnvKeys(name).databaseUrlKeys);
  return hit?.value ?? null;
}
