// Server data-backend resolution for the vendored Hasna storage kit.
//
// A server has exactly one technical switch: `sqlite | postgresql`.
// A configured DATABASE_URL selects PostgreSQL; otherwise SQLite is
// authoritative. Old storage-mode variables are rejected with migration
// guidance and are never interpreted.

import { ownString } from "./own.js";

export const SERVER_DATA_BACKENDS = ["sqlite", "postgresql"] as const;
export type ServerDataBackend = (typeof SERVER_DATA_BACKENDS)[number];

export type Env = Record<string, string | undefined>;

/** Upper-snake env token for an app name, e.g. `todos` -> `TODOS`. */
export function envToken(name: string): string {
  return name.toUpperCase().replace(/-/g, "_");
}

export interface ServerDataBackendEnvKeys {
  databaseUrlKeys: string[];
}

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

// Both loops read the env as OWN properties. `env` is caller-supplied and
// `process.env` is itself prototype-pollutable, so an unguarded `env[key]` let a
// polluted `HASNA_<APP>_DATABASE_URL` flip the backend to postgresql and hand
// back a connection string the operator never configured.
function firstEnv(env: Env, keys: readonly string[]): { key: string; value: string } | null {
  for (const key of keys) {
    const value = ownString(env, key)?.trim();
    if (value) return { key, value };
  }
  return null;
}

function firstDefinedEnvKey(env: Env, keys: readonly string[]): string | null {
  for (const key of keys) {
    if (Object.hasOwn(env, key) && env[key] !== undefined) return key;
  }
  return null;
}

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
  source: string;
  databaseUrlPresent: boolean;
  databaseUrlSource: string | null;
}

export function resolveServerDataBackend(
  name: string,
  env: Env = process.env,
): ServerDataBackendResolution {
  assertNoLegacyStorageMode(name, env);
  const databaseUrl = firstEnv(env, serverDataBackendEnvKeys(name).databaseUrlKeys);
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
