// Reference storage-backend normalizer for the Hasna Service Contract v1.
//
// The runtime-placement axis was removed entirely (owner directive
// 2026-07-29): there are no placement "modes" and no aliases for them. The
// only switch a repo carries is its server's DATA BACKEND:
//   - `sqlite`   : SQLite at ~/.hasna/<name>/<name>.db is authoritative.
//   - `postgres` : reads AND writes go to a PostgreSQL server (DATABASE_URL).
// The long spelling `postgresql` normalizes to `postgres`. Every removed
// placement word is rejected with a migration hint, never silently mapped.
//
// The OSS CLIENT never opens PostgreSQL directly — it is sqlite-or-http; see
// `./client/transport.ts` for the client seam.

import { type StorageMode } from "./schemas";
import { envToken } from "./env-token";

// `STORAGE_MODES` and the `StorageMode` type are the canonical exports from
// `./schemas` (re-exported from the package root). Import them from there.

export type Env = Record<string, string | undefined>;

export interface StorageModeNormalization {
  mode: StorageMode;
}

/**
 * Normalize a raw storage-backend string to the `sqlite | postgres` enum.
 * `postgresql` is accepted as the long spelling of `postgres`. Everything
 * else — including every removed placement word — throws the same migration
 * hint; nothing is silently mapped.
 */
export function normalizeStorageMode(value: string): StorageModeNormalization {
  const normalized = value.trim().toLowerCase().replace(/-/g, "_");
  if (normalized === "sqlite") return { mode: "sqlite" };
  if (normalized === "postgres" || normalized === "postgresql") return { mode: "postgres" };
  throw new Error(
    `Unknown storage mode '${value}'. The runtime-placement axis was removed; ` +
      `set sqlite for the on-box SQLite file or postgres for a PostgreSQL server (DATABASE_URL).`
  );
}

// The derivation itself lives in a leaf module so `src/auth/*` can share it
// without importing this one (and, through it, the Zod schema bundle).
export { envToken };

export interface StorageEnvKeys {
  /** `HASNA_<NAME>_STORAGE_MODE` then the optional `<NAME>_STORAGE_MODE` alias. */
  modeKeys: string[];
  /** `HASNA_<NAME>_DATABASE_URL` then the optional `<NAME>_DATABASE_URL` alias. */
  databaseUrlKeys: string[];
}

/** Resolve the canonical env-key spec for an app's storage config. */
export function storageEnvKeys(name: string): StorageEnvKeys {
  const token = envToken(name);
  return {
    modeKeys: [`HASNA_${token}_STORAGE_MODE`, `${token}_STORAGE_MODE`],
    databaseUrlKeys: [`HASNA_${token}_DATABASE_URL`, `${token}_DATABASE_URL`]
  };
}

function firstEnv(env: Env, keys: readonly string[]): { key: string; value: string } | null {
  for (const key of keys) {
    const value = env[key]?.trim();
    if (value) return { key, value };
  }
  return null;
}

export interface StorageModeResolution {
  mode: StorageMode;
  /** Env key the backend came from, or `"default"`. */
  source: string;
  databaseUrlPresent: boolean;
  /** Env key the database URL came from, or `null`. */
  databaseUrlSource: string | null;
  warning: string | null;
}

/**
 * Resolve an app's storage backend from the environment per the contract env
 * spec. Precedence: `HASNA_<NAME>_STORAGE_MODE`, then `<NAME>_STORAGE_MODE`;
 * absent both, a present `DATABASE_URL` selects `postgres`, else `sqlite`.
 * Never reads secret values — only detects DATABASE_URL presence.
 */
export function resolveStorageMode(name: string, env: Env = process.env): StorageModeResolution {
  const { modeKeys, databaseUrlKeys } = storageEnvKeys(name);
  const dbHit = firstEnv(env, databaseUrlKeys);
  const databaseUrlPresent = Boolean(dbHit);
  const databaseUrlSource = dbHit ? dbHit.key : null;

  const modeHit = firstEnv(env, modeKeys);
  if (!modeHit) {
    return {
      mode: databaseUrlPresent ? "postgres" : "sqlite",
      source: databaseUrlPresent ? databaseUrlSource! : "default",
      databaseUrlPresent,
      databaseUrlSource,
      warning: null
    };
  }

  const { mode } = normalizeStorageMode(modeHit.value);
  const warnings: string[] = [];
  if (mode === "postgres" && !databaseUrlPresent) {
    warnings.push(`postgres storage needs ${databaseUrlKeys[0]} (reads and writes go to PostgreSQL).`);
  }
  if (modeHit.key !== modeKeys[0]) {
    warnings.push(`Using alias env ${modeHit.key}; the canonical key is ${modeKeys[0]}.`);
  }

  return {
    mode,
    source: modeHit.key,
    databaseUrlPresent,
    databaseUrlSource,
    warning: warnings.length > 0 ? warnings.join(" ") : null
  };
}
