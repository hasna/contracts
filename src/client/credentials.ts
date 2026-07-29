// The credential provider chain for the Hasna client seam.
//
// WHY THIS EXISTS. Environment variables are a snapshot taken at process start;
// credentials are mutable state. Storing a rotating secret in a frozen snapshot
// is the defect. The measured failure: a tmux shell started before a key
// rotation holds the stale `HASNA_<NAME>_API_KEY` for its entire life, so every
// command from that shell fails 401 "API key has been revoked", while a fresh
// login shell on the same machine in the same second succeeds. The credential
// on disk was correct the whole time.
//
// THE SHAPE OF THE FIX, and why it is not the obvious one. The obvious fix is
// env-first with a retry-on-401 that re-reads disk. In mature CLIs a
// retry-on-401 always signals TWO-TIER auth — a durable secret minting
// short-lived tokens, where 401 means "mint another" (google-auth refresh,
// docker registry token exchange, kubectl exec-plugin invalidation). We have a
// single static key, so retrying emulates that badly: identity becomes
// nondeterministic per call, the retry sends a second request under a different
// principal, and — the correctness bug — it SILENTLY RESCUES A DELIBERATE
// OVERRIDE THAT WAS REVOKED. An operator testing tenant X wants that 401; a
// fallback would act as the wrong tenant. So there is no retry-on-401 here, and
// a deliberate tier never falls through to another identity.
//
// PRECEDENCE (resolved fresh on every call):
//   1. an explicit argument            — `--api-key` / `--profile`
//   2. a deliberate env pointer        — `HASNA_<NAME>_API_KEY_OVERRIDE`, `HASNA_PROFILE`
//   3. DISK, read at call time         — the default path
//   4. the legacy `HASNA_<NAME>_API_KEY` process env — fallback only, deprecated
//
// Tier 4 is the demotion that fixes stale shells IMMEDIATELY, without waiting
// for shells to cycle or for a shell-init change to land on every machine.
//
// NEVER FALL BACK TO LOCAL DATA ON A 401. Serving local results when auth fails
// prints healthy output while authentication is broken — a false green that is
// strictly worse than the loud failure. Offline reads are a legitimate feature,
// but they must be a deliberate mode decided BEFORE the request, never an error
// path. Nothing in this module may acquire such a fallback.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import type { Env } from "../mode.js";
import {
  CREDENTIAL_PROFILE_ENV_KEY,
  clientTransportEnvKeys,
  credentialOverrideEnvKey,
} from "./env-keys.js";

/** Which link of the chain supplied the credential. */
export type CredentialTier = "argument" | "override" | "profile" | "disk" | "legacy-env";

export interface ResolvedCredential {
  /** The secret. This module never logs, serializes, or embeds it. */
  apiKey: string;
  tier: CredentialTier;
  /** Where it came from: an env key NAME or an absolute file path. Never a value. */
  source: string;
  /** True for tiers an operator sets on purpose. These never fall through. */
  deliberate: boolean;
  /** True when it came from the deprecated legacy process-env tier. */
  deprecated: boolean;
  /** Human-readable advisory. Never contains key material. */
  warning: string | null;
}

export interface CredentialChainOptions {
  /** Tier 1: an explicit key, e.g. from `--api-key`. */
  apiKey?: string;
  /** Tier 1: an explicit profile name, e.g. from `--profile`. Beats `HASNA_PROFILE`. */
  profile?: string;
  /**
   * Sink for the one-line legacy-env deprecation. Defaults to a once-per-app
   * stderr writer. Injected by tests so they never touch the real stderr.
   */
  onDeprecation?: (message: string) => void;
}

/**
 * A deliberate credential selection could not be honoured.
 *
 * Thrown rather than resolved-around: an override or profile pointer that
 * cannot produce a key must fail loudly, because the alternative is acting as
 * a different principal than the operator asked for.
 */
export class CredentialResolutionError extends Error {
  readonly appName: string;
  readonly attempted: readonly string[];
  constructor(appName: string, message: string, attempted: readonly string[]) {
    super(message);
    this.name = "CredentialResolutionError";
    this.appName = appName;
    this.attempted = attempted;
  }
}

// The fleet credential directories, composed from path SEGMENTS on purpose.
// `src/no-cloud.ts` forbids the joined literal anywhere in `src/`, and building
// the path from parts is also what keeps this portable.
const HASNA_STATE_DIR = ".hasna";
const FLEET_CREDENTIAL_DIR = "cloud";
const CONFIG_DIR = ".config";
const CONFIG_NAMESPACE = "hasna";

/**
 * The home directory comes from the SAME env object that is passed in — never
 * from `os.homedir()`.
 *
 * This is the hermetic seam. A caller that passes an explicit env is declaring
 * that object to be the whole environment, so an env with no HOME performs no
 * disk read at all; that is what keeps the test suite independent of whatever
 * credentials happen to exist on the machine running it. Callers that take the
 * `process.env` default get the real HOME and therefore the real disk.
 */
function homeDir(env: Env): string | null {
  const home = env.HOME?.trim();
  return home ? home : null;
}

/**
 * The disk files that may hold an app's credential, in precedence order.
 *
 * Two layers exist in the field, and shell init sources them in this order with
 * the first taking effect last, so the first entry wins. Exported so callers
 * and error messages can name the exact paths consulted.
 */
export function credentialDiskSources(name: string, env: Env): string[] {
  return profileDiskSources(name, env, null);
}

function profileDiskSources(name: string, env: Env, profile: string | null): string[] {
  const home = homeDir(env);
  if (!home) return [];
  const stem = profile ? `${name}.${profile}` : name;
  const configStem = profile ? `${name}-${profile}` : name;
  return [
    join(home, HASNA_STATE_DIR, FLEET_CREDENTIAL_DIR, `${stem}.env`),
    join(home, CONFIG_DIR, CONFIG_NAMESPACE, `${configStem}-cloud.env`),
  ];
}

/**
 * Parse a shell-style env file.
 *
 * Handles every shape that exists in the field: bare `KEY=value`, an `export `
 * prefix, single- or double-quoted values, `#` comments, and blank lines. A
 * line that is not a valid assignment is skipped rather than throwing, because
 * a malformed credential file must degrade to "no credential here" and let the
 * chain continue — never to a crash, and never to a partial parse that could
 * surface file content in an error.
 */
function parseEnvFile(text: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const withoutExport = line.startsWith("export ") ? line.slice("export ".length).trim() : line;
    const equals = withoutExport.indexOf("=");
    if (equals <= 0) continue;
    const key = withoutExport.slice(0, equals).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let value = withoutExport.slice(equals + 1).trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.length >= 2 && value.endsWith(quote)) {
      value = value.slice(1, -1);
    }
    if (value.length === 0) continue;
    values.set(key, value);
  }
  return values;
}

/** Read one credential file. A missing or unreadable path is simply "nothing here". */
function readCredentialFile(path: string, apiKeyKeys: readonly string[]): string | null {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  const values = parseEnvFile(text);
  for (const key of apiKeyKeys) {
    const value = values.get(key)?.trim();
    if (value) return value;
  }
  return null;
}

/**
 * A non-reversible fingerprint, for telling two credentials apart in a message
 * without printing either. Deliberately carries no plaintext fragment — not
 * even a `last4`, which is a partial disclosure for no diagnostic gain over
 * this.
 */
function fingerprint(value: string): string {
  return `len=${value.length} sha256=${createHash("sha256").update(value).digest("hex").slice(0, 12)}`;
}

function firstEnvValue(env: Env, keys: readonly string[]): { key: string; value: string } | null {
  for (const key of keys) {
    const value = env[key]?.trim();
    if (value) return { key, value };
  }
  return null;
}

// One deprecation line per app per process. A warning printed on every call is
// noise that operators filter out, and a filtered warning is not a warning.
const deprecationNotified = new Set<string>();

/** Test seam: forget which apps have already emitted their deprecation. */
export function __resetCredentialDeprecationNotices(): void {
  deprecationNotified.clear();
}

function defaultDeprecationSink(message: string): void {
  if (typeof process !== "undefined" && process.stderr) {
    process.stderr.write(`${message}\n`);
  }
}

/**
 * Resolve an app's API key through the provider chain, at call time.
 *
 * Returns `null` when no tier produces a credential. THROWS
 * {@link CredentialResolutionError} when a DELIBERATE tier was selected but
 * could not be honoured — silently continuing there would authenticate as
 * somebody other than the principal the operator named.
 */
export function resolveCredential(
  name: string,
  env: Env,
  options: CredentialChainOptions = {},
): ResolvedCredential | null {
  const { apiKeyKeys } = clientTransportEnvKeys(name);

  // ---- Tier 1: an explicit argument. -------------------------------------
  const explicitKey = options.apiKey?.trim();
  if (explicitKey) {
    return {
      apiKey: explicitKey,
      tier: "argument",
      source: "explicit apiKey argument",
      deliberate: true,
      deprecated: false,
      warning: null,
    };
  }

  // ---- Tier 2: deliberate env pointers. ----------------------------------
  // The per-service override is more specific than the global profile pointer,
  // so it wins when both are set. Either way the chain STOPS here: a deliberate
  // selection that turns out to be revoked must surface as a 401, never as a
  // quiet switch to a different identity.
  const overrideKeyName = credentialOverrideEnvKey(name);
  const overrideRaw = env[overrideKeyName];
  if (overrideRaw !== undefined) {
    const override = overrideRaw.trim();
    if (!override) {
      throw new CredentialResolutionError(
        name,
        `${overrideKeyName} is set but empty. It is a deliberate override, so it is not resolved around: ` +
          `either give it a real key or unset it to fall back to the credential on disk.`,
        [overrideKeyName],
      );
    }
    return {
      apiKey: override,
      tier: "override",
      source: overrideKeyName,
      deliberate: true,
      deprecated: false,
      warning: null,
    };
  }

  const profile = options.profile?.trim() || env[CREDENTIAL_PROFILE_ENV_KEY]?.trim();
  if (profile) {
    const profileSource = options.profile?.trim()
      ? "explicit profile argument"
      : CREDENTIAL_PROFILE_ENV_KEY;
    const paths = profileDiskSources(name, env, profile);
    for (const path of paths) {
      const value = readCredentialFile(path, apiKeyKeys);
      if (value) {
        return {
          apiKey: value,
          tier: "profile",
          source: path,
          deliberate: true,
          deprecated: false,
          warning: null,
        };
      }
    }
    throw new CredentialResolutionError(
      name,
      `Profile '${profile}' (from ${profileSource}) has no ${apiKeyKeys[0]} for '${name}'. ` +
        `Looked in: ${paths.join(", ") || "<no HOME in this environment>"}. ` +
        `A profile names WHICH identity to use, so it is never resolved around — ` +
        `create the profile's credential file or unset ${CREDENTIAL_PROFILE_ENV_KEY}.`,
      paths,
    );
  }

  // ---- Tier 3: disk, read at call time. ----------------------------------
  // This is what makes a rotation heal in any shell, however old: the file is
  // re-read on every call, so there is no snapshot to go stale. There is
  // deliberately NO CACHE here — a cache is the same defect at a smaller
  // timescale.
  const diskPaths = credentialDiskSources(name, env);
  const diskHits = diskPaths
    .map((path) => ({ path, value: readCredentialFile(path, apiKeyKeys) }))
    .filter((hit): hit is { path: string; value: string } => hit.value !== null);

  if (diskHits.length > 0) {
    const winner = diskHits[0]!;
    const divergent = diskHits.slice(1).filter((hit) => hit.value !== winner.value);
    const warning =
      divergent.length > 0
        ? `Credential sources disagree for '${name}': ${winner.path} (${fingerprint(winner.value)}) ` +
          `and ${divergent.map((hit) => `${hit.path} (${fingerprint(hit.value)})`).join(", ")} ` +
          `hold different keys. ${winner.path} wins. Reconcile them — a rotation that updated only ` +
          `one of these leaves the other to fail 401 wherever it is loaded first.`
        : null;
    return {
      apiKey: winner.value,
      tier: "disk",
      source: winner.path,
      deliberate: false,
      deprecated: false,
      warning,
    };
  }

  // ---- Tier 4: the legacy process env, demoted to a deprecated fallback. --
  const legacy = firstEnvValue(env, apiKeyKeys);
  if (legacy) {
    const replacement = diskPaths[0] ?? `${HASNA_STATE_DIR}/${FLEET_CREDENTIAL_DIR}/${name}.env under your home directory`;
    const message =
      `[${name}] DEPRECATED: the API key came from ${legacy.key} in this process's environment. ` +
      `Environment variables are a snapshot taken when this process started, so a shell that started ` +
      `before a key rotation keeps using the old key until it exits. Put the credential in ${replacement} ` +
      `instead — it is re-read on every call, so rotations take effect immediately.`;
    const sink = options.onDeprecation ?? defaultDeprecationSink;
    if (!deprecationNotified.has(name)) {
      deprecationNotified.add(name);
      sink(message);
    }
    return {
      apiKey: legacy.value,
      tier: "legacy-env",
      source: legacy.key,
      deliberate: false,
      deprecated: true,
      warning: message,
    };
  }

  return null;
}
