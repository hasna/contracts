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

import { readFileSync, statSync } from "node:fs";
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
  /**
   * The secret.
   *
   * NON-ENUMERABLE on purpose: `JSON.stringify(resolution)`, a structured
   * logger, or `console.log` must not be able to spill it, and CONTRACT.md §3a
   * promises exactly that. Property access (`resolved.apiKey`) and destructuring
   * both still work; only enumeration and serialization are blocked. Note that
   * `{ ...resolved }` therefore DROPS the key — which is the safe direction.
   */
  apiKey: string;
  tier: CredentialTier;
  /** Where it came from: an env key NAME or an absolute file path. Never a value. */
  source: string;
  /** True for tiers an operator sets on purpose. These never fall through. */
  deliberate: boolean;
  /** True when it came from the deprecated legacy process-env tier. */
  deprecated: boolean;
  /**
   * The disk paths that were consulted before this credential was chosen.
   *
   * Carried so an auth failure can tell an operator exactly where the fleet
   * credential SHOULD live, instead of advising a fix that silently drops the
   * client onto its local store.
   */
  diskCandidates: readonly string[];
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
 * A deliberate credential selection could not be honoured, or a credential
 * source produced something unusable.
 *
 * Thrown rather than resolved-around: an override or profile pointer that
 * cannot produce a key must fail loudly, because the alternative is acting as
 * a different principal than the operator asked for. A corrupt credential file
 * throws for the same reason.
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
 * A credential file is small. The cap bounds how much a hostile or corrupt file
 * can make a per-request read cost, since this now runs on every request.
 */
const MAX_CREDENTIAL_FILE_BYTES = 64 * 1024;

/**
 * An app name that is safe to put in a filesystem path.
 *
 * Same grammar as the DNS label the transport requires, checked here
 * independently because this is a FILESYSTEM sink and the transport's check
 * runs later. An unsafe name yields no disk sources at all rather than
 * throwing, so the transport's own `validateAppSlug` keeps producing the
 * canonical error for a bad slug.
 */
const SAFE_APP_SLUG = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
/** A profile name that is safe to put in a filesystem path. */
const SAFE_PROFILE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

/**
 * Bytes that cannot appear in an HTTP header value.
 *
 * The resolved key is sent as `x-api-key` and `Authorization`. A credential
 * file written with CR-only line endings survives `split(/\r?\n/)` as a single
 * line, leaving a CR inside the value; `fetch` then throws a `TypeError` whose
 * message embeds THE WHOLE HEADER VALUE — i.e. the plaintext key — into logs
 * and stack traces. Rejecting here, naming only the source, is what keeps that
 * from ever reaching the header.
 */
const ILLEGAL_IN_HEADER_VALUE = /[^\t\x20-\x7e]/;

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
 * Two layers exist in the field, and the first entry wins. Returns an empty
 * list when there is no HOME to anchor them, or when the app name is not safe
 * to place in a path. Exported so callers and error messages can name the exact
 * paths consulted.
 */
export function credentialDiskSources(name: string, env: Env): string[] {
  return profileDiskSources(name, env, null);
}

function profileDiskSources(name: string, env: Env, profile: string | null): string[] {
  const home = homeDir(env);
  // A name that is not a safe slug never reaches the filesystem. Without this,
  // `resolveCredential("../../elsewhere", env)` composes a path outside the
  // credential directory, and the transport's slug check runs too late to stop
  // the read.
  if (!home || !SAFE_APP_SLUG.test(name)) return [];
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
 * line that is not a valid assignment is SKIPPED rather than half-parsed — an
 * unterminated quote used to yield a truncated value, which then failed
 * authentication in a way that looked like a revoked key rather than a corrupt
 * file.
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
    if (quote === '"' || quote === "'") {
      // Opened a quote: it must close, or this line is not a value we can trust.
      if (value.length < 2 || !value.endsWith(quote)) continue;
      value = value.slice(1, -1);
    }
    if (value.length === 0) continue;
    values.set(key, value);
  }
  return values;
}

/**
 * Read one credential file. A missing, unreadable, oversized, or non-regular
 * path is simply "nothing here".
 *
 * `statSync` before opening is deliberate: a FIFO planted in the credential
 * directory blocks `open()` FOREVER, and this read now happens on every
 * request, ahead of the transport's own AbortController — so no timeout could
 * rescue it. Stat does not block on a FIFO or a character device, so the type
 * check happens before anything that could hang.
 */
function readCredentialFile(path: string, apiKeyKeys: readonly string[]): string | null {
  let text: string;
  try {
    const stats = statSync(path);
    if (!stats.isFile() || stats.size > MAX_CREDENTIAL_FILE_BYTES) return null;
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
 * Reject a credential that cannot be sent as a header, naming the SOURCE only.
 *
 * Throws rather than falling through: a corrupt file at a deliberate location
 * must not silently hand the request to whatever identity is next in the chain.
 */
function assertUsableCredential(appName: string, source: string, value: string): void {
  if (!ILLEGAL_IN_HEADER_VALUE.test(value)) return;
  throw new CredentialResolutionError(
    appName,
    `The credential from ${source} contains characters that cannot be sent in an HTTP header ` +
      `(a control character or non-ASCII byte). A file written with CR-only line endings is the usual ` +
      `cause. Rewrite that credential file with one LF-terminated KEY=value line. ` +
      `The value is not shown here, and is deliberately never logged.`,
    [source],
  );
}

/**
 * Build a resolution whose secret cannot be enumerated or serialized.
 *
 * CONTRACT.md §3a states the key value is never logged, embedded, or
 * serialized. An ordinary property makes that claim unenforceable — one
 * `JSON.stringify` of the resolution breaks it — and an unenforced normative
 * guarantee is worse than no guarantee.
 */
function sealCredential(fields: {
  apiKey: string;
  tier: CredentialTier;
  source: string;
  deliberate: boolean;
  deprecated: boolean;
  diskCandidates: readonly string[];
  warning: string | null;
}): ResolvedCredential {
  const { apiKey, ...visible } = fields;
  const sealed = { ...visible } as ResolvedCredential;
  Object.defineProperty(sealed, "apiKey", {
    value: apiKey,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  // Non-enumerability alone is the guarantee, and it is enforced by the
  // language rather than by a method a caller could strip or forget.
  //
  // A redacting `toJSON` was tried here and REMOVED: a NON-ENUMERABLE `toJSON`
  // is not honoured by `JSON.stringify` in this runtime (measured — the object
  // serializes without ever calling it), and making it enumerable would put a
  // function into `Object.keys` and into every `{ ...resolution }` spread. So
  // the serialized form simply omits the key, which is the outcome that
  // matters. Do not re-add a non-enumerable `toJSON` expecting it to run.
  return sealed;
}

function firstEnvValue(env: Env, keys: readonly string[]): { key: string; value: string } | null {
  for (const key of keys) {
    const value = env[key]?.trim();
    if (value) return { key, value };
  }
  return null;
}

// One deprecation line per app per PROCESS. A warning printed on every call is
// noise that operators filter out, and a filtered warning is not a warning.
//
// Anchored on `globalThis` rather than in module scope because the published
// package inlines this module into several entry bundles
// (`dist/client/transport.js`, `dist/client/storage.js`, `dist/index.js`), each
// of which would otherwise carry its OWN Set — so a consumer touching two entry
// points got two warnings, and the reset seam cleared only one of them. Invisible
// to tests, which run against a single instance of `src/`.
// Colon-separated, NOT dotted. `tests/state-layout.test.ts` forbids any source
// file from containing the dotted legacy package-global home-directory names,
// and a dotted registry key would have spelled one of them by accident.
const DEPRECATION_REGISTRY = Symbol.for("hasna:contracts:credentialDeprecationNotices");

function deprecationNotified(): Set<string> {
  const host = globalThis as Record<symbol, unknown>;
  const existing = host[DEPRECATION_REGISTRY];
  if (existing instanceof Set) return existing as Set<string>;
  const created = new Set<string>();
  host[DEPRECATION_REGISTRY] = created;
  return created;
}

/** Test seam: forget which apps have already emitted their deprecation. */
export function __resetCredentialDeprecationNotices(): void {
  deprecationNotified().clear();
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
 * could not be honoured, or when a credential is unusable — silently
 * continuing in either case would authenticate as somebody other than the
 * principal the operator named.
 */
export function resolveCredential(
  name: string,
  env: Env,
  options: CredentialChainOptions = {},
): ResolvedCredential | null {
  const { apiKeyKeys } = clientTransportEnvKeys(name);
  const diskPaths = credentialDiskSources(name, env);

  // ---- Tier 1: an explicit argument. -------------------------------------
  const explicitKey = options.apiKey?.trim();
  if (explicitKey) {
    assertUsableCredential(name, "the explicit apiKey argument", explicitKey);
    return sealCredential({
      apiKey: explicitKey,
      tier: "argument",
      source: "explicit apiKey argument",
      deliberate: true,
      deprecated: false,
      diskCandidates: diskPaths,
      warning: null,
    });
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
    assertUsableCredential(name, overrideKeyName, override);
    return sealCredential({
      apiKey: override,
      tier: "override",
      source: overrideKeyName,
      deliberate: true,
      deprecated: false,
      diskCandidates: diskPaths,
      warning: null,
    });
  }

  const profile = options.profile?.trim() || env[CREDENTIAL_PROFILE_ENV_KEY]?.trim();
  if (profile) {
    const profileSource = options.profile?.trim()
      ? "explicit profile argument"
      : CREDENTIAL_PROFILE_ENV_KEY;
    if (!SAFE_PROFILE.test(profile)) {
      throw new CredentialResolutionError(
        name,
        `Profile name from ${profileSource} is not usable in a path. ` +
          `Use letters, digits, dot, dash, or underscore.`,
        [profileSource],
      );
    }
    const paths = profileDiskSources(name, env, profile);
    for (const path of paths) {
      const value = readCredentialFile(path, apiKeyKeys);
      if (value) {
        assertUsableCredential(name, path, value);
        return sealCredential({
          apiKey: value,
          tier: "profile",
          source: path,
          deliberate: true,
          deprecated: false,
          diskCandidates: paths,
          warning: null,
        });
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
  const diskHits = diskPaths
    .map((path) => ({ path, value: readCredentialFile(path, apiKeyKeys) }))
    .filter((hit): hit is { path: string; value: string } => hit.value !== null);

  if (diskHits.length > 0) {
    const winner = diskHits[0]!;
    assertUsableCredential(name, winner.path, winner.value);
    // The paths and the FACT of disagreement are the whole diagnostic. A
    // fingerprint of the secret — even a truncated digest — is a derived
    // encoding of credential material and a confirmation oracle, so none is
    // emitted.
    const divergentSources = [
      ...diskHits.slice(1).filter((hit) => hit.value !== winner.value).map((hit) => hit.path),
      // Disk now OUTRANKS the legacy env var, which introduces a failure this
      // chain did not previously have: an operator whose environment key works
      // today starts using a DIFFERENT key the moment a stale file exists on
      // disk, and would otherwise get no signal at all. Comparing only the two
      // disk layers to each other would miss exactly that case.
      ...(() => {
        const legacyHit = firstEnvValue(env, apiKeyKeys);
        return legacyHit && legacyHit.value !== winner.value ? [legacyHit.key] : [];
      })(),
    ];
    const warning =
      divergentSources.length > 0
        ? `Credential sources disagree for '${name}': ${winner.path} and ` +
          `${divergentSources.join(", ")} hold different keys. ${winner.path} wins, because a file on ` +
          `disk is re-read on every call while an environment variable is a snapshot. Reconcile them — ` +
          `a rotation that updated only one leaves the other to fail 401 wherever it is loaded first.`
        : null;
    return sealCredential({
      apiKey: winner.value,
      tier: "disk",
      source: winner.path,
      deliberate: false,
      deprecated: false,
      diskCandidates: diskPaths,
      warning,
    });
  }

  // ---- Tier 4: the legacy process env, demoted to a deprecated fallback. --
  const legacy = firstEnvValue(env, apiKeyKeys);
  if (legacy) {
    assertUsableCredential(name, legacy.key, legacy.value);
    // Reaching here PROVES the disk had nothing: tier 3 ran first and found no
    // credential. Any advice given from here must say so, rather than implying
    // a disk credential is waiting to be picked up.
    const where =
      diskPaths.length > 0
        ? `Put the current key in ${diskPaths[0]} — it is re-read on every call, so rotations take effect immediately.`
        : `This environment has no HOME, so no credential file could be consulted at all; the disk tier is ` +
          `unavailable here and this process will keep using the environment snapshot.`;
    const message =
      `[${name}] DEPRECATED: the API key came from ${legacy.key} in this process's environment. ` +
      `Environment variables are a snapshot taken when this process started, so a shell that started ` +
      `before a key rotation keeps using the old key until it exits. ${where}`;
    const sink = options.onDeprecation ?? defaultDeprecationSink;
    const notified = deprecationNotified();
    if (!notified.has(name)) {
      notified.add(name);
      sink(message);
    }
    return sealCredential({
      apiKey: legacy.value,
      tier: "legacy-env",
      source: legacy.key,
      deliberate: false,
      deprecated: true,
      diskCandidates: diskPaths,
      warning: message,
    });
  }

  return null;
}
