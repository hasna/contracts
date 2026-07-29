// Client-side transport resolver for the Hasna Service Contract v1.
//
// THIS IS THE B2 CORE FIX. Historically, setting a client to cloud/self_hosted
// mode was a NO-OP: the CLI/MCP still read the local SQLite/db.json store even
// though `HASNA_<APP>_STORAGE_MODE=cloud` and a DATABASE_URL were set. A DSN on
// the client does NOT switch the dataset a CLI reads.
//
// This module makes the client actually talk to the cloud. Given an app name and
// the environment it decides whether reads AND writes should be routed to the
// app's cloud HTTP API (`<API_URL>/v1`, default
// `https://<app>.<HASNA_FLEET_API_DOMAIN>/v1`)
// with the API key, or fall through to the local store.
//
// THE CLIENT-FLIP CONTRACT (env vars). For app `<NAME>` = envToken(name):
//
//   Mode   (any one, first match wins; aliases self_hosted/remote/hybrid -> cloud):
//     HASNA_<NAME>_STORAGE_MODE = cloud | self_hosted | local | ...
//     HASNA_<NAME>_MODE         = cloud | self_hosted | local | ...   (alias)
//     <NAME>_STORAGE_MODE                                             (alias)
//     <NAME>_MODE                                                     (alias)
//   API base URL (optional; `/v1` is appended automatically):
//     HASNA_<NAME>_API_URL = https://<app>.your-deployment.example
//     <NAME>_API_URL                                                  (alias)
//   API key (bearer / x-api-key):
//     HASNA_<NAME>_API_KEY -> value from the app-owned vault
//     <NAME>_API_KEY                                                  (alias)
//
// DECISION: transport is `cloud-http` IFF the resolved mode is `cloud` AND an API
// key is present. The mode is `cloud` when either (a) an explicit mode env resolves
// to cloud, OR (b) no mode env is set but BOTH the API URL and API key are present —
// the fleet env-flip writes exactly those two vars (no STORAGE_MODE), so their joint
// presence is inferred as self_hosted intent. When a key is present but no explicit
// URL is set, the base URL falls back to `https://<app>.<domain>` where `<domain>`
// comes from `HASNA_FLEET_API_DOMAIN` (REQUIRED for a real deployment) or else a
// neutral, non-resolving placeholder — this published package never bakes in a real
// internal hostname. Missing, malformed, or app-prefix-incompatible fleet-domain
// configuration resolves to that app-specific placeholder with
// `misconfigured: true`; callers fail before constructing an authenticated
// client. If mode is `cloud` but the API key is MISSING, we do NOT silently serve
// wrong local data — we return `local` with a loud warning and `misconfigured:
// true` so the caller can hard-fail instead of drifting.
//
// SAFETY: this module never returns, logs, or embeds the API key value. Callers
// receive only presence flags and env-key names.

import { normalizeStorageMode, type Env } from "../mode.js";
import type { StorageMode } from "../schemas.js";
import { isIP } from "node:net";
import { clientTransportEnvKeys } from "./env-keys.js";
import {
  resolveCredential,
  type CredentialChainOptions,
  type CredentialTier,
  type ResolvedCredential,
} from "./credentials.js";

// The credential chain is part of this module's public surface: callers wire
// `--api-key` / `--profile` through it, and consumers migrating off a direct
// `process.env` read need its types.
import { credentialDiskSources } from "./credentials.js";

export {
  CredentialResolutionError,
  credentialDiskSources,
  resolveCredential,
  __resetCredentialDeprecationNotices,
} from "./credentials.js";
export type { CredentialChainOptions, CredentialTier, ResolvedCredential } from "./credentials.js";
export { clientTransportEnvKeys, credentialOverrideEnvKey, CREDENTIAL_PROFILE_ENV_KEY } from "./env-keys.js";
export type { ClientTransportEnvKeys } from "./env-keys.js";

const FLEET_API_DOMAIN_ENV_KEY = "HASNA_FLEET_API_DOMAIN";
const NEUTRAL_FLEET_API_DOMAIN = "your-deployment.example";
const ASCII_CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

interface FleetApiDomainResolution {
  domain: string;
  source: typeof FLEET_API_DOMAIN_ENV_KEY | "default";
  misconfigured: boolean;
  warning: string | null;
}

interface DefaultCloudBaseUrlResolution {
  baseUrl: string;
  source: FleetApiDomainResolution["source"];
  misconfigured: boolean;
  warning: string | null;
}

function isValidDnsDomain(value: string): boolean {
  if (
    value.length === 0 ||
    value.length > 253 ||
    ASCII_CONTROL_PATTERN.test(value) ||
    /[^\x00-\x7f]/.test(value)
  ) {
    return false;
  }
  return value
    .split(".")
    .every(
      (label) =>
        label.length <= 63 &&
        !label.startsWith("xn--") &&
        DNS_LABEL_PATTERN.test(label),
    );
}

function resolveFleetApiDomain(env: Env): FleetApiDomainResolution {
  const raw = env[FLEET_API_DOMAIN_ENV_KEY];
  if (raw === undefined) {
    return {
      domain: NEUTRAL_FLEET_API_DOMAIN,
      source: "default",
      misconfigured: true,
      warning: `${FLEET_API_DOMAIN_ENV_KEY} is not set; using the non-resolving ${NEUTRAL_FLEET_API_DOMAIN} fallback.`,
    };
  }

  const configured = raw.trim().toLowerCase();
  if (ASCII_CONTROL_PATTERN.test(raw) || !isValidDnsDomain(configured)) {
    return {
      domain: NEUTRAL_FLEET_API_DOMAIN,
      source: FLEET_API_DOMAIN_ENV_KEY,
      misconfigured: true,
      warning: `${FLEET_API_DOMAIN_ENV_KEY} is blank or invalid; using the non-resolving ${NEUTRAL_FLEET_API_DOMAIN} fallback.`,
    };
  }

  return {
    domain: configured,
    source: FLEET_API_DOMAIN_ENV_KEY,
    misconfigured: false,
    warning: null,
  };
}

function validateAppSlug(name: string): string {
  if (name.length > 63 || !DNS_LABEL_PATTERN.test(name)) {
    throw new Error("App name must be one lowercase DNS label.");
  }
  return name;
}

function composeCloudHostname(name: string, domain: string): string {
  const hostname = `${validateAppSlug(name)}.${domain}`;
  if (!isValidDnsDomain(hostname)) {
    throw new Error("Composed cloud hostname must be a valid DNS domain");
  }
  return hostname;
}

function resolveDefaultCloudBaseUrl(
  name: string,
  env: Env,
): DefaultCloudBaseUrlResolution {
  const appSlug = validateAppSlug(name);
  const fleetDomain = resolveFleetApiDomain(env);
  const configuredHostname = `${appSlug}.${fleetDomain.domain}`;
  if (isValidDnsDomain(configuredHostname)) {
    return {
      baseUrl: `https://${configuredHostname}`,
      source: fleetDomain.source,
      misconfigured: fleetDomain.misconfigured,
      warning: fleetDomain.warning,
    };
  }

  const fallbackHostname = composeCloudHostname(
    appSlug,
    NEUTRAL_FLEET_API_DOMAIN,
  );
  return {
    baseUrl: `https://${fallbackHostname}`,
    source: fleetDomain.source,
    misconfigured: true,
    warning: `${FLEET_API_DOMAIN_ENV_KEY} cannot form a valid composed cloud hostname for app '${appSlug}'; using the non-resolving ${NEUTRAL_FLEET_API_DOMAIN} fallback.`,
  };
}

/**
 * Fleet API domain suffix. This published package never ships a real internal
 * hostname: override with `HASNA_FLEET_API_DOMAIN` (REQUIRED in a real
 * deployment) or set an explicit `HASNA_<NAME>_API_URL` per app. Absent both,
 * this falls back to a neutral placeholder that intentionally does not
 * resolve to any service. Blank, malformed, and suffixes that cannot form a
 * valid total hostname with the app prefix use the same deterministic
 * placeholder; `resolveClientTransport()` marks that fallback misconfigured so
 * authenticated clients fail before making a request.
 */
export function fleetApiDomain(env: Env = process.env as Env): string {
  return resolveFleetApiDomain(env).domain;
}

/** Default cloud host template. `<app>` is the app slug. */
export function defaultCloudBaseUrl(name: string, env: Env = process.env as Env): string {
  return resolveDefaultCloudBaseUrl(name, env).baseUrl;
}

function firstEnv(
  env: Env,
  keys: readonly string[],
  options: { preserveRaw?: boolean } = {},
): { key: string; value: string } | null {
  for (const key of keys) {
    const raw = env[key];
    const value = raw?.trim();
    if (value) return { key, value: options.preserveRaw ? raw! : value };
  }
  return null;
}

function rawAuthority(value: string): string {
  const match = /^[a-z][a-z0-9+.-]*:\/\//i.exec(value);
  if (!match) throw new Error("API URL must be absolute.");
  const afterScheme = value.slice(match[0].length);
  const boundary = afterScheme.search(/[/?#]/);
  const authority = boundary === -1 ? afterScheme : afterScheme.slice(0, boundary);
  if (!authority) throw new Error("API URL must include a hostname.");
  return authority;
}

function assertCanonicalPort(port: string): void {
  if (!/^[0-9]+$/.test(port) || (port.length > 1 && port.startsWith("0"))) {
    throw new Error("API URL authority must contain a canonical port between 1 and 65535.");
  }
  const numericPort = Number(port);
  if (!Number.isSafeInteger(numericPort) || numericPort < 1 || numericPort > 65_535) {
    throw new Error("API URL authority must contain a canonical port between 1 and 65535.");
  }
}

function canonicalAuthorityHostname(authority: string): string {
  let rawHostname: string;
  if (authority.startsWith("[")) {
    const closingBracket = authority.indexOf("]");
    if (closingBracket === -1) {
      throw new Error("API URL authority must contain a canonical hostname.");
    }
    rawHostname = authority.slice(0, closingBracket + 1);
    const portSuffix = authority.slice(closingBracket + 1);
    if (portSuffix) {
      if (!portSuffix.startsWith(":")) {
        throw new Error("API URL authority must contain a canonical hostname and port.");
      }
      assertCanonicalPort(portSuffix.slice(1));
    }
    if (isIP(rawHostname.slice(1, -1)) !== 6) {
      throw new Error("API URL authority must contain a canonical IPv6 literal.");
    }
  } else {
    const firstColon = authority.indexOf(":");
    const lastColon = authority.lastIndexOf(":");
    if (firstColon !== lastColon) {
      throw new Error("IPv6 API URL authorities must use brackets.");
    }
    if (lastColon !== -1) {
      const port = authority.slice(lastColon + 1);
      assertCanonicalPort(port);
      rawHostname = authority.slice(0, lastColon);
    } else {
      rawHostname = authority;
    }
    const ipVersion = isIP(rawHostname);
    const numericAddressParts = rawHostname.split(".");
    const looksLikeNonCanonicalIpv4 =
      numericAddressParts.every((part) =>
        /^(?:0x[0-9a-f]+|[0-9]+)$/i.test(part)
      );
    if (
      (ipVersion !== 4 && looksLikeNonCanonicalIpv4) ||
      (ipVersion !== 4 && !isValidDnsDomain(rawHostname.toLowerCase()))
    ) {
      throw new Error("API URL authority must contain a canonical ASCII hostname.");
    }
  }
  return rawHostname.toLowerCase();
}

function isDeliberateLoopbackHttpAuthority(authority: string): boolean {
  return /^(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]+)?$/i.test(authority);
}

/**
 * Normalize an explicit API base URL to `<origin>/v1`.
 *
 * HTTPS may target any explicit ASCII hostname. HTTP is restricted to exact
 * loopback authorities for local development. Paths and ports are preserved;
 * query strings, fragments, credentials, controls, IDNs, and punycode are
 * rejected rather than silently normalized.
 */
export function toV1BaseUrl(apiUrl: string): string {
  if (ASCII_CONTROL_PATTERN.test(apiUrl)) {
    throw new Error("API URL must not contain ASCII control characters.");
  }
  const input = apiUrl.trim();
  const authority = rawAuthority(input);
  if (
    authority.includes("@") ||
    authority.includes("\\") ||
    authority.includes("%") ||
    /[^\x00-\x7f]/.test(authority)
  ) {
    throw new Error("API URL authority must be canonical ASCII without credentials.");
  }

  const canonicalHostname = canonicalAuthorityHostname(authority);
  const url = new URL(input);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("API URL must use http or https.");
  }
  if (url.username || url.password) {
    throw new Error("API URL must not include credentials.");
  }
  if (!url.hostname || url.hostname.endsWith(".")) {
    throw new Error("API URL must include a canonical hostname.");
  }
  if (url.hostname.toLowerCase() !== canonicalHostname) {
    throw new Error("API URL authority must not rely on parser hostname normalization.");
  }
  if (url.hostname.split(".").some((label) => label.toLowerCase().startsWith("xn--"))) {
    throw new Error("API URL must not use IDN or punycode hostnames.");
  }
  if (url.protocol === "http:" && !isDeliberateLoopbackHttpAuthority(authority)) {
    throw new Error("API URL may use http only for an exact loopback authority.");
  }
  if (url.search || url.hash) {
    throw new Error("API URL must not include a query string or fragment.");
  }
  let path = url.pathname.replace(/\/+$/, "");
  if (path.endsWith("/v1")) path = path.slice(0, -"/v1".length);
  url.pathname = `${path}/v1`;
  return url.toString().replace(/\/+$/, "");
}

export type ClientTransportKind = "local" | "cloud-http";

export interface ClientTransportResolution {
  /** Where the client should read/write from. */
  transport: ClientTransportKind;
  /** Resolved storage mode (`local` | `cloud`). */
  mode: StorageMode;
  /** Deprecated mode alias that was normalized (e.g. `self_hosted`), if any. */
  deprecatedAlias: string | null;
  /** Env key the mode was read from, or `"default"`. */
  modeSource: string;
  /** `<origin>/v1` base for the cloud API when transport is cloud-http, else null. */
  baseUrl: string | null;
  /** Env key the API URL/domain came from, `"default"` (neutral placeholder), or null. */
  apiUrlSource: string | null;
  /** Whether an API key is present (value never exposed). */
  apiKeyPresent: boolean;
  /**
   * WHERE the API key came from: an env key NAME or an absolute file path.
   * Never the value.
   *
   * In `local` mode this reports only whether the legacy env key is set, since
   * a local client resolves no credential at all. In `cloud` mode it names the
   * tier of the provider chain that actually supplied the key.
   */
  apiKeySource: string | null;
  /**
   * Which tier of the credential chain supplied the key, or null in local mode
   * / when no credential resolved. See {@link CredentialTier}.
   */
  apiKeyTier: CredentialTier | null;
  /**
   * True when the operator asked for cloud but the config is incomplete. Missing
   * keys fall back to local; missing or malformed default-domain config resolves
   * to a neutral placeholder. Callers SHOULD treat either result as an error.
   */
  misconfigured: boolean;
  /** Human-readable warning, or null. Never contains secret values. */
  warning: string | null;
}

export interface ResolveClientTransportOptions {
  /** Tier-1 credential inputs, e.g. from `--api-key` / `--profile` flags. */
  credentials?: CredentialChainOptions;
}

/**
 * Resolve how a client should reach an app's data given the environment.
 *
 * Precedence for the mode: the first present of `HASNA_<NAME>_STORAGE_MODE`,
 * `HASNA_<NAME>_MODE`, `<NAME>_STORAGE_MODE`, `<NAME>_MODE`, else `local`.
 *
 * MODE AND CREDENTIAL ARE RESOLVED SEPARATELY, and deliberately so. The mode
 * decision stays exactly as it was — env only — so that a credential file
 * sitting on disk can never flip a client that reads its local store today
 * into reading the network instead. Only once the mode is already `cloud` does
 * the credential provider chain run, and then it resolves at CALL TIME through
 * {@link resolveCredential}: argument, then a deliberate override/profile
 * pointer, then disk, then the deprecated legacy env var.
 */
export function resolveClientTransport(
  name: string,
  env: Env = process.env,
  options: ResolveClientTransportOptions = {},
): ClientTransportResolution {
  const keys = clientTransportEnvKeys(name);
  const modeHit = firstEnv(env, keys.modeKeys);
  const urlHit = firstEnv(env, keys.apiUrlKeys, { preserveRaw: true });
  const keyHit = firstEnv(env, keys.apiKeyKeys);

  let mode: StorageMode = "local";
  let deprecatedAlias: string | null = null;
  let modeSource = "default";
  const warnings: string[] = [];

  if (modeHit) {
    const normalized = normalizeStorageMode(modeHit.value);
    mode = normalized.mode;
    deprecatedAlias = normalized.deprecatedAlias;
    modeSource = modeHit.key;
    if (deprecatedAlias) {
      warnings.push(
        `Deprecated mode '${deprecatedAlias}' from ${modeHit.key} is treated as 'cloud'. Prefer ${keys.modeKeys[0]}=cloud.`,
      );
    }
  } else if (urlHit && keyHit) {
    // Flip signal: the fleet env-flip writes EXACTLY HASNA_<APP>_API_URL +
    // HASNA_<APP>_API_KEY per app and NO explicit STORAGE_MODE (see machines
    // FLEET-FLIP.md). Their joint presence IS the self_hosted intent, so infer
    // `cloud`. Revert removes both vars, so the client falls back to local. Without
    // this, a flipped client with only url+key silently kept reading its local store.
    mode = "cloud";
    modeSource = `${urlHit.key}+${keyHit.key}`;
  }

  // Local mode: never route to the network, regardless of URL/key presence.
  // The credential chain is NOT run here: a local client authenticates to
  // nothing, so resolving a secret would be pure side effect (including a
  // spurious deprecation warning for an env var this process never uses).
  if (mode === "local") {
    return {
      transport: "local",
      mode,
      deprecatedAlias,
      modeSource,
      baseUrl: null,
      apiUrlSource: null,
      apiKeyPresent: Boolean(keyHit),
      apiKeySource: keyHit ? keyHit.key : null,
      apiKeyTier: null,
      misconfigured: false,
      warning: warnings.length > 0 ? warnings.join(" ") : null,
    };
  }

  // Cloud mode: resolve the credential through the chain, at call time. A
  // CredentialResolutionError from a deliberate tier propagates on purpose —
  // an override or profile that cannot be honoured must fail loudly rather
  // than authenticate as a different principal.
  const credential = resolveCredential(name, env, options.credentials);

  // Cloud mode but no credential from any tier: fall back to local, loudly.
  if (!credential) {
    const diskHint = credentialDiskSourcesForMessage(name, env);
    warnings.push(
      `${modeSource}=cloud but no API key could be resolved for '${name}'. Refusing to route to cloud; using local store. ` +
        `Looked for a credential file at ${diskHint}, then for ${keys.apiKeyKeys[0]} in the environment.`,
    );
    return {
      transport: "local",
      mode,
      deprecatedAlias,
      modeSource,
      baseUrl: null,
      apiUrlSource: null,
      apiKeyPresent: false,
      apiKeySource: null,
      apiKeyTier: null,
      misconfigured: true,
      warning: warnings.join(" "),
    };
  }
  if (credential.warning) warnings.push(credential.warning);

  let defaultBaseUrl: DefaultCloudBaseUrlResolution | null = null;
  let apiUrlSource: string =
    urlHit?.key ??
    (env[FLEET_API_DOMAIN_ENV_KEY] === undefined
      ? "default"
      : FLEET_API_DOMAIN_ENV_KEY);
  let baseUrl: string;
  try {
    if (!urlHit) {
      defaultBaseUrl = resolveDefaultCloudBaseUrl(name, env);
      apiUrlSource = defaultBaseUrl.source;
    }
    const rawUrl = urlHit?.value ?? defaultBaseUrl!.baseUrl;
    baseUrl = toV1BaseUrl(rawUrl);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    warnings.push(`Invalid API URL from ${apiUrlSource}: ${message}. Using local store.`);
    return {
      transport: "local",
      mode,
      deprecatedAlias,
      modeSource,
      baseUrl: null,
      apiUrlSource: null,
      apiKeyPresent: true,
      apiKeySource: credential.source,
      apiKeyTier: credential.tier,
      misconfigured: true,
      warning: warnings.join(" "),
    };
  }

  if (defaultBaseUrl?.warning) warnings.push(defaultBaseUrl.warning);

  return {
    transport: "cloud-http",
    mode,
    deprecatedAlias,
    modeSource,
    baseUrl,
    apiUrlSource,
    apiKeyPresent: true,
    apiKeySource: credential.source,
    apiKeyTier: credential.tier,
    misconfigured: defaultBaseUrl?.misconfigured ?? false,
    warning: warnings.length > 0 ? warnings.join(" ") : null,
  };
}

/** Render the disk candidates for a diagnostic, without touching their contents. */
function credentialDiskSourcesForMessage(name: string, env: Env): string {
  const paths = credentialDiskSources(name, env);
  return paths.length > 0 ? paths.join(" or ") : "<no HOME set in this environment, so no credential file was consulted>";
}

/** Thrown when a cloud HTTP request returns a non-2xx status, including redirects. */
export class HasnaHttpError extends Error {
  readonly status: number;
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  /** WHICH source supplied the rejected key (an env key name or a file path). Never a value. */
  readonly credentialSource: string | null;
  /** Which tier of the provider chain supplied it. */
  readonly credentialTier: CredentialTier | null;
  constructor(
    method: string,
    path: string,
    status: number,
    body: unknown,
    credential?: { source: string; tier: CredentialTier; guidance: string } | null,
  ) {
    // The base message is byte-stable when there is no credential context, so
    // callers matching on it keep working; guidance is strictly additive.
    const guidance = credential ? `. ${credential.guidance}` : "";
    super(`Hasna cloud request failed: ${method} ${path} -> ${status}${guidance}`);
    this.name = "HasnaHttpError";
    this.status = status;
    this.method = method;
    this.path = path;
    this.body = body;
    this.credentialSource = credential?.source ?? null;
    this.credentialTier = credential?.tier ?? null;
  }
}

/**
 * A credential resolved fresh for one request.
 *
 * The transport takes a PROVIDER rather than a string so that a long-lived
 * process — an MCP server, a daemon — picks up a key rotation without being
 * rebuilt. Resolving once when the client is constructed would just move the
 * stale snapshot from process start to client construction.
 */
export type CredentialProvider = () => ResolvedCredential;

function currentCredential(apiKey: string | CredentialProvider): ResolvedCredential {
  if (typeof apiKey === "function") return apiKey();
  return {
    apiKey,
    tier: "argument",
    source: "explicit apiKey option",
    deliberate: true,
    deprecated: false,
    warning: null,
  };
}

/**
 * What a human should do about a 401/403, given where the key came from.
 *
 * The opaque "API key has been revoked" this replaces cost an engineer an hour:
 * it named neither the source nor the fix, and the most likely cause — a shell
 * older than the last rotation — is invisible from inside that shell.
 */
function authFailureGuidance(credential: ResolvedCredential): string {
  const origin = `The API key for this request came from ${credential.source}`;
  if (credential.deliberate) {
    return (
      `${origin} — a credential you selected deliberately. It was NOT substituted with any other key: ` +
      `falling back here would authenticate as a different principal than the one you named, which is ` +
      `exactly the failure an override exists to prevent. Rotate that key, or unset the override to use ` +
      `the credential on disk.`
    );
  }
  if (credential.deprecated) {
    return (
      `${origin}, a variable in this process's environment — which is a snapshot taken when the process ` +
      `started. A STALE SHELL is the most common cause of this error: this shell exported the key before ` +
      `it was rotated, and will keep sending the old one until it exits. The credential on disk is re-read ` +
      `on every call, so unsetting ${credential.source} in this shell (or starting a new shell) picks up ` +
      `the current key immediately.`
    );
  }
  return (
    `${origin}, which was re-read from disk on this very call — so a stale shell is NOT the cause here. ` +
    `The stored credential is genuinely being rejected: rotate it, or re-run the fleet key distribution ` +
    `so this machine gets the current key.`
  );
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Query params for a request. Nullish values are dropped; arrays repeat the key. */
export type QueryParams =
  | URLSearchParams
  | Record<string, string | number | boolean | null | undefined | ReadonlyArray<string | number | boolean>>;

/** Retry policy for transient failures (network errors, timeouts, 5xx, 429). */
export interface HasnaRetryOptions {
  /** Max RETRY attempts after the first try. Default 2 (=> up to 3 total tries). */
  retries?: number;
  /** Base backoff in ms for exponential backoff. Default 200. */
  baseDelayMs?: number;
  /** Backoff ceiling in ms. Default 2000. */
  maxDelayMs?: number;
  /** HTTP statuses that trigger a retry. Default 408, 425, 429, 500, 502, 503, 504. */
  retryStatuses?: number[];
}

/** Per-call request options: query, idempotency, timeout, retry, extra headers. */
export interface HasnaRequestOptions {
  /** Query string params appended to the URL. */
  query?: QueryParams;
  /**
   * Idempotency key sent as `Idempotency-Key`. When set, unsafe methods (POST)
   * become safe to retry: the server dedupes replays. Auto-generated for
   * `create()` in the storage client.
   */
  idempotencyKey?: string;
  /** Override the transport timeout for this call (ms). */
  timeoutMs?: number;
  /** Extra headers merged into this call (override transport headers). */
  headers?: Record<string, string>;
  /** Override or disable retry for this call. `false` disables retries. */
  retry?: HasnaRetryOptions | false;
  /** Caller abort signal, combined with the internal timeout. */
  signal?: AbortSignal;
}

const DEFAULT_RETRY_STATUSES = [408, 425, 429, 500, 502, 503, 504] as const;
/** Methods that are idempotent by definition and always safe to retry. */
const IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "PUT", "DELETE", "OPTIONS"]);
const AUTHORITY_OVERRIDE_HEADERS = new Set([
  "host",
  ":authority",
  "forwarded",
  "x-forwarded-host",
  "x-original-host"
]);

function assertNoAuthorityOverrideHeaders(
  headers: Record<string, string> | undefined,
  source: "transport" | "request"
): void {
  if (!headers) return;
  const forbidden = Object.keys(headers).find((name) =>
    AUTHORITY_OVERRIDE_HEADERS.has(name.trim().toLowerCase())
  );
  if (forbidden) {
    throw new Error(
      `Authenticated ${source} headers must not set authority header '${forbidden}'.`
    );
  }
}

export interface HasnaHttpTransportOptions {
  /** App slug (for error context / default host). */
  name: string;
  /** `<origin>/v1` base. Usually from `resolveClientTransport().baseUrl`. */
  baseUrl: string;
  /**
   * The API key (secret), or a provider that resolves one per request.
   *
   * Pass a provider (see {@link CredentialProvider}) so rotation heals inside a
   * long-lived process. A plain string is still accepted and is treated as a
   * deliberate, explicit credential.
   */
  apiKey: string | CredentialProvider;
  /** Override fetch (tests). Defaults to global fetch. */
  fetchImpl?: FetchLike;
  /** Extra headers merged into every request. */
  headers?: Record<string, string>;
  /** Per-request timeout in ms. Default 30000. */
  timeoutMs?: number;
  /** Default retry policy for all requests. Pass `false` to disable. */
  retry?: HasnaRetryOptions | false;
  /** Injectable sleep (tests). Defaults to a real timer. */
  sleepImpl?: (ms: number) => Promise<void>;
}

export interface HasnaHttpTransport {
  readonly baseUrl: string;
  request<T = unknown>(method: string, path: string, body?: unknown, opts?: HasnaRequestOptions): Promise<T>;
  get<T = unknown>(path: string, opts?: HasnaRequestOptions): Promise<T>;
  post<T = unknown>(path: string, body?: unknown, opts?: HasnaRequestOptions): Promise<T>;
  put<T = unknown>(path: string, body?: unknown, opts?: HasnaRequestOptions): Promise<T>;
  patch<T = unknown>(path: string, body?: unknown, opts?: HasnaRequestOptions): Promise<T>;
  del<T = unknown>(path: string, body?: unknown, opts?: HasnaRequestOptions): Promise<T>;
}

/** Append query params to a `/v1`-relative path (no-op when empty). */
export function appendQuery(path: string, query?: QueryParams): string {
  if (!query) return path;
  const params = query instanceof URLSearchParams ? query : new URLSearchParams();
  if (!(query instanceof URLSearchParams)) {
    for (const [key, value] of Object.entries(query)) {
      if (value === null || value === undefined) continue;
      if (Array.isArray(value)) {
        for (const v of value) params.append(key, String(v));
      } else {
        params.append(key, String(value));
      }
    }
  }
  const qs = params.toString();
  if (!qs) return path;
  return `${path}${path.includes("?") ? "&" : "?"}${qs}`;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Build an authenticated HTTP transport for an app's cloud `/v1` API. Sends the
 * API key on every request as BOTH `x-api-key` and `Authorization: Bearer`
 * (serve apps accept either), returns parsed JSON, times out, and retries
 * transient failures with exponential backoff + jitter. Never logs the key.
 * Redirects are never followed: every 3xx response fails closed at the validated
 * base origin so credentials and request bodies cannot cross an authority
 * boundary through runtime-specific redirect behavior.
 *
 * Retry safety: idempotent methods (GET/HEAD/PUT/DELETE/OPTIONS) are always
 * retried on transient failure; POST/PATCH are retried ONLY when an
 * `Idempotency-Key` is supplied, so replays can't create duplicates.
 */
export function createHasnaHttpTransport(options: HasnaHttpTransportOptions): HasnaHttpTransport {
  const fetchImpl: FetchLike = options.fetchImpl ?? ((input, init) => fetch(input, init));
  const base = toV1BaseUrl(options.baseUrl);
  const timeoutMs = options.timeoutMs ?? 30_000;
  const sleep = options.sleepImpl ?? defaultSleep;
  const defaultRetry = options.retry;

  function resolveRetry(callRetry: HasnaRequestOptions["retry"]): Required<HasnaRetryOptions> | null {
    const chosen = callRetry !== undefined ? callRetry : defaultRetry;
    if (chosen === false) return null;
    const r = chosen ?? {};
    return {
      retries: r.retries ?? 2,
      baseDelayMs: r.baseDelayMs ?? 200,
      maxDelayMs: r.maxDelayMs ?? 2_000,
      retryStatuses: r.retryStatuses ?? [...DEFAULT_RETRY_STATUSES],
    };
  }

  async function once<T>(
    method: string,
    rel: string,
    url: string,
    body: unknown,
    opts: HasnaRequestOptions,
    credential: ResolvedCredential,
  ): Promise<{ ok: true; value: T } | { ok: false; retryable: boolean; error: Error }> {
    assertNoAuthorityOverrideHeaders(options.headers, "transport");
    assertNoAuthorityOverrideHeaders(opts.headers, "request");
    const headers: Record<string, string> = {
      "x-api-key": credential.apiKey,
      Authorization: `Bearer ${credential.apiKey}`,
      Accept: "application/json",
      ...(options.headers ?? {}),
      ...(opts.headers ?? {}),
    };
    if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;
    const init: RequestInit = {
      method,
      headers,
      // Authentication is attached before fetch. Following here would let the
      // runtime decide which custom credentials or bodies cross the redirect
      // boundary, so every redirect is surfaced to the caller instead.
      redirect: "manual",
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    if (opts.signal) {
      if (opts.signal.aborted) controller.abort();
      else opts.signal.addEventListener("abort", onAbort, { once: true });
    }
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? timeoutMs);
    init.signal = controller.signal;
    let response: Response;
    try {
      response = await fetchImpl(url, init);
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      // A caller-initiated abort is a cancellation, not a transient failure —
      // propagate it immediately instead of retrying. Our own timeout abort and
      // ordinary network errors ARE transient and retryable.
      if (opts.signal?.aborted) return { ok: false, retryable: false, error: err };
      return { ok: false, retryable: true, error: err };
    } finally {
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", onAbort);
    }
    const text = await response.text();
    let parsed: unknown = undefined;
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }
    if (!response.ok) {
      // A caller-provided retry status list must not turn a redirect into
      // repeated authenticated requests. Redirects are terminal regardless of
      // retry policy.
      if (response.status >= 300 && response.status < 400) {
        return {
          ok: false,
          retryable: false,
          error: new HasnaHttpError(method, rel, response.status, parsed),
        };
      }
      // An authentication failure is TERMINAL, regardless of retry policy — the
      // same rule redirects already follow, and for the same reason: a caller's
      // retry list must not turn one failure into repeated authenticated
      // requests. A rejected key does not become valid by being sent again, so
      // retrying only multiplies failed-auth events in the server's audit log
      // and delays the actionable error. This is also the boundary that keeps
      // 401 handling from drifting back toward retry-on-401 — the pattern that
      // silently rescues a revoked deliberate override as the wrong principal.
      if (response.status === 401 || response.status === 403) {
        return {
          ok: false,
          retryable: false,
          error: new HasnaHttpError(method, rel, response.status, parsed, {
            source: credential.source,
            tier: credential.tier,
            guidance: authFailureGuidance(credential),
          }),
        };
      }
      const retry = resolveRetry(opts.retry);
      const retryable = retry ? retry.retryStatuses.includes(response.status) : false;
      return { ok: false, retryable, error: new HasnaHttpError(method, rel, response.status, parsed) };
    }
    return { ok: true, value: parsed as T };
  }

  async function request<T>(method: string, path: string, body?: unknown, opts: HasnaRequestOptions = {}): Promise<T> {
    const upper = method.toUpperCase();
    const rel = appendQuery(path.startsWith("/") ? path : `/${path}`, opts.query);
    const url = `${base}${rel}`;
    const retry = resolveRetry(opts.retry);
    const methodRetryable = IDEMPOTENT_METHODS.has(upper) || Boolean(opts.idempotencyKey);
    const maxAttempts = retry && methodRetryable ? retry.retries + 1 : 1;

    // ONE request, ONE identity. The credential is resolved fresh here — so a
    // rotation is picked up by the next request without rebuilding the client —
    // but it is resolved exactly once for the whole retry loop. Re-resolving per
    // attempt would let a rotation land mid-request and send two attempts of the
    // same logical call under two different principals, which is precisely the
    // audit-log confusion that makes retry-on-401 the wrong pattern here.
    const credential = currentCredential(options.apiKey);

    let last: { retryable: boolean; error: Error } | null = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const result = await once<T>(upper, rel, url, body, opts, credential);
      if (result.ok) return result.value;
      last = result;
      const canRetry = retry !== null && methodRetryable && result.retryable && attempt < maxAttempts;
      if (!canRetry) break;
      const backoff = Math.min(retry!.maxDelayMs, retry!.baseDelayMs * 2 ** (attempt - 1));
      const jitter = Math.floor(Math.random() * (backoff / 2 + 1));
      await sleep(backoff + jitter);
    }
    throw last!.error;
  }

  return {
    baseUrl: base,
    request,
    get: (path, opts) => request("GET", path, undefined, opts),
    post: (path, body, opts) => request("POST", path, body, opts),
    put: (path, body, opts) => request("PUT", path, body, opts),
    patch: (path, body, opts) => request("PATCH", path, body, opts),
    del: (path, body, opts) => request("DELETE", path, body, opts),
  };
}

/**
 * Convenience: resolve transport from env and, when cloud-http, build the HTTP
 * client in one call. Returns `{ transport: 'local', resolution }` for local, or
 * `{ transport: 'cloud-http', client, resolution }` for cloud. Throws if the
 * config is `misconfigured` (cloud requested but unusable) so callers can't drift
 * onto local data by accident.
 */
export function createClientTransport(
  name: string,
  env: Env = process.env,
  overrides?: Partial<Pick<HasnaHttpTransportOptions, "fetchImpl" | "headers" | "timeoutMs" | "retry" | "sleepImpl">> & {
    /** Tier-1 credential inputs, e.g. from `--api-key` / `--profile` flags. */
    credentials?: CredentialChainOptions;
  },
):
  | { transport: "local"; client: null; resolution: ClientTransportResolution }
  | { transport: "cloud-http"; client: HasnaHttpTransport; resolution: ClientTransportResolution } {
  const credentialOptions = overrides?.credentials;
  const resolution = resolveClientTransport(name, env, { ...(credentialOptions ? { credentials: credentialOptions } : {}) });
  if (resolution.misconfigured) {
    throw new Error(resolution.warning ?? `Client for '${name}' is misconfigured for cloud mode.`);
  }
  if (resolution.transport === "local" || !resolution.baseUrl) {
    return { transport: "local", client: null, resolution };
  }
  // The credential is NOT read here. It is resolved per request through the
  // same chain `resolveClientTransport` used, so this path cannot drift from
  // that one — an earlier version of this function re-read the key straight out
  // of `env`, which was a second, divergent resolution on the code path most
  // callers actually take.
  const credentialProvider: CredentialProvider = () => {
    const resolved = resolveCredential(name, env, credentialOptions);
    if (!resolved) {
      throw new Error(
        `Client for '${name}' resolved to cloud-http but no API key is available any more. ` +
          `Looked at ${credentialDiskSourcesForMessage(name, env)}, then the environment. ` +
          `A credential file that was removed after this client was built is the usual cause.`,
      );
    }
    return resolved;
  };
  return {
    transport: "cloud-http",
    client: createHasnaHttpTransport({
      name,
      baseUrl: resolution.baseUrl,
      apiKey: credentialProvider,
      ...(overrides?.fetchImpl ? { fetchImpl: overrides.fetchImpl } : {}),
      ...(overrides?.headers ? { headers: overrides.headers } : {}),
      ...(overrides?.timeoutMs ? { timeoutMs: overrides.timeoutMs } : {}),
      ...(overrides?.retry !== undefined ? { retry: overrides.retry } : {}),
      ...(overrides?.sleepImpl ? { sleepImpl: overrides.sleepImpl } : {}),
    }),
    resolution,
  };
}
