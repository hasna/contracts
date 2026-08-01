// Client-side transport resolver for the Hasna Service Contract v1.
//
// An OSS client has exactly two connections: its on-box SQLite file or the
// server's HTTP API. It never opens PostgreSQL directly. An explicit API URL
// plus a resolved credential selects HTTP; otherwise the client stays local.
// Server backend configuration never participates in this decision.
//
// SAFETY: this module never returns, logs, or embeds an API-key value. Callers
// receive only presence flags and source names.

import { envToken, type Env } from "../env-token.js";
import { isIP } from "node:net";
import { clientTransportEnvKeys } from "./env-keys.js";
import {
  CALLER_SUPPLIED_CREDENTIAL_PROVIDER_SOURCE,
  explicitCredential,
  resolveCredential,
  validateAndSealResolvedCredential,
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
  explicitCredential,
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

function firstDefinedEnvKey(env: Env, keys: readonly string[]): string | null {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(env, key) && env[key] !== undefined) return key;
  }
  return null;
}

function assertNoLegacyClientMode(name: string, env: Env): void {
  const token = envToken(name);
  const legacyKey = firstDefinedEnvKey(env, [
    `HASNA_${token}_STORAGE_MODE`,
    `HASNA_${token}_MODE`,
    `${token}_STORAGE_MODE`,
    `${token}_MODE`,
  ]);
  if (!legacyKey) return;
  const apiUrlKey = clientTransportEnvKeys(name).apiUrlKeys[0];
  throw new Error(
    `${legacyKey} was removed. Delete the mode variable; ` +
      `set ${apiUrlKey} with an API credential to select HTTP, ` +
      `or leave it unset for local SQLite.`,
  );
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

export const CLIENT_TRANSPORTS = ["sqlite", "http"] as const;
export type ClientTransportKind = (typeof CLIENT_TRANSPORTS)[number];

export interface ClientTransportResolution {
  /** Where the client should read/write from. */
  transport: ClientTransportKind;
  /** API URL key that selected HTTP, or `"default"` for local SQLite. */
  transportSource: string;
  /** `<origin>/v1` base for the server API when transport is http, else null. */
  baseUrl: string | null;
  /** Env key the API URL/domain came from, `"default"` (neutral placeholder), or null. */
  apiUrlSource: string | null;
  /** Whether an API key is present (value never exposed). */
  apiKeyPresent: boolean;
  /**
   * WHERE the API key came from: an env key NAME or an absolute file path.
   * Never the value.
   *
   * On local SQLite this reports only whether the legacy env key is set, since
   * a client reading its own file resolves no credential at all. On HTTP it
   * names the tier of the provider chain that supplied the key.
   */
  apiKeySource: string | null;
  /**
   * Which tier of the credential chain supplied the key, or null on the
   * local SQLite / when no credential resolved. See {@link CredentialTier}.
   */
  apiKeyTier: CredentialTier | null;
  /**
   * True when an API URL requests HTTP but the connection is incomplete.
   * Callers SHOULD treat this as an error rather than reading stale local data.
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
 * An explicit API URL requests HTTP. The credential resolves at CALL TIME
 * through {@link resolveCredential}: argument, deliberate override/profile,
 * disk, then the deprecated legacy env variable. Without an API URL, the
 * client stays on local SQLite and never consults credential files.
 */
export function resolveClientTransport(
  name: string,
  env: Env = process.env,
  options: ResolveClientTransportOptions = {},
): ClientTransportResolution {
  assertNoLegacyClientMode(name, env);
  const keys = clientTransportEnvKeys(name);
  const urlHit = firstEnv(env, keys.apiUrlKeys, { preserveRaw: true });
  const keyHit = firstEnv(env, keys.apiKeyKeys);
  const warnings: string[] = [];

  // No URL means local SQLite. Do not resolve the credential chain here: a
  // client authenticating to nothing must not read or emit credential state.
  if (!urlHit) {
    return {
      transport: "sqlite",
      transportSource: "default",
      baseUrl: null,
      apiUrlSource: null,
      apiKeyPresent: Boolean(keyHit),
      apiKeySource: keyHit ? keyHit.key : null,
      apiKeyTier: null,
      misconfigured: false,
      warning: null,
    };
  }

  // An API URL explicitly selects HTTP. Resolve the credential at call time.
  // A deliberate tier that cannot be honoured still throws rather than
  // authenticating as a different principal.
  const credential: ResolvedCredential | null = resolveCredential(name, env, options.credentials);

  if (!credential) {
    const diskHint = credentialDiskSourcesForMessage(name, env);
    warnings.push(
      `${urlHit.key} selects the HTTP server for '${name}', but no API key could be resolved; ` +
        `refusing to route and leaving the local sqlite store selected. ` +
        `Looked for a credential file at ${diskHint}, then for ${keys.apiKeyKeys[0]} in the environment.`,
    );
    return {
      transport: "sqlite",
      transportSource: urlHit.key,
      baseUrl: null,
      apiUrlSource: urlHit.key,
      apiKeyPresent: false,
      apiKeySource: null,
      apiKeyTier: null,
      misconfigured: true,
      warning: warnings.join(" "),
    };
  }
  if (credential.warning) warnings.push(credential.warning);

  const apiUrlSource = urlHit.key;
  let baseUrl: string;
  try {
    baseUrl = toV1BaseUrl(urlHit.value);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    warnings.push(`Invalid API URL from ${apiUrlSource}: ${message}. Using local store.`);
    return {
      transport: "sqlite",
      transportSource: urlHit.key,
      baseUrl: null,
      apiUrlSource: urlHit.key,
      apiKeyPresent: true,
      apiKeySource: credential.source,
      apiKeyTier: credential.tier,
      misconfigured: true,
      warning: warnings.join(" "),
    };
  }

  return {
    transport: "http",
    transportSource: urlHit.key,
    baseUrl,
    apiUrlSource,
    apiKeyPresent: true,
    apiKeySource: credential.source,
    apiKeyTier: credential.tier,
    misconfigured: false,
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

function currentCredential(name: string, apiKey: string | CredentialProvider): ResolvedCredential {
  if (typeof apiKey === "function") {
    return validateAndSealResolvedCredential(name, apiKey());
  }
  // A bare string goes through the SAME constructor as a resolved one. Building
  // it as an object literal here is what let a key with a CR in it reach `fetch`,
  // whose TypeError quotes the whole header value and so leaks the plaintext key.
  return explicitCredential(name, apiKey);
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
    const remedy =
      credential.source === CALLER_SUPPLIED_CREDENTIAL_PROVIDER_SOURCE
        ? `Fix that provider so it returns the current key, or replace it with resolveCredential() ` +
          `so diagnostics can name the original source.`
        : `Rotate that key, or unset the override to use the credential on disk.`;
    return (
      `${origin} — a credential you selected deliberately. It was NOT substituted with any other key: ` +
      `falling back here would authenticate as a different principal than the one you named, which is ` +
      `exactly the failure an override exists to prevent. ${remedy}`
    );
  }
  if (credential.deprecated) {
    // Reaching the legacy tier PROVES the disk had no credential — tier 3 runs
    // first. So the advice must be "write the key to disk", never "unset this
    // variable": unsetting it with nothing on disk leaves the client with no
    // credential at all, which drops it back to its local store and prints
    // healthy output from the wrong dataset.
    const target = credential.diskCandidates[0];
    const remedy = target
      ? `Write the CURRENT key to ${target} — that file is re-read on every call, so rotations take ` +
        `effect immediately and in every shell. Do not simply unset ${credential.source}: nothing was ` +
        `found on disk, so that would leave this client with no credential at all.`
      : `This environment has no HOME, so no credential file could be consulted; the disk tier is ` +
        `unavailable here and there is nothing to fall back to. Set HOME, or supply the key explicitly.`;
    return (
      `${origin}, a variable in this process's environment — which is a snapshot taken when the process ` +
      `started. A STALE SHELL is the most common cause of this error: this shell exported the key before ` +
      `it was rotated, and will keep sending the old one until it exits. ${remedy}`
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
    const credential = currentCredential(options.name, options.apiKey);

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
 * Convenience: resolve transport from env and, when http, build the HTTP
 * client in one call. Returns `{ transport: 'sqlite', resolution }` for the
 * local file, or `{ transport: 'http', client, resolution }` for server data.
 * Throws if the config is `misconfigured` (server data requested but unusable)
 * so callers can't drift onto local data by accident.
 */
export function createClientTransport(
  name: string,
  env: Env = process.env,
  overrides?: Partial<Pick<HasnaHttpTransportOptions, "fetchImpl" | "headers" | "timeoutMs" | "retry" | "sleepImpl">> & {
    /** Tier-1 credential inputs, e.g. from `--api-key` / `--profile` flags. */
    credentials?: CredentialChainOptions;
  },
):
  | { transport: "sqlite"; client: null; resolution: ClientTransportResolution }
  | { transport: "http"; client: HasnaHttpTransport; resolution: ClientTransportResolution } {
  const credentialOptions = overrides?.credentials;
  const resolution = resolveClientTransport(name, env, { ...(credentialOptions ? { credentials: credentialOptions } : {}) });
  if (resolution.misconfigured) {
    throw new Error(resolution.warning ?? `Client for '${name}' is misconfigured for the API client.`);
  }
  if (resolution.transport === "sqlite" || !resolution.baseUrl) {
    return { transport: "sqlite", client: null, resolution };
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
        `Client for '${name}' resolved to the http transport but no API key is available any more. ` +
          `Looked at ${credentialDiskSourcesForMessage(name, env)}, then the environment. ` +
          `A credential file that was removed after this client was built is the usual cause.`,
      );
    }
    return resolved;
  };
  return {
    transport: "http",
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
