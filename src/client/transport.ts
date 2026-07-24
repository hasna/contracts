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

import { normalizeStorageMode, envToken, type Env } from "../mode.js";
import type { StorageMode } from "../schemas.js";
import { isIP } from "node:net";

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

export interface ClientTransportEnvKeys {
  /** Mode keys, in precedence order. */
  modeKeys: string[];
  /** API base-URL keys, in precedence order. */
  apiUrlKeys: string[];
  /** API-key keys, in precedence order. */
  apiKeyKeys: string[];
}

/** Resolve the canonical client-flip env-key spec for an app. */
export function clientTransportEnvKeys(name: string): ClientTransportEnvKeys {
  const envSegment = envToken(name);
  return {
    modeKeys: [
      `HASNA_${envSegment}_STORAGE_MODE`,
      `HASNA_${envSegment}_MODE`,
      `${envSegment}_STORAGE_MODE`,
      `${envSegment}_MODE`,
    ],
    apiUrlKeys: [`HASNA_${envSegment}_API_URL`, `${envSegment}_API_URL`],
    apiKeyKeys: [`HASNA_${envSegment}_API_KEY`, `${envSegment}_API_KEY`],
  };
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
  /** Env key the API key came from, or null. */
  apiKeySource: string | null;
  /**
   * True when the operator asked for cloud but the config is incomplete. Missing
   * keys fall back to local; missing or malformed default-domain config resolves
   * to a neutral placeholder. Callers SHOULD treat either result as an error.
   */
  misconfigured: boolean;
  /** Human-readable warning, or null. Never contains secret values. */
  warning: string | null;
}

/**
 * Resolve how a client should reach an app's data given the environment.
 *
 * Precedence for the mode: the first present of `HASNA_<NAME>_STORAGE_MODE`,
 * `HASNA_<NAME>_MODE`, `<NAME>_STORAGE_MODE`, `<NAME>_MODE`, else `local`.
 */
export function resolveClientTransport(name: string, env: Env = process.env): ClientTransportResolution {
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
      misconfigured: false,
      warning: warnings.length > 0 ? warnings.join(" ") : null,
    };
  }

  // Cloud mode but no API key: fall back to local, but flag it loudly.
  if (!keyHit) {
    warnings.push(
      `${modeSource}=cloud but no API key is set (${keys.apiKeyKeys[0]}). Refusing to route to cloud; using local store. Set ${keys.apiKeyKeys[0]} to enable the cloud client.`,
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
      misconfigured: true,
      warning: warnings.join(" "),
    };
  }

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
      apiKeySource: keyHit.key,
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
    apiKeySource: keyHit.key,
    misconfigured: defaultBaseUrl?.misconfigured ?? false,
    warning: warnings.length > 0 ? warnings.join(" ") : null,
  };
}

/** Thrown when a cloud HTTP request returns a non-2xx status, including redirects. */
export class HasnaHttpError extends Error {
  readonly status: number;
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  constructor(method: string, path: string, status: number, body: unknown) {
    super(`Hasna cloud request failed: ${method} ${path} -> ${status}`);
    this.name = "HasnaHttpError";
    this.status = status;
    this.method = method;
    this.path = path;
    this.body = body;
  }
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
  /** The API key (secret). Sent as both `x-api-key` and `Authorization: Bearer`. */
  apiKey: string;
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
  ): Promise<{ ok: true; value: T } | { ok: false; retryable: boolean; error: Error }> {
    assertNoAuthorityOverrideHeaders(options.headers, "transport");
    assertNoAuthorityOverrideHeaders(opts.headers, "request");
    const headers: Record<string, string> = {
      "x-api-key": options.apiKey,
      Authorization: `Bearer ${options.apiKey}`,
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

    let last: { retryable: boolean; error: Error } | null = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const result = await once<T>(upper, rel, url, body, opts);
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
  overrides?: Partial<Pick<HasnaHttpTransportOptions, "fetchImpl" | "headers" | "timeoutMs" | "retry" | "sleepImpl">>,
):
  | { transport: "local"; client: null; resolution: ClientTransportResolution }
  | { transport: "cloud-http"; client: HasnaHttpTransport; resolution: ClientTransportResolution } {
  const resolution = resolveClientTransport(name, env);
  if (resolution.misconfigured) {
    throw new Error(resolution.warning ?? `Client for '${name}' is misconfigured for cloud mode.`);
  }
  if (resolution.transport === "local" || !resolution.baseUrl) {
    return { transport: "local", client: null, resolution };
  }
  const keys = clientTransportEnvKeys(name);
  const apiKey = firstEnv(env, keys.apiKeyKeys)?.value;
  if (!apiKey) {
    // Should be unreachable given resolution logic, but never build without a key.
    throw new Error(`Client for '${name}' resolved to cloud-http without an API key.`);
  }
  return {
    transport: "cloud-http",
    client: createHasnaHttpTransport({
      name,
      baseUrl: resolution.baseUrl,
      apiKey,
      ...(overrides?.fetchImpl ? { fetchImpl: overrides.fetchImpl } : {}),
      ...(overrides?.headers ? { headers: overrides.headers } : {}),
      ...(overrides?.timeoutMs ? { timeoutMs: overrides.timeoutMs } : {}),
      ...(overrides?.retry !== undefined ? { retry: overrides.retry } : {}),
      ...(overrides?.sleepImpl ? { sleepImpl: overrides.sleepImpl } : {}),
    }),
    resolution,
  };
}
