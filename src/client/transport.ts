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
// presence is inferred as self_hosted intent. When a key is present but no
// explicit URL is set, the base URL falls back to `https://<app>.<domain>` where
// `<domain>` comes from `HASNA_FLEET_API_DOMAIN` (required for a real
// deployment) or else a neutral, non-resolving placeholder. This published
// package never bakes in a real internal hostname. If mode is `cloud` but the
// API key is MISSING, we do NOT silently serve wrong local data — we return
// `local` with a loud `warning` and `misconfigured: true` so the caller can
// hard-fail instead of drifting.
//
// SAFETY: this module never returns, logs, or embeds the API key value. Callers
// receive only presence flags and env-key names.

import { normalizeStorageMode, envToken, type Env } from "../mode.js";
import type { StorageMode } from "../schemas.js";

const FLEET_API_DOMAIN_ENV_KEY = "HASNA_FLEET_API_DOMAIN";
const NEUTRAL_FLEET_API_DOMAIN = "your-deployment.example";

/**
 * Fleet API domain suffix. This published package never ships a real internal
 * hostname: override with `HASNA_FLEET_API_DOMAIN` for a real deployment or set
 * an explicit `HASNA_<NAME>_API_URL` per app. Absent both, this falls back to a
 * neutral placeholder that intentionally does not resolve to any service.
 * Non-blank malformed values throw so callers fail closed.
 */
export function fleetApiDomain(env: Env = process.env as Env): string {
  const configured = env[FLEET_API_DOMAIN_ENV_KEY]?.trim();
  if (!configured) return NEUTRAL_FLEET_API_DOMAIN;

  const normalized = configured.toLowerCase();
  if (normalized.length > 253) {
    throw new Error(`${FLEET_API_DOMAIN_ENV_KEY} must be a valid DNS domain.`);
  }

  const labels = normalized.split(".");
  const valid = labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  );
  if (!valid) {
    throw new Error(`${FLEET_API_DOMAIN_ENV_KEY} must be a valid DNS domain.`);
  }

  return normalized;
}

/** Default cloud host template. `<app>` is the app slug. */
export function defaultCloudBaseUrl(name: string, env: Env = process.env as Env): string {
  return `https://${name}.${fleetApiDomain(env)}`;
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

function firstEnv(env: Env, keys: readonly string[]): { key: string; value: string } | null {
  for (const key of keys) {
    const value = env[key]?.trim();
    if (value) return { key, value };
  }
  return null;
}

/** Normalize a base URL to `<origin>/v1` (dropping any trailing slash or existing /v1). */
export function toV1BaseUrl(apiUrl: string): string {
  const url = new URL(apiUrl);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("API URL must use http or https.");
  }
  let path = url.pathname.replace(/\/+$/, "");
  if (path.endsWith("/v1")) path = path.slice(0, -"/v1".length);
  url.pathname = `${path}/v1`;
  url.search = "";
  url.hash = "";
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
   * True when the operator asked for cloud but the config is incomplete (no API
   * key), so we fell back to local. Callers SHOULD treat this as an error rather
   * than silently reading local data.
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
  const urlHit = firstEnv(env, keys.apiUrlKeys);
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

  const configuredFleetDomain = env[FLEET_API_DOMAIN_ENV_KEY]?.trim();
  const apiUrlSource = urlHit
    ? urlHit.key
    : configuredFleetDomain
      ? FLEET_API_DOMAIN_ENV_KEY
      : "default";
  let baseUrl: string;
  try {
    const rawUrl = urlHit?.value ?? defaultCloudBaseUrl(name, env);
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

  return {
    transport: "cloud-http",
    mode,
    deprecatedAlias,
    modeSource,
    baseUrl,
    apiUrlSource,
    apiKeyPresent: true,
    apiKeySource: keyHit.key,
    misconfigured: false,
    warning: warnings.length > 0 ? warnings.join(" ") : null,
  };
}

/** Thrown when a cloud HTTP request returns a non-2xx status. */
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
 *
 * Retry safety: idempotent methods (GET/HEAD/PUT/DELETE/OPTIONS) are always
 * retried on transient failure; POST/PATCH are retried ONLY when an
 * `Idempotency-Key` is supplied, so replays can't create duplicates.
 */
export function createHasnaHttpTransport(options: HasnaHttpTransportOptions): HasnaHttpTransport {
  const fetchImpl: FetchLike = options.fetchImpl ?? ((input, init) => fetch(input, init));
  const base = options.baseUrl.replace(/\/+$/, "");
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
    const headers: Record<string, string> = {
      "x-api-key": options.apiKey,
      Authorization: `Bearer ${options.apiKey}`,
      Accept: "application/json",
      ...(options.headers ?? {}),
      ...(opts.headers ?? {}),
    };
    if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;
    const init: RequestInit = { method, headers };
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
