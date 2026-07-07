// Client-side transport resolver for the Hasna Service Contract v1.
//
// THIS IS THE B2 CORE FIX. Historically, setting a client to cloud/self_hosted
// mode was a NO-OP: the CLI/MCP still read the local SQLite/db.json store even
// though `HASNA_<APP>_STORAGE_MODE=cloud` and a DATABASE_URL were set. A DSN on
// the client does NOT switch the dataset a CLI reads.
//
// This module makes the client actually talk to the cloud. Given an app name and
// the environment it decides whether reads AND writes should be routed to the
// app's cloud HTTP API (`<API_URL>/v1`, default `https://<app>.hasna.xyz/v1`)
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
//     HASNA_<NAME>_API_URL = https://<app>.hasna.xyz
//     <NAME>_API_URL                                                  (alias)
//   API key (bearer / x-api-key):
//     HASNA_<NAME>_API_KEY = hasna_<app>_...
//     <NAME>_API_KEY                                                  (alias)
//
// DECISION: transport is `cloud-http` IFF the resolved mode is `cloud` AND an API
// key is present. The base URL defaults to `https://<app>.hasna.xyz` when a key is
// present but no URL is set. If mode is `cloud` but the API key is MISSING, we do
// NOT silently serve wrong local data — we return `local` with a loud `warning`
// and `misconfigured: true` so the caller can hard-fail instead of drifting.
//
// SAFETY: this module never returns, logs, or embeds the API key value. Callers
// receive only presence flags and env-key names.

import { normalizeStorageMode, envToken, type Env } from "../mode.js";
import type { StorageMode } from "../schemas.js";

/** Default cloud host template. `<app>` is the app slug. */
export function defaultCloudBaseUrl(name: string): string {
  return `https://${name}.hasna.xyz`;
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
  const token = envToken(name);
  return {
    modeKeys: [
      `HASNA_${token}_STORAGE_MODE`,
      `HASNA_${token}_MODE`,
      `${token}_STORAGE_MODE`,
      `${token}_MODE`,
    ],
    apiUrlKeys: [`HASNA_${token}_API_URL`, `${token}_API_URL`],
    apiKeyKeys: [`HASNA_${token}_API_KEY`, `${token}_API_KEY`],
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
  /** Env key the API URL came from, `"default"` (host template), or null. */
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

  const rawUrl = urlHit?.value ?? defaultCloudBaseUrl(name);
  const apiUrlSource = urlHit ? urlHit.key : "default";
  let baseUrl: string;
  try {
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
}

export interface HasnaHttpTransport {
  readonly baseUrl: string;
  request<T = unknown>(method: string, path: string, body?: unknown): Promise<T>;
  get<T = unknown>(path: string): Promise<T>;
  post<T = unknown>(path: string, body?: unknown): Promise<T>;
  put<T = unknown>(path: string, body?: unknown): Promise<T>;
  patch<T = unknown>(path: string, body?: unknown): Promise<T>;
  del<T = unknown>(path: string, body?: unknown): Promise<T>;
}

/**
 * Build an authenticated HTTP transport for an app's cloud `/v1` API. Sends the
 * API key on every request as BOTH `x-api-key` and `Authorization: Bearer`
 * (serve apps accept either), and returns parsed JSON. Never logs the key.
 */
export function createHasnaHttpTransport(options: HasnaHttpTransportOptions): HasnaHttpTransport {
  const fetchImpl: FetchLike = options.fetchImpl ?? ((input, init) => fetch(input, init));
  const base = options.baseUrl.replace(/\/+$/, "");
  const timeoutMs = options.timeoutMs ?? 30_000;

  async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const rel = path.startsWith("/") ? path : `/${path}`;
    const url = `${base}${rel}`;
    const headers: Record<string, string> = {
      "x-api-key": options.apiKey,
      Authorization: `Bearer ${options.apiKey}`,
      Accept: "application/json",
      ...(options.headers ?? {}),
    };
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    init.signal = controller.signal;
    let response: Response;
    try {
      response = await fetchImpl(url, init);
    } finally {
      clearTimeout(timer);
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
      throw new HasnaHttpError(method, rel, response.status, parsed);
    }
    return parsed as T;
  }

  return {
    baseUrl: base,
    request,
    get: (path) => request("GET", path),
    post: (path, body) => request("POST", path, body),
    put: (path, body) => request("PUT", path, body),
    patch: (path, body) => request("PATCH", path, body),
    del: (path, body) => request("DELETE", path, body),
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
  overrides?: Partial<Pick<HasnaHttpTransportOptions, "fetchImpl" | "headers" | "timeoutMs">>,
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
    }),
    resolution,
  };
}
