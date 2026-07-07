// HTTP storage client for the Hasna Service Contract v1.
//
// This is the piece that makes `mode=self_hosted` real for a client. It sits on
// top of `createHasnaHttpTransport` and implements the generic resource CRUD
// vocabulary every Hasna serve app exposes under `/v1`:
//
//   list   -> GET    /v1/<resource>            -> { items, total, ... }
//   get    -> GET    /v1/<resource>/<id>       -> <entity> | null (404 => null)
//   create -> POST   /v1/<resource>            -> <entity>   (auto Idempotency-Key)
//   update -> PATCH  /v1/<resource>/<id>       -> <entity>   (PUT via method opt)
//   delete -> DELETE /v1/<resource>/<id>       -> void       (204/404 => ok)
//
// An app's storage resolver selects this client when the client-flip contract
// resolves to `cloud-http` (mode=cloud/self_hosted AND API_URL+API_KEY set), and
// falls through to the local store otherwise. See `resolveClientTransport` /
// `createClientTransport` in ./transport.ts.
//
// Guarantees carried up from the transport: JSON in/out, per-request timeout,
// retries with exponential backoff + jitter for transient failures, and
// idempotency (create() attaches an `Idempotency-Key` so a retried POST cannot
// duplicate). Non-2xx responses surface as `HasnaHttpError` (status + body).
//
// SAFETY: never logs, returns, or embeds the API key. The key lives only inside
// the transport it wraps.

import type { Env } from "../mode.js";
import {
  createClientTransport,
  HasnaHttpError,
  type HasnaHttpTransport,
  type HasnaRequestOptions,
  type QueryParams,
} from "./transport.js";

/** Options for a list() call: filters/pagination as query params. */
export interface StorageListOptions extends Pick<HasnaRequestOptions, "timeoutMs" | "headers" | "retry" | "signal"> {
  /** Query params (limit, offset, cursor, filters, ...). */
  query?: QueryParams;
}

/** Options for a get() call. */
export type StorageGetOptions = Pick<HasnaRequestOptions, "timeoutMs" | "headers" | "retry" | "signal" | "query">;

/** Options for a create() call. */
export interface StorageCreateOptions extends Pick<HasnaRequestOptions, "timeoutMs" | "headers" | "retry" | "signal" | "query"> {
  /**
   * Idempotency key for the create. Defaults to a fresh UUID so a transparently
   * retried POST is deduped by the server instead of creating a duplicate. Pass
   * a stable value to make an app-level operation idempotent across calls.
   */
  idempotencyKey?: string;
}

/** Options for an update() call. */
export interface StorageUpdateOptions extends Pick<HasnaRequestOptions, "timeoutMs" | "headers" | "retry" | "signal" | "query"> {
  /** HTTP verb for the update. Default `PATCH` (partial); use `PUT` for replace. */
  method?: "PATCH" | "PUT";
  /** Idempotency key. PUT is idempotent by definition; set this to make PATCH retry-safe too. */
  idempotencyKey?: string;
}

/** Options for a delete() call. */
export type StorageDeleteOptions = Pick<HasnaRequestOptions, "timeoutMs" | "headers" | "retry" | "signal" | "query">;

/** Result of a list() call. `items` is the extracted array; `raw` is the full envelope. */
export interface StorageListResult<T> {
  items: T[];
  /** Total count when the server reports one (`total`/`count`), else null. */
  total: number | null;
  /** Opaque pagination cursor when the server reports one, else null. */
  cursor: string | null;
  /** The full parsed response body (envelope preserved). */
  raw: unknown;
}

/**
 * The app storage interface, HTTP edition. This is deliberately the same small
 * CRUD surface a local store exposes, so an app's resolver can return either a
 * local implementation or this one behind one interface.
 */
export interface HasnaStorageClient {
  /** App slug this client targets. */
  readonly name: string;
  /** `<origin>/v1` base URL. */
  readonly baseUrl: string;
  /** The underlying HTTP transport (escape hatch for non-CRUD routes). */
  readonly transport: HasnaHttpTransport;

  /** List a collection. Returns extracted `items` plus the raw envelope. */
  list<T = unknown>(resource: string, options?: StorageListOptions): Promise<StorageListResult<T>>;
  /** Fetch one entity by id. Returns `null` on 404. */
  get<T = unknown>(resource: string, id: string, options?: StorageGetOptions): Promise<T | null>;
  /** Create one entity. Retry-safe via an auto `Idempotency-Key`. */
  create<T = unknown>(resource: string, body: unknown, options?: StorageCreateOptions): Promise<T>;
  /** Update one entity by id (PATCH by default). */
  update<T = unknown>(resource: string, id: string, patch: unknown, options?: StorageUpdateOptions): Promise<T>;
  /** Delete one entity by id. Resolves for 2xx and 404 (already gone). */
  delete(resource: string, id: string, options?: StorageDeleteOptions): Promise<void>;
}

function resourcePath(resource: string): string {
  const trimmed = resource.replace(/^\/+|\/+$/g, "");
  if (!trimmed) throw new Error("resource must be a non-empty path segment");
  return `/${trimmed}`;
}

function entityPath(resource: string, id: string): string {
  if (id === undefined || id === null || `${id}`.length === 0) {
    throw new Error("id must be a non-empty string");
  }
  return `${resourcePath(resource)}/${encodeURIComponent(String(id))}`;
}

function newIdempotencyKey(): string {
  const g = globalThis as { crypto?: { randomUUID?: () => string } };
  if (g.crypto?.randomUUID) return g.crypto.randomUUID();
  // Fallback for runtimes without WebCrypto.
  return `idmp_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 12)}`;
}

function extractItems<T>(raw: unknown): T[] {
  if (Array.isArray(raw)) return raw as T[];
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    for (const key of ["items", "data", "results", "rows", "records"]) {
      if (Array.isArray(obj[key])) return obj[key] as T[];
    }
  }
  return [];
}

function extractTotal(raw: unknown): number | null {
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    for (const key of ["total", "count", "totalCount", "total_count"]) {
      if (typeof obj[key] === "number") return obj[key] as number;
    }
  }
  return null;
}

function extractCursor(raw: unknown): string | null {
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    for (const key of ["cursor", "nextCursor", "next_cursor", "next"]) {
      if (typeof obj[key] === "string") return obj[key] as string;
    }
  }
  return null;
}

/**
 * Wrap an HTTP transport with the resource CRUD storage interface. Use this when
 * you already have a transport (e.g. from `createClientTransport`).
 */
export function createHasnaStorageClient(name: string, transport: HasnaHttpTransport): HasnaStorageClient {
  return {
    name,
    baseUrl: transport.baseUrl,
    transport,

    async list<T = unknown>(resource: string, options: StorageListOptions = {}): Promise<StorageListResult<T>> {
      const raw = await transport.get<unknown>(resourcePath(resource), options);
      return {
        items: extractItems<T>(raw),
        total: extractTotal(raw),
        cursor: extractCursor(raw),
        raw,
      };
    },

    async get<T = unknown>(resource: string, id: string, options: StorageGetOptions = {}): Promise<T | null> {
      try {
        return await transport.get<T>(entityPath(resource, id), options);
      } catch (error) {
        if (error instanceof HasnaHttpError && error.status === 404) return null;
        throw error;
      }
    },

    async create<T = unknown>(resource: string, body: unknown, options: StorageCreateOptions = {}): Promise<T> {
      const { idempotencyKey, ...rest } = options;
      return transport.post<T>(resourcePath(resource), body, {
        ...rest,
        idempotencyKey: idempotencyKey ?? newIdempotencyKey(),
      });
    },

    async update<T = unknown>(resource: string, id: string, patch: unknown, options: StorageUpdateOptions = {}): Promise<T> {
      const { method = "PATCH", idempotencyKey, ...rest } = options;
      const call = method === "PUT" ? transport.put<T> : transport.patch<T>;
      return call(entityPath(resource, id), patch, { ...rest, ...(idempotencyKey ? { idempotencyKey } : {}) });
    },

    async delete(resource: string, id: string, options: StorageDeleteOptions = {}): Promise<void> {
      try {
        await transport.del(entityPath(resource, id), undefined, options);
      } catch (error) {
        // Deleting an already-absent entity is not an error (idempotent delete).
        if (error instanceof HasnaHttpError && error.status === 404) return;
        throw error;
      }
    },
  };
}

/** Result of {@link resolveStorageClient}. */
export type ResolveStorageClientResult =
  | { transport: "local"; client: null }
  | { transport: "cloud-http"; client: HasnaStorageClient };

/**
 * The one call an app's storage resolver makes. Reads the client-flip env for
 * `name`; when it resolves to `cloud-http` (mode=cloud/self_hosted + API_URL +
 * API_KEY), returns a ready {@link HasnaStorageClient}. Otherwise returns
 * `{ transport: 'local', client: null }` so the app uses its local store.
 * Throws if cloud was requested but is misconfigured (so callers never silently
 * read the wrong dataset).
 */
export function resolveStorageClient(
  name: string,
  env: Env = process.env,
  overrides?: Parameters<typeof createClientTransport>[2],
): ResolveStorageClientResult {
  const wired = createClientTransport(name, env, overrides);
  if (wired.transport === "cloud-http") {
    return { transport: "cloud-http", client: createHasnaStorageClient(name, wired.client) };
  }
  return { transport: "local", client: null };
}
