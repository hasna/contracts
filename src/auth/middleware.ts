// Express/Hono-agnostic API-key verification middleware for Hasna serve apps.
//
// The core `verifyApiKey()` returns a framework-free `authenticate()` function
// that takes a header source (a `Headers`, a plain object, or a getter) and
// returns an allow/deny decision with an HTTP status. Thin `expressApiKey()` /
// `honoApiKey()` adapters wrap it for the two supported servers. Every decision
// fires the optional audit hook — the per-request auth AUDIT trail.

import {
  verifyApiKeyToken,
  type ApiKeyClaims,
  type ApiKeyVerifyFailureReason,
} from "./keys.js";

/** Header sources the middleware can read tokens from. */
export type HeaderSource =
  | Headers
  | Record<string, string | string[] | undefined>
  | ((name: string) => string | null | undefined);

function readHeader(source: HeaderSource, name: string): string | null {
  const lower = name.toLowerCase();
  if (typeof source === "function") {
    return source(name) ?? source(lower) ?? null;
  }
  if (typeof Headers !== "undefined" && source instanceof Headers) {
    return source.get(name);
  }
  const record = source as Record<string, string | string[] | undefined>;
  const value = record[name] ?? record[lower] ?? record[name.toUpperCase()];
  if (Array.isArray(value)) return value[0] ?? null;
  return value ?? null;
}

/** Authenticated principal attached to a request on success. */
export interface ApiKeyPrincipal {
  kid: string;
  app: string;
  scopes: string[];
  agent: string | null;
  claims: ApiKeyClaims;
}

export interface AuthAuditEvent {
  outcome: "allow" | "deny";
  app: string;
  kid: string | null;
  reason: ApiKeyVerifyFailureReason | "missing_token" | null;
  scopesRequired: string[];
  method: string | null;
  path: string | null;
  status: number;
  at: string;
}

export type AuthAuditHook = (event: AuthAuditEvent) => void | Promise<void>;

export type AuthDecision =
  | { ok: true; status: 200; principal: ApiKeyPrincipal }
  | { ok: false; status: 401 | 403; reason: ApiKeyVerifyFailureReason | "missing_token"; message: string };

export interface ApiKeyAuthContext {
  method?: string | null;
  path?: string | null;
  /** Concrete `app:action` scopes ALL of which must be granted for this call. */
  requiredScopes?: readonly string[];
}

export interface VerifyApiKeyOptions {
  /** App slug this service authenticates (tokens for other apps are rejected). */
  app: string;
  /** HMAC signing secret (server-held). Required — no insecure default. */
  signingSecret: string | Buffer;
  /**
   * Revocation check: return true to DENY. Typically `store.isRevoked` (explicit
   * revocations) or `store.statusChecker()` (strict: unknown or revoked deny).
   */
  isRevoked?: (kid: string) => boolean | Promise<boolean>;
  /** Per-request audit hook. Fires on every allow and deny. */
  audit?: AuthAuditHook;
  /** Scopes required for every request this middleware guards. */
  requiredScopes?: readonly string[];
  /** Custom header for the raw key. Default `x-api-key`. */
  headerName?: string;
  /** Authorization scheme also accepted. Default `Bearer`. */
  scheme?: string;
  /** Clock-skew leeway (seconds) for iat/exp. Default 0. */
  leewaySeconds?: number;
  /** Epoch-ms clock override (tests). */
  nowMs?: () => number;
}

/** Extract the raw token from `x-api-key` or `Authorization: <scheme> <token>`. */
export function extractToken(source: HeaderSource, headerName = "x-api-key", scheme = "Bearer"): string | null {
  const direct = readHeader(source, headerName);
  if (direct && direct.trim().length > 0) return direct.trim();
  const authz = readHeader(source, "authorization");
  if (authz) {
    const prefix = `${scheme} `;
    if (authz.toLowerCase().startsWith(prefix.toLowerCase())) {
      const token = authz.slice(prefix.length).trim();
      if (token.length > 0) return token;
    }
  }
  return null;
}

export interface ApiKeyVerifier {
  /** Authenticate a request from its headers. Never throws on auth failure. */
  authenticate(headers: HeaderSource, context?: ApiKeyAuthContext): Promise<AuthDecision>;
  readonly app: string;
}

/**
 * Build the framework-agnostic verifier. This is the primary entry point the
 * serve services call; `expressApiKey`/`honoApiKey` are thin wrappers over it.
 */
export function verifyApiKey(options: VerifyApiKeyOptions): ApiKeyVerifier {
  if (!options.app) throw new Error("verifyApiKey requires an 'app' slug.");
  if (!options.signingSecret) {
    throw new Error("verifyApiKey requires a 'signingSecret'. Set it from HASNA_<APP>_API_SIGNING_KEY.");
  }
  const headerName = options.headerName ?? "x-api-key";
  const scheme = options.scheme ?? "Bearer";
  const clock = options.nowMs ?? (() => Date.now());

  async function emit(event: AuthAuditEvent): Promise<void> {
    if (!options.audit) return;
    try {
      await options.audit(event);
    } catch {
      // Auditing must never break the request path.
    }
  }

  async function authenticate(headers: HeaderSource, context: ApiKeyAuthContext = {}): Promise<AuthDecision> {
    const method = context.method ?? null;
    const path = context.path ?? null;
    const requiredScopes = [...(options.requiredScopes ?? []), ...(context.requiredScopes ?? [])];
    const at = new Date(clock()).toISOString();

    const token = extractToken(headers, headerName, scheme);
    if (!token) {
      const decision: AuthDecision = {
        ok: false,
        status: 401,
        reason: "missing_token",
        message: `Missing API key. Send it as '${headerName}: <key>' or 'Authorization: ${scheme} <key>'.`,
      };
      await emit({ outcome: "deny", app: options.app, kid: null, reason: "missing_token", scopesRequired: requiredScopes, method, path, status: 401, at });
      return decision;
    }

    const verified = verifyApiKeyToken(token, {
      signingSecret: options.signingSecret,
      expectedApp: options.app,
      nowMs: clock(),
      ...(options.leewaySeconds !== undefined ? { leewaySeconds: options.leewaySeconds } : {}),
      requiredScopes,
    });

    if (!verified.ok) {
      const status: 401 | 403 = verified.reason === "insufficient_scope" ? 403 : 401;
      await emit({ outcome: "deny", app: options.app, kid: null, reason: verified.reason, scopesRequired: requiredScopes, method, path, status, at });
      return { ok: false, status, reason: verified.reason, message: verified.message };
    }

    if (options.isRevoked) {
      const revoked = await options.isRevoked(verified.kid);
      if (revoked) {
        await emit({ outcome: "deny", app: options.app, kid: verified.kid, reason: "revoked", scopesRequired: requiredScopes, method, path, status: 401, at });
        return { ok: false, status: 401, reason: "revoked", message: "API key has been revoked." };
      }
    }

    const principal: ApiKeyPrincipal = {
      kid: verified.kid,
      app: verified.app,
      scopes: verified.claims.scopes,
      agent: verified.claims.agent ?? null,
      claims: verified.claims,
    };
    await emit({ outcome: "allow", app: options.app, kid: verified.kid, reason: null, scopesRequired: requiredScopes, method, path, status: 200, at });
    return { ok: true, status: 200, principal };
  }

  return { authenticate, app: options.app };
}

// --- Framework adapters (typed loosely to avoid runtime framework deps) ---

/**
 * Express middleware. On success sets `req.apiKey` (the principal) and calls
 * `next()`. On failure responds `{ error, reason }` with the right status.
 */
export function expressApiKey(options: VerifyApiKeyOptions) {
  const verifier = verifyApiKey(options);
  return async (req: any, res: any, next: any): Promise<void> => {
    const decision = await verifier.authenticate(req.headers, {
      method: req.method,
      path: req.originalUrl ?? req.url ?? req.path,
    });
    if (decision.ok) {
      req.apiKey = decision.principal;
      next();
      return;
    }
    res.status(decision.status).json({ error: decision.message, reason: decision.reason });
  };
}

/**
 * Hono middleware. On success sets `c.set("apiKey", principal)` and awaits
 * `next()`. On failure returns a JSON error with the right status.
 */
export function honoApiKey(options: VerifyApiKeyOptions) {
  const verifier = verifyApiKey(options);
  return async (c: any, next: any): Promise<unknown> => {
    const decision = await verifier.authenticate((name: string) => c.req.header(name), {
      method: c.req.method,
      path: c.req.path,
    });
    if (decision.ok) {
      c.set("apiKey", decision.principal);
      return next();
    }
    return c.json({ error: decision.message, reason: decision.reason }, decision.status);
  };
}
