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
import type { ApiKeyStatus } from "./store.js";
import { isValidTenantId, ownTenantId, tenantIdsEqual } from "./tenant.js";

/**
 * Every reason a request can be refused, including the two the token verifier
 * cannot see: no credential was sent at all, and the credential is authentic
 * but names a key this service has no record of.
 */
export type AuthDenyReason = ApiKeyVerifyFailureReason | "missing_token" | "unknown_key";

/**
 * Resolve a key's lifecycle status. This is the strict, RECOMMENDED hook —
 * `ApiKeyStore.keyStatus` implements it — and it is strict precisely because it
 * can say `"unknown"`. Anything other than `"active"` denies.
 */
export type KeyStatusResolver = (kid: string) => ApiKeyStatus | Promise<ApiKeyStatus>;

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
  /**
   * Canonical tenant id, or `null` when the key is untenanted. Handlers that
   * scope data by organization read this instead of digging into `claims`.
   * `null` here means "no tenant claimed" — never "every tenant".
   */
  tid: string | null;
  claims: ApiKeyClaims;
}

export interface AuthAuditEvent {
  outcome: "allow" | "deny";
  app: string;
  kid: string | null;
  /**
   * Tenant the request authenticated as, or `null` when the key is untenanted
   * or the request never got far enough to establish one. Present so an audit
   * trail can answer "which organization did this" without re-parsing tokens.
   */
  tid: string | null;
  reason: AuthDenyReason | null;
  scopesRequired: string[];
  method: string | null;
  path: string | null;
  status: number;
  at: string;
}

export type AuthAuditHook = (event: AuthAuditEvent) => void | Promise<void>;

export type AuthDecision =
  | { ok: true; status: 200; principal: ApiKeyPrincipal }
  | { ok: false; status: 401 | 403; reason: AuthDenyReason; message: string };

export interface ApiKeyAuthContext {
  method?: string | null;
  path?: string | null;
  /** Concrete `app:action` scopes ALL of which must be granted for this call. */
  requiredScopes?: readonly string[];
  /**
   * Tenant this specific call must belong to — for routes that address an
   * organization directly (`/v1/orgs/:tid/...`). Denies with `tenant_mismatch`
   * when the token names a different tenant, and with `tenant_required` when it
   * names none. A malformed value denies rather than throwing, because it can
   * come from a request path.
   *
   * Only OMITTING the key means "no per-call expectation". Supplying one that
   * did not resolve — `null`, `""`, an Express multi-value array — is a denial,
   * never a fallback to the middleware-wide setting and never a wildcard.
   */
  expectedTid?: string;
}

export interface VerifyApiKeyOptions {
  /** App slug this service authenticates (tokens for other apps are rejected). */
  app: string;
  /** HMAC signing secret (server-held). Required — no insecure default. */
  signingSecret: string | Buffer;
  /**
   * Lifecycle lookup for the presented key — the RECOMMENDED hook. Wire
   * `store.keyStatus`. Anything other than `"active"` denies, including
   * `"unknown"`, so a token this service has no record of cannot authenticate.
   *
   * Prefer this over {@link isRevoked} in every service. A boolean predicate
   * cannot distinguish "known and fine" from "never heard of it", and that
   * ambiguity is the whole defect: it resolved to ALLOW.
   */
  keyStatus?: KeyStatusResolver;
  /**
   * Revocation check: return true to DENY.
   *
   * @deprecated Lossy. Returns `false` both for an active key and for a key
   * with no record at all, so it cannot refuse an unregistered kid. Supplying
   * it now requires {@link allowUnregisteredKeys}, which makes the residual
   * risk explicit and greppable. Use {@link keyStatus} instead.
   */
  isRevoked?: (kid: string) => boolean | Promise<boolean>;
  /**
   * Accept keys this service has no record of. **Unsafe, and deliberately
   * awkward to type.**
   *
   * Defaults to `false`: a verifier must be able to refuse an unregistered kid,
   * or say in its own source that it cannot. Set this only while a service is
   * still migrating to registered keys — a key with no row cannot be revoked,
   * because revocation writes `revoked_at` to a row that does not exist.
   *
   * Combines with {@link keyStatus}: unknown kids are tolerated, revoked and
   * expired ones are still refused.
   */
  allowUnregisteredKeys?: boolean;
  /** Per-request audit hook. Fires on every allow and deny. */
  audit?: AuthAuditHook;
  /** Scopes required for every request this middleware guards. */
  requiredScopes?: readonly string[];
  /**
   * Reject untenanted keys for every request this middleware guards. Turn this
   * on in any service whose rows carry an organization reference — otherwise a
   * pre-`tid` key authenticates with no organization and the tenant check has
   * to be remembered in every handler.
   */
  requireTenant?: boolean;
  /**
   * Pin the whole middleware to one tenant. Implies {@link requireTenant}.
   * Validated eagerly: an invalid value throws at construction rather than
   * denying every request at runtime.
   */
  expectedTid?: string;
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
  if (options.expectedTid !== undefined && !isValidTenantId(options.expectedTid)) {
    throw new Error(`verifyApiKey received an invalid 'expectedTid': '${options.expectedTid}'.`);
  }

  // --- fail closed on the KEY-STATUS wiring, at construction, not per request ---
  //
  // This block exists because the previous default was ALLOW. A service that
  // passed `isRevoked: store.isRevoked` accepted any validly-signed token whose
  // kid had no `api_keys` row, and a service that passed no hook at all could
  // not revoke a single one of its keys. Neither said so anywhere; both read as
  // "auth is wired". So the check is a construction-time throw rather than a
  // runtime deny: it fails at boot, in CI, in front of whoever wired it, rather
  // than silently admitting traffic in production. A missing answer is not an
  // answer of "yes".
  const allowUnregistered = options.allowUnregisteredKeys === true;
  if (options.keyStatus && options.isRevoked) {
    throw new Error(
      "verifyApiKey received both 'keyStatus' and 'isRevoked'. Supply exactly one — " +
        "letting one silently win would hide which check is actually guarding the service. " +
        "Use 'keyStatus' (store.keyStatus); drop 'isRevoked'.",
    );
  }
  if (!options.keyStatus && !allowUnregistered) {
    throw new Error(
      options.isRevoked
        ? "verifyApiKey was given only 'isRevoked', which cannot refuse a key this service has " +
          "no record of: it returns false both for an active key and for one that was never " +
          "registered, so an unregistered key is irrevocable. Wire 'keyStatus: store.keyStatus' " +
          "(or 'isRevoked: store.statusChecker()'), or set 'allowUnregisteredKeys: true' to " +
          "accept that risk explicitly."
        : "verifyApiKey requires a key-status hook. Without one this service performs NO " +
          "revocation check and cannot turn any of its keys off. Wire " +
          "'keyStatus: store.keyStatus', or set 'allowUnregisteredKeys: true' to declare that " +
          "this service intentionally cannot revoke keys.",
    );
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

    // A per-call tenant NARROWS the middleware-wide one; it must never replace
    // it. `context.expectedTid` typically comes from a request path
    // (`/v1/orgs/:tid/...`), so letting it win outright would let any holder of
    // a valid token for this app defeat a service pinned to another tenant just
    // by addressing their own org in the URL. When both are set they must agree,
    // and disagreement is a denial — not a silent preference for either one.
    //
    // PRESENCE, not truthiness, decides whether the caller expressed an
    // expectation. A `??` here collapsed a NULLISH per-call value into "no
    // expectation at all", so an un-pinned service whose route computed
    // `req.params.tid ?? null` (or read a JSON body carrying `orgId: null`) sent
    // NO tenant to the verifier and let another organization's token straight
    // through the route it meant to guard. Absence is not a wildcard — and
    // neither is a value that failed to resolve. Anything the caller actually
    // supplied is forwarded as-is and denied downstream by `verifyApiKeyToken`,
    // which refuses every non-grammatical expectation including `null`; only a
    // genuinely absent key falls back to the middleware-wide pin.
    //
    // Read as an OWN property for the same reason `ownTenantId` exists: a plain
    // read on a caller-built options bag resolves through the prototype chain,
    // so one `Object.prototype.expectedTid` write would pin every un-pinned
    // route to a tenant nothing validated.
    const perCallTid = Object.hasOwn(context, "expectedTid") ? context.expectedTid : undefined;
    const expectedTid = perCallTid !== undefined ? perCallTid : options.expectedTid;
    if (
      perCallTid !== undefined &&
      options.expectedTid !== undefined &&
      !tenantIdsEqual(perCallTid, options.expectedTid)
    ) {
      await emit({ outcome: "deny", app: options.app, kid: null, tid: null, reason: "tenant_mismatch", scopesRequired: requiredScopes, method, path, status: 403, at });
      return {
        ok: false,
        status: 403,
        reason: "tenant_mismatch",
        message: "This route addresses a tenant other than the one this service is pinned to.",
      };
    }

    const token = extractToken(headers, headerName, scheme);
    if (!token) {
      const decision: AuthDecision = {
        ok: false,
        status: 401,
        reason: "missing_token",
        message: `Missing API key. Send it as '${headerName}: <key>' or 'Authorization: ${scheme} <key>'.`,
      };
      await emit({ outcome: "deny", app: options.app, kid: null, tid: null, reason: "missing_token", scopesRequired: requiredScopes, method, path, status: 401, at });
      return decision;
    }

    const verified = verifyApiKeyToken(token, {
      signingSecret: options.signingSecret,
      expectedApp: options.app,
      nowMs: clock(),
      ...(options.leewaySeconds !== undefined ? { leewaySeconds: options.leewaySeconds } : {}),
      ...(options.requireTenant !== undefined ? { requireTenant: options.requireTenant } : {}),
      ...(expectedTid !== undefined ? { expectedTid } : {}),
      requiredScopes,
    });

    if (!verified.ok) {
      // 403, not 401, for both tenant reasons: the credential is authentic and
      // unexpired, so telling the client to re-authenticate would be wrong. It
      // is simply not permitted for this organization — the same shape as
      // `insufficient_scope`.
      const status: 401 | 403 =
        verified.reason === "insufficient_scope" ||
        verified.reason === "tenant_mismatch" ||
        verified.reason === "tenant_required"
          ? 403
          : 401;
      // `kid`/`tid` are present only once the signature has verified, which is
      // exactly when a denial is worth attributing to a specific key. Their
      // ABSENCE is therefore meaningful, so `tid` is read as an own property
      // (see `ownTenantId`) — an audit line must never name an organization the
      // request never proved.
      await emit({ outcome: "deny", app: options.app, kid: verified.kid ?? null, tid: ownTenantId(verified) ?? null, reason: verified.reason, scopesRequired: requiredScopes, method, path, status, at });
      return { ok: false, status, reason: verified.reason, message: verified.message };
    }

    // The signature is authentic; now ask whether this specific key is still one
    // we honour. `keyStatus` reports WHICH way it failed, so an operator reading
    // the audit trail can tell a revoked key (we turned it off) from an unknown
    // one (someone is presenting a key we never issued — the interesting case).
    if (options.keyStatus) {
      const status = await options.keyStatus(verified.kid);
      if (status !== "active") {
        // "unknown" is tolerated ONLY under the explicit opt-out; revoked and
        // expired are refused regardless, since those are recorded decisions.
        if (!(status === "unknown" && allowUnregistered)) {
          const reason: AuthDenyReason = status === "unknown" ? "unknown_key" : status;
          const message =
            status === "unknown"
              ? "API key is not registered with this service."
              : status === "expired"
                ? "API key has expired."
                : "API key has been revoked.";
          await emit({ outcome: "deny", app: options.app, kid: verified.kid, tid: verified.tid, reason, scopesRequired: requiredScopes, method, path, status: 401, at });
          return { ok: false, status: 401, reason, message };
        }
      }
    } else if (options.isRevoked) {
      const revoked = await options.isRevoked(verified.kid);
      if (revoked) {
        await emit({ outcome: "deny", app: options.app, kid: verified.kid, tid: verified.tid, reason: "revoked", scopesRequired: requiredScopes, method, path, status: 401, at });
        return { ok: false, status: 401, reason: "revoked", message: "API key has been revoked." };
      }
    }

    const principal: ApiKeyPrincipal = {
      kid: verified.kid,
      app: verified.app,
      scopes: verified.claims.scopes,
      agent: verified.claims.agent ?? null,
      tid: verified.tid,
      claims: verified.claims,
    };
    await emit({ outcome: "allow", app: options.app, kid: verified.kid, tid: verified.tid, reason: null, scopesRequired: requiredScopes, method, path, status: 200, at });
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
