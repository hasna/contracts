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
export type AuthDenyReason =
  | ApiKeyVerifyFailureReason
  | "missing_token"
  | "unknown_key"
  /** The status lookup itself failed; the key was never judged. Deny, 503. */
  | "status_unavailable";

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
  /**
   * The key's issued-to agent/subject, so an audit trail can answer "WHO did
   * this" without a second lookup. Without it the only route from a log line to
   * an agent is `kid` in the log then `SELECT agent FROM api_keys WHERE kid`,
   * which needs database access at log-read time — exactly when you least have
   * it.
   *
   * Three-state, and the distinction is deliberate:
   *   `undefined` — never established, because the request was refused BEFORE
   *                 the signature verified. Nothing in an unverified token may
   *                 be believed, so no value is reported rather than a wrong one.
   *   `null`      — established, and the key carries no `agent` claim.
   *   a string    — the claim, which is authentic: `agent` lives inside the
   *                 signed body, so altering it invalidates the signature.
   *
   * Optional rather than required because services construct this object
   * themselves — `open-emails` and `open-mailery` each build an `AuthAuditEvent`
   * literal inside their own API-key verifier — and a required field would break
   * their type-check on upgrade.
   */
  agent?: string | null;
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
  | { ok: false; status: 401 | 403 | 503; reason: AuthDenyReason; message: string };

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
  /**
   * Authenticate a request from its headers. Never throws — every failure,
   * including an unavailable status lookup, comes back as a deny decision.
   */
  authenticate(headers: HeaderSource, context?: ApiKeyAuthContext): Promise<AuthDecision>;
  readonly app: string;
}

/**
 * Read `name` from a CALLER-SUPPLIED bag only when the caller actually set it.
 *
 * Every options object this module receives is built by a caller and therefore
 * has `Object.prototype` in its chain, so `bag.x`, `bag.x ?? d`, `!bag.x` and
 * `bag.x !== undefined` all resolve happily to a value some other code in this
 * process planted via a `__proto__`/`constructor.prototype` write. Absence is
 * the whole signal these options carry — "the caller did not pin a tenant",
 * "the caller set no clock" — and a prototype lookup converts absence into an
 * attacker-chosen answer.
 *
 * This is the same accessor `verifyApiKeyToken` and `mintApiKey` apply to their
 * own bags in `./keys.js`; it is duplicated rather than imported only because
 * that copy is module-private there. Folding the two into one shared helper is
 * a follow-up, deliberately not done here while a PR is open against that file.
 */
function ownOption<T extends object, K extends keyof T & string>(bag: T, name: K): T[K] | undefined {
  return Object.hasOwn(bag, name) ? bag[name] : undefined;
}

/**
 * Build the framework-agnostic verifier. This is the primary entry point the
 * serve services call; `expressApiKey`/`honoApiKey` are thin wrappers over it.
 */
export function verifyApiKey(options: VerifyApiKeyOptions): ApiKeyVerifier {
  // --- EVERY option read ONCE, HERE, as an OWN property ---
  //
  // Read the whole bag up front so nothing below this block ever touches
  // `options` again; past this point the closures see locals only. That shape
  // is what makes the guarantee checkable by reading the file rather than by
  // trusting each site: a bare `options.` anywhere under here is now a visible
  // defect, where previously it was indistinguishable from the twenty-nine
  // beside it.
  //
  // `signingSecret` is the site that made this urgent, and it is read twice by
  // the original code — once as the construction guard below and once as the
  // value handed to `verifyApiKeyToken`, which decides WHICH KEY THE HMAC IS
  // COMPUTED UNDER. So a single `Object.prototype.signingSecret` write did two
  // things at once: it silenced the boot-time throw that exists to catch a
  // missing secret, and it made every signature check run under the attacker's
  // key. A token minted by the attacker then authenticated, with whatever
  // scopes they chose to put in it. That needs a pollution primitive already
  // present in this process — it is not reachable from a request — but unlike
  // its siblings it sits on the READ path and decides ACCEPTANCE rather than
  // mislabelling an audit field.
  //
  // `app` is the same shape one step down: it is the construction guard, the
  // `expectedApp` the token is checked against, and the app named on every
  // audit line.
  const optionApp = ownOption(options, "app");
  const optionSigningSecret = ownOption(options, "signingSecret");
  const optionExpectedTid = ownOption(options, "expectedTid");
  const optionRequiredScopes = ownOption(options, "requiredScopes");
  const optionRequireTenant = ownOption(options, "requireTenant");
  const optionLeewaySeconds = ownOption(options, "leewaySeconds");
  const audit = ownOption(options, "audit");
  const headerName = ownOption(options, "headerName") ?? "x-api-key";
  const scheme = ownOption(options, "scheme") ?? "Bearer";
  const clock = ownOption(options, "nowMs") ?? (() => Date.now());

  // Throw order is preserved exactly: app, then signingSecret, then expectedTid.
  // The reads above are pure, so hoisting them past these guards changes which
  // error a misconfigured service sees not at all.
  if (!optionApp) throw new Error("verifyApiKey requires an 'app' slug.");
  if (!optionSigningSecret) {
    throw new Error("verifyApiKey requires a 'signingSecret'. Set it from HASNA_<APP>_API_SIGNING_KEY.");
  }
  if (optionExpectedTid !== undefined && !isValidTenantId(optionExpectedTid)) {
    throw new Error(`verifyApiKey received an invalid 'expectedTid': '${optionExpectedTid}'.`);
  }

  // Re-bound past the guards so `authenticate` closes over plain values. A
  // closure does not inherit the narrowing the guards above establish, and the
  // alternative — a non-null assertion at each of the eight use sites — would
  // put the claim "this was checked" in eight places instead of one.
  const app: string = optionApp;
  const signingSecret: string | Buffer = optionSigningSecret;

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
  //
  // These three options decide fail-open versus fail-closed, so resolving them
  // through the prototype chain would let ONE
  // `Object.prototype.allowUnregisteredKeys = true` write do two things at
  // once: flip every correctly-wired strict verifier back to accepting unknown
  // kids, AND silence the construction-time throw that exists to catch exactly
  // that. Both defenses would fall to a single write. A polluted
  // `keyStatus`/`isRevoked` is worse still — it injects an attacker-chosen
  // verdict.
  const ownKeyStatus = ownOption(options, "keyStatus");
  const ownIsRevoked = ownOption(options, "isRevoked");
  const allowUnregistered = ownOption(options, "allowUnregisteredKeys") === true;
  if (ownKeyStatus && ownIsRevoked) {
    throw new Error(
      "verifyApiKey received both 'keyStatus' and 'isRevoked'. Supply exactly one — " +
        "letting one silently win would hide which check is actually guarding the service. " +
        "Use 'keyStatus' (store.keyStatus); drop 'isRevoked'.",
    );
  }
  if (!ownKeyStatus && !allowUnregistered) {
    throw new Error(
      ownIsRevoked
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
  async function emit(event: AuthAuditEvent): Promise<void> {
    // `audit` is an attacker-supplied FUNCTION when it comes off the prototype,
    // awaited here on every allow and every deny and handed the kid, tid, agent,
    // method and path of every request the service serves. The own-property read
    // happens once at construction, so a hook planted afterwards is never
    // reached either.
    if (!audit) return;
    try {
      await audit(event);
    } catch {
      // Auditing must never break the request path.
    }
  }

  async function authenticate(headers: HeaderSource, context: ApiKeyAuthContext = {}): Promise<AuthDecision> {
    // `context` is a SECOND caller-supplied bag with the same exposure as
    // `options`, and it is typically an object literal a route handler builds
    // per request. `context.requiredScopes` is the one that matters: it is
    // concatenated into the set the token must satisfy, so an inherited
    // `["<app>:admin"]` imposes a scope no caller ever required and refuses
    // every request the service was built to serve. `method` and `path` are
    // lesser and not nothing — they are written straight onto the audit line,
    // so a planted pair mislabels the route recorded for every request.
    const method = ownOption(context, "method") ?? null;
    const path = ownOption(context, "path") ?? null;
    const requiredScopes = [
      ...(optionRequiredScopes ?? []),
      ...(ownOption(context, "requiredScopes") ?? []),
    ];
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
    const perCallTid = ownOption(context, "expectedTid");
    const expectedTid = perCallTid !== undefined ? perCallTid : optionExpectedTid;
    if (
      perCallTid !== undefined &&
      optionExpectedTid !== undefined &&
      !tenantIdsEqual(perCallTid, optionExpectedTid)
    ) {
      await emit({ outcome: "deny", app, kid: null, tid: null, reason: "tenant_mismatch", scopesRequired: requiredScopes, method, path, status: 403, at });
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
      await emit({ outcome: "deny", app, kid: null, tid: null, reason: "missing_token", scopesRequired: requiredScopes, method, path, status: 401, at });
      return decision;
    }

    const verified = verifyApiKeyToken(token, {
      signingSecret,
      expectedApp: app,
      nowMs: clock(),
      ...(optionLeewaySeconds !== undefined ? { leewaySeconds: optionLeewaySeconds } : {}),
      ...(optionRequireTenant !== undefined ? { requireTenant: optionRequireTenant } : {}),
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
      // ABSENCE is therefore meaningful, so all three are read as own properties
      // — an audit line must never name a key or an organization the request
      // never proved.
      //
      // `kid` in particular: `verifyApiKeyToken` returns it only for
      // `tenant_required`/`tenant_mismatch`. On `malformed`, `bad_signature`,
      // `unsupported_version`, `app_mismatch`, `not_yet_valid`, `expired` and
      // `insufficient_scope` it is absent, so a bare read resolved up the
      // prototype chain and `?? null` could not catch it — the planted value is
      // not nullish. Measured on this branch before the guard: a tampered token
      // denied `bad_signature` audited `kid: "FORGED-KID-attacker-chosen"`,
      // against `kid: null` on a clean prototype. Audit integrity only; it does
      // not decide acceptance.
      await emit({
        outcome: "deny",
        app,
        kid: ownOption(verified, "kid") ?? null,
        tid: ownTenantId(verified) ?? null,
        ...(Object.hasOwn(verified, "agent") ? { agent: verified.agent } : {}),
        reason: verified.reason,
        scopesRequired: requiredScopes,
        method,
        path,
        status,
        at,
      });
      return { ok: false, status, reason: verified.reason, message: verified.message };
    }

    // The signature is authentic; now ask whether this specific key is still one
    // we honour. `keyStatus` reports WHICH way it failed, so an operator reading
    // the audit trail can tell a revoked key (we turned it off) from an unknown
    // one (someone is presenting a key we never issued — the interesting case).
    if (ownKeyStatus) {
      // The status lookup is a per-request DB read in every realistic store, so
      // it can fail independently of the credential. A thrown lookup must not
      // escape: an unhandled rejection here hangs the request under Express 4
      // (no response at all) instead of answering. It must equally not become
      // an allow — an unavailable revocation check is exactly when an attacker
      // wants one. So: deny, distinctly, with 503 rather than 401, because the
      // credential was never judged and telling the client to re-authenticate
      // would be a lie.
      let status: ApiKeyStatus;
      try {
        status = await ownKeyStatus(verified.kid);
      } catch {
        await emit({ outcome: "deny", app, kid: verified.kid, tid: verified.tid, agent: verified.agent, reason: "status_unavailable", scopesRequired: requiredScopes, method, path, status: 503, at });
        return {
          ok: false,
          status: 503,
          reason: "status_unavailable",
          message: "Could not verify API key status. Try again shortly.",
        };
      }
      if (status !== "active") {
        // "unknown" is tolerated ONLY under the explicit opt-out; revoked and
        // expired are refused regardless, since those are recorded decisions.
        // Any value outside the union is treated as unknown: a store that
        // answers something we do not understand has not said "active", and an
        // unrecognized string must not be minted into the audit trail as if it
        // were a reason the contract defines.
        const known = status === "revoked" || status === "expired" || status === "unknown";
        if (!(status === "unknown" && allowUnregistered)) {
          const reason: AuthDenyReason =
            status === "revoked" || status === "expired" ? status : "unknown_key";
          const message =
            reason === "unknown_key"
              ? known
                ? "API key is not registered with this service."
                : "API key status could not be recognized."
              : status === "expired"
                ? "API key has expired."
                : "API key has been revoked.";
          await emit({ outcome: "deny", app, kid: verified.kid, tid: verified.tid, agent: verified.agent, reason, scopesRequired: requiredScopes, method, path, status: 401, at });
          return { ok: false, status: 401, reason, message };
        }
      }
    } else if (ownIsRevoked) {
      // Same treatment as `keyStatus` above. This path is deprecated, but a
      // deprecated path still runs in production, and `isRevoked` is the same
      // per-request DB read — so the same Postgres blip hung the same request.
      // Wrapping it is what makes `authenticate`'s "never throws" contract
      // true; leaving it unwrapped and softening the docstring instead would
      // just move the defect from the code into the prose.
      let revoked: boolean;
      try {
        revoked = await ownIsRevoked(verified.kid);
      } catch {
        await emit({ outcome: "deny", app, kid: verified.kid, tid: verified.tid, agent: verified.agent, reason: "status_unavailable", scopesRequired: requiredScopes, method, path, status: 503, at });
        return {
          ok: false,
          status: 503,
          reason: "status_unavailable",
          message: "Could not verify API key status. Try again shortly.",
        };
      }
      if (revoked) {
        await emit({ outcome: "deny", app, kid: verified.kid, tid: verified.tid, agent: verified.agent, reason: "revoked", scopesRequired: requiredScopes, method, path, status: 401, at });
        return { ok: false, status: 401, reason: "revoked", message: "API key has been revoked." };
      }
    }

    const principal: ApiKeyPrincipal = {
      kid: verified.kid,
      app: verified.app,
      scopes: verified.claims.scopes,
      agent: verified.agent,
      tid: verified.tid,
      claims: verified.claims,
    };
    await emit({ outcome: "allow", app, kid: verified.kid, tid: verified.tid, agent: verified.agent, reason: null, scopesRequired: requiredScopes, method, path, status: 200, at });
    return { ok: true, status: 200, principal };
  }

  return { authenticate, app, };
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
