// Core API-key crypto for Hasna: stateless, verifiable, HMAC-signed tokens.
//
// A key is a compact, self-describing signed token:
//
//   hasna_<app>_<body>.<sig>
//
//   <app>  = app slug ([a-z][a-z0-9-]*), also embedded in the signed claims
//   <body> = base64url(JSON claims) — { v, kid, app, tid?, scopes, iat, exp, agent? }
//   <sig>  = base64url(HMAC-SHA256(signingSecret, "hasna_<app>_<body>"))
//
// Verification is STATELESS: the server recomputes the HMAC with its signing
// secret and constant-time compares it — no database round-trip is required to
// prove authenticity, TTL, or scopes. Revocation is the only stateful check and
// is layered on top (see store.ts / middleware.ts) keyed by the claims `kid`.
//
// AT REST the issuer stores sha256(token) (never the plaintext) plus metadata,
// so the secret is shown exactly once at issue time and can never be recovered.

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { isValidScope } from "./scopes.js";
import { canonicalizeTenantId, isValidTenantId, normalizeTenantId, ownTenantId, tenantIdsEqual } from "./tenant.js";

/** Token wire-format version. Bump only on a breaking format change. */
export const API_KEY_TOKEN_VERSION = 1;

/** Literal token namespace prefix. */
export const API_KEY_NAMESPACE = "hasna";

/** App slug grammar shared by the token prefix and claims. */
export const APP_SLUG_PATTERN = /^[a-z][a-z0-9-]*$/;

/**
 * Full-token structural matcher: `hasna_<app>_<body>.<sig>`.
 *
 * Exported because the public-manifest guard in `src/conformance.ts` needs to
 * recognise a leaked key, and a second hand-written approximation of this
 * grammar is how that guard came to flag `HASNA_LOOPS_DATABASE_URL` — the env
 * name CONTRACT.md section 3 requires — as a credential.
 */
export const API_KEY_TOKEN_PATTERN = /^hasna_([a-z][a-z0-9-]*)_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;
const TOKEN_PATTERN = API_KEY_TOKEN_PATTERN;

/** Default TTL applied when a caller does not specify one: 90 days. */
export const DEFAULT_API_KEY_TTL_SECONDS = 90 * 24 * 60 * 60;

export interface ApiKeyClaims {
  /** Token format version. */
  v: number;
  /** Key id — stable identifier used for revocation and record lookup. */
  kid: string;
  /** App slug the key authenticates against. */
  app: string;
  /**
   * Tenant (organization) the key acts for, in the issuer's namespace.
   *
   * OPTIONAL AND ADDITIVE. Absent means the key is UNTENANTED — it names no
   * organization. Absent is NOT a wildcard: a service that scopes data by
   * tenant must reject an untenanted key rather than treat it as "all
   * tenants". Pass `requireTenant` to {@link verifyApiKeyToken} to get that
   * rejection from the kit instead of hand-rolling it per service.
   *
   * The value is inside the signed body, so it is tamper-evident: changing
   * `tid` invalidates the signature.
   */
  tid?: string;
  /** Granted scopes (`<app>:<action>` or wildcards). */
  scopes: string[];
  /** Issued-at, epoch seconds. */
  iat: number;
  /** Expiry, epoch seconds; `null` means the key never expires. */
  exp: number | null;
  /** Optional issued-to agent/subject (informational). */
  agent?: string;
}

/**
 * Read the `agent` claim as an OWN, string-valued property — the single guard
 * for this claim, and the sibling of `ownTenantId`.
 *
 * A claims object is either `JSON.parse` output (verification) or a locally
 * built object literal (minting). Both have `Object.prototype` in their chain,
 * so a bare `claims.agent` on a token that carries no agent resolves to
 * whatever a `__proto__`/`constructor.prototype` write primitive elsewhere in
 * the process planted there. That value is not in the signed body, so it is not
 * authentic, and it must never reach an audit trail, a principal, or a stored
 * key record as if it were.
 *
 * A missing claim is `null` — authenticated, and naming no subject. That is a
 * different fact from "never established", which callers express by omitting
 * the field entirely rather than by calling this.
 */
export function ownAgentClaim(source: { agent?: unknown }): string | null {
  return Object.hasOwn(source, "agent") && typeof source.agent === "string" ? source.agent : null;
}

/**
 * Read the `scopes` claim as an OWN, array-valued property — the sibling of
 * {@link ownAgentClaim} and of `ownTenantId`, and the last claim in this file
 * that was still read straight off the prototype chain.
 *
 * `scopes` is the authorization claim, so the consequence of an inherited read
 * is not a mislabelled audit line but a grant: a single
 * `Object.prototype.scopes = ["*"]` write primitive anywhere in the process
 * hands a wildcard to every claim set that carries no own `scopes` key, and
 * `*` satisfies every `requiredScopes` check the kit performs.
 *
 * This is DEFENCE IN DEPTH, not a hole this kit leaves open, and the
 * distinction is worth stating so nobody later "simplifies" the property that
 * closes it. `mintApiKey` is the only place in this module that builds a
 * signed body; it refuses fewer than one scope and always writes `scopes` as
 * an own property, and an own property shadows the prototype. So no token this
 * kit can mint reaches the inherited read. A body that does reach it — from an
 * older minter, a sibling implementation, a hand-rolled issuance path — is a
 * malformed token, and `null` here makes the structural check say so.
 *
 * `null` for absent rather than `undefined`, matching `ownAgentClaim`: the
 * caller must handle the missing case explicitly rather than let it flow on as
 * a value that happens to be falsy.
 */
export function ownScopesClaim(source: { scopes?: unknown }): string[] | null {
  return Object.hasOwn(source, "scopes") && Array.isArray(source.scopes) ? (source.scopes as string[]) : null;
}

/**
 * Read one field of a caller-supplied OPTIONS BAG as an OWN property — the
 * sibling of `ownAgentClaim`, `ownScopesClaim` and `ownTenantId`, applied to the
 * bags rather than to the claims. The same accessor already exists on the CLI's
 * write path in `src/cli/issue-key.ts`; this is that convention reaching the
 * layer underneath it, so the guard does not depend on which caller arrives.
 *
 * An options bag is an object literal, so it has `Object.prototype` in its
 * chain, and a field the caller did not set is genuinely absent rather than
 * defined as `undefined`. `options.x ?? fallback`, `options.x === undefined` and
 * `Array.isArray(options.x)` therefore all perform a real prototype lookup for
 * exactly those fields, and a `__proto__`/`constructor.prototype` write
 * primitive anywhere else in the process decides what they return. Every one of
 * those three forms accepts the inherited value silently — `??` because it is
 * not nullish, `=== undefined` because it is defined, `Array.isArray` because it
 * is an array.
 *
 * ON THE MINT PATH THAT IS NOT A MISREAD, IT IS A SIGNATURE. Values read in
 * `mintApiKey` are written into the claims BEFORE the HMAC is computed, so the
 * token that comes out is cryptographically authentic and no verify-time guard
 * can — or should — reject it: `ownAgentClaim`, `ownScopesClaim` and
 * `ownTenantId` all sit downstream of the signature and cannot help here. The
 * consequence is durability rather than access. The attack still needs a
 * pollution primitive in the issuer's own process, but a primitive that lasts
 * one mint yields a PERMANENTLY valid credential — a wildcard `scopes`, an
 * attacker-chosen `kid` (the value revocation keys on), or a moved `iat`/`exp`.
 * Removing the pollution afterwards does not revoke what was signed while it was
 * there. This is the only place those values can be stopped.
 *
 * On the verify path the reads are not signed and the consequence is narrower:
 * they decide whether an authentic token is accepted here and now. It is still
 * both directions — an inherited `nowMs`/`leewaySeconds` accepts a lapsed token,
 * an inherited `expectedApp`/`requiredScopes`/`requireTenant`/`expectedTid`
 * denies a good one.
 */
function ownOption<T extends object, K extends keyof T & string>(options: T, name: K): T[K] | undefined {
  return Object.hasOwn(options, name) ? options[name] : undefined;
}

export interface MintApiKeyOptions {
  app: string;
  scopes: string[];
  /**
   * Tenant (organization) the key acts for. Omit to mint an untenanted key —
   * the pre-`tid` behaviour, and still the correct choice for a single-org
   * deployment or an operator/bootstrap key. Validated and canonicalized by
   * `normalizeTenantId` at mint time so a malformed id can never enter a token.
   */
  tid?: string;
  /** HMAC signing secret (server-held). Never embedded in the token. */
  signingSecret: string | Buffer;
  /** Seconds until expiry. Omit for the default; pass `null` for no expiry. */
  ttlSeconds?: number | null;
  /** Optional issued-to agent/subject. */
  agent?: string;
  /** Override the generated key id (tests / deterministic reissue). */
  kid?: string;
  /** Epoch milliseconds override for deterministic issuance (tests). */
  nowMs?: number;
}

export interface MintedApiKey {
  /** The secret token — returned ONCE, never stored in plaintext. */
  token: string;
  /** Key id (also inside the claims). */
  kid: string;
  /** Decoded claims. */
  claims: ApiKeyClaims;
  /** sha256 hex digest of the full token — this is what to store at rest. */
  tokenHash: string;
  /** Human-recognizable prefix: `hasna_<app>_`. */
  prefix: string;
}

function base64urlEncode(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

function toBuffer(secret: string | Buffer): Buffer {
  return typeof secret === "string" ? Buffer.from(secret, "utf8") : secret;
}

function hmac(signingSecret: string | Buffer, message: string): Buffer {
  return createHmac("sha256", toBuffer(signingSecret)).update(message, "utf8").digest();
}

/** sha256 hex of the full token — the value persisted at rest. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** The `hasna_<app>_` prefix for an app slug. */
export function apiKeyPrefix(app: string): string {
  return `${API_KEY_NAMESPACE}_${app}_`;
}

/** Generate a short, url-safe key id (default 16 hex chars = 8 random bytes). */
export function generateKid(bytes = 8): string {
  return randomBytes(bytes).toString("hex");
}

/**
 * Mint a new API key. Returns the plaintext token (show once) alongside the
 * sha256 hash and metadata to persist. The signing secret is NEVER embedded.
 */
export function mintApiKey(options: MintApiKeyOptions): MintedApiKey {
  // EVERY option is read exactly once, here, as an own property, and past this
  // block the function sees locals and never `options`. Reading them in one
  // place is the point rather than a tidiness preference: a single bare
  // `options.x` left further down reopens the hole for that field alone, and a
  // bare read is invisible at a glance because it is spelled identically to a
  // correct one. Six of these were bare until this change — `app`, `scopes`
  // (three separate reads, one of them spread straight into the signed claims),
  // `signingSecret`, `kid`, `nowMs` and `ttlSeconds` — while `tid` and `agent`
  // beside them were already guarded, which is exactly how the gap survived
  // review: the file looked like it applied the convention.
  const requestedApp = ownOption(options, "app");
  const requestedScopes = ownOption(options, "scopes");
  const requestedSecret = ownOption(options, "signingSecret");
  const requestedKid = ownOption(options, "kid");
  const requestedNowMs = ownOption(options, "nowMs");
  const requestedTtlSeconds = ownOption(options, "ttlSeconds");
  // `undefined` means untenanted and stays out of the body entirely, so a token
  // minted without a tenant is byte-identical to one minted before `tid`
  // existed. Any other value must be well-formed — a silently-dropped bad
  // tenant id would mint a key that authenticates as untenanted.
  const requestedTid = ownTenantId(options);
  const agent = ownAgentClaim(options);

  // A non-string app is now the same failure as a malformed one instead of a
  // `TypeError` out of `.trim()`. Both throw; this one names the field.
  const app = typeof requestedApp === "string" ? requestedApp.trim() : "";
  if (!APP_SLUG_PATTERN.test(app)) {
    throw new Error(`Invalid app slug '${String(requestedApp ?? "")}'. Expected ${APP_SLUG_PATTERN}.`);
  }
  if (!Array.isArray(requestedScopes) || requestedScopes.length === 0) {
    throw new Error("At least one scope is required to mint an API key.");
  }
  for (const scope of requestedScopes) {
    if (!isValidScope(scope)) {
      throw new Error(`Invalid scope '${scope}'. Expected '*' or '<app>:<action>'.`);
    }
  }
  // An absent or non-secret-shaped value becomes an empty buffer so it lands on
  // the entropy check below, which already says the right thing. Previously an
  // absent `signingSecret` threw a `TypeError` off `undefined.length`; it still
  // throws, now with this module's own message.
  const secret =
    typeof requestedSecret === "string" || Buffer.isBuffer(requestedSecret)
      ? toBuffer(requestedSecret)
      : Buffer.alloc(0);
  if (secret.length < 16) {
    throw new Error("signingSecret must be at least 16 bytes of entropy.");
  }

  const kid = requestedKid ?? generateKid();
  if (!/^[A-Za-z0-9_-]+$/.test(kid)) {
    throw new Error(`Invalid kid '${kid}'. Expected url-safe characters only.`);
  }

  const tid = requestedTid === undefined ? undefined : normalizeTenantId(requestedTid);

  const nowMs = requestedNowMs ?? Date.now();
  const iat = Math.floor(nowMs / 1000);
  const ttl = requestedTtlSeconds === undefined ? DEFAULT_API_KEY_TTL_SECONDS : requestedTtlSeconds;
  if (ttl !== null && (!Number.isFinite(ttl) || ttl <= 0)) {
    throw new Error("ttlSeconds must be a positive number or null (no expiry).");
  }
  const exp = ttl === null ? null : iat + Math.floor(ttl);

  const claims: ApiKeyClaims = {
    v: API_KEY_TOKEN_VERSION,
    kid,
    app,
    ...(tid !== undefined ? { tid } : {}),
    scopes: [...requestedScopes],
    iat,
    exp,
    ...(agent !== null ? { agent } : {}),
  };

  const body = base64urlEncode(JSON.stringify(claims));
  const signingInput = `${apiKeyPrefix(app)}${body}`;
  const sig = base64urlEncode(hmac(secret, signingInput));
  const token = `${signingInput}.${sig}`;

  return {
    token,
    kid,
    claims,
    tokenHash: hashToken(token),
    prefix: apiKeyPrefix(app),
  };
}

export interface ParsedApiKey {
  app: string;
  body: string;
  sig: string;
  claims: ApiKeyClaims;
}

/** Structural parse (no signature check). Returns null when malformed. */
export function parseApiKey(token: string): ParsedApiKey | null {
  if (typeof token !== "string") return null;
  const match = TOKEN_PATTERN.exec(token);
  if (!match) return null;
  const [, app, body, sig] = match;
  if (!app || !body || !sig) return null;
  let claims: ApiKeyClaims;
  try {
    claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as ApiKeyClaims;
  } catch {
    return null;
  }
  if (
    typeof claims !== "object" ||
    claims === null ||
    typeof claims.kid !== "string" ||
    typeof claims.app !== "string" ||
    // The OWN scopes claim, for the same reason `tid` is read as an own
    // property below: validating the own property while a later consumer reads
    // the inherited one is worse than not checking at all.
    ownScopesClaim(claims) === null
  ) {
    return null;
  }
  // A present-but-malformed `tid` is a malformed token, not an untenanted one.
  // Treating it as absent would let a body with `tid: null` or `tid: 0` slip
  // past a `requireTenant` gate as "no tenant claimed". The value validated
  // here is the OWN one, and so is every later read of it — validating the own
  // property while consuming the inherited one would be worse than no check.
  const claimedTid = ownTenantId(claims);
  if (claimedTid !== undefined && !isValidTenantId(claimedTid)) {
    return null;
  }
  return { app, body, sig, claims };
}

export type ApiKeyVerifyFailureReason =
  | "malformed"
  | "unsupported_version"
  | "app_mismatch"
  | "bad_signature"
  | "not_yet_valid"
  | "expired"
  | "revoked"
  | "insufficient_scope"
  | "tenant_required"
  | "tenant_mismatch";

export type ApiKeyVerifyResult =
  | {
      ok: true;
      claims: ApiKeyClaims;
      kid: string;
      app: string;
      /** Canonical tenant id, or `null` for an untenanted key. */
      tid: string | null;
      /**
       * The issued-to agent/subject, or `null` when the token claims none.
       *
       * ALWAYS present on success, which is the point: callers read this
       * instead of reaching back into `claims`. `claims` is `JSON.parse`
       * output, so a plain `claims.agent` read walks the prototype chain and,
       * in a process whose `Object.prototype` has been polluted, yields a
       * subject the signature never covered. Reading it here is an own-property
       * read of a value that was guarded once, at the single site below.
       */
      agent: string | null;
    }
  | {
      ok: false;
      reason: ApiKeyVerifyFailureReason;
      message: string;
      /**
       * Key id and tenant, when the failure path already exposes them for audit.
       */
      kid?: string;
      tid?: string | null;
      /**
       * Agent is populated once the SIGNATURE has verified, so every
       * authenticated denial can name its subject. Absent before authenticity
       * is established because nothing in an unverified token may be believed.
       */
      agent?: string | null;
    };

export interface VerifyApiKeyTokenOptions {
  signingSecret: string | Buffer;
  /** Restrict verification to a single app slug (recommended per-service). */
  expectedApp?: string;
  /** Epoch milliseconds override for deterministic checks (tests). */
  nowMs?: number;
  /** Clock-skew leeway in seconds applied to iat/exp. Default 0. */
  leewaySeconds?: number;
  /** Concrete `app:action` scopes ALL of which must be granted. */
  requiredScopes?: readonly string[];
  /**
   * Reject untenanted tokens. Set this in any service whose data is scoped by
   * organization: without it, a pre-`tid` token authenticates and the caller is
   * left to remember the tenant check itself.
   */
  requireTenant?: boolean;
  /**
   * Restrict verification to one tenant. Implies {@link requireTenant}.
   * Compared with `tenantIdsEqual`, so a `uuid`-column tenant and a `text`-column
   * tenant holding the same UUID match regardless of case.
   */
  expectedTid?: string;
}

/**
 * Fully verify a token's authenticity, TTL, app binding, tenant, and
 * (optionally) scopes. Stateless — no revocation lookup. Layer revocation on
 * top via the store/middleware. Constant-time on the signature comparison.
 */
export function verifyApiKeyToken(token: string, options: VerifyApiKeyTokenOptions): ApiKeyVerifyResult {
  // Same one-read-per-option block as `mintApiKey`, for the same reason. These
  // reads are not signed, so the consequence is narrower than on the mint path
  // and it runs in both directions: an inherited `nowMs` or `leewaySeconds`
  // accepts a token whose expiry has lapsed, and an inherited `expectedApp`,
  // `requiredScopes`, `requireTenant` or `expectedTid` denies a token the caller
  // never asked to be checked that way. `signingSecret` is the sharp one — an
  // inherited value would compute the expected HMAC from a secret the attacker
  // chose, so a token they signed themselves would verify. It is deliberately
  // NOT given a fallback: an absent secret still throws exactly as it does today
  // when a caller passes `undefined` explicitly, because inventing a new denial
  // reason in the request path would turn a caller's configuration bug into a
  // silent rejection that looks like a bad token.
  const optSigningSecret = ownOption(options, "signingSecret");
  const optExpectedApp = ownOption(options, "expectedApp");
  const optNowMs = ownOption(options, "nowMs");
  const optLeewaySeconds = ownOption(options, "leewaySeconds");
  const optRequiredScopes = ownOption(options, "requiredScopes");
  const optRequireTenant = ownOption(options, "requireTenant");
  const optExpectedTid = ownOption(options, "expectedTid");

  const parsed = parseApiKey(token);
  if (!parsed) {
    return { ok: false, reason: "malformed", message: "Token is malformed." };
  }
  const { app, body, sig, claims } = parsed;

  if (claims.v !== API_KEY_TOKEN_VERSION) {
    return { ok: false, reason: "unsupported_version", message: `Unsupported token version ${claims.v}.` };
  }
  if (claims.app !== app) {
    return { ok: false, reason: "app_mismatch", message: "Token prefix app does not match claims." };
  }
  if (optExpectedApp !== undefined && app !== optExpectedApp) {
    return { ok: false, reason: "app_mismatch", message: `Token is for app '${app}', expected '${optExpectedApp}'.` };
  }

  const expected = hmac(optSigningSecret as string | Buffer, `${apiKeyPrefix(app)}${body}`);
  let provided: Buffer;
  try {
    provided = Buffer.from(sig, "base64url");
  } catch {
    return { ok: false, reason: "bad_signature", message: "Signature is not valid base64url." };
  }
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return { ok: false, reason: "bad_signature", message: "Signature verification failed." };
  }

  // Every result below — the denials AND the success — carries this value out,
  // so no caller has cause to reach into `claims.agent` itself. That is
  // deliberate: the guard used to be inline here while the success result
  // omitted `agent` entirely, which left the middleware re-reading
  // `verified.claims.agent` unguarded on the allow path and on four post-status
  // denials. Six copies of a guard is six chances for the seventh reader to
  // forget; one guarded value has none.
  const agent = ownAgentClaim(claims);
  const now = Math.floor((optNowMs ?? Date.now()) / 1000);
  const leeway = optLeewaySeconds ?? 0;
  if (typeof claims.iat === "number" && now + leeway < claims.iat) {
    return { ok: false, reason: "not_yet_valid", message: "Token is not yet valid.", agent };
  }
  if (claims.exp !== null && typeof claims.exp === "number" && now - leeway >= claims.exp) {
    return { ok: false, reason: "expired", message: "Token has expired.", agent };
  }

  // Tenant binding is an identity check, so it runs before authorization: a
  // token for the wrong organization must not be reported as merely
  // under-scoped.
  const verifiedTid = ownTenantId(claims);
  const tid = verifiedTid === undefined ? null : canonicalizeTenantId(verifiedTid);
  // Any truthy value enables the gate. `=== true` would fail OPEN for a config
  // value that arrived as the string "true" or the number 1 — the wrong
  // direction for a security control to be strict in.
  const tenantRequired = Boolean(optRequireTenant) || optExpectedTid !== undefined;
  if (tenantRequired && tid === null) {
    return {
      ok: false,
      reason: "tenant_required",
      message: "Token carries no tenant id ('tid') and this service requires one.",
      kid: claims.kid,
      tid: null,
      agent,
    };
  }
  if (optExpectedTid !== undefined && !tenantIdsEqual(tid, optExpectedTid)) {
    // A malformed `expectedTid` lands here too, and deliberately: this runs in
    // the request path, so a misconfigured expectation must deny rather than
    // throw a 500. That includes values that are not strings at ALL — Express
    // turns `?tid=a&tid=b` into an array, and a JSON body can carry a number or
    // `null` — so the type is checked BEFORE any string method is reached.
    // Calling `.trim()` first threw a TypeError straight out of the request
    // path, which is the very 500 this branch exists to avoid. `tenantIdsEqual`
    // already refuses non-strings, so the deny itself was never in doubt; only
    // the message needed the guard. The message still distinguishes the two so
    // it is diagnosable. Construction-time config is validated eagerly by
    // `verifyApiKey()`.
    const expectationIsWellFormed =
      typeof optExpectedTid === "string" && isValidTenantId(optExpectedTid.trim());
    return {
      ok: false,
      reason: "tenant_mismatch",
      message: expectationIsWellFormed
        ? "Token is for a different tenant than the one this service accepts."
        : "Token tenant cannot be checked: the expected tenant id is not a valid tenant id.",
      kid: claims.kid,
      tid,
      agent,
    };
  }

  if (optRequiredScopes && optRequiredScopes.length > 0) {
    // Local import avoided to keep the crypto module leaf; inline the check.
    // `parseApiKey` has already refused a body with no own `scopes`, so the
    // `?? []` is unreachable today. It is here anyway, and it denies rather
    // than throws, because this is the read that decides authorization: an
    // empty grant set satisfies nothing, which is the only safe answer if a
    // future caller ever reaches this check by another route. Reading
    // `claims.scopes` directly would instead make that future caller inherit
    // the prototype's value and authorize on it.
    const granted = ownScopesClaim(claims) ?? [];
    const satisfies = (required: string): boolean =>
      granted.some((g) => {
        if (g === "*") return true;
        const gi = g.indexOf(":");
        const ri = required.indexOf(":");
        if (gi < 0 || ri < 0) return false;
        const gApp = g.slice(0, gi);
        const gAction = g.slice(gi + 1);
        const rApp = required.slice(0, ri);
        const rAction = required.slice(ri + 1);
        return (gApp === "*" || gApp === rApp) && (gAction === "*" || gAction === rAction);
      });
    for (const required of optRequiredScopes) {
      if (!satisfies(required)) {
        return { ok: false, reason: "insufficient_scope", message: `Missing required scope '${required}'.`, agent };
      }
    }
  }

  return { ok: true, claims, kid: claims.kid, app, tid, agent };
}
