// The identity seam: offline EdDSA fleet-token verification.
//
// WHAT THIS IS FOR. Every Hasna OSS server keeps its complete in-repo API-key
// default (see keys.ts / middleware.ts) and ADDITIONALLY exposes an identity
// option: verify EdDSA tokens minted by a configured issuer against a
// configured JWKS, and map the token's `tid` onto one of the server's own
// organizations. The reference issuer is `open-tenants`. It is a REFERENCE
// BEHIND A SEAM, never a dependency — a self-hoster must be able to run the
// whole stack from one repo, so nothing here imports it and nothing here
// requires it to exist.
//
// OFFLINE BY CONSTRUCTION, NOT BY POLICY. "Downstream services never call back
// to the IdP" is easy to write in a document and easy to violate in a hot path.
// So this module cannot make a network call: `verifyFleetToken` takes a JWKS
// *value*, not a URI, and the module imports nothing that can reach the
// network. `jwksUri` is recorded as operator configuration and is never
// dereferenced here — refreshing the key set is the operator's job, out of the
// request path. `tests/auth-identity.test.ts` asserts this structurally.
//
// THE WIRE SHAPE IS NOT INVENTED. It is the shape `open-tenants` already mints
// (`src/idp/tokens.ts`): a compact JWS with header `{alg:"EdDSA", kid, typ:
// "at+jwt"}` over claims `{iss, aud, sub, tid, pt, scope, iat, exp, jti}`. This
// module standardizes that shape and hardens the checks around it, so six
// servers implement one verification, not six.
//
// WHAT IS HARDENED RELATIVE TO THE REFERENCE VERIFIER:
//   * `exp` is REQUIRED. A verifier that skips the expiry check when `exp` is
//     absent turns a missing claim into an immortal token.
//   * `aud` is REQUIRED and always checked. An optional audience check means a
//     token minted for one app is accepted by every other app.
//   * `tid` is REQUIRED. Unlike the additive API-key claim, the identity seam
//     is tenant-native: a fleet token that names no organization has no meaning.
//   * JWKS entries carrying private material (`d`) are rejected outright — a
//     private key in a published key set is an incident, not a usable key.
//   * An EMPTY key set fails. A guard that passes when it has nothing to check
//     is the failure mode this program keeps rediscovering.
//   * `nbf` is honoured, `typ` is pinned, and `alg` confusion (including
//     `"none"`) is rejected before any key is loaded.
//
// REVOCATION IS A KNOWN GAP, MADE EXPLICIT. Offline verification cannot see a
// revocation; the reference issuer has no fleet-wide revocation at all, so a
// revoked token stays acceptable for the remainder of its (≤24h) life. This
// module therefore REQUIRES `jti` — so revocation is at least possible — and
// `createIdentityVerifier` takes the same optional `isRevoked` hook shape the
// API-key middleware uses. A service that needs prompt revocation supplies it.

import { createPublicKey, verify as edVerify } from "node:crypto";
import { isValidScope, scopeMatches } from "./scopes.js";
import { canonicalizeTenantId, isValidTenantId, tenantIdsEqual } from "./tenant.js";
import { envToken } from "../env-token.js";

/** The only signature algorithm this seam accepts. */
export const FLEET_TOKEN_ALG = "EdDSA";

/** The `typ` header the reference issuer stamps on access tokens. */
export const FLEET_TOKEN_TYP = "at+jwt";

/**
 * Ceiling on a fleet token's lifetime. Offline verification cannot see a
 * revocation, so the token's TTL *is* the revocation window. 24h matches the
 * reference issuer's own server-side clamp.
 */
export const MAX_FLEET_TOKEN_TTL_SECONDS = 24 * 60 * 60;

/** Principal type carried in the `pt` claim. */
export const PRINCIPAL_TYPES = ["user", "service"] as const;
export type PrincipalType = (typeof PRINCIPAL_TYPES)[number];

/** A published Ed25519 verification key. Public material only. */
export interface Ed25519PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  /** base64url-encoded public key. */
  x: string;
  kid: string;
  use?: "sig";
  alg?: "EdDSA";
}

/** A JWKS document holding one or more Ed25519 verification keys. */
export interface FleetJwks {
  keys: Ed25519PublicJwk[];
}

/** Claims carried by a fleet access token. */
export interface FleetTokenClaims {
  /** Issuer — an opaque wire-contract string, NOT necessarily a URL. */
  iss: string;
  /** Audience — the app slug the token is for. Accepts a JWT array form too. */
  aud: string | string[];
  /** Subject — the principal id in the issuer's namespace. */
  sub: string;
  /** Tenant/organization. Required: the identity seam is tenant-native. */
  tid: string;
  /** Principal type. */
  pt: PrincipalType;
  /** Granted scopes, in the same `<app>:<action>` grammar as API keys. */
  scope: string[];
  /** Issued-at, epoch seconds. */
  iat: number;
  /** Expiry, epoch seconds. Required. */
  exp: number;
  /** Not-before, epoch seconds. Optional. */
  nbf?: number;
  /** Token id — the handle any revocation list is keyed by. Required. */
  jti: string;
}

// --- JWKS validation ---

export type FleetJwksProblem =
  | "not_an_object"
  | "keys_not_an_array"
  | "empty_key_set"
  | "no_usable_key"
  | "private_material";

export type ParseFleetJwksResult =
  | { ok: true; jwks: FleetJwks }
  | { ok: false; problem: FleetJwksProblem; message: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUsableEd25519Jwk(value: unknown): value is Ed25519PublicJwk {
  if (!isRecord(value)) return false;
  if (value.kty !== "OKP" || value.crv !== "Ed25519") return false;
  if (typeof value.x !== "string" || value.x.length === 0) return false;
  if (typeof value.kid !== "string" || value.kid.length === 0) return false;
  if (value.use !== undefined && value.use !== "sig") return false;
  if (value.alg !== undefined && value.alg !== FLEET_TOKEN_ALG) return false;
  return true;
}

/**
 * Validate an untrusted JWKS document — the JSON an operator loaded from a
 * file, an env var, or their own out-of-band refresh.
 *
 * Fails on an empty or all-unusable key set rather than returning one: a
 * verifier holding zero keys rejects everything, which is correct but produces
 * a per-request failure that looks like a token problem. Surfacing it here
 * makes it a startup problem, which is what it is.
 */
export function parseFleetJwks(value: unknown): ParseFleetJwksResult {
  const document = typeof value === "string" ? safeJsonParse(value) : value;
  if (!isRecord(document)) {
    return { ok: false, problem: "not_an_object", message: "JWKS must be a JSON object." };
  }
  if (!Array.isArray(document.keys)) {
    return { ok: false, problem: "keys_not_an_array", message: "JWKS must have a 'keys' array." };
  }
  if (document.keys.length === 0) {
    return { ok: false, problem: "empty_key_set", message: "JWKS contains no keys." };
  }
  // A published key set must never carry private material. Silently dropping
  // such an entry would hide a serious issuer misconfiguration.
  if (document.keys.some((key) => isRecord(key) && typeof key.d === "string")) {
    return {
      ok: false,
      problem: "private_material",
      message: "JWKS contains a private key component ('d'). Publish public keys only.",
    };
  }
  const keys = document.keys.filter(isUsableEd25519Jwk);
  if (keys.length === 0) {
    return {
      ok: false,
      problem: "no_usable_key",
      message: `JWKS contains no usable Ed25519 signing key (need kty 'OKP', crv 'Ed25519', a 'kid', and alg '${FLEET_TOKEN_ALG}' when present).`,
    };
  }
  return { ok: true, jwks: { keys } };
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// --- verification ---

export type IdentityVerifyFailureReason =
  | "malformed"
  | "unsupported_alg"
  | "unsupported_typ"
  | "missing_kid"
  | "unknown_kid"
  | "no_usable_key"
  | "bad_signature"
  | "issuer_mismatch"
  | "audience_mismatch"
  | "missing_expiry"
  | "excessive_ttl"
  | "expired"
  | "not_yet_valid"
  | "invalid_claims"
  | "tenant_mismatch"
  | "revoked"
  | "insufficient_scope";

/** An authenticated fleet principal. Field names mirror `ApiKeyPrincipal`. */
export interface IdentityPrincipal {
  /** Principal id in the issuer's namespace. */
  sub: string;
  /** Canonical tenant id — the value a service maps onto its own org. */
  tid: string;
  principalType: PrincipalType;
  /** Granted scopes. Same name and grammar as `ApiKeyPrincipal.scopes`. */
  scopes: string[];
  /** Token id — the revocation handle. */
  jti: string;
  /** Key id the signature verified against. */
  kid: string;
  issuer: string;
  audience: string;
  /** Expiry as an ISO timestamp, for logging and audit. */
  expiresAt: string;
  claims: FleetTokenClaims;
}

export type IdentityVerifyResult =
  | { ok: true; principal: IdentityPrincipal }
  | { ok: false; reason: IdentityVerifyFailureReason; message: string };

export interface VerifyFleetTokenOptions {
  /**
   * The verification key set — a VALUE, never a URI. This is what makes
   * offline verification structural: there is no code path here that could
   * fetch it.
   */
  jwks: FleetJwks;
  /** Expected `iss`. Required — an unpinned issuer accepts anyone's tokens. */
  issuer: string;
  /** Expected `aud` (this app's slug). Required. */
  audience: string;
  /** Epoch-ms clock override (tests). */
  nowMs?: number;
  /** Clock-skew leeway in seconds. Default 0. */
  leewaySeconds?: number;
  /** Restrict to one tenant, compared with `tenantIdsEqual`. */
  expectedTid?: string;
  /** Concrete `app:action` scopes ALL of which must be granted. */
  requiredScopes?: readonly string[];
  /** Reject tokens whose lifetime exceeds this. Default 24h. */
  maxTtlSeconds?: number;
}

function decodeSegment(segment: string): unknown {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function audienceMatches(aud: unknown, audience: string): boolean {
  if (typeof aud === "string") return aud === audience;
  if (Array.isArray(aud)) return aud.some((entry) => typeof entry === "string" && entry === audience);
  return false;
}

function claimsProblem(claims: Record<string, unknown>): string | null {
  if (typeof claims.iss !== "string" || claims.iss.length === 0) return "iss must be a non-empty string";
  if (typeof claims.sub !== "string" || claims.sub.length === 0) return "sub must be a non-empty string";
  if (typeof claims.jti !== "string" || claims.jti.length === 0) {
    return "jti must be a non-empty string (it is the revocation handle)";
  }
  if (!isValidTenantId(claims.tid)) return "tid must be a valid tenant id";
  if (!(PRINCIPAL_TYPES as readonly unknown[]).includes(claims.pt)) {
    return `pt must be one of ${PRINCIPAL_TYPES.join(", ")}`;
  }
  if (!Array.isArray(claims.scope) || claims.scope.some((entry) => typeof entry !== "string" || !isValidScope(entry))) {
    return "scope must be an array of valid '<app>:<action>' scopes";
  }
  if (!Number.isFinite(claims.iat as number)) return "iat must be a number";
  return null;
}

/**
 * Fully verify a fleet access token offline: header, signature, issuer,
 * audience, lifetime, tenant, and (optionally) scopes.
 *
 * Order is deliberate. The header is checked and the algorithm pinned BEFORE
 * any key is loaded, so an attacker-chosen `alg` never selects a code path.
 * The signature is checked before any claim is trusted. Tenant is checked
 * before scopes, so a wrong-organization token is never reported as merely
 * under-scoped.
 */
export function verifyFleetToken(token: string, options: VerifyFleetTokenOptions): IdentityVerifyResult {
  if (typeof token !== "string") {
    return { ok: false, reason: "malformed", message: "Token must be a string." };
  }
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    return { ok: false, reason: "malformed", message: "Token is not a compact JWS." };
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts as [string, string, string];

  const header = decodeSegment(headerSegment);
  if (!isRecord(header)) {
    return { ok: false, reason: "malformed", message: "Token header is not a JSON object." };
  }
  // Pin the algorithm before touching a key. `alg: "none"` and every
  // HMAC/RSA/ECDSA confusion variant die here.
  if (header.alg !== FLEET_TOKEN_ALG) {
    return {
      ok: false,
      reason: "unsupported_alg",
      message: `Token alg must be '${FLEET_TOKEN_ALG}'.`,
    };
  }
  if (header.typ !== undefined && header.typ !== FLEET_TOKEN_TYP) {
    return { ok: false, reason: "unsupported_typ", message: `Token typ must be '${FLEET_TOKEN_TYP}'.` };
  }
  if (typeof header.kid !== "string" || header.kid.length === 0) {
    return { ok: false, reason: "missing_kid", message: "Token header must carry a 'kid'." };
  }

  const usableKeys = options.jwks?.keys?.filter(isUsableEd25519Jwk) ?? [];
  if (usableKeys.length === 0) {
    // An empty key set must FAIL. Anything else is a verifier that accepts
    // everything the moment its configuration goes missing.
    return { ok: false, reason: "no_usable_key", message: "No usable Ed25519 key in the configured JWKS." };
  }
  const jwk = usableKeys.find((key) => key.kid === header.kid);
  if (!jwk) {
    return { ok: false, reason: "unknown_kid", message: "No configured key matches the token's 'kid'." };
  }

  let signatureValid = false;
  try {
    const publicKey = createPublicKey({ key: jwk as unknown as Record<string, unknown>, format: "jwk" });
    signatureValid = edVerify(
      null,
      Buffer.from(`${headerSegment}.${payloadSegment}`, "utf8"),
      publicKey,
      Buffer.from(signatureSegment, "base64url"),
    );
  } catch {
    return { ok: false, reason: "bad_signature", message: "Signature verification failed." };
  }
  if (!signatureValid) {
    return { ok: false, reason: "bad_signature", message: "Signature verification failed." };
  }

  const payload = decodeSegment(payloadSegment);
  if (!isRecord(payload)) {
    return { ok: false, reason: "malformed", message: "Token payload is not a JSON object." };
  }
  const problem = claimsProblem(payload);
  if (problem) {
    return { ok: false, reason: "invalid_claims", message: `Token claims are invalid: ${problem}.` };
  }
  const claims = payload as unknown as FleetTokenClaims;

  if (claims.iss !== options.issuer) {
    return { ok: false, reason: "issuer_mismatch", message: "Token was issued by a different issuer." };
  }
  if (!audienceMatches(claims.aud, options.audience)) {
    return { ok: false, reason: "audience_mismatch", message: "Token was issued for a different audience." };
  }

  // A missing or non-numeric `exp` is a REJECTION, never a skipped check.
  if (!Number.isFinite(claims.exp as unknown as number)) {
    return { ok: false, reason: "missing_expiry", message: "Token must carry a numeric 'exp'." };
  }
  const maxTtl = options.maxTtlSeconds ?? MAX_FLEET_TOKEN_TTL_SECONDS;
  if (claims.exp - claims.iat > maxTtl) {
    return {
      ok: false,
      reason: "excessive_ttl",
      message: `Token lifetime exceeds the ${maxTtl}s ceiling; offline verification cannot see a revocation, so the TTL is the revocation window.`,
    };
  }

  const now = Math.floor((options.nowMs ?? Date.now()) / 1000);
  const leeway = options.leewaySeconds ?? 0;
  if (now - leeway >= claims.exp) {
    return { ok: false, reason: "expired", message: "Token has expired." };
  }
  if (now + leeway < claims.iat) {
    return { ok: false, reason: "not_yet_valid", message: "Token is not yet valid." };
  }
  if (claims.nbf !== undefined) {
    if (!Number.isFinite(claims.nbf)) {
      return { ok: false, reason: "invalid_claims", message: "Token claims are invalid: nbf must be a number." };
    }
    if (now + leeway < claims.nbf) {
      return { ok: false, reason: "not_yet_valid", message: "Token is not yet valid." };
    }
  }

  const tid = canonicalizeTenantId(claims.tid);
  if (options.expectedTid !== undefined && !tenantIdsEqual(tid, options.expectedTid)) {
    return {
      ok: false,
      reason: "tenant_mismatch",
      message: isValidTenantId(options.expectedTid)
        ? "Token is for a different tenant than the one this service accepts."
        : "Token tenant cannot be checked: the expected tenant id is not a valid tenant id.",
    };
  }

  if (options.requiredScopes && options.requiredScopes.length > 0) {
    for (const required of options.requiredScopes) {
      if (!claims.scope.some((granted) => scopeMatches(granted, required))) {
        return { ok: false, reason: "insufficient_scope", message: `Missing required scope '${required}'.` };
      }
    }
  }

  return {
    ok: true,
    principal: {
      sub: claims.sub,
      tid,
      principalType: claims.pt,
      scopes: [...claims.scope],
      jti: claims.jti,
      kid: header.kid,
      issuer: claims.iss,
      audience: options.audience,
      expiresAt: new Date(claims.exp * 1000).toISOString(),
      claims,
    },
  };
}

// --- the seam ---

/**
 * How a service hands the verifier its key set. Async so an operator may back
 * it with a cache they refresh out of band; the kit never triggers a refresh
 * and never fetches. Returning a stale-but-valid key set is the operator's
 * call, and is exactly what "offline" means here.
 */
export type JwksSource = () => FleetJwks | Promise<FleetJwks>;

export interface IdentityProviderConfig {
  /** Expected `iss`. An opaque wire-contract string, not necessarily a URL. */
  issuer: string;
  /** Expected `aud` — this app's slug. */
  audience: string;
  /**
   * Where the operator's own refresher fetches the key set. RECORDED ONLY —
   * nothing in this module dereferences it.
   */
  jwksUri: string | null;
  leewaySeconds: number;
  maxTtlSeconds: number;
}

export interface IdentityVerifierOptions {
  /**
   * Revocation check keyed by `jti`: return true to DENY. Offline
   * verification cannot see a revocation on its own, so a service that needs
   * one supplies it here — the same shape as the API-key middleware's
   * `isRevoked(kid)`.
   */
  isRevoked?: (jti: string) => boolean | Promise<boolean>;
}

export interface IdentityAuthContext {
  expectedTid?: string;
  requiredScopes?: readonly string[];
}

export interface IdentityVerifier {
  verify(token: string, context?: IdentityAuthContext): Promise<IdentityVerifyResult>;
  readonly config: IdentityProviderConfig;
}

/**
 * Build the identity verifier a server mounts alongside — never instead of —
 * its in-repo API-key default.
 */
export function createIdentityVerifier(
  config: IdentityProviderConfig,
  jwksSource: JwksSource,
  options: IdentityVerifierOptions = {},
): IdentityVerifier {
  if (!config.issuer) throw new Error("createIdentityVerifier requires a non-empty 'issuer'.");
  if (!config.audience) throw new Error("createIdentityVerifier requires a non-empty 'audience'.");
  if (typeof jwksSource !== "function") {
    throw new Error("createIdentityVerifier requires a jwksSource function returning the key set.");
  }

  async function verify(token: string, context: IdentityAuthContext = {}): Promise<IdentityVerifyResult> {
    let jwks: FleetJwks;
    try {
      jwks = await jwksSource();
    } catch (error) {
      // A key set the operator cannot produce means DENY, never allow.
      const message = error instanceof Error ? error.message : String(error);
      return { ok: false, reason: "no_usable_key", message: `Could not resolve the JWKS: ${message}` };
    }

    const result = verifyFleetToken(token, {
      jwks,
      issuer: config.issuer,
      audience: config.audience,
      leewaySeconds: config.leewaySeconds,
      maxTtlSeconds: config.maxTtlSeconds,
      ...(context.expectedTid !== undefined ? { expectedTid: context.expectedTid } : {}),
      ...(context.requiredScopes !== undefined ? { requiredScopes: context.requiredScopes } : {}),
    });
    if (!result.ok) return result;

    if (options.isRevoked) {
      const revoked = await options.isRevoked(result.principal.jti);
      if (revoked) {
        return { ok: false, reason: "revoked", message: "Token has been revoked." };
      }
    }
    return result;
  }

  return { verify, config };
}

// --- tid -> org ---

/**
 * The `tid` -> org half of the seam. The token names a tenant in the ISSUER's
 * namespace; the service resolves it to one of its OWN organization rows. The
 * resolver returning `null` means "this issuer's tenant is not provisioned
 * here", which must DENY — a service that silently invents an org on an
 * unknown `tid` has no isolation boundary at all.
 */
export type TenantOrgResolver<Org> = (tid: string) => Org | null | Promise<Org | null>;

export type TenantOrgResolution<Org> =
  | { ok: true; org: Org; tid: string }
  | { ok: false; reason: "unknown_tenant"; message: string };

export async function resolveTenantOrg<Org>(
  principal: IdentityPrincipal,
  resolver: TenantOrgResolver<Org>,
): Promise<TenantOrgResolution<Org>> {
  const org = await resolver(principal.tid);
  if (org === null || org === undefined) {
    return {
      ok: false,
      reason: "unknown_tenant",
      message: "Token names a tenant that is not provisioned in this service.",
    };
  }
  return { ok: true, org, tid: principal.tid };
}

// --- configuration ---

export interface IdentityEnvKeys {
  issuerKeys: string[];
  audienceKeys: string[];
  jwksUriKeys: string[];
  /** Inline JWKS JSON — the fully-offline option, no refresher required. */
  jwksKeys: string[];
  leewayKeys: string[];
}

/**
 * Canonical env-key spec for the identity option, following the same
 * `HASNA_<NAME>_*` + `<NAME>_*` alias convention as `storageEnvKeys`.
 */
export function identityEnvKeys(name: string): IdentityEnvKeys {
  const token = envToken(name);
  return {
    issuerKeys: [`HASNA_${token}_IDENTITY_ISSUER`, `${token}_IDENTITY_ISSUER`],
    audienceKeys: [`HASNA_${token}_IDENTITY_AUDIENCE`, `${token}_IDENTITY_AUDIENCE`],
    jwksUriKeys: [`HASNA_${token}_IDENTITY_JWKS_URI`, `${token}_IDENTITY_JWKS_URI`],
    jwksKeys: [`HASNA_${token}_IDENTITY_JWKS`, `${token}_IDENTITY_JWKS`],
    leewayKeys: [`HASNA_${token}_IDENTITY_LEEWAY_SECONDS`, `${token}_IDENTITY_LEEWAY_SECONDS`],
  };
}

/**
 * Environment shape. Structurally identical to `Env` in `./mode`, spelled out
 * here rather than imported so this module stays off the Zod schema graph, and
 * NOT re-exported so the package root keeps a single `Env`.
 */
type IdentityEnv = Record<string, string | undefined>;

export type IdentityConfigResolution =
  | { enabled: false; reason: "unconfigured"; checkedKeys: string[] }
  | { enabled: false; reason: "invalid"; error: string; checkedKeys: string[] }
  | { enabled: true; config: IdentityProviderConfig; inlineJwks: FleetJwks | null; sources: Record<string, string> };

function firstEnv(env: IdentityEnv, keys: readonly string[]): { key: string; value: string } | null {
  for (const key of keys) {
    const value = env[key]?.trim();
    if (value) return { key, value };
  }
  return null;
}

/**
 * Resolve the identity option from the environment.
 *
 * Three outcomes, and the middle one is the point:
 *   * NOTHING set -> disabled. The server runs on its in-repo API-key default,
 *     which is what R2/R3 require: one repo, fully runnable, no vendor
 *     endpoint and no vendor default. There is deliberately NO default issuer
 *     and NO default JWKS URI.
 *   * PARTIALLY set -> `invalid`, naming the missing variable. A half-configured
 *     identity option must NOT silently degrade to "API keys only": an operator
 *     who set an issuer believes tokens are being checked.
 *   * Fully set -> enabled.
 *
 * `audience` defaults to the app name, because the issuer stamps `aud` with the
 * app slug; it is overridable for services whose slug differs from their name.
 */
export function resolveIdentityConfig(name: string, env: IdentityEnv = process.env as IdentityEnv): IdentityConfigResolution {
  const keys = identityEnvKeys(name);
  const checkedKeys = [...keys.issuerKeys, ...keys.audienceKeys, ...keys.jwksUriKeys, ...keys.jwksKeys];

  const issuer = firstEnv(env, keys.issuerKeys);
  const audience = firstEnv(env, keys.audienceKeys);
  const jwksUri = firstEnv(env, keys.jwksUriKeys);
  const inline = firstEnv(env, keys.jwksKeys);
  const leeway = firstEnv(env, keys.leewayKeys);

  if (!issuer && !audience && !jwksUri && !inline) {
    return { enabled: false, reason: "unconfigured", checkedKeys };
  }

  const invalid = (error: string): IdentityConfigResolution => ({
    enabled: false,
    reason: "invalid",
    error,
    checkedKeys,
  });

  if (!issuer) {
    return invalid(`Identity option is partially configured: set ${keys.issuerKeys[0]} (expected token 'iss').`);
  }
  if (!jwksUri && !inline) {
    return invalid(
      `Identity option is partially configured: set ${keys.jwksUriKeys[0]} (fetched out of band by your own refresher) or ${keys.jwksKeys[0]} (inline JWKS JSON).`,
    );
  }

  let inlineJwks: FleetJwks | null = null;
  if (inline) {
    const parsed = parseFleetJwks(inline.value);
    if (!parsed.ok) return invalid(`${inline.key} is not a usable JWKS: ${parsed.message}`);
    inlineJwks = parsed.jwks;
  }

  if (jwksUri) {
    const uriProblem = jwksUriProblem(jwksUri.value);
    if (uriProblem) return invalid(`${jwksUri.key} is not a usable JWKS URI: ${uriProblem}`);
  }

  let leewaySeconds = 0;
  if (leeway) {
    const parsed = Number(leeway.value);
    if (!Number.isFinite(parsed) || parsed < 0) {
      return invalid(`${leeway.key} must be a non-negative number of seconds.`);
    }
    leewaySeconds = Math.floor(parsed);
  }

  const sources: Record<string, string> = { issuer: issuer.key };
  if (audience) sources.audience = audience.key;
  if (jwksUri) sources.jwksUri = jwksUri.key;
  if (inline) sources.jwks = inline.key;
  if (leeway) sources.leewaySeconds = leeway.key;

  return {
    enabled: true,
    config: {
      issuer: issuer.value,
      audience: audience?.value ?? name,
      jwksUri: jwksUri?.value ?? null,
      leewaySeconds,
      maxTtlSeconds: MAX_FLEET_TOKEN_TTL_SECONDS,
    },
    inlineJwks,
    sources,
  };
}

/**
 * Reject a JWKS URI that no operator should be configuring.
 *
 * Scoped deliberately: this module NEVER dereferences the URI, so it does not
 * need — and must not import — the full parser-confusion defence in
 * `src/client/transport.ts` (`toV1BaseUrl`), which exists because that code
 * sends an API key to the authority it parses. Importing it would drag the HTTP
 * transport into this module's graph and destroy the offline-by-construction
 * property. What is checked here is what a *recorded* value must satisfy:
 * absolute, transport-secure, no embedded credentials, no control characters.
 */
function jwksUriProblem(value: string): string | null {
  if (/[\u0000-\u001f\u007f]/.test(value)) return "it contains control characters";
  if (/\s/.test(value)) return "it contains whitespace";
  const match = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)/i.exec(value);
  if (!match) return "it must be an absolute URL";
  const scheme = match[1]!.toLowerCase();
  const authority = match[2]!;
  if (!authority) return "it must include a host";
  if (authority.includes("@")) return "it must not embed credentials";
  if (!isPlausibleAuthority(authority)) return "its host is not a plain hostname, IPv4, or bracketed IPv6 with an optional port";
  const isLoopback = /^(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]+)?$/i.test(authority);
  if (scheme === "https") return null;
  if (scheme === "http" && isLoopback) return null;
  return "it must use https (http is accepted only for an exact loopback host)";
}

/** `host[:port]` where host is a DNS name, an IPv4 literal, or `[IPv6]`. */
function isPlausibleAuthority(authority: string): boolean {
  const match = /^(\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)(?::([0-9]{1,5}))?$/i.exec(
    authority,
  );
  if (!match) return false;
  if (match[2] === undefined) return true;
  const port = Number(match[2]);
  return port >= 1 && port <= 65_535 && String(port) === match[2];
}
