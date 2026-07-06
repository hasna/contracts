// Core API-key crypto for Hasna: stateless, verifiable, HMAC-signed tokens.
//
// A key is a compact, self-describing signed token:
//
//   hasna_<app>_<body>.<sig>
//
//   <app>  = app slug ([a-z][a-z0-9-]*), also embedded in the signed claims
//   <body> = base64url(JSON claims) — { v, kid, app, scopes, iat, exp, agent? }
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

/** Token wire-format version. Bump only on a breaking format change. */
export const API_KEY_TOKEN_VERSION = 1;

/** Literal token namespace prefix. */
export const API_KEY_NAMESPACE = "hasna";

/** App slug grammar shared by the token prefix and claims. */
export const APP_SLUG_PATTERN = /^[a-z][a-z0-9-]*$/;

/** Full-token structural matcher: hasna_<app>_<body>.<sig>. */
const TOKEN_PATTERN = /^hasna_([a-z][a-z0-9-]*)_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;

/** Default TTL applied when a caller does not specify one: 90 days. */
export const DEFAULT_API_KEY_TTL_SECONDS = 90 * 24 * 60 * 60;

export interface ApiKeyClaims {
  /** Token format version. */
  v: number;
  /** Key id — stable identifier used for revocation and record lookup. */
  kid: string;
  /** App slug the key authenticates against. */
  app: string;
  /** Granted scopes (`<app>:<action>` or wildcards). */
  scopes: string[];
  /** Issued-at, epoch seconds. */
  iat: number;
  /** Expiry, epoch seconds; `null` means the key never expires. */
  exp: number | null;
  /** Optional issued-to agent/subject (informational). */
  agent?: string;
}

export interface MintApiKeyOptions {
  app: string;
  scopes: string[];
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
  const app = options.app.trim();
  if (!APP_SLUG_PATTERN.test(app)) {
    throw new Error(`Invalid app slug '${options.app}'. Expected ${APP_SLUG_PATTERN}.`);
  }
  if (!Array.isArray(options.scopes) || options.scopes.length === 0) {
    throw new Error("At least one scope is required to mint an API key.");
  }
  for (const scope of options.scopes) {
    if (!isValidScope(scope)) {
      throw new Error(`Invalid scope '${scope}'. Expected '*' or '<app>:<action>'.`);
    }
  }
  const secret = toBuffer(options.signingSecret);
  if (secret.length < 16) {
    throw new Error("signingSecret must be at least 16 bytes of entropy.");
  }

  const kid = options.kid ?? generateKid();
  if (!/^[A-Za-z0-9_-]+$/.test(kid)) {
    throw new Error(`Invalid kid '${kid}'. Expected url-safe characters only.`);
  }

  const nowMs = options.nowMs ?? Date.now();
  const iat = Math.floor(nowMs / 1000);
  const ttl = options.ttlSeconds === undefined ? DEFAULT_API_KEY_TTL_SECONDS : options.ttlSeconds;
  if (ttl !== null && (!Number.isFinite(ttl) || ttl <= 0)) {
    throw new Error("ttlSeconds must be a positive number or null (no expiry).");
  }
  const exp = ttl === null ? null : iat + Math.floor(ttl);

  const claims: ApiKeyClaims = {
    v: API_KEY_TOKEN_VERSION,
    kid,
    app,
    scopes: [...options.scopes],
    iat,
    exp,
    ...(options.agent !== undefined ? { agent: options.agent } : {}),
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
    !Array.isArray(claims.scopes)
  ) {
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
  | "insufficient_scope";

export type ApiKeyVerifyResult =
  | { ok: true; claims: ApiKeyClaims; kid: string; app: string }
  | { ok: false; reason: ApiKeyVerifyFailureReason; message: string };

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
}

/**
 * Fully verify a token's authenticity, TTL, app binding, and (optionally)
 * scopes. Stateless — no revocation lookup. Layer revocation on top via the
 * store/middleware. Constant-time on the signature comparison.
 */
export function verifyApiKeyToken(token: string, options: VerifyApiKeyTokenOptions): ApiKeyVerifyResult {
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
  if (options.expectedApp !== undefined && app !== options.expectedApp) {
    return { ok: false, reason: "app_mismatch", message: `Token is for app '${app}', expected '${options.expectedApp}'.` };
  }

  const expected = hmac(options.signingSecret, `${apiKeyPrefix(app)}${body}`);
  let provided: Buffer;
  try {
    provided = Buffer.from(sig, "base64url");
  } catch {
    return { ok: false, reason: "bad_signature", message: "Signature is not valid base64url." };
  }
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return { ok: false, reason: "bad_signature", message: "Signature verification failed." };
  }

  const now = Math.floor((options.nowMs ?? Date.now()) / 1000);
  const leeway = options.leewaySeconds ?? 0;
  if (typeof claims.iat === "number" && now + leeway < claims.iat) {
    return { ok: false, reason: "not_yet_valid", message: "Token is not yet valid." };
  }
  if (claims.exp !== null && typeof claims.exp === "number" && now - leeway >= claims.exp) {
    return { ok: false, reason: "expired", message: "Token has expired." };
  }

  if (options.requiredScopes && options.requiredScopes.length > 0) {
    // Local import avoided to keep the crypto module leaf; inline the check.
    const granted = claims.scopes;
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
    for (const required of options.requiredScopes) {
      if (!satisfies(required)) {
        return { ok: false, reason: "insufficient_scope", message: `Missing required scope '${required}'.` };
      }
    }
  }

  return { ok: true, claims, kid: claims.kid, app };
}
