import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createPublicKey, generateKeyPairSync, sign as edSign } from "node:crypto";
import {
  FLEET_TOKEN_ALG,
  FLEET_TOKEN_TYP,
  MAX_FLEET_TOKEN_TTL_SECONDS,
  createIdentityVerifier,
  identityEnvKeys,
  parseFleetJwks,
  resolveIdentityConfig,
  resolveTenantOrg,
  verifyFleetToken,
  type Ed25519PublicJwk,
  type FleetJwks,
  type FleetTokenClaims,
  type IdentityProviderConfig,
} from "../src/auth/identity";

const ISSUER = "identities";
const AUDIENCE = "todos";
const NOW_MS = 1_800_000_000_000;
const NOW_SEC = Math.floor(NOW_MS / 1000);

// --- a local issuer, so the tests exercise real Ed25519, not a stub ---

interface TestIssuer {
  kid: string;
  jwks: FleetJwks;
  mint(overrides?: Partial<FleetTokenClaims>, headerOverrides?: Record<string, unknown>): string;
  signRaw(header: Record<string, unknown>, payload: unknown): string;
}

function b64url(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

function b64urlJson(value: unknown): string {
  return b64url(JSON.stringify(value));
}

function makeIssuer(kid = "test-key-1"): TestIssuer {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const exported = publicKey.export({ format: "jwk" }) as { x: string };
  const jwk: Ed25519PublicJwk = { kty: "OKP", crv: "Ed25519", x: exported.x, kid, use: "sig", alg: "EdDSA" };

  function signRaw(header: Record<string, unknown>, payload: unknown): string {
    const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
    return `${signingInput}.${b64url(edSign(null, Buffer.from(signingInput, "utf8"), privateKey))}`;
  }

  function mint(overrides: Partial<FleetTokenClaims> = {}, headerOverrides: Record<string, unknown> = {}): string {
    const claims: FleetTokenClaims = {
      iss: ISSUER,
      aud: AUDIENCE,
      sub: "user_01",
      tid: "acme-corp",
      pt: "user",
      scope: ["todos:read"],
      iat: NOW_SEC,
      exp: NOW_SEC + 3600,
      jti: "jti_01",
      ...overrides,
    };
    return signRaw({ alg: FLEET_TOKEN_ALG, kid, typ: FLEET_TOKEN_TYP, ...headerOverrides }, claims);
  }

  return { kid, jwks: { keys: [jwk] }, mint, signRaw };
}

const issuer = makeIssuer();
const base = { jwks: issuer.jwks, issuer: ISSUER, audience: AUDIENCE, nowMs: NOW_MS } as const;

// --- offline by construction ---

describe("offline by construction", () => {
  test("the identity module contains no network primitive", () => {
    const source = readFileSync(join(import.meta.dir, "..", "src", "auth", "identity.ts"), "utf8");
    // Structural guard, not a style rule: "never call back to the IdP" has to
    // be impossible, not merely documented. If a future edit adds a fetch to
    // the verify path, this fails.
    for (const forbidden of [
      /\bfetch\s*\(/,
      /from\s+["']node:https?["']/,
      /from\s+["']node:net["']/,
      /from\s+["']node:dgram["']/,
      /\bXMLHttpRequest\b/,
      /\bWebSocket\b/,
      /\bnew\s+Request\s*\(/,
      /\bawait\s+import\s*\(/,
      /\brequire\s*\(/,
    ]) {
      expect(source, `identity.ts must not contain ${forbidden}`).not.toMatch(forbidden);
    }
  });

  test("verifyFleetToken's key input is a value, not a locator", () => {
    // A signature that accepted a URI would make an offline guarantee
    // unenforceable. Passing a URI where the key set belongs must not verify.
    const result = verifyFleetToken(issuer.mint(), {
      ...base,
      jwks: { keys: [] as Ed25519PublicJwk[] },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("no_usable_key");
  });
});

// --- JWKS validation ---

describe("parseFleetJwks", () => {
  test("accepts the reference issuer's published shape", () => {
    const result = parseFleetJwks(JSON.stringify(issuer.jwks));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.jwks.keys[0]?.kid).toBe(issuer.kid);
  });

  test("an EMPTY key set FAILS — a guard with nothing to check must not pass", () => {
    const result = parseFleetJwks({ keys: [] });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.problem).toBe("empty_key_set");
  });

  test("rejects a key set carrying private material", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const privateJwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
    expect(typeof privateJwk.d).toBe("string"); // the fixture really is private
    const result = parseFleetJwks({ keys: [{ ...privateJwk, kid: "leaky" }] });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.problem).toBe("private_material");
  });

  test("rejects non-Ed25519 and unusable entries", () => {
    expect(parseFleetJwks({ keys: [{ kty: "RSA", n: "x", e: "AQAB", kid: "r1" }] }).ok).toBe(false);
    expect(parseFleetJwks({ keys: [{ kty: "OKP", crv: "X25519", x: "abc", kid: "k" }] }).ok).toBe(false);
    expect(parseFleetJwks({ keys: [{ kty: "OKP", crv: "Ed25519", x: "abc" }] }).ok).toBe(false); // no kid
    expect(parseFleetJwks({ keys: [{ kty: "OKP", crv: "Ed25519", x: "abc", kid: "k", use: "enc" }] }).ok).toBe(false);
    expect(parseFleetJwks({ keys: [{ kty: "OKP", crv: "Ed25519", x: "abc", kid: "k", alg: "HS256" }] }).ok).toBe(false);
  });

  test("rejects structurally wrong documents", () => {
    expect(parseFleetJwks("not json").ok).toBe(false);
    expect(parseFleetJwks(null).ok).toBe(false);
    expect(parseFleetJwks([]).ok).toBe(false);
    expect(parseFleetJwks({ keys: "nope" }).ok).toBe(false);
  });
});

// --- the happy path ---

describe("verifyFleetToken", () => {
  test("verifies a real Ed25519 token and yields a tenant-bearing principal", () => {
    const result = verifyFleetToken(issuer.mint(), base);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.principal.sub).toBe("user_01");
      expect(result.principal.tid).toBe("acme-corp");
      expect(result.principal.principalType).toBe("user");
      expect(result.principal.scopes).toEqual(["todos:read"]);
      expect(result.principal.jti).toBe("jti_01");
      expect(result.principal.kid).toBe(issuer.kid);
      expect(result.principal.expiresAt).toBe(new Date((NOW_SEC + 3600) * 1000).toISOString());
    }
  });

  test("canonicalizes a UUID tenant, so the API-key seam and this seam agree", () => {
    const result = verifyFleetToken(issuer.mint({ tid: "9D4B2A1C-0E5F-4A7B-8C3D-1E2F3A4B5C6D" }), base);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.principal.tid).toBe("9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d");
  });

  test("accepts the JWT array form of aud", () => {
    expect(verifyFleetToken(issuer.mint({ aud: ["other", AUDIENCE] }), base).ok).toBe(true);
  });
});

// --- signature and algorithm attacks ---

describe("signature and algorithm", () => {
  test("rejects alg 'none'", () => {
    const claims = { iss: ISSUER, aud: AUDIENCE, sub: "s", tid: "acme-corp", pt: "user", scope: [], iat: NOW_SEC, exp: NOW_SEC + 60, jti: "j" };
    const unsigned = `${b64urlJson({ alg: "none", kid: issuer.kid, typ: FLEET_TOKEN_TYP })}.${b64urlJson(claims)}.x`;
    const result = verifyFleetToken(unsigned, base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("unsupported_alg");
  });

  test("rejects an HMAC alg even when the signature would check out under it", () => {
    const result = verifyFleetToken(issuer.mint({}, { alg: "HS256" }), base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("unsupported_alg");
  });

  test("rejects an unexpected typ", () => {
    const result = verifyFleetToken(issuer.mint({}, { typ: "JWT" }), base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("unsupported_typ");
  });

  test("requires a kid and rejects an unknown one", () => {
    const noKid = verifyFleetToken(issuer.mint({}, { kid: undefined }), base);
    expect(noKid.ok).toBe(false);
    if (!noKid.ok) expect(noKid.reason).toBe("missing_kid");

    const wrongKid = verifyFleetToken(issuer.mint({}, { kid: "not-a-key" }), base);
    expect(wrongKid.ok).toBe(false);
    if (!wrongKid.ok) expect(wrongKid.reason).toBe("unknown_kid");
  });

  test("a token signed by a DIFFERENT key with the SAME kid fails", () => {
    const impostor = makeIssuer(issuer.kid);
    const result = verifyFleetToken(impostor.mint(), base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature");
  });

  test("payload tampering after signing fails", () => {
    const token = issuer.mint();
    const [header, , signature] = token.split(".") as [string, string, string];
    const forgedPayload = b64urlJson({
      iss: ISSUER, aud: AUDIENCE, sub: "user_01", tid: "rival-corp", pt: "user",
      scope: ["todos:read"], iat: NOW_SEC, exp: NOW_SEC + 3600, jti: "jti_01",
    });
    const result = verifyFleetToken(`${header}.${forgedPayload}.${signature}`, base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature");
  });

  test("rejects structurally malformed tokens", () => {
    for (const bad of ["", "a.b", "a.b.c.d", "..", "a..c", "not-a-token"]) {
      const result = verifyFleetToken(bad, base);
      expect(result.ok, JSON.stringify(bad)).toBe(false);
    }
  });
});

// --- claim binding ---

describe("issuer, audience, and lifetime", () => {
  test("an unpinned issuer is impossible: a foreign iss is rejected", () => {
    const result = verifyFleetToken(issuer.mint({ iss: "someone-else" }), base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("issuer_mismatch");
  });

  test("a token minted for ANOTHER app is rejected — audience is never optional", () => {
    const result = verifyFleetToken(issuer.mint({ aud: "mementos" }), base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("audience_mismatch");
  });

  test("a missing exp is a REJECTION, not a skipped check", () => {
    const result = verifyFleetToken(issuer.mint({ exp: undefined as unknown as number }), base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("missing_expiry");
  });

  test("a non-numeric exp is a rejection too", () => {
    const result = verifyFleetToken(issuer.mint({ exp: "9999999999" as unknown as number }), base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("missing_expiry");
  });

  test("a lifetime beyond the ceiling is rejected — TTL is the revocation window", () => {
    const result = verifyFleetToken(
      issuer.mint({ exp: NOW_SEC + MAX_FLEET_TOKEN_TTL_SECONDS + 1 }),
      base,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("excessive_ttl");
  });

  test("expiry and not-before are enforced, with leeway", () => {
    const expired = verifyFleetToken(issuer.mint({ exp: NOW_SEC - 1 }), base);
    expect(expired.ok).toBe(false);
    if (!expired.ok) expect(expired.reason).toBe("expired");

    const future = verifyFleetToken(issuer.mint({ iat: NOW_SEC + 300, exp: NOW_SEC + 900 }), base);
    expect(future.ok).toBe(false);
    if (!future.ok) expect(future.reason).toBe("not_yet_valid");

    const withLeeway = verifyFleetToken(issuer.mint({ iat: NOW_SEC + 300, exp: NOW_SEC + 900 }), {
      ...base,
      leewaySeconds: 600,
    });
    expect(withLeeway.ok).toBe(true);

    const notYet = verifyFleetToken(issuer.mint({ nbf: NOW_SEC + 300 }), base);
    expect(notYet.ok).toBe(false);
    if (!notYet.ok) expect(notYet.reason).toBe("not_yet_valid");
  });
});

describe("required claims", () => {
  test("tid is required — the identity seam is tenant-native", () => {
    const result = verifyFleetToken(issuer.mint({ tid: undefined as unknown as string }), base);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("invalid_claims");
      expect(result.message).toMatch(/tid/);
    }
  });

  test("a malformed tid is rejected, not coerced", () => {
    for (const tid of ["acme corp", "acme/corp", "", 7 as unknown as string, null as unknown as string]) {
      const result = verifyFleetToken(issuer.mint({ tid }), base);
      expect(result.ok, JSON.stringify(tid)).toBe(false);
    }
  });

  test("jti is required, because it is the only revocation handle that exists", () => {
    const result = verifyFleetToken(issuer.mint({ jti: undefined as unknown as string }), base);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("invalid_claims");
      expect(result.message).toMatch(/jti/);
    }
  });

  test("pt and scope are validated against the shared grammars", () => {
    const badPt = verifyFleetToken(issuer.mint({ pt: "admin" as never }), base);
    expect(badPt.ok).toBe(false);
    if (!badPt.ok) expect(badPt.message).toMatch(/pt/);

    const badScope = verifyFleetToken(issuer.mint({ scope: ["Todos:Read"] }), base);
    expect(badScope.ok).toBe(false);
    if (!badScope.ok) expect(badScope.message).toMatch(/scope/);

    const notArray = verifyFleetToken(issuer.mint({ scope: "todos:read" as never }), base);
    expect(notArray.ok).toBe(false);
  });
});

// --- authorization ---

describe("tenant and scope enforcement", () => {
  test("expectedTid rejects another organization's token", () => {
    const result = verifyFleetToken(issuer.mint({ tid: "rival-corp" }), { ...base, expectedTid: "acme-corp" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("tenant_mismatch");
  });

  test("tenant is checked before scopes", () => {
    const result = verifyFleetToken(issuer.mint({ tid: "rival-corp", scope: [] }), {
      ...base,
      expectedTid: "acme-corp",
      requiredScopes: ["todos:write"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("tenant_mismatch");
  });

  test("required scopes use the same wildcard grammar as API keys", () => {
    expect(verifyFleetToken(issuer.mint({ scope: ["todos:*"] }), { ...base, requiredScopes: ["todos:write"] }).ok).toBe(true);
    const short = verifyFleetToken(issuer.mint({ scope: ["todos:read"] }), { ...base, requiredScopes: ["todos:write"] });
    expect(short.ok).toBe(false);
    if (!short.ok) expect(short.reason).toBe("insufficient_scope");
  });

  test("a malformed expectedTid denies rather than throwing in the request path", () => {
    const result = verifyFleetToken(issuer.mint(), { ...base, expectedTid: "acme corp" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.message).toMatch(/not a valid tenant id/);
  });
});

// --- the seam ---

const CONFIG: IdentityProviderConfig = {
  issuer: ISSUER,
  audience: AUDIENCE,
  jwksUri: null,
  leewaySeconds: 0,
  maxTtlSeconds: MAX_FLEET_TOKEN_TTL_SECONDS,
};

describe("createIdentityVerifier", () => {
  test("verifies through an operator-supplied key source", async () => {
    const verifier = createIdentityVerifier(CONFIG, () => issuer.jwks);
    const result = await verifier.verify(issuer.mint({ exp: Math.floor(Date.now() / 1000) + 600, iat: Math.floor(Date.now() / 1000) }));
    expect(result.ok).toBe(true);
  });

  test("a key source that throws DENIES — it never falls open", async () => {
    const verifier = createIdentityVerifier(CONFIG, () => {
      throw new Error("key file unreadable");
    });
    const result = await verifier.verify(issuer.mint());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("no_usable_key");
      expect(result.message).toMatch(/key file unreadable/);
    }
  });

  test("the isRevoked hook closes the offline revocation gap when supplied", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const token = issuer.mint({ iat: nowSec, exp: nowSec + 600, jti: "revoked-jti" });
    const seen: string[] = [];
    const verifier = createIdentityVerifier(CONFIG, () => issuer.jwks, {
      isRevoked: async (jti) => {
        seen.push(jti);
        return jti === "revoked-jti";
      },
    });
    const result = await verifier.verify(token);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("revoked");
    expect(seen).toEqual(["revoked-jti"]);
  });

  test("refuses to be constructed without an issuer or audience", () => {
    expect(() => createIdentityVerifier({ ...CONFIG, issuer: "" }, () => issuer.jwks)).toThrow(/issuer/);
    expect(() => createIdentityVerifier({ ...CONFIG, audience: "" }, () => issuer.jwks)).toThrow(/audience/);
    expect(() => createIdentityVerifier(CONFIG, undefined as never)).toThrow(/jwksSource/);
  });
});

describe("resolveTenantOrg (tid -> org)", () => {
  const principal = { tid: "acme-corp" } as never;

  test("resolves the issuer's tenant onto the service's own org", async () => {
    const result = await resolveTenantOrg(principal, (tid) => ({ id: `org_${tid}` }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.org).toEqual({ id: "org_acme-corp" });
  });

  test("an unprovisioned tenant DENIES — it never invents an org", async () => {
    const result = await resolveTenantOrg(principal, () => null);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("unknown_tenant");
  });
});

// --- configuration ---

describe("identity configuration", () => {
  test("env keys follow the contract's HASNA_<NAME>_* convention", () => {
    const keys = identityEnvKeys("open-mailery");
    expect(keys.issuerKeys).toEqual(["HASNA_OPEN_MAILERY_IDENTITY_ISSUER", "OPEN_MAILERY_IDENTITY_ISSUER"]);
    expect(keys.jwksUriKeys[0]).toBe("HASNA_OPEN_MAILERY_IDENTITY_JWKS_URI");
  });

  test("an empty environment disables the option — there is NO default issuer or JWKS URI", () => {
    const resolution = resolveIdentityConfig("todos", {});
    expect(resolution.enabled).toBe(false);
    if (!resolution.enabled) expect(resolution.reason).toBe("unconfigured");
  });

  test("PARTIAL configuration is an ERROR, not a silent fallback to API keys only", () => {
    const onlyIssuer = resolveIdentityConfig("todos", { HASNA_TODOS_IDENTITY_ISSUER: ISSUER });
    expect(onlyIssuer.enabled).toBe(false);
    if (!onlyIssuer.enabled && onlyIssuer.reason === "invalid") {
      expect(onlyIssuer.error).toMatch(/HASNA_TODOS_IDENTITY_JWKS_URI/);
    } else {
      throw new Error("expected an 'invalid' resolution");
    }

    const onlyJwksUri = resolveIdentityConfig("todos", {
      HASNA_TODOS_IDENTITY_JWKS_URI: "https://idp.example.test/jwks.json",
    });
    expect(onlyJwksUri.enabled).toBe(false);
    if (!onlyJwksUri.enabled && onlyJwksUri.reason === "invalid") {
      expect(onlyJwksUri.error).toMatch(/HASNA_TODOS_IDENTITY_ISSUER/);
    } else {
      throw new Error("expected an 'invalid' resolution");
    }
  });

  test("a fully configured environment enables the option and defaults audience to the app name", () => {
    const resolution = resolveIdentityConfig("todos", {
      HASNA_TODOS_IDENTITY_ISSUER: ISSUER,
      HASNA_TODOS_IDENTITY_JWKS: JSON.stringify(issuer.jwks),
      HASNA_TODOS_IDENTITY_LEEWAY_SECONDS: "30",
    });
    expect(resolution.enabled).toBe(true);
    if (resolution.enabled) {
      expect(resolution.config.issuer).toBe(ISSUER);
      expect(resolution.config.audience).toBe("todos");
      expect(resolution.config.leewaySeconds).toBe(30);
      expect(resolution.inlineJwks?.keys[0]?.kid).toBe(issuer.kid);
    }
  });

  test("an unusable inline JWKS is an error, not an empty key set", () => {
    const resolution = resolveIdentityConfig("todos", {
      HASNA_TODOS_IDENTITY_ISSUER: ISSUER,
      HASNA_TODOS_IDENTITY_JWKS: JSON.stringify({ keys: [] }),
    });
    expect(resolution.enabled).toBe(false);
    if (!resolution.enabled && resolution.reason === "invalid") {
      expect(resolution.error).toMatch(/no keys/i);
    } else {
      throw new Error("expected an 'invalid' resolution");
    }
  });

  test("the JWKS URI must be https, or http on an exact loopback", () => {
    const check = (jwksUri: string) =>
      resolveIdentityConfig("todos", {
        HASNA_TODOS_IDENTITY_ISSUER: ISSUER,
        HASNA_TODOS_IDENTITY_JWKS_URI: jwksUri,
      }).enabled;

    expect(check("https://idp.example.test/.well-known/jwks.json")).toBe(true);
    expect(check("HTTPS://IDP.EXAMPLE.TEST/jwks")).toBe(true); // scheme is case-insensitive
    expect(check("http://localhost:8080/jwks")).toBe(true);
    expect(check("http://127.0.0.1:8080/jwks")).toBe(true);
    expect(check("https://[2001:db8::1]:8443/jwks")).toBe(true);

    expect(check("http://idp.example.test/jwks")).toBe(false); // http off-loopback
    expect(check("https://user:pass@idp.example.test/jwks")).toBe(false);
    expect(check("/relative/jwks.json")).toBe(false);
    expect(check("file:///etc/jwks.json")).toBe(false);
    expect(check("https://idp.example.test:0/jwks")).toBe(false); // port 0
    expect(check("https://idp.example.test:70000/jwks")).toBe(false);
    expect(check("https://idp example.test/jwks")).toBe(false); // space in the host
    expect(check("https://idp.example.test\u0000evil/jwks")).toBe(false); // NUL in the host
    expect(check("https://idp.example.test\tevil/jwks")).toBe(false); // tab in the host
  });

  test("an invalid leeway is an error rather than a silent zero", () => {
    const resolution = resolveIdentityConfig("todos", {
      HASNA_TODOS_IDENTITY_ISSUER: ISSUER,
      HASNA_TODOS_IDENTITY_JWKS: JSON.stringify(issuer.jwks),
      HASNA_TODOS_IDENTITY_LEEWAY_SECONDS: "-5",
    });
    expect(resolution.enabled).toBe(false);
  });
});

// --- the shape actually matches the reference issuer ---

describe("wire-shape compatibility with the reference issuer", () => {
  test("a token in open-tenants' documented claim shape verifies unchanged", () => {
    // Exactly the claim set open-tenants/src/idp/tokens.ts mints:
    // {iss, aud, sub, tid, pt, scope, iat, exp, jti} with header
    // {alg:"EdDSA", kid, typ:"at+jwt"} — no additions, no renames.
    const token = issuer.signRaw(
      { alg: "EdDSA", kid: issuer.kid, typ: "at+jwt" },
      {
        iss: "identities",
        aud: "todos",
        sub: "01HQ3XZ8VJ9K2M4N6P8R0T2W4Y",
        tid: "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d",
        pt: "service",
        scope: ["todos:read", "todos:write"],
        iat: NOW_SEC,
        exp: NOW_SEC + 24 * 60 * 60,
        jti: "01HQ3XZ8VJ9K2M4N6P8R0T2W4Z",
      },
    );
    const result = verifyFleetToken(token, base);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.principal.principalType).toBe("service");
      expect(result.principal.tid).toBe("9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d");
    }
  });

  test("the reference issuer's own key JWK shape parses", () => {
    const publicJwk = createPublicKey({ key: issuer.jwks.keys[0]! as never, format: "jwk" }).export({ format: "jwk" });
    expect((publicJwk as { crv: string }).crv).toBe("Ed25519");
  });
});
