import { describe, expect, test } from "bun:test";
import { createHmac, generateKeyPairSync, sign as edSign } from "node:crypto";
import {
  API_KEY_TOKEN_VERSION,
  apiKeyPrefix,
  mintApiKey,
  parseApiKey,
  verifyApiKeyToken,
} from "../src/auth/keys";
import {
  FLEET_TOKEN_ALG,
  FLEET_TOKEN_TYP,
  verifyFleetToken,
  type Ed25519PublicJwk,
  type FleetJwks,
} from "../src/auth/identity";

const SIGNING = "test-signing-secret-not-a-real-credential-000";

/**
 * The value an attacker with an `Object.prototype` write primitive plants.
 *
 * A wildcard, because that is the worst case for this particular claim: `*`
 * satisfies every `requiredScopes` check in the kit, so if a scope read walks
 * the prototype the answer is "authorized for everything" rather than merely
 * "authorized for something wrong".
 */
const POLLUTED_SCOPES = ["*"];

function b64url(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

/**
 * Sign an arbitrary claims body with the real HMAC construction from
 * `keys.ts` — same prefix, same signing input, same base64url encoding.
 *
 * This exists because `mintApiKey` cannot produce the body under test: it
 * refuses fewer than one scope and always writes `scopes` as an OWN property,
 * which is exactly why this defect is not reachable through a token this kit
 * mints. The signed-but-scopeless body is still a body the VERIFIER can be
 * handed — by an older minter, a sibling implementation, a hand-rolled
 * issuance path, or a body built from a `JSON.parse` that dropped the key —
 * and the verifier is what these tests are about.
 */
function signClaims(app: string, claims: Record<string, unknown>): string {
  const body = b64url(JSON.stringify(claims));
  const signingInput = `${apiKeyPrefix(app)}${body}`;
  const sig = b64url(createHmac("sha256", Buffer.from(SIGNING, "utf8")).update(signingInput, "utf8").digest());
  return `${signingInput}.${sig}`;
}

/** A validly signed token whose body carries NO `scopes` key at all. */
function scopelessToken(app = "todos"): string {
  const claims: Record<string, unknown> = {
    v: API_KEY_TOKEN_VERSION,
    kid: "scopelesskid001",
    app,
    iat: Math.floor(Date.now() / 1000) - 60,
    exp: null,
  };
  expect(Object.hasOwn(claims, "scopes")).toBe(false);
  return signClaims(app, claims);
}

/**
 * Run `fn` with `Object.prototype.scopes` and `Object.prototype.scope` set,
 * then remove both.
 *
 * Both names are planted together because the two token families spell the
 * claim differently — the HMAC API-key path reads `scopes` (plural) and the
 * Ed25519 fleet-token path reads `scope` (singular) — and a fix that guards
 * one while leaving the other is the whole reason these live in one file.
 *
 * Non-enumerable so the planted keys cannot leak into unrelated `for...in`
 * loops while staying visible to the prototype-chain reads under test; those
 * reads are identical either way.
 *
 * Restored in a `finally` so pollution cannot escape into sibling tests. A
 * polluted prototype leaking into the rest of the suite is its own outage.
 */
async function withPollutedScopePrototype<T>(fn: () => T | Promise<T>): Promise<T> {
  for (const key of ["scopes", "scope"] as const) {
    Object.defineProperty(Object.prototype, key, {
      value: POLLUTED_SCOPES,
      configurable: true,
      enumerable: false,
      writable: true,
    });
  }
  try {
    // The pollution must actually be in place, or every assertion below is
    // vacuous — it would pass just as well against code that never had the
    // defect, and prove nothing.
    expect(({} as unknown as { scopes?: string[] }).scopes).toBe(POLLUTED_SCOPES);
    expect(({} as unknown as { scope?: string[] }).scope).toBe(POLLUTED_SCOPES);
    return await fn();
  } finally {
    delete (Object.prototype as unknown as { scopes?: string[] }).scopes;
    delete (Object.prototype as unknown as { scope?: string[] }).scope;
  }
}

describe("api-key `scopes` claim under a polluted Object.prototype", () => {
  test("the crafted body genuinely omits `scopes`, so the read under test is a real prototype lookup", async () => {
    // Guards the FIXTURE rather than the code. If this body ever gained an own
    // `scopes` key, every assertion in this file would pass for the wrong
    // reason — an own property shadows the prototype, so the defect would be
    // masked and the suite would go quiet about it.
    const token = scopelessToken();

    // Clean prototype: the claim is simply missing and the token is malformed.
    expect(parseApiKey(token)).toBeNull();

    // Polluted: whatever the verdict, the decoded BODY must still carry no own
    // `scopes`. This is the assertion a clean prototype cannot satisfy by
    // accident, and it is what `toBeUndefined()` would have missed — an absent
    // key reads `undefined` when clean and the planted array when polluted.
    await withPollutedScopePrototype(() => {
      const parsed = parseApiKey(token);
      const decoded = JSON.parse(Buffer.from(token.split(".")[0]!.split("_").pop()!, "base64url").toString("utf8"));
      expect(Object.hasOwn(decoded, "scopes")).toBe(false);
      if (parsed) expect(Object.hasOwn(parsed.claims, "scopes")).toBe(false);
    });
  });

  test("parsing a scopeless body under pollution rejects it instead of inheriting scopes", async () => {
    const token = scopelessToken();

    const parsed = await withPollutedScopePrototype(() => parseApiKey(token));

    // Before the fix this returned a ParsedApiKey: `!Array.isArray(claims.scopes)`
    // resolved through the prototype to the planted array and the structural
    // check passed. A present-but-inherited scope set is a malformed token, not
    // an authorized one.
    expect(parsed).toBeNull();
  });

  test("verifying a scopeless body under pollution never grants a prototype-supplied scope", async () => {
    const token = scopelessToken();

    const [wildcardDemand, ordinaryDemand, noDemand] = await withPollutedScopePrototype(() => [
      verifyApiKeyToken(token, {
        signingSecret: SIGNING,
        expectedApp: "todos",
        requiredScopes: ["todos:admin"],
      }),
      verifyApiKeyToken(token, {
        signingSecret: SIGNING,
        expectedApp: "todos",
        requiredScopes: ["todos:read"],
      }),
      verifyApiKeyToken(token, { signingSecret: SIGNING, expectedApp: "todos" }),
    ]);

    // The signature over this body is REAL — it was produced with the same
    // secret the verifier holds — so the only thing standing between it and a
    // grant is the scope read. Before the fix, the planted `["*"]` satisfied
    // every demand and all three returned ok.
    expect(wildcardDemand.ok).toBe(false);
    expect(ordinaryDemand.ok).toBe(false);
    expect(noDemand.ok).toBe(false);
  });

  test("a real low-scope token still denies under pollution — the fix does not fail open", async () => {
    // The negative control. A token that legitimately carries `todos:read` must
    // still be refused `todos:write`, and the planted wildcard must not rescue
    // it. Without this, a fix that simply hard-denied everything would pass the
    // tests above while proving nothing about the scope check itself.
    const low = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    expect(Object.hasOwn(low.claims, "scopes")).toBe(true);

    const denied = await withPollutedScopePrototype(() =>
      verifyApiKeyToken(low.token, {
        signingSecret: SIGNING,
        expectedApp: "todos",
        requiredScopes: ["todos:write"],
      }),
    );

    expect(denied.ok).toBe(false);
    if (!denied.ok) expect(denied.reason).toBe("insufficient_scope");
  });

  test("a legitimate scope still grants under pollution — the fix does not fail closed", async () => {
    // The opposite failure mode, and the more expensive one: a guard that
    // dropped real scopes would deny every authorized request in production
    // while looking like a security improvement.
    const low = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });

    const granted = await withPollutedScopePrototype(() =>
      verifyApiKeyToken(low.token, {
        signingSecret: SIGNING,
        expectedApp: "todos",
        requiredScopes: ["todos:read"],
      }),
    );

    expect(granted.ok).toBe(true);
    if (granted.ok) expect(granted.claims.scopes).toEqual(["todos:read"]);
  });

  test("a real wildcard token still grants under pollution", async () => {
    // Proves the guard READS the claim rather than defaulting to empty: an own
    // `["*"]` must keep working, and it must be the token's own value doing it.
    const wild = mintApiKey({ app: "todos", scopes: ["*"], signingSecret: SIGNING });

    const granted = await withPollutedScopePrototype(() =>
      verifyApiKeyToken(wild.token, {
        signingSecret: SIGNING,
        expectedApp: "todos",
        requiredScopes: ["todos:admin", "knowledge:write"],
      }),
    );

    expect(granted.ok).toBe(true);
  });

  test("minting under pollution still writes `scopes` as an OWN property", async () => {
    // The property that makes this defect unreachable through a kit-minted
    // token, asserted rather than assumed — if minting ever stopped writing an
    // own key, the tests above would go quiet and the hole would open.
    const minted = await withPollutedScopePrototype(() =>
      mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING }),
    );

    expect(Object.hasOwn(minted.claims, "scopes")).toBe(true);
    expect(minted.claims.scopes).toEqual(["todos:read"]);
  });
});

// --- the Ed25519 twin: `scope`, singular ---

const ISSUER = "identities";
const AUDIENCE = "todos";
const NOW_MS = 1_800_000_000_000;
const NOW_SEC = Math.floor(NOW_MS / 1000);

interface TestIssuer {
  jwks: FleetJwks;
  signRaw(payload: Record<string, unknown>): string;
}

function makeIssuer(kid = "scope-pollution-key"): TestIssuer {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const exported = publicKey.export({ format: "jwk" }) as { x: string };
  const jwk: Ed25519PublicJwk = { kty: "OKP", crv: "Ed25519", x: exported.x, kid, use: "sig", alg: "EdDSA" };

  function signRaw(payload: Record<string, unknown>): string {
    const header = { alg: FLEET_TOKEN_ALG, kid, typ: FLEET_TOKEN_TYP };
    const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
    return `${signingInput}.${b64url(edSign(null, Buffer.from(signingInput, "utf8"), privateKey))}`;
  }

  return { jwks: { keys: [jwk] }, signRaw };
}

const fleetIssuer = makeIssuer();
const fleetBase = { jwks: fleetIssuer.jwks, issuer: ISSUER, audience: AUDIENCE, nowMs: NOW_MS } as const;

function fleetClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: "user_01",
    tid: "acme-corp",
    pt: "user",
    iat: NOW_SEC,
    exp: NOW_SEC + 3600,
    jti: "jti_01",
    ...overrides,
  };
}

describe("fleet-token `scope` claim under a polluted Object.prototype", () => {
  test("the crafted payload genuinely omits `scope`", () => {
    const payload = fleetClaims();
    expect(Object.hasOwn(payload, "scope")).toBe(false);
    // Clean prototype: the claim is simply missing and the token is invalid.
    const result = verifyFleetToken(fleetIssuer.signRaw(payload), fleetBase);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("invalid_claims");
  });

  test("a scopeless payload under pollution is rejected, not granted the prototype's scopes", async () => {
    const token = fleetIssuer.signRaw(fleetClaims());

    const [demanded, undemanded] = await withPollutedScopePrototype(() => [
      verifyFleetToken(token, { ...fleetBase, requiredScopes: ["todos:admin"] }),
      verifyFleetToken(token, fleetBase),
    ]);

    // Before the fix, `claimsProblem`'s `!Array.isArray(claims.scope)` walked
    // the prototype, accepted the planted `["*"]`, and both of these returned
    // ok — the second one handing back a principal whose `scopes` array was
    // the attacker's, copied out at identity.ts's `[...claims.scope]`.
    expect(demanded.ok).toBe(false);
    expect(undemanded.ok).toBe(false);
    if (!undemanded.ok) expect(undemanded.reason).toBe("invalid_claims");
  });

  test("a real low-scope fleet token still denies under pollution", async () => {
    const token = fleetIssuer.signRaw(fleetClaims({ scope: ["todos:read"] }));

    const denied = await withPollutedScopePrototype(() =>
      verifyFleetToken(token, { ...fleetBase, requiredScopes: ["todos:write"] }),
    );

    expect(denied.ok).toBe(false);
    if (!denied.ok) expect(denied.reason).toBe("insufficient_scope");
  });

  test("a legitimate fleet scope still grants under pollution, and the principal carries only its own scopes", async () => {
    const token = fleetIssuer.signRaw(fleetClaims({ scope: ["todos:read"] }));

    const granted = await withPollutedScopePrototype(() =>
      verifyFleetToken(token, { ...fleetBase, requiredScopes: ["todos:read"] }),
    );

    expect(granted.ok).toBe(true);
    if (granted.ok) {
      expect(granted.principal.scopes).toEqual(["todos:read"]);
      // The copy handed to the caller must be the token's, not the prototype's.
      expect(granted.principal.scopes).not.toEqual(POLLUTED_SCOPES);
    }
  });

  test("the pollution helper restores the prototype", () => {
    // Proof the `finally` actually fires, so a failure inside a polluted block
    // cannot leave the rest of the suite running dirty.
    expect(Object.hasOwn(Object.prototype, "scopes")).toBe(false);
    expect(Object.hasOwn(Object.prototype, "scope")).toBe(false);
    expect(({} as unknown as { scopes?: string[] }).scopes).toBeUndefined();
    expect(({} as unknown as { scope?: string[] }).scope).toBeUndefined();
  });
});
