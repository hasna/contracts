// `mintApiKey` and `verifyApiKeyToken` read their options off a caller-supplied
// object that has `Object.prototype` in its chain. `??`, `!== undefined` and
// `Array.isArray` all accept an inherited value happily, so every option the
// caller does not set as an OWN property is a genuine prototype lookup decided
// by whatever a `__proto__`/`constructor.prototype` write primitive elsewhere in
// the process planted there.
//
// WHY THE MINT HALF IS THE SERIOUS HALF, AND WHAT ITS SEVERITY ACTUALLY IS.
// A value read in `mintApiKey` is written INTO the claims before the HMAC is
// computed, so the token that comes out is cryptographically authentic. No
// verify-time guard can reject it, and none should — the signature is genuine.
// That is the whole consequence and it is a DURABILITY consequence rather than
// an access one: the attack still needs a pre-existing pollution primitive in
// the issuer's process, but a transient primitive that lasts one mint produces a
// PERMANENTLY valid signed credential — a wildcard `scopes`, an attacker-chosen
// `kid` (which is the revocation key), or a moved `iat`/`exp`. Cleaning up the
// prototype afterwards does not revoke it.
//
// The verify half is a different and lesser fact, kept separate below: those
// reads are not signed, they decide whether an authentic token is accepted here
// and now. A polluted `nowMs`/`leewaySeconds` accepts an expired token; a
// polluted `expectedApp`/`requiredScopes`/`requireTenant`/`expectedTid` denies a
// good one.
//
// THE ASSERTION TRAP, which is the whole difficulty of testing the mint half.
// An ABSENT key reads `undefined` on a clean prototype and the attacker's value
// on a polluted one — including inside the assertion itself. So
// `expect(x).toBeUndefined()` PASSES against the broken build and proves
// nothing. Every assertion here is `Object.hasOwn` on the signed claims, an
// exact positive value, or a thrown error.

import { describe, expect, test } from "bun:test";
import { main } from "../src/cli/index";
import { DEFAULT_API_KEY_TTL_SECONDS, mintApiKey, parseApiKey, verifyApiKeyToken } from "../src/auth/keys";

const SIGNING = "test-signing-secret-not-a-real-credential-000";
const APP = "todos";
const DAY = 24 * 60 * 60;

/** Values an attacker with an `Object.prototype` write primitive plants. */
const POLLUTION = {
  app: "attacker-app",
  scopes: ["*"],
  signingSecret: "attacker-signing-secret-0000000000000000",
  kid: "attacker-controlled-kid",
  // 2100-01-01T00:00:00Z. Far enough out that no clock skew explains it.
  nowMs: 4_102_444_800_000,
  ttlSeconds: null,
  leewaySeconds: 10 * 365 * DAY,
  expectedApp: "attacker-app",
  requiredScopes: ["todos:admin"],
  requireTenant: true,
  expectedTid: "11111111-1111-4111-8111-111111111111",
} as const;

/**
 * Run `fn` with the listed keys planted on `Object.prototype`, then remove them.
 *
 * Non-enumerable so the planted keys cannot leak into unrelated `for...in` loops
 * (the test runner's included) while staying fully visible to the
 * prototype-chain reads under test — those reads are identical either way.
 *
 * Restored in a `finally`, because a polluted prototype escaping into sibling
 * tests is its own outage.
 */
async function withPolluted<T>(
  keys: ReadonlyArray<keyof typeof POLLUTION>,
  fn: () => T | Promise<T>,
  // A per-test override for a planted value. One clock value cannot make both
  // verify-side directions discriminating — a clock in the future exposes the
  // not-yet-valid read and a clock in the past exposes the expired one — and a
  // planted value that produces the SAME verdict on both builds is a test that
  // cannot fail. Overriding is how each direction gets the value that can.
  overrides: Partial<Record<keyof typeof POLLUTION, unknown>> = {},
): Promise<T> {
  const planted = (key: keyof typeof POLLUTION): unknown =>
    Object.hasOwn(overrides, key) ? overrides[key] : POLLUTION[key];
  for (const key of keys) {
    Object.defineProperty(Object.prototype, key, {
      value: planted(key),
      configurable: true,
      enumerable: false,
      writable: true,
    });
  }
  try {
    // The pollution must actually be in place, or every assertion below is
    // vacuous — it would pass just as well against code that never had the
    // defect. This is the control that proves the probe is armed.
    for (const key of keys) {
      expect((({} as Record<string, unknown>)[key])).toBe(planted(key));
    }
    return await fn();
  } finally {
    for (const key of keys) delete (Object.prototype as Record<string, unknown>)[key];
  }
}

/**
 * A mint options bag with the listed keys DELIBERATELY ABSENT, built without a
 * spread so absence is exact. `as never` because the absence is the point: the
 * TypeScript signature requires these fields, and the callers that reach the
 * prototype are the ones the type system does not police — a JavaScript caller,
 * a bag assembled by spreads, or a field the shipped CLI simply never sets (see
 * the shipped-program section below, where `kid` and `nowMs` are exactly that).
 */
function bagWithout(absent: ReadonlyArray<string>): Parameters<typeof mintApiKey>[0] {
  const full: Record<string, unknown> = {
    app: APP,
    scopes: ["todos:read"],
    signingSecret: SIGNING,
  };
  const bag: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(full)) {
    if (!absent.includes(key)) bag[key] = value;
  }
  for (const key of absent) {
    expect(Object.hasOwn(bag, key)).toBe(false);
  }
  return bag as never;
}

/** The claims actually inside the HMAC-signed body of a token. */
function signedClaims(token: string): Record<string, unknown> {
  const parsed = parseApiKey(token);
  expect(parsed).not.toBeNull();
  return parsed!.claims as unknown as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// The SHIPPED PROGRAM, end to end, in this process.
//
// This is the reachability evidence and it is deliberately not a hand-declared
// commander copy. A sibling test in this repo asserts the option shape against a
// `new Command()` it builds itself, and a reviewer showed that making
// `--bootstrap` negatable in `src/cli/index.ts` left that test at 17 pass / 0
// fail — it pins a replica, so it cannot see the shipped program change.
//
// So this drives `main()` from `src/cli/index.ts` with a real argv. It runs
// in-process rather than as a subprocess for the reason the whole file exists:
// prototype pollution does not cross a process boundary, so a `Bun.spawnSync`
// harness could not observe this defect at all. Everything between argv and the
// HMAC — the commander wiring in `index.ts`, the option reads in
// `issue-key.ts`, and the mint in `auth/keys.ts` — is the real code. Change any
// of the three and this test sees it.
//
// `kid` and `nowMs` are the two reachable here, and it is the CLI's own shape
// that makes them so: `index.ts` calls `runIssueKey(options, { report })` with
// no `now` dependency, and `issue-key.ts` builds the mint bag as an object
// literal that sets `app`, `scopes`, `signingSecret` and `ttlSeconds` but never
// `kid`, and `nowMs` only when `deps.now` is supplied. Both are therefore
// missing as own properties on every real invocation.
// ---------------------------------------------------------------------------
describe("shipped CLI: no polluted option reaches the signed body", () => {
  async function issueKeyViaShippedCli(): Promise<Record<string, unknown>> {
    const original = console.log;
    const lines: string[] = [];
    const previousSecret = process.env.HASNA_TODOS_API_SIGNING_KEY;
    process.env.HASNA_TODOS_API_SIGNING_KEY = SIGNING;
    console.log = (...args: unknown[]) => void lines.push(args.map((a) => String(a)).join(" "));
    try {
      await main(["bun", "contracts", "issue-key", "--app", APP, "--scopes", "todos:read", "--no-store", "--json"]);
    } finally {
      console.log = original;
      if (previousSecret === undefined) delete process.env.HASNA_TODOS_API_SIGNING_KEY;
      else process.env.HASNA_TODOS_API_SIGNING_KEY = previousSecret;
    }
    const parsed = JSON.parse(lines.join("\n")) as { token?: string };
    expect(typeof parsed.token).toBe("string");
    return signedClaims(parsed.token as string);
  }

  test("a polluted `kid` cannot become the signed key id the revocation record keys on", async () => {
    const claims = await withPolluted(["kid"], issueKeyViaShippedCli);

    // Broken build: `options.kid ?? generateKid()` takes the prototype's value,
    // it passes the url-safe check, and it is signed. The attacker then knows
    // the exact `kid` a revocation lookup will key on — and can collide it with
    // another key's, so revoking one revokes the wrong credential.
    expect(claims.kid).not.toBe(POLLUTION.kid);
    expect(claims.kid).toMatch(/^[0-9a-f]{16}$/);
  });

  test("a polluted `nowMs` cannot move the signed `iat`/`exp` of a CLI-issued key", async () => {
    const before = Math.floor(Date.now() / 1000);
    const claims = await withPolluted(["nowMs"], issueKeyViaShippedCli);
    const after = Math.floor(Date.now() / 1000);

    // Broken build: `iat` is signed as the year 2100 and `exp` 90 days past it,
    // so the key outlives every expiry check by 74 years — and, being in the
    // future, is `not_yet_valid` today, which reads as an outage rather than an
    // attack until someone waits.
    expect(claims.iat).not.toBe(Math.floor(POLLUTION.nowMs / 1000));
    expect(typeof claims.iat).toBe("number");
    expect(claims.iat as number).toBeGreaterThanOrEqual(before);
    expect(claims.iat as number).toBeLessThanOrEqual(after);
    expect(claims.exp).toBe((claims.iat as number) + DEFAULT_API_KEY_TTL_SECONDS);
  });

  test("a CLI-issued key still verifies under the app's own secret while both are polluted", async () => {
    const original = console.log;
    const lines: string[] = [];
    const previousSecret = process.env.HASNA_TODOS_API_SIGNING_KEY;
    process.env.HASNA_TODOS_API_SIGNING_KEY = SIGNING;
    console.log = (...args: unknown[]) => void lines.push(args.map((a) => String(a)).join(" "));
    let token: string;
    try {
      token = await withPolluted(["kid", "nowMs"], async () => {
        await main(["bun", "contracts", "issue-key", "--app", APP, "--scopes", "todos:read", "--no-store", "--json"]);
        return (JSON.parse(lines.join("\n")) as { token: string }).token;
      });
    } finally {
      console.log = original;
      if (previousSecret === undefined) delete process.env.HASNA_TODOS_API_SIGNING_KEY;
      else process.env.HASNA_TODOS_API_SIGNING_KEY = previousSecret;
    }

    // Both directions in one: the guards must not break issuance. A key that
    // fails to verify is a different outage, not a fix.
    const result = verifyApiKeyToken(token, { signingSecret: SIGNING });
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// `mintApiKey` directly. It is a public export of the auth kit, so a programmatic
// caller reaches every read below without going near the CLI.
// ---------------------------------------------------------------------------
describe("mintApiKey: no polluted option reaches the signed body", () => {
  test("a polluted `scopes` cannot mint a wildcard grant", async () => {
    await withPolluted(["scopes"], () => {
      // Broken build: `Array.isArray(options.scopes)` is satisfied by the
      // inherited `["*"]`, the loop validates it, and `[...options.scopes]` is
      // spread DIRECTLY into the signed claims. `*` satisfies every
      // `requiredScopes` check this kit performs, permanently.
      expect(() => mintApiKey(bagWithout(["scopes"]))).toThrow("At least one scope is required");
    });
  });

  test("a polluted `app` cannot mint a key for an app the caller never named", async () => {
    await withPolluted(["app"], () => {
      // Broken build: `attacker-app` is a valid slug, so it passes the pattern
      // and is signed into both the token prefix and the `app` claim — a key
      // that authenticates against a service the caller never issued for.
      expect(() => mintApiKey(bagWithout(["app"]))).toThrow("Invalid app slug");
    });
  });

  test("a polluted `signingSecret` cannot decide which secret signs the key", async () => {
    await withPolluted(["signingSecret"], () => {
      // Broken build: the token is signed with a secret the attacker chose, so
      // it verifies for them and not for the app. Fixed build has no secret at
      // all and refuses on the existing entropy check.
      expect(() => mintApiKey(bagWithout(["signingSecret"]))).toThrow("signingSecret must be at least 16 bytes");
    });
  });

  test("a polluted `kid` is not the signed key id", async () => {
    const minted = await withPolluted(["kid"], () => mintApiKey(bagWithout([])));

    expect(minted.kid).not.toBe(POLLUTION.kid);
    expect(minted.claims.kid).not.toBe(POLLUTION.kid);
    expect(minted.claims.kid).toMatch(/^[0-9a-f]{16}$/);
    // The returned `kid` and the signed one are the same value — a mismatch
    // would store a revocation record that no token can ever be matched to.
    expect(signedClaims(minted.token).kid).toBe(minted.kid);
  });

  test("a polluted `nowMs` does not move the signed `iat`", async () => {
    const before = Math.floor(Date.now() / 1000);
    const minted = await withPolluted(["nowMs"], () => mintApiKey(bagWithout([])));
    const after = Math.floor(Date.now() / 1000);

    expect(minted.claims.iat).not.toBe(Math.floor(POLLUTION.nowMs / 1000));
    expect(minted.claims.iat).toBeGreaterThanOrEqual(before);
    expect(minted.claims.iat).toBeLessThanOrEqual(after);
  });

  test("a polluted `ttlSeconds` cannot mint a key that never expires", async () => {
    const minted = await withPolluted(["ttlSeconds"], () => mintApiKey(bagWithout([])));

    // Broken build: `options.ttlSeconds === undefined` is false because the
    // prototype supplies `null`, so `exp` is signed as null — a forever key,
    // and expiry is the only thing that limits a leaked credential without a
    // revocation lookup.
    expect(minted.claims.exp).not.toBeNull();
    expect(minted.claims.exp).toBe(minted.claims.iat + DEFAULT_API_KEY_TTL_SECONDS);
    expect(signedClaims(minted.token).exp).toBe(minted.claims.exp);
  });

  test("every polluted mint option at once still yields a clean signed body", async () => {
    const before = Math.floor(Date.now() / 1000);
    const minted = await withPolluted(["kid", "nowMs", "ttlSeconds"], () => mintApiKey(bagWithout([])));

    expect(minted.claims.kid).toMatch(/^[0-9a-f]{16}$/);
    expect(minted.claims.iat).toBeGreaterThanOrEqual(before);
    expect(minted.claims.exp).toBe(minted.claims.iat + DEFAULT_API_KEY_TTL_SECONDS);
    expect(minted.claims.app).toBe(APP);
    expect(minted.claims.scopes).toEqual(["todos:read"]);
    expect(Object.hasOwn(minted.claims, "agent")).toBe(false);
    expect(Object.hasOwn(minted.claims, "tid")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// BOTH DIRECTIONS. A guard that fails closed on legitimate input is a different
// outage, not a fix. Under the SAME pollution, real own values must still reach
// the signed body unchanged.
// ---------------------------------------------------------------------------
describe("mintApiKey: real option values still work under pollution", () => {
  test("every explicitly-passed option reaches the signed body unchanged", async () => {
    const realKid = "deadbeefdeadbeef";
    const realNowMs = 1_700_000_000_000;
    const minted = await withPolluted(
      ["app", "scopes", "signingSecret", "kid", "nowMs", "ttlSeconds"],
      () =>
        mintApiKey({
          app: APP,
          scopes: ["todos:read", "todos:write"],
          signingSecret: SIGNING,
          kid: realKid,
          nowMs: realNowMs,
          ttlSeconds: DAY,
          agent: "station01",
        }),
    );

    const claims = signedClaims(minted.token);
    expect(claims.app).toBe(APP);
    expect(claims.scopes).toEqual(["todos:read", "todos:write"]);
    expect(claims.kid).toBe(realKid);
    expect(claims.iat).toBe(Math.floor(realNowMs / 1000));
    expect(claims.exp).toBe(Math.floor(realNowMs / 1000) + DAY);
    expect(Object.hasOwn(claims, "agent")).toBe(true);
    expect(claims.agent).toBe("station01");
    // Signed with the caller's secret, not the prototype's.
    expect(verifyApiKeyToken(minted.token, { signingSecret: SIGNING, nowMs: realNowMs }).ok).toBe(true);
  });

  test("an explicit `ttlSeconds: null` still mints a non-expiring key", async () => {
    const minted = await withPolluted(["ttlSeconds", "nowMs"], () =>
      mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: SIGNING, ttlSeconds: null }),
    );

    expect(minted.claims.exp).toBeNull();
  });

  test("a Buffer signingSecret is still accepted", async () => {
    const secret = Buffer.from(SIGNING, "utf8");
    const minted = await withPolluted(["signingSecret"], () =>
      mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: secret }),
    );

    expect(verifyApiKeyToken(minted.token, { signingSecret: secret }).ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The VERIFY half. Not signed — these reads decide whether an authentic token is
// accepted here and now, so the consequence is an acceptance or a denial rather
// than a durable credential. Kept in its own section so the two severities are
// not read as one.
// ---------------------------------------------------------------------------
describe("verifyApiKeyToken: no polluted option changes the verdict", () => {
  const EXPIRED_AT_MS = 1_700_000_000_000;
  function expiredToken(): string {
    return mintApiKey({
      app: APP,
      scopes: ["todos:read"],
      signingSecret: SIGNING,
      nowMs: EXPIRED_AT_MS,
      ttlSeconds: DAY,
    }).token;
  }

  test("a polluted `nowMs` cannot make an expired token verify", async () => {
    const token = expiredToken();
    // The control that this token really is expired against the real clock.
    expect(verifyApiKeyToken(token, { signingSecret: SIGNING })).toMatchObject({ ok: false, reason: "expired" });

    // A clock planted BEFORE the token was issued. Broken build reads it, finds
    // the token not yet expired, and accepts a credential that lapsed years ago.
    const result = await withPolluted(["nowMs"], () => verifyApiKeyToken(token, { signingSecret: SIGNING }), {
      nowMs: EXPIRED_AT_MS - DAY * 1000,
    });

    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("expired");
  });

  test("a polluted `nowMs` cannot make a not-yet-valid token verify", async () => {
    const future = Date.now() + 365 * DAY * 1000;
    const token = mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: SIGNING, nowMs: future }).token;
    expect(verifyApiKeyToken(token, { signingSecret: SIGNING })).toMatchObject({
      ok: false,
      reason: "not_yet_valid",
    });

    // Broken build: the prototype's year-2100 clock is past this token's `iat`,
    // so a token that is not yet valid verifies successfully.
    const result = await withPolluted(["nowMs"], () => verifyApiKeyToken(token, { signingSecret: SIGNING }));
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("not_yet_valid");
  });

  test("a polluted `leewaySeconds` cannot stretch the expiry window", async () => {
    const token = expiredToken();

    // Broken build: a ten-year inherited leeway makes every expired token
    // verify, and expiry is the only stateless limit on a leaked key.
    const result = await withPolluted(["leewaySeconds"], () => verifyApiKeyToken(token, { signingSecret: SIGNING }));
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("expired");
  });

  test("a polluted `expectedApp` cannot deny a good token", async () => {
    const token = mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: SIGNING }).token;

    const result = await withPolluted(["expectedApp"], () => verifyApiKeyToken(token, { signingSecret: SIGNING }));
    expect(result.ok).toBe(true);
  });

  test("a polluted `requiredScopes` cannot deny a caller that required none", async () => {
    const token = mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: SIGNING }).token;

    const result = await withPolluted(["requiredScopes"], () => verifyApiKeyToken(token, { signingSecret: SIGNING }));
    expect(result.ok).toBe(true);
  });

  test("a polluted `requireTenant` cannot deny an untenanted token", async () => {
    const token = mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: SIGNING }).token;

    const result = await withPolluted(["requireTenant"], () => verifyApiKeyToken(token, { signingSecret: SIGNING }));
    expect(result.ok).toBe(true);
  });

  test("a polluted `expectedTid` cannot deny an untenanted token", async () => {
    const token = mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: SIGNING }).token;

    // Broken build: `options.expectedTid !== undefined` is true, so the gate
    // engages and the token is refused as `tenant_required` for an expectation
    // the caller never set.
    const result = await withPolluted(["expectedTid"], () => verifyApiKeyToken(token, { signingSecret: SIGNING }));
    expect(result.ok).toBe(true);
  });

  test("real verify options still bind under the same pollution", async () => {
    const tid = "22222222-2222-4222-8222-222222222222";
    const token = mintApiKey({
      app: APP,
      scopes: ["todos:read"],
      signingSecret: SIGNING,
      tid,
    }).token;

    const result = await withPolluted(
      ["expectedApp", "requiredScopes", "requireTenant", "expectedTid", "nowMs", "leewaySeconds"],
      () =>
        verifyApiKeyToken(token, {
          signingSecret: SIGNING,
          expectedApp: APP,
          requiredScopes: ["todos:read"],
          requireTenant: true,
          expectedTid: tid,
        }),
    );
    expect(result.ok).toBe(true);

    // And the explicit expectations still DENY when they should.
    const denied = await withPolluted(["expectedApp"], () =>
      verifyApiKeyToken(token, { signingSecret: SIGNING, expectedApp: "loops" }),
    );
    expect(denied.ok).toBe(false);
    expect(denied.ok === false && denied.reason).toBe("app_mismatch");

    const underScoped = await withPolluted(["requiredScopes"], () =>
      verifyApiKeyToken(token, { signingSecret: SIGNING, requiredScopes: ["todos:write"] }),
    );
    expect(underScoped.ok).toBe(false);
    expect(underScoped.ok === false && underScoped.reason).toBe("insufficient_scope");
  });
});
