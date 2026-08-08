// `verifyApiKey` in src/auth/middleware.ts reads its whole options bag off an
// object that has `Object.prototype` in its chain. `!options.x`, `options.x ?? d`
// and `options.x !== undefined` all accept an INHERITED value, so every option a
// caller does not set as an OWN property is a genuine prototype lookup decided by
// whatever a `__proto__`/`constructor.prototype` write primitive elsewhere in the
// process planted there.
//
// WHY `signingSecret` IS THE SERIOUS ONE, AND WHAT ITS SEVERITY ACTUALLY IS.
// `signingSecret` is read twice: once as the construction-time guard
// (`if (!options.signingSecret) throw`) and once as the value handed to
// `verifyApiKeyToken`, which is what decides WHICH KEY THE HMAC IS COMPUTED
// UNDER. One planted value therefore does two things with a single write: it
// silences the boot-time throw that exists to catch a missing secret, and it
// makes the verifier compute signatures under the attacker's key. A token the
// attacker minted themselves then authenticates — with whatever scopes they put
// in it, `["*"]` included.
//
// This is NOT a remote authentication bypass. Like everything in this class it
// needs a prototype-pollution primitive already present in the verifying
// process; nothing here is reachable from a request alone. What separates it
// from its siblings is that it sits on the READ path and decides ACCEPTANCE:
// the other polluted options in this file mislabel an audit field or deny a good
// request, while this one admits a credential the service never issued.
//
// THE ASSERTION TRAP, which is the whole difficulty of testing this class.
// An ABSENT key reads `undefined` on a clean prototype and the attacker's value
// on a polluted one — including inside the assertion itself. So
// `expect(x).toBeUndefined()` PASSES against the broken build and proves
// nothing. Every assertion here is `Object.hasOwn`, an exact positive value, a
// thrown error, or an exact deny reason.

import { describe, expect, test } from "bun:test";
import { mintApiKey } from "../src/auth/keys";
import { verifyApiKey, type VerifyApiKeyOptions } from "../src/auth/middleware";
import type { ApiKeyStatus } from "../src/auth/store";

const SIGNING = "real-app-signing-secret-0000000000000000";
const ATTACKER_SIGNING = "attacker-signing-secret-1111111111111111";
const APP = "todos";
const DAY = 24 * 60 * 60;
const TID = "22222222-2222-4222-8222-222222222222";
const OTHER_TID = "33333333-3333-4333-8333-333333333333";

/** Values an attacker with an `Object.prototype` write primitive plants. */
const POLLUTION = {
  app: "attacker-app",
  signingSecret: ATTACKER_SIGNING,
  requiredScopes: ["todos:admin"],
  requireTenant: true,
  expectedTid: OTHER_TID,
  headerName: "x-attacker-header",
  scheme: "Attacker",
  leewaySeconds: 10 * 365 * DAY,
  nowMs: () => 4_102_444_800_000,
  audit: () => {},
  // The three fail-open/fail-closed switches. A planted `keyStatus`/`isRevoked`
  // is an attacker-chosen VERDICT on every key; a planted
  // `allowUnregisteredKeys` re-opens the unknown-kid hole AND silences the
  // construction throw that exists to catch it.
  keyStatus: (): ApiKeyStatus => "revoked",
  isRevoked: () => true,
  allowUnregisteredKeys: true,
  // Written straight onto the audit line, so a planted pair forges the route
  // recorded for every request the service serves.
  method: "DELETE",
  path: "/v1/admin/purge",
  // Not an option — a field of the token verifier's own RESULT, absent on most
  // denial reasons and therefore reachable through the chain on the deny emit.
  kid: "FORGED-KID-attacker-chosen",
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
  // A per-test override for a planted value. One planted clock cannot make both
  // directions discriminating — a clock in the future exposes the not-yet-valid
  // read and one in the past exposes the expired read — and a planted value that
  // produces the SAME verdict on both builds is a test that cannot fail.
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
 * A verifier options bag with the listed keys DELIBERATELY ABSENT, built without
 * a spread so absence is exact. `as never` because the absence is the point: the
 * TypeScript signature requires `app` and `signingSecret`, and the callers that
 * reach the prototype are the ones the type system does not police — a
 * JavaScript caller, or a bag assembled by spreads from a config object whose
 * env var was unset.
 */
function bagWithout(
  absent: ReadonlyArray<string>,
  extra: Record<string, unknown> = {},
): VerifyApiKeyOptions {
  const full: Record<string, unknown> = {
    app: APP,
    signingSecret: SIGNING,
    keyStatus: (): ApiKeyStatus => "active",
  };
  const bag: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(full)) {
    if (!absent.includes(key)) bag[key] = value;
  }
  for (const [key, value] of Object.entries(extra)) bag[key] = value;
  for (const key of absent) {
    expect(Object.hasOwn(bag, key)).toBe(false);
  }
  return bag as never;
}

function tokenFor(overrides: Record<string, unknown> = {}): string {
  return mintApiKey({
    app: APP,
    scopes: ["todos:read"],
    signingSecret: SIGNING,
    ...overrides,
  } as never).token;
}

// ---------------------------------------------------------------------------
// `signingSecret` — the ACCEPTANCE site. This section is the defect.
// ---------------------------------------------------------------------------
describe("verifyApiKey: a polluted `signingSecret` cannot decide which key the HMAC is computed under", () => {
  // The attacker mints under their OWN secret, outside any pollution, with
  // `signingSecret` set as an own property so this token is unambiguously theirs.
  const attackerToken = mintApiKey({
    app: APP,
    scopes: ["*"],
    signingSecret: ATTACKER_SIGNING,
  }).token;

  test("CONTROL: the attacker's token verifies under the attacker's secret and not under the app's", async () => {
    // Both controls, stated as assertions rather than prose. Without these the
    // bypass test below could pass for a reason that has nothing to do with the
    // guard — a token that verifies nowhere denies everywhere.
    const underAttacker = verifyApiKey({
      app: APP,
      signingSecret: ATTACKER_SIGNING,
      keyStatus: (): ApiKeyStatus => "active",
    });
    const a = await underAttacker.authenticate({ "x-api-key": attackerToken });
    expect(a.ok).toBe(true);

    const underReal = verifyApiKey({
      app: APP,
      signingSecret: SIGNING,
      keyStatus: (): ApiKeyStatus => "active",
    });
    const b = await underReal.authenticate({ "x-api-key": attackerToken });
    expect(b.ok).toBe(false);
    expect(b.ok === false && b.reason).toBe("bad_signature");
  });

  test("construction still fails closed when `signingSecret` is absent and the prototype supplies one", async () => {
    await withPolluted(["signingSecret"], () => {
      // Broken build: `!options.signingSecret` reads the attacker's value, finds
      // it truthy, and the boot-time throw that exists to catch a missing secret
      // never fires. The service starts, and reads as correctly wired.
      expect(() => verifyApiKey(bagWithout(["signingSecret"]))).toThrow(
        "verifyApiKey requires a 'signingSecret'",
      );
    });
  });

  test("an attacker-signed token cannot authenticate against a bag whose `signingSecret` is absent", async () => {
    const outcome = await withPolluted(["signingSecret"], async () => {
      let verifier: ReturnType<typeof verifyApiKey> | null = null;
      try {
        verifier = verifyApiKey(bagWithout(["signingSecret"]));
      } catch (error) {
        return { constructed: false as const, error: (error as Error).message };
      }
      const decision = await verifier.authenticate({ "x-api-key": attackerToken });
      return { constructed: true as const, decision };
    });

    // Broken build: construction succeeds, `verifyApiKeyToken` is handed the
    // attacker's secret at the call site, the HMAC matches, and the decision is
    // `{ok:true, status:200, reason:null}` with the wildcard scope the attacker
    // minted. Measured on 0a037408 before this guard:
    //   AUTHENTICATE -> {"ok":true,"status":200,"reason":null,"scopes":["*"]}
    expect(outcome.constructed).toBe(false);
    expect(outcome.constructed === false && outcome.error).toContain(
      "verifyApiKey requires a 'signingSecret'",
    );
  });

  test("a polluted `signingSecret` cannot override an own one that IS supplied", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["signingSecret"], async () => {
      // `signingSecret` is present as an own property here, so the only way the
      // attacker's value wins is if the read never asked whose it was.
      const verifier = verifyApiKey(bagWithout([]));
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(true);
    expect(decision.ok === true && decision.principal.app).toBe(APP);
    expect(decision.ok === true && decision.principal.scopes).toEqual(["todos:read"]);
  });
});

// ---------------------------------------------------------------------------
// `app` — the second acceptance-relevant read. It is the construction guard, the
// `expectedApp` handed to the token verifier, and the `app` on every audit line.
// ---------------------------------------------------------------------------
describe("verifyApiKey: a polluted `app` cannot name the app this service authenticates", () => {
  test("construction still fails closed when `app` is absent and the prototype supplies one", async () => {
    await withPolluted(["app"], () => {
      // Broken build: `attacker-app` is truthy, the throw never fires, and the
      // verifier goes on to accept tokens minted for an app this service is not.
      expect(() => verifyApiKey(bagWithout(["app"]))).toThrow("verifyApiKey requires an 'app' slug");
    });
  });

  test("an own `app` still decides `expectedApp`, the audit line, and `verifier.app`", async () => {
    const events: Array<Record<string, unknown>> = [];
    const good = tokenFor();
    const result = await withPolluted(["app"], async () => {
      const verifier = verifyApiKey(
        bagWithout([], { audit: (e: Record<string, unknown>) => void events.push(e) }),
      );
      const decision = await verifier.authenticate({ "x-api-key": good });
      return { verifierApp: verifier.app, decision };
    });

    expect(result.verifierApp).toBe(APP);
    expect(result.decision.ok).toBe(true);
    expect(events).toHaveLength(1);
    expect(Object.hasOwn(events[0]!, "app")).toBe(true);
    expect(events[0]!.app).toBe(APP);
    expect(events[0]!.outcome).toBe("allow");
  });

  test("a token minted for another app is still refused while `app` is polluted", async () => {
    const foreign = mintApiKey({ app: "loops", scopes: ["loops:read"], signingSecret: SIGNING }).token;
    const decision = await withPolluted(["app"], async () => {
      const verifier = verifyApiKey(bagWithout([]));
      return verifier.authenticate({ "x-api-key": foreign });
    });

    expect(decision.ok).toBe(false);
    expect(decision.ok === false && decision.reason).toBe("app_mismatch");
  });
});

// ---------------------------------------------------------------------------
// The remaining ACCEPT-path reads: a polluted value that widens what is accepted.
// ---------------------------------------------------------------------------
describe("verifyApiKey: polluted clock and leeway cannot widen what is accepted", () => {
  const EXPIRED_AT_MS = 1_700_000_000_000;
  function expiredToken(): string {
    return tokenFor({ nowMs: EXPIRED_AT_MS, ttlSeconds: DAY });
  }

  test("CONTROL: the expired token really is expired against the real clock", async () => {
    const verifier = verifyApiKey(bagWithout([]));
    const decision = await verifier.authenticate({ "x-api-key": expiredToken() });
    expect(decision.ok).toBe(false);
    expect(decision.ok === false && decision.reason).toBe("expired");
  });

  test("a polluted `leewaySeconds` cannot make an expired token authenticate", async () => {
    const token = expiredToken();
    const decision = await withPolluted(["leewaySeconds"], async () => {
      // Broken build: `options.leewaySeconds !== undefined` is satisfied by the
      // inherited ten years, it is spread into the verify options, and every
      // expired token in the fleet authenticates. Expiry is the only stateless
      // limit on a leaked credential.
      const verifier = verifyApiKey(bagWithout([]));
      return verifier.authenticate({ "x-api-key": token });
    });

    expect(decision.ok).toBe(false);
    expect(decision.ok === false && decision.reason).toBe("expired");
  });

  test("a polluted `nowMs` cannot move the clock the expiry check runs against", async () => {
    const token = expiredToken();
    const decision = await withPolluted(
      ["nowMs"],
      async () => {
        // Broken build: `options.nowMs ?? (() => Date.now())` takes the
        // inherited clock, which is set before this token was issued, so a
        // credential that lapsed years ago verifies as current.
        const verifier = verifyApiKey(bagWithout([]));
        return verifier.authenticate({ "x-api-key": token });
      },
      { nowMs: () => EXPIRED_AT_MS - DAY * 1000 },
    );

    expect(decision.ok).toBe(false);
    expect(decision.ok === false && decision.reason).toBe("expired");
  });

  test("an own `nowMs` still binds while the prototype supplies another", async () => {
    const token = expiredToken();
    const decision = await withPolluted(["nowMs"], async () => {
      // An own clock set inside the token's validity window must still accept it.
      const verifier = verifyApiKey(bagWithout([], { nowMs: () => EXPIRED_AT_MS + 60_000 }));
      return verifier.authenticate({ "x-api-key": token });
    });

    expect(decision.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The DENY-path reads: a polluted value that refuses a request the service
// should have allowed. Lesser than the acceptance sites and still an outage —
// one `Object.prototype` write turns every verifier in the process into a
// blanket denier.
// ---------------------------------------------------------------------------
describe("verifyApiKey: polluted options cannot deny a request the caller permitted", () => {
  test("a polluted `requiredScopes` cannot impose a scope the caller never required", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["requiredScopes"], async () => {
      const verifier = verifyApiKey(bagWithout([]));
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(true);
    expect(decision.ok === true && decision.principal.scopes).toEqual(["todos:read"]);
  });

  test("a polluted `requireTenant` cannot refuse an untenanted key", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["requireTenant"], async () => {
      const verifier = verifyApiKey(bagWithout([]));
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(true);
    expect(decision.ok === true && decision.principal.tid).toBeNull();
  });

  test("a polluted `expectedTid` cannot pin an unpinned verifier to a tenant", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["expectedTid"], async () => {
      // Broken build: `options.expectedTid !== undefined` is true at both the
      // construction check and the per-call fallback, so the verifier is pinned
      // to a tenant nothing validated and every untenanted key is refused.
      const verifier = verifyApiKey(bagWithout([]));
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(true);
  });

  test("a polluted INVALID `expectedTid` cannot make construction throw", async () => {
    await withPolluted(
      ["expectedTid"],
      () => {
        // Broken build: the eager validity check reads the inherited value and
        // throws at boot — one prototype write takes every service down.
        const verifier = verifyApiKey(bagWithout([]));
        expect(verifier.app).toBe(APP);
      },
      { expectedTid: "not-a-tenant-id" },
    );
  });

  test("an own `expectedTid` still pins the verifier while the prototype supplies another", async () => {
    const tenanted = tokenFor({ tid: TID });
    const decision = await withPolluted(["expectedTid"], async () => {
      const verifier = verifyApiKey(bagWithout([], { expectedTid: TID }));
      return verifier.authenticate({ "x-api-key": tenanted });
    });

    expect(decision.ok).toBe(true);
    expect(decision.ok === true && decision.principal.tid).toBe(TID);

    // And it still DENIES the tenant it is not pinned to.
    const denied = await withPolluted(["expectedTid"], async () => {
      const verifier = verifyApiKey(bagWithout([], { expectedTid: OTHER_TID }));
      return verifier.authenticate({ "x-api-key": tenanted });
    });
    expect(denied.ok).toBe(false);
    expect(denied.ok === false && denied.reason).toBe("tenant_mismatch");
  });

  test("a polluted `headerName` cannot move which header the token is read from", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["headerName"], async () => {
      // Broken build: `options.headerName ?? "x-api-key"` takes the inherited
      // name, so every well-formed request is refused `missing_token` — and a
      // header of the attacker's choosing becomes the one that IS read.
      const verifier = verifyApiKey(bagWithout([]));
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(true);
  });

  test("a polluted `scheme` cannot move which Authorization scheme is accepted", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["scheme"], async () => {
      const verifier = verifyApiKey(bagWithout([]));
      return verifier.authenticate({ authorization: `Bearer ${good}` });
    });

    expect(decision.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// `audit` — not an accept/deny read. A planted hook is an attacker-supplied
// FUNCTION that this file awaits on every decision, handed the kid, tid, agent,
// method and path of every authenticated request.
// ---------------------------------------------------------------------------
describe("verifyApiKey: a polluted `audit` hook is never called", () => {
  test("an inherited audit hook receives nothing on an allow or a deny", async () => {
    const good = tokenFor();
    const seen: Array<Record<string, unknown>> = [];
    const planted = (event: Record<string, unknown>) => void seen.push(event);

    const decisions = await withPolluted(
      ["audit"],
      async () => {
        const verifier = verifyApiKey(bagWithout([]));
        return [
          await verifier.authenticate({ "x-api-key": good }),
          await verifier.authenticate({}),
        ];
      },
      { audit: planted },
    );

    // Both paths exercised, so a fix that only covers one is visible here.
    expect(decisions[0]!.ok).toBe(true);
    expect(decisions[1]!.ok).toBe(false);
    // Broken build: `emit` reads `options.audit` twice — once to decide whether
    // to fire and once to call it — so the attacker's function is invoked with
    // the full audit event for every request the service serves.
    expect(seen).toHaveLength(0);
  });

  test("an own audit hook still fires under the same pollution", async () => {
    const good = tokenFor();
    const events: Array<Record<string, unknown>> = [];
    await withPolluted(["audit"], async () => {
      const verifier = verifyApiKey(
        bagWithout([], { audit: (e: Record<string, unknown>) => void events.push(e) }),
      );
      await verifier.authenticate({ "x-api-key": good });
    });

    expect(events).toHaveLength(1);
    expect(events[0]!.outcome).toBe("allow");
    expect(events[0]!.status).toBe(200);
    expect(Object.hasOwn(events[0]!, "reason")).toBe(true);
    expect(events[0]!.reason).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The three FAIL-OPEN/FAIL-CLOSED switches. These were already read as own
// properties before this change and are re-expressed through the same accessor
// as everything else — but a per-site mutation control showed that reverting
// any of the three left the suite at zero failures, so the guard existed and
// nothing could detect its removal. That is the property this file exists to
// not have, so each one gets an arm that fails without it.
// ---------------------------------------------------------------------------
describe("verifyApiKey: a polluted key-status switch cannot decide whether a key is honoured", () => {
  test("a polluted `allowUnregisteredKeys` cannot silence the construction-time throw", async () => {
    await withPolluted(["allowUnregisteredKeys"], () => {
      // Broken build: the inherited `true` satisfies `allowUnregistered`, so a
      // service that wired NO key-status hook at all boots clean and cannot
      // revoke a single one of its keys.
      expect(() => verifyApiKey(bagWithout(["keyStatus"]))).toThrow(
        "verifyApiKey requires a key-status hook",
      );
    });
  });

  test("a polluted `allowUnregisteredKeys` cannot admit a kid this service has no record of", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["allowUnregisteredKeys"], async () => {
      // The service DID wire a strict hook, and it answers "unknown".
      const verifier = verifyApiKey(
        bagWithout([], { keyStatus: (): ApiKeyStatus => "unknown" }),
      );
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(false);
    expect(decision.ok === false && decision.reason).toBe("unknown_key");
  });

  test("a polluted `keyStatus` cannot inject a verdict for a service that wired none", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["keyStatus"], async () => {
      // Broken build: the inherited resolver is treated as this service's own
      // hook and answers "revoked" for every key presented.
      const verifier = verifyApiKey(
        bagWithout(["keyStatus"], { allowUnregisteredKeys: true }),
      );
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(true);
    expect(decision.ok === true && decision.principal.app).toBe(APP);
  });

  test("a polluted `isRevoked` cannot inject a verdict for a service that wired none", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["isRevoked"], async () => {
      const verifier = verifyApiKey(
        bagWithout(["keyStatus"], { allowUnregisteredKeys: true }),
      );
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(true);
  });

  test("an own `keyStatus` still decides, and still denies, under the same pollution", async () => {
    const good = tokenFor();
    const decision = await withPolluted(["keyStatus", "isRevoked"], async () => {
      const verifier = verifyApiKey(
        bagWithout([], { keyStatus: (): ApiKeyStatus => "expired" }),
      );
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(false);
    expect(decision.ok === false && decision.reason).toBe("expired");
  });

  test("a polluted `keyStatus` cannot trip the both-hooks-supplied construction throw", async () => {
    await withPolluted(["keyStatus"], () => {
      // Broken build: the service supplied only `isRevoked`, but the inherited
      // `keyStatus` makes it look like it supplied both, and construction
      // throws — one prototype write takes every such service down at boot.
      const verifier = verifyApiKey(
        bagWithout(["keyStatus"], { isRevoked: () => false, allowUnregisteredKeys: true }),
      );
      expect(verifier.app).toBe(APP);
    });
  });
});

// ---------------------------------------------------------------------------
// The AUDIT-LINE reads on the per-request `context` bag. Not accept/deny — they
// decide what the audit trail SAYS happened, which is the record an operator
// reads back when answering "what did this key do".
// ---------------------------------------------------------------------------
describe("verifyApiKey: polluted `context.method`/`context.path` cannot forge the audit line", () => {
  test("a context that names no route audits null, not the planted route", async () => {
    const good = tokenFor();
    const events: Array<Record<string, unknown>> = [];
    const decision = await withPolluted(["method", "path"], async () => {
      const verifier = verifyApiKey(
        bagWithout([], { audit: (e: Record<string, unknown>) => void events.push(e) }),
      );
      // An empty context — the shape `expressApiKey` produces when a framework
      // supplies neither, and the shape every direct caller uses by default.
      return verifier.authenticate({ "x-api-key": good }, {});
    });

    expect(decision.ok).toBe(true);
    expect(events).toHaveLength(1);
    // Exact values, both ways: the broken build writes the planted strings onto
    // this line, so an operator reading the trail sees a DELETE against an admin
    // purge route that no request ever made.
    expect(Object.hasOwn(events[0]!, "method")).toBe(true);
    expect(Object.hasOwn(events[0]!, "path")).toBe(true);
    expect(events[0]!.method).toBeNull();
    expect(events[0]!.path).toBeNull();
  });

  test("a polluted `kid` cannot be attributed on a denial that never established one", async () => {
    // `verifyApiKeyToken` returns `kid` as an own property only for
    // `tenant_required`/`tenant_mismatch`. On every other denial — including
    // `bad_signature` here — it is absent, so a bare `verified.kid ?? null`
    // resolved up the prototype chain, and `??` cannot catch a planted string
    // because it is not nullish.
    //
    // Found by the adversarial reviewer on #87, not by the mutation harness:
    // that harness only reverts sites the fix touched, and this one was not a
    // site until now. A per-site control cannot find a site nobody listed.
    const good = tokenFor();
    const tampered = `${good.slice(0, -4)}AAAA`;
    const events: Array<Record<string, unknown>> = [];
    const decision = await withPolluted(["kid"], async () => {
      const verifier = verifyApiKey(
        bagWithout([], { audit: (e: Record<string, unknown>) => void events.push(e) }),
      );
      return verifier.authenticate({ "x-api-key": tampered });
    });

    // The denial itself is unaffected — this is audit integrity, not acceptance.
    expect(decision.ok).toBe(false);
    expect(decision.ok === false && decision.reason).toBe("bad_signature");
    expect(events).toHaveLength(1);
    expect(Object.hasOwn(events[0]!, "kid")).toBe(true);
    // Exact value both ways: the broken build audits the planted string, so an
    // operator reading the trail attributes an unauthenticated request to a key
    // the attacker named — and `kid` is the field revocation lookups key on.
    expect(events[0]!.kid).toBeNull();
  });

  test("a real `kid` is still attributed on a denial that DID establish one", async () => {
    // The other direction: `tenant_mismatch` is one of the two reasons that DOES
    // carry a kid, so the guard must not blank a genuine attribution.
    const tenanted = tokenFor({ tid: TID });
    const events: Array<Record<string, unknown>> = [];
    const decision = await withPolluted(["kid"], async () => {
      const verifier = verifyApiKey(
        bagWithout([], {
          expectedTid: OTHER_TID,
          audit: (e: Record<string, unknown>) => void events.push(e),
        }),
      );
      return verifier.authenticate({ "x-api-key": tenanted });
    });

    expect(decision.ok).toBe(false);
    expect(decision.ok === false && decision.reason).toBe("tenant_mismatch");
    expect(events).toHaveLength(1);
    expect(typeof events[0]!.kid).toBe("string");
    expect(events[0]!.kid).toMatch(/^[0-9a-f]{16}$/);
  });

  test("an own method/path still reaches the audit line under the same pollution", async () => {
    const good = tokenFor();
    const events: Array<Record<string, unknown>> = [];
    await withPolluted(["method", "path"], async () => {
      const verifier = verifyApiKey(
        bagWithout([], { audit: (e: Record<string, unknown>) => void events.push(e) }),
      );
      await verifier.authenticate({ "x-api-key": good }, { method: "GET", path: "/v1/todos" });
    });

    expect(events).toHaveLength(1);
    expect(events[0]!.method).toBe("GET");
    expect(events[0]!.path).toBe("/v1/todos");
  });
});

// ---------------------------------------------------------------------------
// BOTH DIRECTIONS, everything at once. A guard that fails closed on legitimate
// input is a different outage, not a fix.
// ---------------------------------------------------------------------------
describe("verifyApiKey: a fully-specified bag is unaffected by pollution of every option name", () => {
  const ALL = [
    "app",
    "signingSecret",
    "requiredScopes",
    "requireTenant",
    "expectedTid",
    "headerName",
    "scheme",
    "leewaySeconds",
    "nowMs",
    "audit",
  ] as const;

  test("every explicitly-passed option still binds", async () => {
    const nowMs = 1_700_000_000_000;
    const tenanted = mintApiKey({
      app: APP,
      scopes: ["todos:read", "todos:write"],
      signingSecret: SIGNING,
      tid: TID,
      agent: "station01",
      nowMs,
      ttlSeconds: DAY,
    }).token;

    const events: Array<Record<string, unknown>> = [];
    const decision = await withPolluted(ALL, async () => {
      const verifier = verifyApiKey({
        app: APP,
        signingSecret: SIGNING,
        keyStatus: (): ApiKeyStatus => "active",
        requiredScopes: ["todos:read"],
        requireTenant: true,
        expectedTid: TID,
        headerName: "x-my-key",
        scheme: "Token",
        leewaySeconds: 30,
        nowMs: () => nowMs + 1000,
        audit: (e) => void events.push(e as unknown as Record<string, unknown>),
      });
      return verifier.authenticate({ "x-my-key": tenanted }, { method: "GET", path: "/v1/todos" });
    });

    expect(decision.ok).toBe(true);
    const principal = decision.ok === true ? decision.principal : null;
    expect(principal!.app).toBe(APP);
    expect(principal!.tid).toBe(TID);
    expect(principal!.agent).toBe("station01");
    expect(principal!.scopes).toEqual(["todos:read", "todos:write"]);

    expect(events).toHaveLength(1);
    expect(events[0]!.app).toBe(APP);
    expect(events[0]!.tid).toBe(TID);
    expect(events[0]!.method).toBe("GET");
    expect(events[0]!.path).toBe("/v1/todos");
    expect(events[0]!.scopesRequired).toEqual(["todos:read"]);
  });

  test("the own scheme still works and the polluted one does not", async () => {
    const good = tokenFor();
    const results = await withPolluted(ALL, async () => {
      const verifier = verifyApiKey(bagWithout([], { scheme: "Token" }));
      return {
        own: await verifier.authenticate({ authorization: `Token ${good}` }),
        planted: await verifier.authenticate({ authorization: `Attacker ${good}` }),
      };
    });

    expect(results.own.ok).toBe(true);
    expect(results.planted.ok).toBe(false);
    expect(results.planted.ok === false && results.planted.reason).toBe("missing_token");
  });

  test("the deprecated `isRevoked` path still denies under full pollution", async () => {
    const good = tokenFor();
    const decision = await withPolluted(ALL, async () => {
      const verifier = verifyApiKey(
        bagWithout([], { keyStatus: undefined, isRevoked: () => true, allowUnregisteredKeys: true }),
      );
      return verifier.authenticate({ "x-api-key": good });
    });

    expect(decision.ok).toBe(false);
    expect(decision.ok === false && decision.reason).toBe("revoked");
  });
});
