// Regression suite for the unknown-kid default-allow defect (todos 0cbc57a2).
//
// The defect: `verifyApiKey({ isRevoked: store.isRevoked })` ACCEPTED any
// validly-signed token whose kid had no `api_keys` row, because a boolean
// revocation predicate cannot express "I have never heard of this key" — it
// returns `false` (meaning "not revoked") for both an active key and a key that
// was never registered. A key minted `--no-store` was therefore irrevocable:
// revocation works by writing `revoked_at` on a row, and there was no row.
//
// Worse, both hooks were OPTIONAL, so a service that wired neither performed no
// revocation check at all and could not turn ANY of its keys off.
//
// These tests pin the fixed contract: a verifier must be constructed with a
// deny-unknown status resolver, or must opt in to the permissive behaviour
// EXPLICITLY and greppably. Silence is no longer a vote for "allow".

import { afterEach, describe, expect, test } from "bun:test";
import { mintApiKey } from "../src/auth/keys";
import { ApiKeyStore, type AuthQueryClient, type Row } from "../src/auth/store";
import { verifyApiKey } from "../src/auth/middleware";

const SIGNING = "test-signing-secret-not-a-real-credential-000";

/** Minimal in-memory stand-in for the Postgres-backed api_keys table. */
class FakeClient implements AuthQueryClient {
  readonly rows = new Map<string, Row>();

  async execute(sql: string, params: readonly unknown[] = []): Promise<void> {
    if (sql.includes("INSERT INTO")) {
      const [kid, app, agent, tid, scopes, token_hash, issued_at, expires_at, created_by] = params as unknown[];
      this.rows.set(String(kid), {
        kid,
        app,
        agent,
        tid,
        scopes,
        token_hash,
        issued_at,
        expires_at,
        revoked_at: null,
        revoked_reason: null,
        last_used_at: null,
        created_by,
      });
    }
  }

  async get<T extends Row>(sql: string, params: readonly unknown[] = []): Promise<T | null> {
    if (sql.startsWith("UPDATE") && sql.includes("RETURNING")) {
      const [kid, at, reason] = params as unknown[];
      const row = this.rows.get(String(kid));
      if (!row) return null;
      if (row.revoked_at === null || row.revoked_at === undefined) {
        row.revoked_at = at;
        row.revoked_reason = reason ?? null;
      }
      return { kid: row.kid } as unknown as T;
    }
    if (sql.startsWith("SELECT revoked_at")) {
      const row = this.rows.get(String(params[0]));
      return row ? ({ revoked_at: row.revoked_at } as unknown as T) : null;
    }
    if (sql.includes("WHERE kid =")) {
      return (this.rows.get(String(params[0])) as unknown as T) ?? null;
    }
    return null;
  }

  async many<T extends Row>(): Promise<T[]> {
    return [...this.rows.values()] as unknown as T[];
  }
}

async function freshStore(): Promise<ApiKeyStore> {
  const store = new ApiKeyStore(new FakeClient());
  await store.ensureSchema();
  return store;
}

function headersFor(token: string): Record<string, string> {
  return { "x-api-key": token };
}

describe("unknown kid is refused by default", () => {
  test("REGRESSION: a validly-signed token with NO api_keys row is DENIED", async () => {
    const store = await freshStore();
    // Minted and never persisted — exactly what `issue-key --no-store` produces,
    // and exactly what an attacker holding the signing secret would produce.
    const ghost = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    expect(await store.findByKid(ghost.kid)).toBeNull();

    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, keyStatus: store.keyStatus });
    const decision = await verifier.authenticate(headersFor(ghost.token));

    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.reason).toBe("unknown_key");
      expect(decision.status).toBe(401);
    }
  });

  test("POSITIVE CONTROL: the same verifier ACCEPTS a registered, active key", async () => {
    // Without this the test above proves nothing — a verifier that denied every
    // request would pass it. This pins that the denial is caused by the missing
    // row and not by the verifier being broken.
    const store = await freshStore();
    const known = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    await store.insertMinted(known, "test");

    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, keyStatus: store.keyStatus });
    const decision = await verifier.authenticate(headersFor(known.token));

    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.principal.kid).toBe(known.kid);
  });

  test("a registered key that is later revoked is denied with reason 'revoked'", async () => {
    const store = await freshStore();
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    await store.insertMinted(minted, "test");
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, keyStatus: store.keyStatus });

    expect((await verifier.authenticate(headersFor(minted.token))).ok).toBe(true);
    expect(await store.revoke(minted.kid, "leaked")).toBe(true);

    const after = await verifier.authenticate(headersFor(minted.token));
    expect(after.ok).toBe(false);
    if (!after.ok) expect(after.reason).toBe("revoked");
  });

  test("a row whose expires_at has passed is denied with reason 'expired'", async () => {
    const store = await freshStore();
    // Token exp is far future so `verifyApiKeyToken` passes; the ROW is what
    // has expired. Without a status resolver this case was invisible.
    const minted = mintApiKey({
      app: "todos",
      scopes: ["todos:read"],
      signingSecret: SIGNING,
      ttlSeconds: 60 * 60 * 24 * 365,
    });
    await store.insert({
      kid: minted.kid,
      app: "todos",
      scopes: ["todos:read"],
      tokenHash: minted.tokenHash,
      issuedAt: new Date(Date.now() - 1000),
      expiresAt: new Date(Date.now() - 1),
    });

    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, keyStatus: store.keyStatus });
    const decision = await verifier.authenticate(headersFor(minted.token));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.reason).toBe("expired");
  });

  test("the deny is attributed to the kid in the audit trail", async () => {
    const store = await freshStore();
    const ghost = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const events: { outcome: string; kid: string | null; reason: string | null }[] = [];
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: store.keyStatus,
      audit: (e) => {
        events.push({ outcome: e.outcome, kid: e.kid, reason: e.reason });
      },
    });

    await verifier.authenticate(headersFor(ghost.token));
    expect(events).toHaveLength(1);
    expect(events[0]?.outcome).toBe("deny");
    expect(events[0]?.reason).toBe("unknown_key");
    // An unregistered key is precisely the one an operator most needs named.
    expect(events[0]?.kid).toBe(ghost.kid);
  });
});

describe("construction fails closed", () => {
  test("REGRESSION: omitting every revocation hook THROWS instead of silently checking nothing", async () => {
    // Seven fleet services spread `...(store ? { isRevoked: store.isRevoked } : {})`,
    // so a missing store produced a verifier that could not revoke ANY key.
    expect(() => verifyApiKey({ app: "todos", signingSecret: SIGNING })).toThrow(/keyStatus/);
  });

  test("REGRESSION: the lossy `isRevoked` hook alone THROWS and names the strict replacement", async () => {
    const store = await freshStore();
    let message = "";
    try {
      verifyApiKey({ app: "todos", signingSecret: SIGNING, isRevoked: store.isRevoked });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toMatch(/isRevoked/);
    expect(message).toMatch(/keyStatus|statusChecker/);
    expect(message).toMatch(/allowUnregisteredKeys/);
  });

  test("both hooks together THROW rather than one silently winning", async () => {
    const store = await freshStore();
    expect(() =>
      verifyApiKey({
        app: "todos",
        signingSecret: SIGNING,
        keyStatus: store.keyStatus,
        isRevoked: store.isRevoked,
      }),
    ).toThrow();
  });
});

describe("explicit, greppable opt-out preserves the old behaviour", () => {
  test("allowUnregisteredKeys + isRevoked accepts an unregistered key (documented, unsafe)", async () => {
    // The migration rung: a service that cannot yet register its keys says so
    // in one auditable place instead of inheriting the hole from a default.
    const store = await freshStore();
    const ghost = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      isRevoked: store.isRevoked,
      allowUnregisteredKeys: true,
    });
    expect((await verifier.authenticate(headersFor(ghost.token))).ok).toBe(true);
  });

  test("allowUnregisteredKeys still denies an explicitly revoked key", async () => {
    const store = await freshStore();
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    await store.insertMinted(minted, "test");
    await store.revoke(minted.kid, "leaked");
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      isRevoked: store.isRevoked,
      allowUnregisteredKeys: true,
    });
    const decision = await verifier.authenticate(headersFor(minted.token));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.reason).toBe("revoked");
  });

  test("allowUnregisteredKeys with NO hook at all is an explicit no-revocation service", async () => {
    // Still legal — an operator who writes this has said, in the source, that
    // this service cannot revoke keys. That is a reviewable claim; silence was not.
    const store = await freshStore();
    const ghost = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    void store;
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, allowUnregisteredKeys: true });
    expect((await verifier.authenticate(headersFor(ghost.token))).ok).toBe(true);
  });

  test("keyStatus + allowUnregisteredKeys tolerates unknown but still denies revoked", async () => {
    const store = await freshStore();
    const ghost = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const known = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    await store.insertMinted(known, "test");
    await store.revoke(known.kid, "leaked");

    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: store.keyStatus,
      allowUnregisteredKeys: true,
    });
    expect((await verifier.authenticate(headersFor(ghost.token))).ok).toBe(true);
    const revoked = await verifier.authenticate(headersFor(known.token));
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) expect(revoked.reason).toBe("revoked");
  });
});

describe("a polluted prototype cannot re-open the hole", () => {
  // The options bag is caller-built, so a plain read resolves through the
  // prototype chain. One `Object.prototype.allowUnregisteredKeys = true` write
  // would otherwise flip every correctly-wired strict verifier back to
  // accepting unknown kids AND silence the construction-time throw — both
  // defenses defeated by a single write. This mirrors the existing
  // `expectedTid` pollution test in tests/auth-tenant.test.ts.
  const POLLUTED: string[] = [];
  function pollute(prop: string, value: unknown): void {
    Object.defineProperty(Object.prototype, prop, { value, configurable: true, enumerable: false, writable: true });
    POLLUTED.push(prop);
  }
  afterEach(() => {
    for (const prop of POLLUTED.splice(0)) {
      delete (Object.prototype as Record<string, unknown>)[prop];
    }
  });

  test("REGRESSION: Object.prototype.allowUnregisteredKeys does NOT make a strict verifier accept an unknown kid", async () => {
    const store = await freshStore();
    const ghost = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });

    // Pollute BEFORE construction. The flag is captured once at construction,
    // so polluting afterwards exercises nothing — an earlier draft of this test
    // did exactly that and stayed green against deliberately broken code.
    // Pre-construction is also the realistic order: a pollution gadget fires
    // during startup or request parsing, before or as the verifier is built.
    pollute("allowUnregisteredKeys", true);

    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, keyStatus: store.keyStatus });
    const decision = await verifier.authenticate(headersFor(ghost.token));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.reason).toBe("unknown_key");
  });

  test("REGRESSION: Object.prototype.allowUnregisteredKeys does NOT silence the construction throw", async () => {
    pollute("allowUnregisteredKeys", true);
    expect(() => verifyApiKey({ app: "todos", signingSecret: SIGNING })).toThrow(/keyStatus/);
  });

  test("an injected Object.prototype.keyStatus cannot supply the verdict", async () => {
    // A polluted resolver answering "active" would authenticate everything.
    // Construction must not see it as a wired hook at all.
    pollute("keyStatus", () => "active");
    expect(() => verifyApiKey({ app: "todos", signingSecret: SIGNING })).toThrow(/keyStatus/);
  });

  test("an injected Object.prototype.isRevoked cannot satisfy the wiring requirement", async () => {
    pollute("isRevoked", () => false);
    expect(() => verifyApiKey({ app: "todos", signingSecret: SIGNING })).toThrow(/keyStatus/);
  });
});

describe("an unavailable status lookup denies rather than throwing or allowing", () => {
  test("REGRESSION: a throwing keyStatus resolver returns 503, never an allow and never an exception", async () => {
    // keyStatus is a per-request DB read in every real store. A Postgres blip
    // must not become an unhandled rejection (which hangs the request under
    // Express 4) and must certainly not become an allow.
    const known = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: () => {
        throw new Error("connection terminated unexpectedly");
      },
    });

    const decision = await verifier.authenticate(headersFor(known.token));
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.reason).toBe("status_unavailable");
      expect(decision.status).toBe(503);
    }
  });

  test("a rejecting async resolver is handled the same way", async () => {
    const known = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const events: string[] = [];
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: async () => Promise.reject(new Error("pool exhausted")),
      audit: (e) => void events.push(`${e.outcome}:${e.reason}`),
    });
    const decision = await verifier.authenticate(headersFor(known.token));
    expect(decision.ok).toBe(false);
    expect(events).toEqual(["deny:status_unavailable"]);
  });

  test("POSITIVE CONTROL: a healthy resolver still allows, so 503 is not blanket-deny", async () => {
    const store = await freshStore();
    const known = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    await store.insertMinted(known, "test");
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, keyStatus: store.keyStatus });
    expect((await verifier.authenticate(headersFor(known.token))).ok).toBe(true);
  });
});

describe("an unrecognized status value is treated as unknown, not minted into the audit trail", () => {
  test("REGRESSION: a store returning 'Active' (wrong case) denies as unknown_key, not as 'Active'", async () => {
    const known = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const events: (string | null)[] = [];
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: () => "Active" as never,
      audit: (e) => void events.push(e.reason),
    });

    const decision = await verifier.authenticate(headersFor(known.token));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.reason).toBe("unknown_key");
    // The contract's reason vocabulary must not grow a value a store invented.
    expect(events).toEqual(["unknown_key"]);
  });

  test("an unrecognized status is NOT tolerated by allowUnregisteredKeys", async () => {
    // Only a genuine "unknown" is opted out of; a value we cannot interpret is
    // not evidence that the key is merely unregistered.
    const known = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: () => "totally-bogus" as never,
      allowUnregisteredKeys: true,
    });
    const decision = await verifier.authenticate(headersFor(known.token));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.reason).toBe("unknown_key");
  });
});

describe("statusChecker remains wired-in and strict", () => {
  test("store.statusChecker() denies unknown, revoked and expired alike", async () => {
    const store = await freshStore();
    const strict = store.statusChecker();
    expect(await strict("never-registered")).toBe(true);

    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    await store.insertMinted(minted, "test");
    // Positive control: the same checker must ALLOW something, or "denies" is vacuous.
    expect(await strict(minted.kid)).toBe(false);

    await store.revoke(minted.kid, "leaked");
    expect(await strict(minted.kid)).toBe(true);
  });
});
