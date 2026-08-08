import { describe, expect, test } from "bun:test";
import { mintApiKey, verifyApiKeyToken } from "../src/auth/keys";
import { verifyApiKey, type AuthAuditEvent } from "../src/auth/middleware";
import { ApiKeyStore, type ApiKeyStatus, type AuthQueryClient, type Row } from "../src/auth/store";

const SIGNING = "test-signing-secret-not-a-real-credential-000";

/**
 * Minimal store client: enough for insert + lookup by kid. Rows are kept
 * exactly as the store hands them over, so what a read gets back is what a
 * write put in — the property this file is actually asserting about.
 */
class FakeStoreClient implements AuthQueryClient {
  rows = new Map<string, Row>();

  async execute(sql: string, params: readonly unknown[] = []): Promise<void> {
    if (sql.includes("CREATE TABLE") || sql.includes("CREATE INDEX") || sql.includes("ALTER TABLE")) return;
    if (sql.startsWith("INSERT INTO")) {
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
    if (sql.startsWith("SELECT revoked_at")) {
      const row = this.rows.get(String(params[0]));
      return row ? ({ revoked_at: row.revoked_at } as unknown as T) : null;
    }
    return (this.rows.get(String(params[0])) as T | undefined) ?? null;
  }

  async many<T extends Row>(): Promise<T[]> {
    return [...this.rows.values()] as T[];
  }
}

/** The value an attacker with an `Object.prototype` write primitive plants. */
const POLLUTED_AGENT = "attacker-agent";

/**
 * Run `fn` with `Object.prototype.agent` set, then remove it.
 *
 * This is the process-wide condition any `__proto__`/`constructor.prototype`
 * write primitive elsewhere in a verifying service creates. Under it, a plain
 * `claims.agent` read resolves to the attacker's value for every token that
 * carries NO agent claim — and the claims object is `JSON.parse` output
 * (`keys.ts`), so it has `Object.prototype` in its chain and the read is a
 * genuine prototype lookup rather than a hypothetical one.
 *
 * Non-enumerable so the planted key cannot leak into unrelated `for...in`
 * loops (the test runner's included) while staying visible to the
 * prototype-chain reads under test — those reads are identical either way.
 *
 * Restored in a `finally` so pollution cannot escape into sibling tests. A
 * polluted prototype leaking into the rest of the suite is its own outage.
 */
async function withPollutedAgentPrototype<T>(fn: () => T | Promise<T>): Promise<T> {
  Object.defineProperty(Object.prototype, "agent", {
    value: POLLUTED_AGENT,
    configurable: true,
    enumerable: false,
    writable: true,
  });
  try {
    // The pollution must actually be in place, or every assertion below is
    // vacuous — it would pass just as well against code that never had the
    // defect, and prove nothing.
    expect(({} as unknown as { agent?: string }).agent).toBe(POLLUTED_AGENT);
    return await fn();
  } finally {
    delete (Object.prototype as unknown as { agent?: string }).agent;
  }
}

describe("agent claim under a polluted Object.prototype", () => {
  test("minting under pollution never signs a prototype-supplied agent", async () => {
    const [anon, named] = await withPollutedAgentPrototype(() => [
      mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING }),
      mintApiKey({
        app: "todos",
        scopes: ["todos:read"],
        signingSecret: SIGNING,
        agent: "station01",
      }),
    ]);

    expect(Object.hasOwn(anon.claims, "agent")).toBe(false);
    expect(anon.claims.agent).toBeUndefined();
    expect(named.claims.agent).toBe("station01");

    const verified = verifyApiKeyToken(anon.token, { signingSecret: SIGNING, expectedApp: "todos" });
    expect(verified.ok).toBe(true);
    if (verified.ok) expect(verified.agent).toBeNull();
  });

  test("the allow path reports no agent for a token that claims none", async () => {
    const events: AuthAuditEvent[] = [];
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      allowUnregisteredKeys: true,
      audit: (e) => void events.push(e),
    });
    // Minted with NO agent: nothing in the signed body names a subject.
    const anon = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });

    const decision = await withPollutedAgentPrototype(() =>
      verifier.authenticate({ "x-api-key": anon.token }, { method: "GET", path: "/tasks" }),
    );

    expect(decision.ok).toBe(true);
    // The principal must not name a subject the token never proved.
    if (decision.ok) expect(decision.principal.agent).toBeNull();

    const allow = events.find((e) => e.outcome === "allow");
    expect(allow).toBeDefined();
    // `null` — established, and the key carries no claim. NOT the planted value.
    expect(allow?.agent).toBeNull();
    expect(allow?.agent).not.toBe(POLLUTED_AGENT);
  });

  test("post-status deny paths report no agent for a token that claims none", async () => {
    // Every deny that happens AFTER the signature verified reads the agent for
    // attribution. Each is exercised separately: one unguarded read left behind
    // is a full audit-attribution forgery on that path.
    const revoked: AuthAuditEvent[] = [];
    const vRevoked = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: async (): Promise<ApiKeyStatus> => "revoked",
      audit: (e) => void revoked.push(e),
    });

    const unavailable: AuthAuditEvent[] = [];
    const vUnavailable = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: async (): Promise<ApiKeyStatus> => {
        throw new Error("status store unreachable");
      },
      audit: (e) => void unavailable.push(e),
    });

    // `isRevoked` is the deprecated resolver and cannot refuse an unregistered
    // key on its own, so the explicit opt-out is required to construct it. The
    // path still runs in production, so it still gets covered.
    const legacyRevoked: AuthAuditEvent[] = [];
    const vLegacyRevoked = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      allowUnregisteredKeys: true,
      isRevoked: async () => true,
      audit: (e) => void legacyRevoked.push(e),
    });

    const legacyUnavailable: AuthAuditEvent[] = [];
    const vLegacyUnavailable = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      allowUnregisteredKeys: true,
      isRevoked: async () => {
        throw new Error("status store unreachable");
      },
      audit: (e) => void legacyUnavailable.push(e),
    });

    const underScoped: AuthAuditEvent[] = [];
    const vUnderScoped = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      allowUnregisteredKeys: true,
      requiredScopes: ["todos:write"],
      audit: (e) => void underScoped.push(e),
    });

    const anon = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });

    await withPollutedAgentPrototype(async () => {
      expect((await vRevoked.authenticate({ "x-api-key": anon.token })).ok).toBe(false);
      expect((await vUnavailable.authenticate({ "x-api-key": anon.token })).ok).toBe(false);
      expect((await vLegacyRevoked.authenticate({ "x-api-key": anon.token })).ok).toBe(false);
      expect((await vLegacyUnavailable.authenticate({ "x-api-key": anon.token })).ok).toBe(false);
      expect((await vUnderScoped.authenticate({ "x-api-key": anon.token })).ok).toBe(false);
    });

    const found = (events: AuthAuditEvent[], reason: string): AuthAuditEvent => {
      const event = events.find((e) => e.reason === reason);
      expect(event, `expected a '${reason}' audit event`).toBeDefined();
      return event as AuthAuditEvent;
    };

    expect(found(revoked, "revoked").agent).toBeNull();
    expect(found(unavailable, "status_unavailable").agent).toBeNull();
    expect(found(legacyRevoked, "revoked").agent).toBeNull();
    expect(found(legacyUnavailable, "status_unavailable").agent).toBeNull();
    expect(found(underScoped, "insufficient_scope").agent).toBeNull();
  });

  test("a real agent claim still reaches the allow path and every deny path", async () => {
    // The failure mode opposite to the defect: a fix that drops real agents is
    // worse than the bug it fixes, because it silently empties the audit trail
    // on exactly the requests that DID name a subject.
    const allowed: AuthAuditEvent[] = [];
    const vAllowed = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      allowUnregisteredKeys: true,
      audit: (e) => void allowed.push(e),
    });

    const revoked: AuthAuditEvent[] = [];
    const vRevoked = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: async (): Promise<ApiKeyStatus> => "revoked",
      audit: (e) => void revoked.push(e),
    });

    const unavailable: AuthAuditEvent[] = [];
    const vUnavailable = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      keyStatus: async (): Promise<ApiKeyStatus> => {
        throw new Error("status store unreachable");
      },
      audit: (e) => void unavailable.push(e),
    });

    const named = mintApiKey({
      app: "todos",
      scopes: ["todos:read"],
      signingSecret: SIGNING,
      agent: "station01",
    });

    // Run under pollution too: the planted value must not win over a real claim
    // either. An own string property shadows the prototype, so this also proves
    // the guard reads the claim rather than merely defaulting to null.
    const decision = await withPollutedAgentPrototype(async () => {
      const d = await vAllowed.authenticate({ "x-api-key": named.token });
      expect((await vRevoked.authenticate({ "x-api-key": named.token })).ok).toBe(false);
      expect((await vUnavailable.authenticate({ "x-api-key": named.token })).ok).toBe(false);
      return d;
    });

    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.principal.agent).toBe("station01");
    expect(allowed.find((e) => e.outcome === "allow")?.agent).toBe("station01");
    expect(revoked.find((e) => e.reason === "revoked")?.agent).toBe("station01");
    expect(unavailable.find((e) => e.reason === "status_unavailable")?.agent).toBe("station01");
  });

  test("a pre-signature deny still reports the agent as undefined, not null and not the planted value", async () => {
    // The three-state contract on `AuthAuditEvent.agent` is load-bearing and
    // this fix must not flatten it: `undefined` means never established, which
    // is a different fact from `null` (established, no claim). Pollution must
    // not turn either into a string.
    const events: AuthAuditEvent[] = [];
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      allowUnregisteredKeys: true,
      audit: (e) => void events.push(e),
    });

    await withPollutedAgentPrototype(async () => {
      expect((await verifier.authenticate({})).ok).toBe(false);
      expect((await verifier.authenticate({ "x-api-key": "hasna_todos_bogus.bogus" })).ok).toBe(false);
    });

    const missing = events.find((e) => e.reason === "missing_token");
    expect(missing).toBeDefined();
    expect(missing?.agent).toBeUndefined();
    expect(Object.hasOwn(missing as object, "agent")).toBe(false);

    const malformed = events.find((e) => e.reason === "malformed" || e.reason === "bad_signature");
    expect(malformed).toBeDefined();
    expect(malformed?.agent).toBeUndefined();
    expect(Object.hasOwn(malformed as object, "agent")).toBe(false);
  });

  test("the carriers hold agent as an OWN property, so read-back is not a second unguarded read", async () => {
    // The specific way this class gets "fixed" and stays broken: guard the read,
    // store the result in a plain object literal, and the NEXT reader's
    // `obj.agent` walks the prototype again because the key is absent. Both
    // carriers this fix introduced must therefore always CARRY the key, even
    // when the value is null — which `toBeNull()` alone would not catch, since
    // an absent key reads as `undefined` on a clean prototype and as the
    // planted string on a polluted one.
    const anon = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });

    const verified = verifyApiKeyToken(anon.token, { signingSecret: SIGNING, expectedApp: "todos" });
    expect(verified.ok).toBe(true);
    expect(Object.hasOwn(verified, "agent")).toBe(true);

    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, allowUnregisteredKeys: true });
    const decision = await verifier.authenticate({ "x-api-key": anon.token });
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(Object.hasOwn(decision.principal, "agent")).toBe(true);
  });

  test("the key record store neither persists nor reads back a prototype-supplied agent", async () => {
    // Two more reads of the same claim, in the store rather than the request
    // path, and both were unguarded: `insertMinted` reading the minted claims,
    // and `rowToRecord` reading a driver row whose `agent` column predates the
    // migration that added it. A polluted value written here outlives the
    // request entirely — every later `SELECT agent FROM api_keys` trusts it.
    const store = new ApiKeyStore(new FakeStoreClient());
    const anon = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const named = mintApiKey({
      app: "todos",
      scopes: ["todos:read"],
      signingSecret: SIGNING,
      agent: "station01",
    });

    const [anonRecord, namedRecord] = await withPollutedAgentPrototype(async () => {
      await store.insertMinted(anon);
      await store.insertMinted(named);
      return [await store.findByKid(anon.kid), await store.findByKid(named.kid)];
    });

    expect(anonRecord).not.toBeNull();
    expect(anonRecord?.agent).toBeNull();
    expect(anonRecord?.agent).not.toBe(POLLUTED_AGENT);
    // A real agent still survives the round trip.
    expect(namedRecord?.agent).toBe("station01");
  });

  test("the public insert path never persists a prototype-supplied agent", async () => {
    const client = new FakeStoreClient();
    const store = new ApiKeyStore(client);

    await withPollutedAgentPrototype(async () => {
      await store.insert({
        kid: "directanonkey01",
        app: "todos",
        scopes: ["todos:read"],
        tokenHash: "0".repeat(64),
        issuedAt: new Date(1_700_000_000_000),
        expiresAt: null,
      });
      await store.insert({
        kid: "directnamedkey1",
        app: "todos",
        agent: "station01",
        scopes: ["todos:read"],
        tokenHash: "1".repeat(64),
        issuedAt: new Date(1_700_000_000_000),
        expiresAt: null,
      });
    });

    expect(client.rows.get("directanonkey01")?.agent).toBeNull();
    expect(client.rows.get("directnamedkey1")?.agent).toBe("station01");
  });

  test("a driver row with NO agent column reads as null, not as the prototype's value", async () => {
    // The row shape that makes `rowToRecord`'s read a real prototype lookup
    // rather than a hypothetical one: a record written before the agent column
    // existed, so the key is genuinely ABSENT rather than null. This is the
    // same case the `tid` own-read directly above it was written for.
    const client = new FakeStoreClient();
    const legacy: Row = {
      kid: "legacyfixedkid01",
      app: "todos",
      // no `agent` key at all — deliberately
      tid: null,
      scopes: JSON.stringify(["todos:read"]),
      token_hash: "0".repeat(64),
      issued_at: new Date(1_700_000_000_000).toISOString(),
      expires_at: null,
      revoked_at: null,
      revoked_reason: null,
      last_used_at: null,
      created_by: null,
    };
    expect(Object.hasOwn(legacy, "agent")).toBe(false);
    client.rows.set("legacyfixedkid01", legacy);
    const store = new ApiKeyStore(client);

    const record = await withPollutedAgentPrototype(() => store.findByKid("legacyfixedkid01"));

    expect(record).not.toBeNull();
    expect(record?.agent).toBeNull();
    expect(record?.agent).not.toBe(POLLUTED_AGENT);
  });

  test("the pollution helper restores the prototype", () => {
    // (c) in the brief: proof the `finally` actually fires, so a failure inside
    // a polluted block cannot leave the rest of the suite running dirty.
    expect(Object.hasOwn(Object.prototype, "agent")).toBe(false);
    expect(({} as unknown as { agent?: string }).agent).toBeUndefined();
  });
});
