import { describe, expect, test } from "bun:test";
import {
  isValidScope,
  isConcreteScope,
  scopeMatches,
  hasScope,
  hasAllScopes,
  normalizeScopes,
} from "../src/auth/scopes";
import {
  mintApiKey,
  parseApiKey,
  verifyApiKeyToken,
  hashToken,
  apiKeyPrefix,
  API_KEY_TOKEN_VERSION,
  DEFAULT_API_KEY_TTL_SECONDS,
} from "../src/auth/keys";
import {
  ApiKeyStore,
  apiKeyMigrations,
  type AuthQueryClient,
  type Row,
} from "../src/auth/store";
import { verifyApiKey, expressApiKey, honoApiKey, extractToken, type AuthAuditEvent } from "../src/auth/middleware";

const SIGNING = "test-signing-secret-not-a-real-credential-000";

// --- scopes ---
describe("scope grammar", () => {
  test("validates grants and concrete requireds", () => {
    expect(isValidScope("*")).toBe(true);
    expect(isValidScope("todos:*")).toBe(true);
    expect(isValidScope("*:read")).toBe(true);
    expect(isValidScope("todos:tasks.create")).toBe(true);
    expect(isValidScope("todos")).toBe(false);
    expect(isValidScope("Todos:Read")).toBe(false);
    expect(isValidScope("todos:")).toBe(false);
    expect(isConcreteScope("todos:read")).toBe(true);
    expect(isConcreteScope("todos:*")).toBe(false);
    expect(isConcreteScope("*")).toBe(false);
  });

  test("wildcard matching", () => {
    expect(scopeMatches("*", "todos:read")).toBe(true);
    expect(scopeMatches("todos:*", "todos:write")).toBe(true);
    expect(scopeMatches("*:read", "todos:read")).toBe(true);
    expect(scopeMatches("todos:read", "todos:read")).toBe(true);
    expect(scopeMatches("todos:read", "todos:write")).toBe(false);
    expect(scopeMatches("todos:*", "mementos:read")).toBe(false);
    // required must be concrete
    expect(scopeMatches("*", "todos:*")).toBe(false);
  });

  test("hasScope / hasAllScopes", () => {
    expect(hasScope(["todos:*"], "todos:read")).toBe(true);
    expect(hasScope(["mementos:read"], "todos:read")).toBe(false);
    expect(hasAllScopes(["todos:*"], ["todos:read", "todos:write"])).toBe(true);
    expect(hasAllScopes(["todos:read"], ["todos:read", "todos:write"])).toBe(false);
  });

  test("normalizeScopes dedupes, sorts, and rejects invalid", () => {
    expect(normalizeScopes(["todos:write", "todos:read", "todos:read"])).toEqual(["todos:read", "todos:write"]);
    expect(() => normalizeScopes(["bad scope"])).toThrow();
    expect(() => normalizeScopes([])).toThrow();
  });
});

// --- keys ---
describe("api key mint + verify", () => {
  test("mints a well-formed token with the hasna_<app>_ prefix", () => {
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    expect(minted.token.startsWith(apiKeyPrefix("todos"))).toBe(true);
    expect(minted.prefix).toBe("hasna_todos_");
    expect(minted.tokenHash).toBe(hashToken(minted.token));
    expect(minted.claims.v).toBe(API_KEY_TOKEN_VERSION);
    expect(minted.claims.app).toBe("todos");
    const parsed = parseApiKey(minted.token);
    expect(parsed?.claims.kid).toBe(minted.kid);
  });

  test("default TTL is applied; explicit null means no expiry", () => {
    const nowMs = 1_700_000_000_000;
    const withTtl = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, nowMs });
    expect(withTtl.claims.exp).toBe(Math.floor(nowMs / 1000) + DEFAULT_API_KEY_TTL_SECONDS);
    const noExp = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, ttlSeconds: null });
    expect(noExp.claims.exp).toBeNull();
  });

  test("verifies a good token and binds the app", () => {
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const result = verifyApiKeyToken(minted.token, { signingSecret: SIGNING, expectedApp: "todos" });
    expect(result.ok).toBe(true);
    const wrongApp = verifyApiKeyToken(minted.token, { signingSecret: SIGNING, expectedApp: "mementos" });
    expect(wrongApp.ok).toBe(false);
    if (!wrongApp.ok) expect(wrongApp.reason).toBe("app_mismatch");
  });

  test("rejects a tampered signature and a wrong signing secret", () => {
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const tampered = minted.token.slice(0, -2) + (minted.token.endsWith("aa") ? "bb" : "aa");
    const r1 = verifyApiKeyToken(tampered, { signingSecret: SIGNING });
    expect(r1.ok).toBe(false);
    const r2 = verifyApiKeyToken(minted.token, { signingSecret: "a-different-secret-16bytes+more" });
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toBe("bad_signature");
  });

  test("rejects a payload with swapped claims (signature covers the body)", () => {
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const forgedClaims = { ...minted.claims, scopes: ["todos:*"] };
    const forgedBody = Buffer.from(JSON.stringify(forgedClaims)).toString("base64url");
    const sig = minted.token.split(".")[1];
    const forged = `${apiKeyPrefix("todos")}${forgedBody}.${sig}`;
    const r = verifyApiKeyToken(forged, { signingSecret: SIGNING });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("bad_signature");
  });

  test("enforces TTL", () => {
    const nowMs = 1_700_000_000_000;
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, ttlSeconds: 60, nowMs });
    const still = verifyApiKeyToken(minted.token, { signingSecret: SIGNING, nowMs: nowMs + 30_000 });
    expect(still.ok).toBe(true);
    const expired = verifyApiKeyToken(minted.token, { signingSecret: SIGNING, nowMs: nowMs + 120_000 });
    expect(expired.ok).toBe(false);
    if (!expired.ok) expect(expired.reason).toBe("expired");
  });

  test("enforces required scopes", () => {
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const ok = verifyApiKeyToken(minted.token, { signingSecret: SIGNING, requiredScopes: ["todos:read"] });
    expect(ok.ok).toBe(true);
    const denied = verifyApiKeyToken(minted.token, { signingSecret: SIGNING, requiredScopes: ["todos:write"] });
    expect(denied.ok).toBe(false);
    if (!denied.ok) expect(denied.reason).toBe("insufficient_scope");
  });

  test("malformed tokens are rejected, not thrown", () => {
    expect(verifyApiKeyToken("nonsense", { signingSecret: SIGNING }).ok).toBe(false);
    expect(parseApiKey("nope")).toBeNull();
  });

  test("mint rejects invalid input", () => {
    expect(() => mintApiKey({ app: "Bad App", scopes: ["todos:read"], signingSecret: SIGNING })).toThrow();
    expect(() => mintApiKey({ app: "todos", scopes: [], signingSecret: SIGNING })).toThrow();
    expect(() => mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: "short" })).toThrow();
  });
});

// --- in-memory store fake (interprets the store's SQL) ---
class FakeStoreClient implements AuthQueryClient {
  rows = new Map<string, Row>();

  async execute(sql: string, params: readonly unknown[] = []): Promise<void> {
    if (sql.includes("CREATE TABLE") || sql.includes("CREATE INDEX")) return;
    if (sql.startsWith("INSERT INTO")) {
      const [kid, app, agent, scopes, token_hash, issued_at, expires_at, created_by] = params as unknown[];
      if (this.rows.has(String(kid))) throw new Error("duplicate key value violates unique constraint (kid)");
      for (const row of this.rows.values()) {
        if (row.token_hash === token_hash) throw new Error("duplicate key value violates unique constraint (token_hash)");
      }
      this.rows.set(String(kid), {
        kid,
        app,
        agent,
        scopes,
        token_hash,
        issued_at,
        expires_at,
        revoked_at: null,
        revoked_reason: null,
        last_used_at: null,
        created_by,
      });
      return;
    }
    if (sql.includes("SET last_used_at")) {
      const [kid, at] = params as unknown[];
      const row = this.rows.get(String(kid));
      if (row) row.last_used_at = at;
      return;
    }
  }

  async get<T extends Row>(sql: string, params: readonly unknown[] = []): Promise<T | null> {
    if (sql.startsWith("SELECT revoked_at")) {
      const row = this.rows.get(String(params[0]));
      return row ? ({ revoked_at: row.revoked_at } as unknown as T) : null;
    }
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
    if (sql.includes("token_hash =")) {
      for (const row of this.rows.values()) {
        if (row.token_hash === params[0]) return row as unknown as T;
      }
      return null;
    }
    if (sql.includes("WHERE kid =")) {
      const row = this.rows.get(String(params[0]));
      return (row as unknown as T) ?? null;
    }
    return null;
  }

  async many<T extends Row>(sql: string, _params: readonly unknown[] = []): Promise<T[]> {
    if (sql.includes("revoked_at IS NOT NULL") && sql.includes("SELECT kid")) {
      return [...this.rows.values()].filter((r) => r.revoked_at).map((r) => ({ kid: r.kid })) as unknown as T[];
    }
    let rows = [...this.rows.values()];
    if (sql.includes("revoked_at IS NULL")) rows = rows.filter((r) => !r.revoked_at);
    return rows as unknown as T[];
  }
}

describe("api key store (fake client)", () => {
  test("migration ids are namespaced and deterministic", () => {
    const m = apiKeyMigrations("api_keys");
    expect(m[0]?.id).toBe("hasna_auth_0001_api_keys");
    expect(m.length).toBe(2);
  });

  test("insert, find, status, revoke lifecycle", async () => {
    const store = new ApiKeyStore(new FakeStoreClient());
    await store.ensureSchema();
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, agent: "alice" });
    await store.insertMinted(minted, "issuer");

    const byKid = await store.findByKid(minted.kid);
    expect(byKid?.app).toBe("todos");
    expect(byKid?.scopes).toEqual(["todos:read"]);
    expect(byKid?.agent).toBe("alice");

    const byHash = await store.findByTokenHash(minted.tokenHash);
    expect(byHash?.kid).toBe(minted.kid);

    expect(await store.status(minted.kid)).toBe("active");
    expect(await store.isRevoked(minted.kid)).toBe(false);

    expect(await store.revoke(minted.kid, "compromised")).toBe(true);
    expect(await store.isRevoked(minted.kid)).toBe(true);
    expect(await store.status(minted.kid)).toBe("revoked");
    expect(await store.revokedKids()).toEqual([minted.kid]);
  });

  test("duplicate insert throws (no silent overwrite)", async () => {
    const store = new ApiKeyStore(new FakeStoreClient());
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, kid: "fixedkid" });
    await store.insertMinted(minted);
    await expect(store.insertMinted(minted)).rejects.toThrow();
  });

  test("unknown kid: isRevoked false, status unknown, strict checker denies", async () => {
    const store = new ApiKeyStore(new FakeStoreClient());
    expect(await store.isRevoked("ghost")).toBe(false);
    expect(await store.status("ghost")).toBe("unknown");
    const strict = store.statusChecker();
    expect(await strict("ghost")).toBe(true);
  });

  test("expired record reports expired status", async () => {
    const store = new ApiKeyStore(new FakeStoreClient());
    const nowMs = 1_700_000_000_000;
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, ttlSeconds: 60, nowMs });
    await store.insertMinted(minted);
    expect(await store.status(minted.kid, nowMs + 120_000)).toBe("expired");
  });
});

// --- middleware ---
describe("verifyApiKey middleware (agnostic)", () => {
  test("extractToken from x-api-key and Authorization: Bearer", () => {
    expect(extractToken({ "x-api-key": "abc" })).toBe("abc");
    expect(extractToken({ authorization: "Bearer xyz" })).toBe("xyz");
    expect(extractToken({ authorization: "bearer xyz" })).toBe("xyz");
    expect(extractToken({})).toBeNull();
  });

  test("allows a valid key and denies missing/invalid", async () => {
    const events: AuthAuditEvent[] = [];
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, audit: (e) => void events.push(e) });
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });

    const ok = await verifier.authenticate({ "x-api-key": minted.token }, { method: "GET", path: "/tasks" });
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(ok.principal.kid).toBe(minted.kid);

    const missing = await verifier.authenticate({});
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.status).toBe(401);

    expect(events.some((e) => e.outcome === "allow")).toBe(true);
    expect(events.some((e) => e.outcome === "deny" && e.reason === "missing_token")).toBe(true);
  });

  test("scope enforcement returns 403", async () => {
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, requiredScopes: ["todos:write"] });
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const decision = await verifier.authenticate({ "x-api-key": minted.token });
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.status).toBe(403);
      expect(decision.reason).toBe("insufficient_scope");
    }
  });

  test("revocation via store denies the key", async () => {
    const store = new ApiKeyStore(new FakeStoreClient());
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    await store.insertMinted(minted);
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, isRevoked: store.isRevoked });

    expect((await verifier.authenticate({ "x-api-key": minted.token })).ok).toBe(true);
    await store.revoke(minted.kid);
    const after = await verifier.authenticate({ "x-api-key": minted.token });
    expect(after.ok).toBe(false);
    if (!after.ok) expect(after.reason).toBe("revoked");
  });

  test("expired token denied via middleware clock override", async () => {
    const nowMs = 1_700_000_000_000;
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, ttlSeconds: 60, nowMs });
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, nowMs: () => nowMs + 120_000 });
    const decision = await verifier.authenticate({ "x-api-key": minted.token });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.reason).toBe("expired");
  });

  test("missing signingSecret throws at construction (no insecure default)", () => {
    expect(() => verifyApiKey({ app: "todos", signingSecret: "" })).toThrow();
  });

  test("express adapter sets req.apiKey and rejects", async () => {
    const mw = expressApiKey({ app: "todos", signingSecret: SIGNING });
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });

    const req: any = { headers: { "x-api-key": minted.token }, method: "GET", url: "/x" };
    let nexted = false;
    await mw(req, {} as any, () => {
      nexted = true;
    });
    expect(nexted).toBe(true);
    expect(req.apiKey.kid).toBe(minted.kid);

    let status = 0;
    let body: any;
    const res: any = { status: (s: number) => ({ json: (b: any) => { status = s; body = b; } }) };
    await mw({ headers: {}, method: "GET", url: "/x" } as any, res, () => {});
    expect(status).toBe(401);
    expect(body.reason).toBe("missing_token");
  });

  test("hono adapter sets context and rejects", async () => {
    const mw = honoApiKey({ app: "todos", signingSecret: SIGNING });
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });

    let stored: any;
    let nexted = false;
    const c: any = {
      req: { header: (n: string) => (n.toLowerCase() === "x-api-key" ? minted.token : undefined), method: "GET", path: "/x" },
      set: (_k: string, v: any) => { stored = v; },
      json: (b: any, s: number) => ({ b, s }),
    };
    await mw(c, async () => { nexted = true; });
    expect(nexted).toBe(true);
    expect(stored.kid).toBe(minted.kid);

    const cFail: any = {
      req: { header: () => undefined, method: "GET", path: "/x" },
      set: () => {},
      json: (b: any, s: number) => ({ b, s }),
    };
    const out: any = await mw(cFail, async () => {});
    expect(out.s).toBe(401);
  });
});

// --- gated live Postgres store test ---
const DATABASE_URL = process.env.AUTH_TEST_DATABASE_URL ?? process.env.KIT_TEST_DATABASE_URL;
const describeLive = DATABASE_URL ? describe : describe.skip;

describeLive("api key store live Postgres", () => {
  test("full lifecycle against a real database", async () => {
    const pgModule: any = await import("pg");
    const Pool = pgModule.default?.Pool ?? pgModule.Pool;
    const pool = new Pool({ connectionString: DATABASE_URL });
    const table = "auth_test_api_keys";
    const client: AuthQueryClient = {
      many: async (sql, params) => (await pool.query(sql, params as unknown[])).rows,
      get: async (sql, params) => (await pool.query(sql, params as unknown[])).rows[0] ?? null,
      execute: async (sql, params) => { await pool.query(sql, params as unknown[]); },
    };
    try {
      await pool.query(`DROP TABLE IF EXISTS ${table}`);
      const store = new ApiKeyStore(client, { table });
      await store.ensureSchema();
      const minted = mintApiKey({ app: "todos", scopes: ["todos:read", "todos:write"], signingSecret: SIGNING, agent: "live" });
      await store.insertMinted(minted, "livetest");
      const found = await store.findByKid(minted.kid);
      expect(found?.scopes.sort()).toEqual(["todos:read", "todos:write"]);
      expect(await store.isRevoked(minted.kid)).toBe(false);
      expect(await store.revoke(minted.kid, "done")).toBe(true);
      expect(await store.isRevoked(minted.kid)).toBe(true);
      const list = await store.list({ app: "todos", includeRevoked: true });
      expect(list.some((r) => r.kid === minted.kid)).toBe(true);
    } finally {
      await pool.query(`DROP TABLE IF EXISTS ${table}`).catch(() => {});
      await pool.end();
    }
  });
});
