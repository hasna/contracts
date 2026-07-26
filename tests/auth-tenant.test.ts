import { describe, expect, test } from "bun:test";
import {
  MAX_TENANT_ID_LENGTH,
  TENANT_ID_PATTERN,
  canonicalizeTenantId,
  isUuidTenantId,
  isValidTenantId,
  normalizeTenantId,
  tenantIdsEqual,
} from "../src/auth/tenant";
import { mintApiKey, parseApiKey, verifyApiKeyToken } from "../src/auth/keys";
import { verifyApiKey, type AuthAuditEvent } from "../src/auth/middleware";
import { ApiKeyStore, apiKeyMigrations, type AuthQueryClient, type Row } from "../src/auth/store";

const SIGNING = "test-signing-secret-not-a-real-credential-000";

/**
 * FROZEN FIXTURE — a token minted by the code as it stood BEFORE the `tid`
 * claim existed (origin/main @ 5149327), with a fixed kid and a fixed clock so
 * the bytes never move. Do not regenerate it: its whole job is to be a token
 * this build did not produce. Regenerating it would turn the backwards-
 * compatibility proof into a tautology about the current code.
 */
const LEGACY_TOKEN =
  "hasna_todos_eyJ2IjoxLCJraWQiOiJsZWdhY3lmaXhlZGtpZDAxIiwiYXBwIjoidG9kb3MiLCJzY29wZXMiOlsidG9kb3M6cmVhZCIsInRvZG9zOndyaXRlIl0sImlhdCI6MTcwMDAwMDAwMCwiZXhwIjpudWxsLCJhZ2VudCI6ImxlZ2FjeS1hZ2VudCJ9.xb8c-LdlAqTjznvVpsNSFYntTjCyKoCrVUnuIvzr_4g";
const LEGACY_NOW_MS = 1_800_000_000_000; // well after the fixture's iat

// --- grammar ---
describe("tenant id grammar", () => {
  test("accepts every identifier shape already in use across the fleet", () => {
    for (const id of [
      "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d", // UUID
      "01HQ3XZ8VJ9K2M4N6P8R0T2W4Y", // ULID
      "org_01HQ3XZ8VJ9K2M4N6P8R0T2W4Y", // prefixed id
      "acme-corp", // slug
      "acme.corp", // dotted slug
      "1", // minimal
      "a".repeat(MAX_TENANT_ID_LENGTH), // at the cap
    ]) {
      expect(isValidTenantId(id), id).toBe(true);
    }
  });

  test("rejects anything unsafe in a log line, header, or URL segment", () => {
    for (const id of [
      "",
      " acme",
      "acme corp",
      "acme/corp",
      "acme:corp", // `:` is the scope separator
      "acme@corp",
      "-acme", // must start alphanumeric
      "_acme",
      "acme\ncorp",
      "acme ", // trailing space
      "acme\u0000corp", // embedded NUL, written as an escape so this file stays text
      "ácme", // non-ASCII
      "a".repeat(MAX_TENANT_ID_LENGTH + 1),
    ]) {
      expect(isValidTenantId(id), JSON.stringify(id)).toBe(false);
    }
  });

  test("rejects non-string values outright — the wire type is a string", () => {
    for (const value of [null, undefined, 42, true, {}, [], ["acme"]]) {
      expect(isValidTenantId(value), JSON.stringify(value ?? null)).toBe(false);
    }
  });

  test("the exported pattern is the same one the validator enforces", () => {
    expect(TENANT_ID_PATTERN.test("acme-corp")).toBe(true);
    expect(TENANT_ID_PATTERN.test("acme corp")).toBe(false);
  });

  test("UUIDs fold to lowercase; nothing else does", () => {
    const upper = "9D4B2A1C-0E5F-4A7B-8C3D-1E2F3A4B5C6D";
    expect(isUuidTenantId(upper)).toBe(true);
    expect(canonicalizeTenantId(upper)).toBe(upper.toLowerCase());

    // The `uuid`-column vs `text`-column drift this exists to close.
    expect(tenantIdsEqual(upper, upper.toLowerCase())).toBe(true);

    // A non-UUID id stays case-sensitive: `Acme` and `acme` are two tenants.
    expect(canonicalizeTenantId("Acme")).toBe("Acme");
    expect(tenantIdsEqual("Acme", "acme")).toBe(false);
  });

  test("tenantIdsEqual never matches on invalid input", () => {
    expect(tenantIdsEqual(null, null)).toBe(false);
    expect(tenantIdsEqual("acme", null)).toBe(false);
    expect(tenantIdsEqual("acme corp", "acme corp")).toBe(false);
  });

  test("normalizeTenantId trims, validates, and canonicalizes", () => {
    expect(normalizeTenantId("  acme-corp  ")).toBe("acme-corp");
    expect(normalizeTenantId(" 9D4B2A1C-0E5F-4A7B-8C3D-1E2F3A4B5C6D ")).toBe(
      "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d",
    );
    expect(() => normalizeTenantId("acme corp")).toThrow(/Invalid tenant id/);
  });
});

// --- backwards compatibility: the whole point of "additively" ---
describe("backwards compatibility with pre-tid tokens", () => {
  test("a token minted BEFORE tid existed still parses", () => {
    const parsed = parseApiKey(LEGACY_TOKEN);
    expect(parsed).not.toBeNull();
    expect(parsed?.claims.kid).toBe("legacyfixedkid01");
    expect(parsed?.claims.tid).toBeUndefined();
  });

  test("a token minted BEFORE tid existed still VERIFIES", () => {
    const result = verifyApiKeyToken(LEGACY_TOKEN, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      nowMs: LEGACY_NOW_MS,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.kid).toBe("legacyfixedkid01");
      expect(result.tid).toBeNull();
      expect(result.claims.agent).toBe("legacy-agent");
    }
  });

  test("a pre-tid token still satisfies scope requirements", () => {
    const result = verifyApiKeyToken(LEGACY_TOKEN, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      nowMs: LEGACY_NOW_MS,
      requiredScopes: ["todos:read", "todos:write"],
    });
    expect(result.ok).toBe(true);
  });

  test("a pre-tid token still authenticates through the middleware", async () => {
    const events: AuthAuditEvent[] = [];
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      nowMs: () => LEGACY_NOW_MS,
      audit: (event) => void events.push(event),
    });
    const decision = await verifier.authenticate({ "x-api-key": LEGACY_TOKEN });
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.principal.tid).toBeNull();
    expect(events[0]?.outcome).toBe("allow");
    expect(events[0]?.tid).toBeNull();
  });

  test("minting without a tenant produces the exact pre-tid body — no new field, no reordering", () => {
    const minted = mintApiKey({
      app: "todos",
      scopes: ["todos:read", "todos:write"],
      signingSecret: SIGNING,
      kid: "legacyfixedkid01",
      agent: "legacy-agent",
      ttlSeconds: null,
      nowMs: 1_700_000_000_000,
    });
    // Byte-for-byte identical to the frozen fixture: an omitted tenant adds
    // nothing to the signed body, so signatures over old bodies stay valid and
    // any consumer storing tokenHash keeps matching.
    expect(minted.token).toBe(LEGACY_TOKEN);
    expect("tid" in minted.claims).toBe(false);
  });

  test("a pre-tid token is still accepted by a store record round-trip", async () => {
    const store = new ApiKeyStore(new FakeStoreClient());
    await store.ensureSchema();
    const minted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    await store.insertMinted(minted);
    const record = await store.findByKid(minted.kid);
    expect(record?.tid).toBeNull();
  });
});

// --- tenanted tokens ---
describe("tenanted API keys", () => {
  test("tid is minted into the signed claims and survives verification", () => {
    const minted = mintApiKey({
      app: "todos",
      scopes: ["todos:read"],
      signingSecret: SIGNING,
      tid: "acme-corp",
    });
    expect(minted.claims.tid).toBe("acme-corp");
    const result = verifyApiKeyToken(minted.token, { signingSecret: SIGNING, expectedApp: "todos" });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.tid).toBe("acme-corp");
  });

  test("mint canonicalizes a UUID tenant so a uuid column and a text column agree", () => {
    const minted = mintApiKey({
      app: "todos",
      scopes: ["todos:read"],
      signingSecret: SIGNING,
      tid: "9D4B2A1C-0E5F-4A7B-8C3D-1E2F3A4B5C6D",
    });
    expect(minted.claims.tid).toBe("9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d");
  });

  test("mint refuses a malformed tenant rather than dropping it", () => {
    expect(() =>
      mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, tid: "acme corp" }),
    ).toThrow(/Invalid tenant id/);
    expect(() =>
      mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, tid: "" }),
    ).toThrow(/Invalid tenant id/);
  });

  test("tid is covered by the signature — tampering invalidates the token", () => {
    const minted = mintApiKey({
      app: "todos",
      scopes: ["todos:read"],
      signingSecret: SIGNING,
      tid: "acme-corp",
    });
    const parsed = parseApiKey(minted.token)!;
    const forgedClaims = { ...parsed.claims, tid: "rival-corp" };
    const forgedBody = Buffer.from(JSON.stringify(forgedClaims)).toString("base64url");
    const forged = `hasna_todos_${forgedBody}.${parsed.sig}`;

    const result = verifyApiKeyToken(forged, { signingSecret: SIGNING, expectedApp: "todos" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature");
  });

  test("a present-but-malformed tid is malformed, not untenanted", () => {
    // Hand-built body with tid: null. If the parser tolerated this, the token
    // would slip past `requireTenant` as "no tenant claimed".
    const body = Buffer.from(
      JSON.stringify({ v: 1, kid: "k1", app: "todos", tid: null, scopes: ["todos:read"], iat: 1, exp: null }),
    ).toString("base64url");
    expect(parseApiKey(`hasna_todos_${body}.sig`)).toBeNull();

    const numeric = Buffer.from(
      JSON.stringify({ v: 1, kid: "k1", app: "todos", tid: 7, scopes: ["todos:read"], iat: 1, exp: null }),
    ).toString("base64url");
    expect(parseApiKey(`hasna_todos_${numeric}.sig`)).toBeNull();

    const unsafe = Buffer.from(
      JSON.stringify({ v: 1, kid: "k1", app: "todos", tid: "a/b", scopes: ["todos:read"], iat: 1, exp: null }),
    ).toString("base64url");
    expect(parseApiKey(`hasna_todos_${unsafe}.sig`)).toBeNull();
  });
});

// --- enforcement ---
describe("tenant enforcement in verifyApiKeyToken", () => {
  const untenanted = () => mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
  const tenanted = (tid: string) =>
    mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, tid });

  test("requireTenant rejects an untenanted token — absence is not a wildcard", () => {
    const result = verifyApiKeyToken(untenanted().token, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      requireTenant: true,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("tenant_required");
  });

  test("expectedTid implies requireTenant", () => {
    const result = verifyApiKeyToken(untenanted().token, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      expectedTid: "acme-corp",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("tenant_required");
  });

  test("expectedTid rejects a token for another tenant", () => {
    const result = verifyApiKeyToken(tenanted("rival-corp").token, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      expectedTid: "acme-corp",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("tenant_mismatch");
  });

  test("expectedTid accepts the matching tenant, case-folding UUIDs only", () => {
    const uuid = "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d";
    const ok = verifyApiKeyToken(tenanted(uuid).token, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      expectedTid: uuid.toUpperCase(),
    });
    expect(ok.ok).toBe(true);

    const slug = verifyApiKeyToken(tenanted("acme-corp").token, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      expectedTid: "ACME-CORP",
    });
    expect(slug.ok).toBe(false);
  });

  test("a malformed expectedTid denies rather than throwing in the request path", () => {
    const result = verifyApiKeyToken(tenanted("acme-corp").token, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      expectedTid: "acme corp",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("tenant_mismatch");
      expect(result.message).toMatch(/not a valid tenant id/);
    }
  });

  test("tenant is checked before scopes — a wrong-tenant token is not merely under-scoped", () => {
    const result = verifyApiKeyToken(tenanted("rival-corp").token, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      expectedTid: "acme-corp",
      requiredScopes: ["todos:write"], // also unsatisfied
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("tenant_mismatch");
  });
});

describe("tenant enforcement in the middleware", () => {
  const tenanted = (tid: string) =>
    mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, tid });

  test("principal and audit event both carry the tenant", async () => {
    const events: AuthAuditEvent[] = [];
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      requireTenant: true,
      audit: (event) => void events.push(event),
    });
    const decision = await verifier.authenticate({ "x-api-key": tenanted("acme-corp").token });
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.principal.tid).toBe("acme-corp");
    expect(events[0]?.tid).toBe("acme-corp");
  });

  test("tenant failures deny with 403, not 401 — the credential is authentic", async () => {
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, requireTenant: true });
    const untenanted = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING });
    const decision = await verifier.authenticate({ "x-api-key": untenanted.token });
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.status).toBe(403);
      expect(decision.reason).toBe("tenant_required");
    }
  });

  test("a per-call expectedTid guards an org-addressed route", async () => {
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING });
    const token = tenanted("acme-corp").token;

    const own = await verifier.authenticate({ "x-api-key": token }, { expectedTid: "acme-corp" });
    expect(own.ok).toBe(true);

    const other = await verifier.authenticate({ "x-api-key": token }, { expectedTid: "rival-corp" });
    expect(other.ok).toBe(false);
    if (!other.ok) {
      expect(other.status).toBe(403);
      expect(other.reason).toBe("tenant_mismatch");
    }
  });

  test("a malformed per-call expectedTid denies instead of throwing", async () => {
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING });
    const decision = await verifier.authenticate(
      { "x-api-key": tenanted("acme-corp").token },
      { expectedTid: "acme corp" },
    );
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.reason).toBe("tenant_mismatch");
  });

  test("a malformed middleware-wide expectedTid throws at construction, not per request", () => {
    expect(() => verifyApiKey({ app: "todos", signingSecret: SIGNING, expectedTid: "acme corp" })).toThrow(
      /invalid 'expectedTid'/,
    );
  });
});

// --- store ---
describe("api-keys tenant column", () => {
  test("0003 is additive: it alters, never recreates", () => {
    const migrations = apiKeyMigrations("api_keys");
    const tenant = migrations.find((m) => m.id === "hasna_auth_0003_api_keys_tenant");
    expect(tenant).toBeDefined();
    expect(tenant!.sql).toContain("ADD COLUMN IF NOT EXISTS tid TEXT");
    expect(tenant!.sql).not.toContain("NOT NULL");
    // Earlier migrations must be untouched, or deployed ledgers would diverge.
    expect(migrations[0]?.id).toBe("hasna_auth_0001_api_keys");
    expect(migrations[1]?.id).toBe("hasna_auth_0002_api_keys_indexes");
  });

  test("insertMinted persists the tenant and list() filters by it", async () => {
    const store = new ApiKeyStore(new FakeStoreClient());
    await store.ensureSchema();
    const acme = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, tid: "acme-corp" });
    const rival = mintApiKey({ app: "todos", scopes: ["todos:read"], signingSecret: SIGNING, tid: "rival-corp" });
    await store.insertMinted(acme);
    await store.insertMinted(rival);

    expect((await store.findByKid(acme.kid))?.tid).toBe("acme-corp");
    const listed = await store.list({ tid: "acme-corp" });
    expect(listed.map((record) => record.kid)).toEqual([acme.kid]);
  });

  test("list() passes its parameters — a filtered list is not an unfiltered one", async () => {
    const client = new FakeStoreClient();
    const store = new ApiKeyStore(client);
    await store.ensureSchema();
    await store.list({ app: "todos", tid: "acme-corp" });
    // Regression guard: `list` built a params array and did not pass it, so a
    // real driver saw `WHERE app = $1 AND tid = $2` with zero bound values.
    expect(client.lastManyParams).toEqual(["todos", "acme-corp"]);
  });
});

/** In-memory client that interprets the store's SQL, with tenant support. */
class FakeStoreClient implements AuthQueryClient {
  rows = new Map<string, Row>();
  lastManyParams: readonly unknown[] = [];

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
    if (sql.includes("WHERE kid =")) {
      return (this.rows.get(String(params[0])) as unknown as T) ?? null;
    }
    return null;
  }

  async many<T extends Row>(sql: string, params: readonly unknown[] = []): Promise<T[]> {
    this.lastManyParams = params;
    let rows = [...this.rows.values()];
    // Interpret the WHERE clause positionally, the way the driver would.
    let index = 0;
    if (sql.includes("app = $")) {
      const app = params[index++];
      rows = rows.filter((row) => row.app === app);
    }
    if (sql.includes("tid = $")) {
      const tid = params[index++];
      rows = rows.filter((row) => row.tid === tid);
    }
    if (sql.includes("revoked_at IS NULL")) rows = rows.filter((row) => !row.revoked_at);
    return rows as unknown as T[];
  }
}
