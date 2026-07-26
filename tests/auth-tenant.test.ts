import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
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
      "a".repeat(64), // at the cap, written literally: a self-referential
      //               `MAX_TENANT_ID_LENGTH` bound can never catch the cap moving
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
      "a".repeat(65), // one over the cap, again a literal
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

  test("the documented cap is 64 — pinned, so widening it is a deliberate act", () => {
    // The "always safe in a header value / URL segment" claim rests on this
    // number. Asserting it against itself would let a change to 4096 pass.
    expect(MAX_TENANT_ID_LENGTH).toBe(64);
    expect(TENANT_ID_PATTERN.source).toBe("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$");
  });

  test("every spelling a PostgreSQL uuid column accepts folds to ONE value", () => {
    const canonical = "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d";
    // These are exactly the forms `SELECT '<x>'::uuid` accepts and rewrites.
    // Recognizing fewer of them leaves the `uuid`-here / `text`-there drift
    // open, which is the entire reason this claim exists.
    for (const spelling of [
      canonical,
      canonical.toUpperCase(),
      "9d4b2a1c0e5f4a7b8c3d1e2f3a4b5c6d", // hyphen-less
      "9D4B2A1C0E5F4A7B8C3D1E2F3A4B5C6D", // hyphen-less, upper
      "{9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d}", // brace-wrapped, as a DB client pastes it
      "{9D4B2A1C0E5F4A7B8C3D1E2F3A4B5C6D}",
    ]) {
      expect(isUuidTenantId(spelling), spelling).toBe(true);
      expect(canonicalizeTenantId(spelling), spelling).toBe(canonical);
      expect(tenantIdsEqual(spelling, canonical), spelling).toBe(true);
    }
  });

  test("nothing but a UUID is folded — including a ULID, deliberately", () => {
    // A non-UUID id stays case-sensitive: `Acme` and `acme` are two tenants.
    expect(canonicalizeTenantId("Acme")).toBe("Acme");
    expect(tenantIdsEqual("Acme", "acme")).toBe(false);

    // Crockford base32 is case-insensitive as an ENCODING, but no database type
    // silently rewrites a ULID the way `uuid` rewrites a UUID. Folding it would
    // only create new ways for two distinct opaque ids to collide, so the
    // contract requires issuers to emit the canonical uppercase form instead.
    expect(tenantIdsEqual("01HQ3XZ8VJ9K2M4N6P8R0T2W4Y", "01hq3xz8vj9k2m4n6p8r0t2w4y")).toBe(false);
    // A prefixed id is opaque all the way through.
    expect(tenantIdsEqual("org_ABC", "org_abc")).toBe(false);
  });

  test("a 32-hex string is treated as the UUID it is, in both directions", () => {
    // Guards the specific drift the reviewer found: a `text` store holding the
    // hyphen-less form and a `uuid` store holding the hyphenated form name the
    // same tenant.
    expect(
      tenantIdsEqual("9D4B2A1C0E5F4A7B8C3D1E2F3A4B5C6D", "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d"),
    ).toBe(true);
    expect(normalizeTenantId("9D4B2A1C0E5F4A7B8C3D1E2F3A4B5C6D")).toBe(
      "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d",
    );
  });

  test("tenantIdsEqual never matches on invalid input", () => {
    expect(tenantIdsEqual(null, null)).toBe(false);
    expect(tenantIdsEqual("acme", null)).toBe(false);
    expect(tenantIdsEqual("acme corp", "acme corp")).toBe(false);
  });

  test("tenantIdsEqual trims, so an env var with a trailing newline still matches", () => {
    // Mint trims. A comparison that did not would deny every request for a
    // reason no operator could see in their config.
    expect(tenantIdsEqual("acme-corp", "  acme-corp\n")).toBe(true);
    expect(tenantIdsEqual("acme-corp", " rival-corp ")).toBe(false);
  });

  test("normalizeTenantId trims, validates, and canonicalizes", () => {
    expect(normalizeTenantId("  acme-corp  ")).toBe("acme-corp");
    expect(normalizeTenantId(" 9D4B2A1C-0E5F-4A7B-8C3D-1E2F3A4B5C6D ")).toBe(
      "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d",
    );
    expect(() => normalizeTenantId("acme corp")).toThrow(/Invalid tenant id/);
    expect(normalizeTenantId("{9D4B2A1C-0E5F-4A7B-8C3D-1E2F3A4B5C6D}")).toBe(
      "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d",
    );
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

  test("tid is read as an OWN property, never through the prototype chain", () => {
    const polluted = Object.create({ tid: "attacker-tenant" }) as Record<string, unknown>;
    Object.assign(polluted, { v: 1, kid: "k1", app: "todos", scopes: ["todos:read"], iat: 1, exp: null });
    // `"tid" in polluted` and `polluted.tid !== undefined` are both true here.
    // Only an own-property check keeps an untenanted token untenanted if some
    // other part of the process ever gains an Object.prototype write primitive.
    expect(Object.hasOwn(polluted, "tid")).toBe(false);
    expect((polluted as { tid?: string }).tid).toBe("attacker-tenant");
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

  test("requireTenant fails CLOSED for any truthy value, not only `true`", () => {
    // A config value that arrived as the string "true" or the number 1 must not
    // silently disable the gate. Strictness in that direction is a fail-open.
    for (const requireTenant of [true, "true", 1, "1", "yes", {}] as unknown[]) {
      const result = verifyApiKeyToken(untenanted().token, {
        signingSecret: SIGNING,
        expectedApp: "todos",
        requireTenant: requireTenant as boolean,
      });
      expect(result.ok, JSON.stringify(requireTenant)).toBe(false);
      if (!result.ok) expect(result.reason).toBe("tenant_required");
    }
    // Falsy values leave the gate off, which is the documented default.
    for (const requireTenant of [false, undefined, 0, ""] as unknown[]) {
      const result = verifyApiKeyToken(untenanted().token, {
        signingSecret: SIGNING,
        expectedApp: "todos",
        requireTenant: requireTenant as boolean,
      });
      expect(result.ok, JSON.stringify(requireTenant ?? null)).toBe(true);
    }
  });

  test("a tenant denial names the offending key, so it can be revoked from the audit log", () => {
    const minted = tenanted("rival-corp");
    const result = verifyApiKeyToken(minted.token, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      expectedTid: "acme-corp",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.kid).toBe(minted.kid);
      expect(result.tid).toBe("rival-corp");
    }
  });

  test("a pre-signature failure attributes NOTHING — an unverified token is not evidence", () => {
    const forged = `${tenanted("rival-corp").token.slice(0, -4)}AAAA`;
    const result = verifyApiKeyToken(forged, {
      signingSecret: SIGNING,
      expectedApp: "todos",
      expectedTid: "acme-corp",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("bad_signature");
      expect(result.kid).toBeUndefined();
      expect(result.tid).toBeUndefined();
    }
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

  test("a per-call expectedTid CANNOT override a middleware-wide pin", async () => {
    // The hole this closes: `context.expectedTid` typically comes from a
    // request path (/v1/orgs/:tid/...). If it simply replaced the pin, any
    // holder of a valid token for this app — they all share the app's signing
    // secret — could defeat a service pinned to another tenant by addressing
    // their own org in the URL.
    const verifier = verifyApiKey({ app: "todos", signingSecret: SIGNING, expectedTid: "acme-corp" });
    const evil = tenanted("evil-corp").token;

    const bypass = await verifier.authenticate({ "x-api-key": evil }, { expectedTid: "evil-corp" });
    expect(bypass.ok).toBe(false);
    if (!bypass.ok) {
      expect(bypass.status).toBe(403);
      expect(bypass.reason).toBe("tenant_mismatch");
    }

    // Agreeing values still work, and still bind to the pinned tenant.
    const agreeing = await verifier.authenticate(
      { "x-api-key": tenanted("acme-corp").token },
      { expectedTid: "acme-corp" },
    );
    expect(agreeing.ok).toBe(true);

    // Without a per-call value the pin alone governs.
    const pinnedOnly = await verifier.authenticate({ "x-api-key": evil });
    expect(pinnedOnly.ok).toBe(false);
  });

  test("a tenant denial is attributable in the audit trail", async () => {
    const events: AuthAuditEvent[] = [];
    const verifier = verifyApiKey({
      app: "todos",
      signingSecret: SIGNING,
      expectedTid: "acme-corp",
      audit: (event) => void events.push(event),
    });
    const minted = tenanted("rival-corp");
    await verifier.authenticate({ "x-api-key": minted.token });
    expect(events[0]?.outcome).toBe("deny");
    expect(events[0]?.reason).toBe("tenant_mismatch");
    expect(events[0]?.kid).toBe(minted.kid);
    expect(events[0]?.tid).toBe("rival-corp");
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
/**
 * Replica of `checksumSql` in src/kit/templates/migrations.ts — the function
 * consumers' migration ledgers actually use. Duplicated rather than imported
 * because that file is a vendored TEMPLATE, and a test that imported it would
 * silently follow the template if the template itself changed.
 */
function ledgerChecksum(sql: string): string {
  return `sha256:${createHash("sha256").update(sql.trim().replace(/\r\n/g, "\n")).digest("hex")}`;
}

describe("api-keys tenant column", () => {
  test("PINNED: already-applied migrations' SQL is byte-frozen", () => {
    // Consumers feed these into a CONTENT-ADDRESSED ledger (open-accounts
    // src/server/migrations.ts, open-emails src/server/self-hosted/migrations.ts).
    // Editing applied SQL does not merely fail to re-run — it aborts the whole
    // migration run with "Migration checksum mismatch", so the upgrade breaks
    // AND the new column never lands. Asserting only the ids, as this test
    // originally did, cannot see that. These hashes are the values on
    // origin/main and MUST NOT be updated to make a change pass.
    const pinned = new Map([
      ["hasna_auth_0001_api_keys", "sha256:95429079245944aa39727486cf92dea0ae8a1bfa889e1940f2d9911eb0b020a5"],
      ["hasna_auth_0002_api_keys_indexes", "sha256:4e646262846e9ae664b5b0d67cb079f788c85d45fcc3a323131df5aa9ba7b777"],
    ]);
    for (const migration of apiKeyMigrations("api_keys")) {
      const expected = pinned.get(migration.id);
      if (expected) expect(ledgerChecksum(migration.sql), migration.id).toBe(expected);
    }
    // 0001 in particular must not have grown the tenant column.
    const first = apiKeyMigrations("api_keys")[0]!;
    expect(first.id).toBe("hasna_auth_0001_api_keys");
    expect(first.sql).not.toContain("tid");
  });

  test("0003 is additive: it alters, never recreates, and back-fills nothing", () => {
    const migrations = apiKeyMigrations("api_keys");
    expect(migrations.map((m) => m.id)).toEqual([
      "hasna_auth_0001_api_keys",
      "hasna_auth_0002_api_keys_indexes",
      "hasna_auth_0003_api_keys_tenant",
    ]);
    const tenant = migrations[2]!;
    expect(tenant.sql).toContain("ADD COLUMN IF NOT EXISTS tid TEXT");
    expect(tenant.sql).not.toContain("NOT NULL");
    // No DEFAULT either: pre-`tid` keys are untenanted, NOT tenant-zero. A
    // default would silently assign every historical key to one organization.
    expect(tenant.sql).not.toMatch(/\bDEFAULT\b/i);
    expect(tenant.sql).not.toMatch(/\bUPDATE\b/i);
    expect(tenant.sql).not.toMatch(/\bDROP\b/i);
  });

  test("the INSERT's column list and its bound parameters stay aligned", () => {
    // Adding `tid` shifted every positional parameter after it. A fake client
    // that destructures params positionally cannot see a column/placeholder
    // swap — on a real driver that silently writes the tenant into `agent`.
    const client = new FakeStoreClient();
    const store = new ApiKeyStore(client);
    void store.insert({
      kid: "k1",
      app: "todos",
      agent: "AGENT-VALUE",
      tid: "acme-corp",
      scopes: ["todos:read"],
      tokenHash: "hash",
      issuedAt: new Date(0),
      expiresAt: null,
      createdBy: "CREATED-BY",
    });

    const sql = client.lastExecuteSql;
    const columns = /\(([^)]*)\)\s*VALUES/i.exec(sql)![1]!.split(",").map((c) => c.trim());
    const placeholders = [...sql.matchAll(/\$(\d+)/g)].map((m) => Number(m[1]));
    expect(columns.length).toBe(placeholders.length);
    expect(placeholders).toEqual(columns.map((_, index) => index + 1));

    // The decisive assertion: each column holds the value meant for it.
    const row = Object.fromEntries(columns.map((column, index) => [column.replace(/::.*$/, ""), client.lastExecuteParams[index]]));
    expect(row.kid).toBe("k1");
    expect(row.agent).toBe("AGENT-VALUE");
    expect(row.tid).toBe("acme-corp");
    expect(row.created_by).toBe("CREATED-BY");
  });

  test("the store refuses a tenant id no token could ever carry", async () => {
    const store = new ApiKeyStore(new FakeStoreClient());
    await expect(
      store.insert({
        kid: "k2",
        app: "todos",
        tid: "not a valid tid/../x",
        scopes: ["todos:read"],
        tokenHash: "hash2",
        issuedAt: new Date(0),
        expiresAt: null,
      }),
    ).rejects.toThrow(/Invalid tenant id/);
  });

  test("the store writes and filters the CANONICAL tenant id", async () => {
    const client = new FakeStoreClient();
    const store = new ApiKeyStore(client);
    await store.insert({
      kid: "k3",
      app: "todos",
      tid: "9D4B2A1C0E5F4A7B8C3D1E2F3A4B5C6D", // hyphen-less, upper
      scopes: ["todos:read"],
      tokenHash: "hash3",
      issuedAt: new Date(0),
      expiresAt: null,
    });
    expect((await store.findByKid("k3"))?.tid).toBe("9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d");

    // Listing by any spelling of the same UUID finds it.
    for (const spelling of [
      "9d4b2a1c-0e5f-4a7b-8c3d-1e2f3a4b5c6d",
      "9D4B2A1C-0E5F-4A7B-8C3D-1E2F3A4B5C6D",
      "9d4b2a1c0e5f4a7b8c3d1e2f3a4b5c6d",
    ]) {
      expect((await store.list({ tid: spelling })).map((r) => r.kid), spelling).toEqual(["k3"]);
    }
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

/**
 * In-memory client that interprets the store's SQL.
 *
 * Deliberately binds INSERT values BY PARSED COLUMN NAME rather than by
 * position. A positional fake is blind to a column/placeholder swap — the
 * exact defect that would silently write a tenant id into `agent` against a
 * real driver.
 */
class FakeStoreClient implements AuthQueryClient {
  rows = new Map<string, Row>();
  lastManyParams: readonly unknown[] = [];
  lastExecuteSql = "";
  lastExecuteParams: readonly unknown[] = [];

  async execute(sql: string, params: readonly unknown[] = []): Promise<void> {
    this.lastExecuteSql = sql;
    this.lastExecuteParams = params;
    if (sql.includes("CREATE TABLE") || sql.includes("CREATE INDEX") || sql.includes("ALTER TABLE")) return;
    if (sql.startsWith("INSERT INTO")) {
      const columns = /\(([^)]*)\)\s*VALUES/i.exec(sql)?.[1]?.split(",").map((column) => column.trim()) ?? [];
      const row: Row = {
        revoked_at: null,
        revoked_reason: null,
        last_used_at: null,
      };
      for (const [index, column] of columns.entries()) {
        row[column.replace(/::.*$/, "")] = params[index];
      }
      this.rows.set(String(row.kid), row);
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
