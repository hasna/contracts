import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { createPublicKey, generateKeyPairSync, sign as edSign } from "node:crypto";
import {
  FLEET_TOKEN_ALG,
  FLEET_TOKEN_TYP,
  MAX_FLEET_TOKEN_LEEWAY_SECONDS,
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

/**
 * Strip comments and string/template literals, leaving only code.
 *
 * Without this the guard matches its own prose: `identity.ts` explains at
 * length that it must never `fetch`, and its URI validator compares
 * `scheme === "https"`. Searching raw text for those words reports the
 * documentation and the validator as network access — noise that would get the
 * guard deleted rather than obeyed.
 */
function codeOnly(source: string): string {
  let out = "";
  let index = 0;
  while (index < source.length) {
    const two = source.slice(index, index + 2);
    if (two === "//") {
      const end = source.indexOf("\n", index);
      index = end === -1 ? source.length : end;
      continue;
    }
    if (two === "/*") {
      const end = source.indexOf("*/", index + 2);
      index = end === -1 ? source.length : end + 2;
      continue;
    }
    const character = source[index]!;
    if (character === '"' || character === "'" || character === "`") {
      index += 1;
      while (index < source.length && source[index] !== character) {
        index += source[index] === "\\" ? 2 : 1;
      }
      index += 1;
      out += '""';
      continue;
    }
    out += character;
    index += 1;
  }
  return out;
}

/** Every module specifier a file imports, requires, or re-exports. */
function moduleSpecifiers(source: string): string[] {
  return [
    ...source.matchAll(/(?:\bfrom|\bimport|\brequire)\s*\(?\s*["']([^"']+)["']/g),
  ].map((match) => match[1]!);
}

/** Relative specifiers only, resolved to real files. */
function importGraph(entry: string): string[] {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.shift()!;
    if (seen.has(file) || !existsSync(file)) continue;
    seen.add(file);
    for (const specifier of moduleSpecifiers(readFileSync(file, "utf8"))) {
      if (!specifier.startsWith(".") && !specifier.startsWith("/")) continue;
      const stem = specifier.replace(/\.js$/, "");
      for (const candidate of [`${stem}.ts`, `${stem}/index.ts`, stem]) {
        const resolved = resolve(dirname(file), candidate);
        if (existsSync(resolved) && statSync(resolved).isFile()) {
          queue.push(resolved);
          break;
        }
      }
    }
  }
  return [...seen];
}

/** Anything that can open a socket, plus every module that can reach one. */
const NETWORK_CAPABLE_MODULES = new Set([
  "http", "https", "http2", "net", "tls", "dgram", "dns", "dns/promises",
  "child_process", "worker_threads", "cluster", "inspector", "repl", "vm",
]);

/** Network entry points that need no import at all. */
const NETWORK_GLOBAL_PATTERNS: Array<[string, RegExp]> = [
  ["fetch(", /\bfetch\s*\(/],
  ["new Request(", /\bnew\s+Request\s*\(/],
  ["XMLHttpRequest", /\bXMLHttpRequest\b/],
  ["WebSocket", /\bWebSocket\b/],
  ["EventSource", /\bEventSource\b/],
  ["sendBeacon", /\bsendBeacon\b/],
  ["dynamic import()", /\bimport\s*\(/],
  ["require()", /\brequire\s*\(/],
  ["globalThis[...]", /\bglobalThis\s*\[/],
  ["process.binding", /\bprocess\s*\.\s*binding\b/],
];

function networkFindings(source: string): string[] {
  const findings: string[] = [];
  for (const specifier of moduleSpecifiers(source)) {
    const bare = specifier.replace(/^node:/, "");
    if (NETWORK_CAPABLE_MODULES.has(bare)) findings.push(`imports ${specifier}`);
  }
  const code = codeOnly(source);
  for (const [label, pattern] of NETWORK_GLOBAL_PATTERNS) {
    if (pattern.test(code)) findings.push(`uses ${label}`);
  }
  return findings;
}

describe("offline by construction", () => {
  test("the guard itself has teeth: it flags each evasion the first version missed", () => {
    // The first version of this guard grepped ONE file's text against a
    // hand-written list. Both of these passed it while shipping a live fetch in
    // the built auth bundle. A guard is only worth having if it fails on the
    // thing it exists to prevent, so that is asserted here directly.
    expect(networkFindings('import { get } from "node:https";')).toContain("imports node:https");
    expect(networkFindings('import { connect } from "node:tls";')).toContain("imports node:tls");
    expect(networkFindings('import { spawn } from "node:child_process";')).toContain("imports node:child_process");
    expect(
      networkFindings(['export { refresh } from "./refresher.js";', "const x = fetch(url);"].join("\n")),
    ).toContain("uses fetch(");
    expect(networkFindings('const f = globalThis["fet" + "ch"];')).toContain("uses globalThis[...]");
    expect(networkFindings('const m = await import("node:http2");')).toContain("uses dynamic import()");

    // And it does NOT flag prose or a scheme comparison, or it would be deleted
    // rather than obeyed.
    expect(networkFindings('// never fetch; the operator refreshes out of band')).toEqual([]);
    expect(networkFindings('if (scheme === "https") return null;')).toEqual([]);
  });

  test("NOTHING reachable from @hasna/contracts/auth can touch the network", () => {
    // "Downstream services never call back to the IdP" is only true if it is
    // impossible, and it is only impossible across the WHOLE graph — a fetch in
    // a sibling module that identity.ts re-exports ships just as surely as one
    // written inline.
    const entry = join(import.meta.dir, "..", "src", "auth", "index.ts");
    const graph = importGraph(entry);
    // Non-emptiness: a walker that resolved nothing would pass vacuously.
    expect(graph.length).toBeGreaterThan(4);
    expect(graph.some((file) => file.endsWith("identity.ts"))).toBe(true);
    expect(graph.some((file) => file.endsWith("tenant.ts"))).toBe(true);

    const offenders = graph
      .map((file) => ({
        file: relative(join(import.meta.dir, ".."), file),
        findings: networkFindings(readFileSync(file, "utf8")),
      }))
      .filter((entry) => entry.findings.length > 0);
    expect(offenders).toEqual([]);
  });

  test("the BUILT auth bundle contains no network primitive", () => {
    // The graph walk reasons about source. This asserts on the artifact that
    // actually ships, which is where any evasion would have to survive.
    const outdir = mkdtempSync(join(tmpdir(), "auth-bundle-"));
    try {
      const built = Bun.spawnSync(
        ["bun", "build", "src/auth/index.ts", "--outdir", outdir, "--target", "bun"],
        { cwd: join(import.meta.dir, ".."), stdout: "pipe", stderr: "pipe" },
      );
      expect(built.exitCode).toBe(0);
      const bundle = readFileSync(join(outdir, "index.js"), "utf8");
      expect(bundle).toContain("verifyFleetToken");
      expect(networkFindings(bundle)).toEqual([]);
      // crypto is expected and required; its presence proves the specifier scan
      // is reading this bundle rather than finding nothing. Bun emits the bare
      // form, so accept either spelling — the network check strips `node:`
      // before comparing, so a bundled "http" is still caught.
      expect(
        moduleSpecifiers(bundle).map((specifier) => specifier.replace(/^node:/, "")),
      ).toContain("crypto");
    } finally {
      rmSync(outdir, { recursive: true, force: true });
    }
  }, 60_000);

  test("verifyFleetToken's key input is a value, not a locator", () => {
    // A signature that accepted a URI would make an offline guarantee
    // unenforceable. An empty key set where the keys belong must not verify.
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
    // 86400 written out: asserting against MAX_FLEET_TOKEN_TTL_SECONDS + 1 is
    // self-referential and passes just as happily if someone widens the
    // constant to a week.
    expect(MAX_FLEET_TOKEN_TTL_SECONDS).toBe(86_400);
    const result = verifyFleetToken(issuer.mint({ exp: NOW_SEC + 86_400 + 1 }), base);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("excessive_ttl");
    expect(verifyFleetToken(issuer.mint({ exp: NOW_SEC + 86_400 }), base).ok).toBe(true);
  });

  test("clock-skew leeway is CAPPED — it widens the revocation window", () => {
    expect(MAX_FLEET_TOKEN_LEEWAY_SECONDS).toBe(300);
    // A token that expired ten years ago must not become acceptable because a
    // caller passed an enormous leeway.
    const ancient = issuer.mint({ iat: NOW_SEC - 400_000_000, exp: NOW_SEC - 315_360_000 });
    const result = verifyFleetToken(ancient, { ...base, leewaySeconds: 315_360_000 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("excessive_ttl");

    // An oversized leeway is CLAMPED, not rejected: a token 60s expired is still
    // accepted (that is what 300s of leeway means), but the caller cannot buy
    // more than the ceiling. A token expired well beyond the ceiling stays dead
    // no matter what leeway is asked for.
    const justExpired = issuer.mint({ iat: NOW_SEC - 3600, exp: NOW_SEC - 60 });
    expect(verifyFleetToken(justExpired, { ...base, leewaySeconds: 120 }).ok).toBe(true);
    expect(verifyFleetToken(justExpired, { ...base, leewaySeconds: 1_000_000 }).ok).toBe(true);

    const longExpired = issuer.mint({ iat: NOW_SEC - 7200, exp: NOW_SEC - 3600 });
    expect(verifyFleetToken(longExpired, { ...base, leewaySeconds: 300 }).ok).toBe(false);
    const stretched = verifyFleetToken(longExpired, { ...base, leewaySeconds: 1_000_000 });
    expect(stretched.ok).toBe(false);
    if (!stretched.ok) expect(stretched.reason).toBe("expired");
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
