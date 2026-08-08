// `contracts issue-key` reads its options off a plain object that has
// `Object.prototype` in its chain. Commander omits an unpassed flag entirely
// rather than defining it as `undefined`, so a bare `options.<flag>` read is a
// genuine prototype lookup for every flag the operator did not type.
//
// WHY THIS FILE EXISTS AND WHY IT IS NOT THE SAME AS THE VERIFY-SIDE GUARDS.
// `ownAgentClaim`/`ownTenantId`/`ownScopesClaim` sit on the READ path: they stop
// a polluted prototype being mistaken for a claim that a token carries. This is
// the WRITE path. A value read here is passed to `mintApiKey` and lands INSIDE
// the HMAC-signed body, so the resulting token is genuinely authentic and no
// verify-time guard downstream can — or should — reject it. The only place the
// value can be stopped is here, before it is signed.
//
// THE ASSERTION TRAP, which is the whole difficulty of testing this.
// An ABSENT key reads `undefined` on a clean prototype and the attacker's value
// on a polluted one. So `expect(x).toBeUndefined()` PASSES against the broken
// build and proves nothing. Every assertion below is therefore either
// `Object.hasOwn` on the minted body, or an exact positive value.

import { describe, expect, test } from "bun:test";
import { Command } from "commander";
import { runIssueKey } from "../src/cli/issue-key";
import { parseApiKey } from "../src/auth/keys";

const SIGNING = "test-signing-secret-not-a-real-credential-000";
const APP = "todos";
const FIXED_NOW_MS = 1_700_000_000_000;
const DAY = 24 * 60 * 60;

/** Values an attacker with an `Object.prototype` write primitive plants. */
const POLLUTION = {
  app: "attacker-app",
  bootstrap: true,
  scopes: "todos:*",
  ttlDays: 36500,
  expiry: false,
  store: false,
  agent: "attacker-agent",
  tid: "11111111-1111-4111-8111-111111111111",
  table: "attacker_keys",
  signingSecretEnv: "ATTACKER_SIGNING_ENV",
  databaseUrlEnv: "ATTACKER_DB_ENV",
  json: true,
} as const;

/**
 * Run `fn` with the listed keys planted on `Object.prototype`, then remove them.
 *
 * Non-enumerable so the planted keys cannot leak into unrelated `for...in`
 * loops (the test runner's included) while staying fully visible to the
 * prototype-chain reads under test — those reads are identical either way.
 *
 * Restored in a `finally`, because a polluted prototype escaping into sibling
 * tests is its own outage.
 */
async function withPolluted<T>(keys: ReadonlyArray<keyof typeof POLLUTION>, fn: () => T | Promise<T>): Promise<T> {
  for (const key of keys) {
    Object.defineProperty(Object.prototype, key, {
      value: POLLUTION[key],
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
      expect((({} as Record<string, unknown>)[key])).toBe(POLLUTION[key]);
    }
    return await fn();
  } finally {
    for (const key of keys) delete (Object.prototype as Record<string, unknown>)[key];
  }
}

function collectReports() {
  const reports: Array<{ error: string; details?: Record<string, unknown> }> = [];
  return {
    reports,
    report: (_o: { json?: boolean }, error: string, details?: Record<string, unknown>) => {
      reports.push({ error, ...(details ? { details } : {}) });
    },
  };
}

async function captureStdout(fn: () => Promise<void>): Promise<string> {
  const original = console.log;
  const lines: string[] = [];
  console.log = (...args: unknown[]) => void lines.push(args.map((a) => String(a)).join(" "));
  try {
    await fn();
  } finally {
    console.log = original;
  }
  return lines.join("\n");
}

interface RunResult {
  out: string;
  reports: Array<{ error: string; details?: Record<string, unknown> }>;
  writes: Array<{ connectionString: string; table: string; createdBy?: string }>;
}

/**
 * Drive `runIssueKey` with an explicit, fully-own options object and a fake
 * store, capturing everything a caller could observe.
 */
async function run(options: Record<string, unknown>, env: NodeJS.ProcessEnv = {}): Promise<RunResult> {
  const { reports, report } = collectReports();
  const writes: RunResult["writes"] = [];
  const out = await captureStdout(async () => {
    await runIssueKey(options, {
      report,
      env,
      now: () => FIXED_NOW_MS,
      connectStore: async (connectionString: string, table: string) => ({
        store: {
          ensureSchema: async () => {},
          insertMinted: async (_minted, createdBy?: string) => {
            writes.push({ connectionString, table, ...(createdBy ? { createdBy } : {}) });
          },
        },
        close: async () => {},
      }),
    });
  });
  return { out, reports, writes };
}

/** The claims actually inside the HMAC-signed body of the emitted token. */
function signedClaims(out: string): Record<string, unknown> {
  const parsed = JSON.parse(out) as { token?: string };
  expect(typeof parsed.token).toBe("string");
  const key = parseApiKey(parsed.token as string);
  expect(key).not.toBeNull();
  return key!.claims as unknown as Record<string, unknown>;
}

const BASE_ENV = {
  HASNA_TODOS_API_SIGNING_KEY: SIGNING,
  HASNA_TODOS_DATABASE_URL: "postgres://unused.example/unused",
} as NodeJS.ProcessEnv;

// ---------------------------------------------------------------------------
// Reachability: what commander actually hands `runIssueKey`.
//
// This decides which of the reads below are reachable through the shipped CLI
// and which are only reachable by a programmatic caller. It is a test rather
// than a comment because it is the fact the severity language rests on, and it
// silently changes if commander changes or a flag is made negatable.
// ---------------------------------------------------------------------------
describe("commander own-property shape for issue-key", () => {
  test("only --app and the NEGATED flags arrive as own properties", () => {
    const program = new Command();
    let captured: Record<string, unknown> | undefined;
    program
      .command("issue-key")
      .requiredOption("--app <app>", "")
      .option("--agent <agent>", "")
      .option("--tid <tenant>", "")
      .option("--scopes <csv>", "")
      .option("--ttl-days <days>", "")
      .option("--no-expiry", "")
      .option("--bootstrap", "")
      .option("--signing-secret-env <name>", "")
      .option("--database-url-env <name>", "")
      .option("--table <name>", "")
      .option("--no-store", "")
      .option("-j, --json", "")
      .action((options: Record<string, unknown>) => {
        captured = options;
      });
    program.parse(["node", "contracts", "issue-key", "--app", APP]);

    // Own => a polluted prototype is SHADOWED on the CLI path.
    expect(Object.hasOwn(captured!, "app")).toBe(true);
    expect(Object.hasOwn(captured!, "expiry")).toBe(true);
    expect(Object.hasOwn(captured!, "store")).toBe(true);

    // NOT own => the bare read is a real prototype lookup on the CLI path.
    for (const absent of [
      "bootstrap",
      "scopes",
      "agent",
      "tid",
      "ttlDays",
      "signingSecretEnv",
      "databaseUrlEnv",
      "table",
      "json",
    ]) {
      expect(Object.hasOwn(captured!, absent)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// The signed body. Every assertion here is about bytes inside the HMAC.
// ---------------------------------------------------------------------------
describe("issue-key: no polluted option reaches the signed body", () => {
  test("a polluted `bootstrap` cannot mint wildcard scopes the operator never asked for", async () => {
    const { reports, out } = await withPolluted(["bootstrap"], () =>
      run({ app: APP, store: false, json: true }, BASE_ENV),
    );

    // Broken build: `bootstrap` reads true, scopes default to `todos:*`, and a
    // wildcard key is minted and signed. Fixed build: no scopes were supplied,
    // so the command refuses.
    expect(reports[0]?.details?.code).toBe("missing_scopes");
    expect(out).toBe("");
  });

  test("a polluted `scopes` cannot put a scope into the signed body", async () => {
    const { reports, out } = await withPolluted(["scopes"], () => run({ app: APP, store: false, json: true }, BASE_ENV));

    expect(reports[0]?.details?.code).toBe("missing_scopes");
    expect(out).toBe("");
  });

  test("a polluted `ttlDays` cannot stretch the signed expiry", async () => {
    const { out, reports } = await withPolluted(["ttlDays"], () =>
      run({ app: APP, scopes: "todos:read", store: false, json: true }, BASE_ENV),
    );

    expect(reports).toEqual([]);
    const claims = signedClaims(out);
    // Default TTL is 90 days. The polluted value would sign 36500.
    expect(claims.exp).toBe((claims.iat as number) + 90 * DAY);
  });

  test("a polluted `expiry` cannot mint a key that never expires", async () => {
    const { out, reports } = await withPolluted(["expiry"], () =>
      run({ app: APP, scopes: "todos:read", store: false, json: true }, BASE_ENV),
    );

    expect(reports).toEqual([]);
    const claims = signedClaims(out);
    // Broken build: `options.expiry === false` is true, ttlSeconds becomes null,
    // and `exp` is signed as null — a forever key.
    expect(claims.exp).not.toBeNull();
    expect(typeof claims.exp).toBe("number");
  });

  test("a polluted `app` cannot mint a key for an app the operator never named", async () => {
    const { out, reports } = await withPolluted(["app"], () => run({ scopes: "todos:read", store: false, json: true }, BASE_ENV));

    // Broken build: `options.app` reads the attacker's slug, which is a valid
    // slug, so a key is minted and signed for a DIFFERENT app entirely.
    expect(reports[0]?.details?.code).toBe("missing_app");
    expect(out).toBe("");
  });

  test("a polluted `agent` is absent from the signed body, not merely undefined", async () => {
    const { out, reports } = await withPolluted(["agent"], () =>
      run({ app: APP, scopes: "todos:read", store: false, json: true }, BASE_ENV),
    );

    expect(reports).toEqual([]);
    const claims = signedClaims(out);
    // `toBeUndefined()` here would pass on the broken build too: the claim is
    // absent, so reading it walks the polluted prototype in the assertion as
    // well. `hasOwn` is the only assertion that can tell the builds apart.
    expect(Object.hasOwn(claims, "agent")).toBe(false);
  });

  test("a polluted `tid` is absent from the signed body, not merely undefined", async () => {
    const { out, reports } = await withPolluted(["tid"], () =>
      run({ app: APP, scopes: "todos:read", store: false, json: true }, BASE_ENV),
    );

    expect(reports).toEqual([]);
    expect(Object.hasOwn(signedClaims(out), "tid")).toBe(false);
  });

  test("a polluted `signingSecretEnv` cannot redirect which secret signs the key", async () => {
    const { reports, out } = await withPolluted(["signingSecretEnv"], () =>
      run({ app: APP, scopes: "todos:read", store: false, json: true }, {
        ...BASE_ENV,
        ATTACKER_SIGNING_ENV: "attacker-controlled-secret-000000000000",
      } as NodeJS.ProcessEnv),
    );

    // Broken build: the secret is read from the attacker's env var, so the token
    // is signed with a secret the app's verifier does not hold — or, worse, one
    // the attacker does. The emitted token must verify under the app's own key.
    expect(reports).toEqual([]);
    const parsed = JSON.parse(out) as { token: string };
    const { verifyApiKeyToken } = await import("../src/auth/keys");
    expect(verifyApiKeyToken(parsed.token, { signingSecret: SIGNING, nowMs: FIXED_NOW_MS }).ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Revocability. Not signed, but a key with no record cannot be revoked, which
// is the property the command's own WARNING block promises.
// ---------------------------------------------------------------------------
describe("issue-key: no polluted option suppresses or misdirects the record", () => {
  test("a polluted `store` cannot suppress the revocation record", async () => {
    const { writes, reports } = await withPolluted(["store"], () =>
      run({ app: APP, scopes: "todos:read", json: true }, BASE_ENV),
    );

    // Broken build: `options.store !== false` is false, the whole persistence
    // block is skipped, and the key silently cannot be revoked.
    expect(reports).toEqual([]);
    expect(writes.length).toBe(1);
  });

  test("a polluted `table` cannot divert the record away from the revocation table", async () => {
    const { writes } = await withPolluted(["table"], () => run({ app: APP, scopes: "todos:read", json: true }, BASE_ENV));

    expect(writes[0]?.table).toBe("api_keys");
  });

  test("a polluted `databaseUrlEnv` cannot divert the record to another database", async () => {
    const { writes } = await withPolluted(["databaseUrlEnv"], () =>
      run({ app: APP, scopes: "todos:read", json: true }, {
        ...BASE_ENV,
        ATTACKER_DB_ENV: "postgres://attacker.example/attacker",
      } as NodeJS.ProcessEnv),
    );

    expect(writes[0]?.connectionString).toBe("postgres://unused.example/unused");
  });

  test("a polluted `json` cannot change the output surface", async () => {
    const { out } = await withPolluted(["json"], () =>
      run({ app: APP, scopes: "todos:read", store: false }, BASE_ENV),
    );

    // Human block, not JSON. Broken build emits a JSON document instead.
    expect(out).toContain("API key (shown once");
    expect(() => JSON.parse(out)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// BOTH DIRECTIONS. A guard that fails closed on legitimate input is a different
// outage, not a fix. Under the SAME pollution, real own values must still reach
// the signed body unchanged.
// ---------------------------------------------------------------------------
describe("issue-key: real option values still work under pollution", () => {
  test("every explicitly-passed option reaches the signed body unchanged", async () => {
    const realTid = "22222222-2222-4222-8222-222222222222";
    const { out, reports, writes } = await withPolluted(
      ["bootstrap", "scopes", "ttlDays", "expiry", "store", "agent", "tid", "table", "json"],
      () =>
        run(
          {
            app: APP,
            scopes: "todos:read,todos:write",
            agent: "station01",
            tid: realTid,
            ttlDays: 1,
            table: "custom_keys",
            store: true,
            expiry: true,
            json: true,
          },
          BASE_ENV,
        ),
    );

    expect(reports).toEqual([]);
    const claims = signedClaims(out);
    expect(claims.app).toBe(APP);
    expect(claims.scopes).toEqual(["todos:read", "todos:write"]);
    expect(Object.hasOwn(claims, "agent")).toBe(true);
    expect(claims.agent).toBe("station01");
    expect(Object.hasOwn(claims, "tid")).toBe(true);
    expect(claims.tid).toBe(realTid);
    expect(claims.exp).toBe((claims.iat as number) + 1 * DAY);
    expect(writes[0]?.table).toBe("custom_keys");
  });

  test("an explicit --bootstrap still mints wildcard scopes and the bootstrap agent", async () => {
    const { out, reports } = await withPolluted(["scopes", "agent"], () =>
      run({ app: APP, bootstrap: true, store: false, json: true }, BASE_ENV),
    );

    expect(reports).toEqual([]);
    const claims = signedClaims(out);
    expect(claims.scopes).toEqual([`${APP}:*`]);
    expect(claims.agent).toBe("bootstrap");
  });

  test("an explicit --no-expiry still mints a non-expiring key", async () => {
    const { out, reports } = await withPolluted(["ttlDays"], () =>
      run({ app: APP, scopes: "todos:read", expiry: false, store: false, json: true }, BASE_ENV),
    );

    expect(reports).toEqual([]);
    expect(signedClaims(out).exp).toBeNull();
  });

  test("an explicit --no-store still suppresses the record", async () => {
    const { writes, reports } = await withPolluted(["store"], () =>
      run({ app: APP, scopes: "todos:read", store: false, json: true }, BASE_ENV),
    );

    expect(reports).toEqual([]);
    expect(writes.length).toBe(0);
  });
});
