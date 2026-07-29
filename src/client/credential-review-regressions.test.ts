// Regressions from the adversarial review of 331e550.
//
// Every test here corresponds to a real defect an independent reviewer found in
// the first version of the credential chain. They live together so the review
// round is legible in one place; each one fails against that commit.

import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CredentialResolutionError,
  __resetCredentialDeprecationNotices,
  credentialDiskSources,
  resolveCredential,
} from "./credentials.js";
import { createHasnaHttpTransport, resolveClientTransport } from "./transport.js";

const SECRET = "hasna_accounts_fresh-on-disk-key";
const homes: string[] = [];

function makeHome(): string {
  const home = mkdtempSync(join(tmpdir(), "hasna-review-"));
  homes.push(home);
  return home;
}

function writeCloudEnv(home: string, app: string, body: string): string {
  const dir = join(home, ".hasna", "cloud");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${app}.env`);
  writeFileSync(path, body);
  return path;
}

function writeConfigEnv(home: string, app: string, body: string): string {
  const dir = join(home, ".config", "hasna");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${app}-cloud.env`);
  writeFileSync(path, body);
  return path;
}

afterEach(() => {
  __resetCredentialDeprecationNotices();
  while (homes.length > 0) rmSync(homes.pop()!, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// P0 — the state this change TELLS operators to migrate to (endpoint in the
// environment, credential on disk) resolved to `local`, silently serving the
// local dataset while a good credential sat on disk. The 401 guidance walked
// people straight into it.
// ---------------------------------------------------------------------------

describe("the recommended steady state is not a silent sqlite read", () => {
  test("URL in env + credential on disk resolves to http, not silently to sqlite", () => {
    const home = makeHome();
    const diskPath = writeCloudEnv(home, "todos", "HASNA_TODOS_API_KEY=good-disk-key\n");

    const r = resolveClientTransport("todos", {
      HOME: home,
      HASNA_TODOS_API_URL: "https://todos.your-deployment.example",
    });

    expect(r.transport).toBe("http");
    expect(r.apiKeyTier).toBe("disk");
    expect(r.modeSource).toBe(`HASNA_TODOS_API_URL+${diskPath}`);
  });

  test("BOUNDARY: a URL alone, with no credential anywhere, stays sqlite and not misconfigured", () => {
    const home = makeHome();

    const r = resolveClientTransport("todos", {
      HOME: home,
      HASNA_TODOS_API_URL: "https://todos.your-deployment.example",
    });

    expect(r.transport).toBe("sqlite");
    expect(r.misconfigured).toBe(false);
  });

  test("BOUNDARY: a credential on disk with NO URL configured still never routes to the network", () => {
    const home = makeHome();
    writeCloudEnv(home, "todos", "HASNA_TODOS_API_KEY=good-disk-key\n");

    expect(resolveClientTransport("todos", { HOME: home }).transport).toBe("sqlite");
  });

  test("a 401 on the legacy tier never advises unsetting the variable", async () => {
    // Reaching the legacy tier proves the disk had nothing, so an unset would
    // strip the client of any credential and drop it onto its local store.
    const home = makeHome();
    const client = createHasnaHttpTransport({
      name: "todos",
      baseUrl: "https://todos.your-deployment.example/v1",
      apiKey: () =>
        resolveCredential(
          "todos",
          { HOME: home, HASNA_TODOS_API_KEY: "stale" },
          { onDeprecation: () => {} },
        )!,
      fetchImpl: async () => new Response("", { status: 401 }),
    });

    let caught: unknown;
    try {
      await client.get("/items");
    } catch (error) {
      caught = error;
    }

    const message = (caught as Error).message;
    expect(message).toMatch(/Write the CURRENT key to/);
    expect(message).toMatch(/Do not simply unset/);
  });
});

// ---------------------------------------------------------------------------
// P1 — secret handling.
// ---------------------------------------------------------------------------

describe("a credential that cannot be sent as a header is rejected, not forwarded", () => {
  test("a CR-only credential file throws instead of leaking the key through fetch", () => {
    // A file written with CR-only line endings is not split by /\r?\n/, so the
    // CR survives inside the value. Passing that to fetch throws a TypeError
    // whose message embeds the WHOLE header value — the plaintext key.
    const home = makeHome();
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=AAAA\rSECRETTAIL");

    let caught: unknown;
    try {
      resolveCredential("accounts", { HOME: home });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(CredentialResolutionError);
    expect((caught as Error).message).not.toContain("SECRETTAIL");
  });

  test("the rejection names the source path but never the value", () => {
    const home = makeHome();
    const path = writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=badvalue");

    expect(() => resolveCredential("accounts", { HOME: home })).toThrow(path);
  });

  test("an ordinary key with punctuation is NOT rejected", () => {
    // The guard must reject control bytes only. A real key is base64url-ish
    // with dots, dashes and underscores; rejecting those breaks every caller.
    const home = makeHome();
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=hasna_accounts_aB3-x_9.sIgNaTuRe-1\n");

    expect(resolveCredential("accounts", { HOME: home })!.apiKey).toBe(
      "hasna_accounts_aB3-x_9.sIgNaTuRe-1",
    );
  });
});

describe("the secret cannot be enumerated or serialized", () => {
  test("JSON.stringify of a resolution never contains the key", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${SECRET}\n`);

    const resolved = resolveCredential("accounts", { HOME: home })!;
    const serialized = JSON.stringify(resolved);

    expect(serialized).not.toContain(SECRET);
    // The property is absent entirely rather than redacted in place — see the
    // note in sealCredential about non-enumerable toJSON not being honoured.
    expect(serialized).not.toContain("apiKey");
    // ...and the diagnostic fields a caller actually logs are still there.
    expect(JSON.parse(serialized).tier).toBe("disk");
  });

  test("Object.keys does not expose the key, but property access still works", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${SECRET}\n`);

    const resolved = resolveCredential("accounts", { HOME: home })!;

    expect(Object.keys(resolved)).not.toContain("apiKey");
    expect(resolved.apiKey).toBe(SECRET);
  });
});

describe("the sqlite backend has no credential side effects at all", () => {
  test("a sqlite client emits no deprecation and consults no credential source", () => {
    // A surviving mutant: injecting resolveCredential() into the local branch
    // left all 104 tests green. Local is the default mode for most fleet CLIs,
    // so a refactor there would spray deprecation banners across every ordinary
    // local invocation.
    const home = makeHome();
    const messages: string[] = [];

    const r = resolveClientTransport(
      "todos",
      { HOME: home, HASNA_TODOS_API_KEY: "legacy-key-this-process-never-uses" },
      { credentials: { onDeprecation: (message) => messages.push(message) } },
    );

    expect(r.transport).toBe("sqlite");
    expect(r.apiKeyTier).toBeNull();
    expect(messages).toEqual([]);
  });

  test("an explicit sqlite backend ignores a deliberate override without throwing", () => {
    const home = makeHome();

    const r = resolveClientTransport("todos", {
      HOME: home,
      HASNA_TODOS_STORAGE_MODE: "sqlite",
      HASNA_TODOS_API_KEY_OVERRIDE: "   ",
    });

    expect(r.transport).toBe("sqlite");
  });
});

describe("a stale file on disk cannot silently displace a working env key", () => {
  test("disk winning over a DIFFERENT legacy env key warns and names both", () => {
    // Disk now outranks the legacy env var, which introduces a failure the old
    // chain did not have: an operator whose env key works today starts using a
    // different key the moment a stale file exists on disk.
    const home = makeHome();
    const diskPath = writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=stale-disk-key\n");

    const resolved = resolveCredential("accounts", {
      HOME: home,
      HASNA_ACCOUNTS_API_KEY: "working-env-key",
    })!;

    expect(resolved.tier).toBe("disk");
    expect(resolved.warning).toContain("disagree");
    expect(resolved.warning).toContain("HASNA_ACCOUNTS_API_KEY");
    expect(resolved.warning).toContain(diskPath);
    expect(resolved.warning).not.toContain("working-env-key");
    expect(resolved.warning).not.toContain("stale-disk-key");
  });

  test("disk and env agreeing produces no warning", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=same-key\n");

    const resolved = resolveCredential("accounts", {
      HOME: home,
      HASNA_ACCOUNTS_API_KEY: "same-key",
    })!;

    expect(resolved.warning).toBeNull();
  });
});

describe("the divergence warning is not a credential oracle", () => {
  test("it names the paths but emits no digest or length of either key", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=primary-key\n");
    writeConfigEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=secondary-key\n");

    const warning = resolveCredential("accounts", { HOME: home })!.warning!;

    expect(warning).toContain("disagree");
    expect(warning).not.toMatch(/sha256|len=/i);
  });
});

// ---------------------------------------------------------------------------
// P1/P2 — hostile paths and files.
// ---------------------------------------------------------------------------

describe("hostile paths and files never reach a blocking or out-of-tree read", () => {
  test("an app name that escapes the credential directory yields no disk sources", () => {
    const home = makeHome();

    expect(credentialDiskSources("../../outside", { HOME: home })).toEqual([]);
    expect(credentialDiskSources("a/b", { HOME: home })).toEqual([]);
    expect(credentialDiskSources("..", { HOME: home })).toEqual([]);
  });

  test("a profile name that escapes the credential directory throws", () => {
    const home = makeHome();

    expect(() =>
      resolveCredential("accounts", { HOME: home, HASNA_PROFILE: "../../../../etc/hosts" }),
    ).toThrow(CredentialResolutionError);
  });

  test("a non-regular file in the credential directory is skipped, never opened", () => {
    // openSync on a FIFO blocks forever, and this read now runs on every
    // request — ahead of the transport's own AbortController, so no timeout
    // could rescue it. stat does not block, so the type check must come first.
    const home = makeHome();
    const dir = join(home, ".hasna", "cloud");
    mkdirSync(dir, { recursive: true });
    const made = Bun.spawnSync(["mkfifo", join(dir, "accounts.env")]);
    if (made.exitCode !== 0) return; // mkfifo unavailable here; nothing to assert

    const started = Date.now();
    const resolved = resolveCredential(
      "accounts",
      { HOME: home, HASNA_ACCOUNTS_API_KEY: "env-fallback" },
      { onDeprecation: () => {} },
    );

    expect(Date.now() - started).toBeLessThan(2000);
    expect(resolved!.tier).toBe("legacy-env");
  });

  test("an oversized credential file is skipped rather than read whole", () => {
    const home = makeHome();
    writeCloudEnv(
      home,
      "accounts",
      `${"#padding\n".repeat(20000)}HASNA_ACCOUNTS_API_KEY=buried\n`,
    );

    expect(resolveCredential("accounts", { HOME: home })).toBeNull();
  });
});

describe("a half-parsed value is rejected rather than silently truncated", () => {
  test("an unterminated quote yields no credential instead of a corrupted one", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", 'HASNA_ACCOUNTS_API_KEY="abc\n');

    expect(resolveCredential("accounts", { HOME: home })).toBeNull();
  });
});

describe("the legacy deprecation tells the truth about the disk", () => {
  test("it says to write the key to disk, and never to unset the variable", () => {
    const home = makeHome();
    const messages: string[] = [];

    resolveCredential(
      "accounts",
      { HOME: home, HASNA_ACCOUNTS_API_KEY: "stale" },
      { onDeprecation: (message) => messages.push(message) },
    );

    expect(messages[0]).toContain("Put the current key in");
    expect(messages[0]).not.toMatch(/unset/i);
  });

  test("with no HOME it says the disk tier is unavailable rather than naming a path", () => {
    const messages: string[] = [];

    const resolved = resolveCredential(
      "accounts",
      { HASNA_ACCOUNTS_API_KEY: "stale" },
      { onDeprecation: (message) => messages.push(message) },
    );

    expect(resolved!.tier).toBe("legacy-env");
    expect(messages[0]).toContain("no HOME");
  });
});

// ---------------------------------------------------------------------------
// P0 — the SECOND review round. `currentCredential()` built the explicit-string
// branch as a plain object literal, so a key passed as a STRING to the exported
// `createHasnaHttpTransport` bypassed BOTH protections this change added: no
// `assertUsableCredential`, no `sealCredential`. `ILLEGAL_IN_HEADER_VALUE` and
// the CONTRACT.md §3a clause exist precisely to close that, and the first suite
// only ever exercised `resolveCredential` — the public constructor was untested.
// ---------------------------------------------------------------------------

describe("an explicit apiKey STRING gets the same protections as a resolved one", () => {
  const PLAINTEXT = "hasna_todos_SUPERSECRET-VALUE";

  function transportWithKey(apiKey: string, onFetch: () => void) {
    return createHasnaHttpTransport({
      name: "todos",
      baseUrl: "https://todos.your-deployment.example/v1",
      apiKey,
      fetchImpl: async (_url, init) => {
        onFetch();
        // Exactly what a real fetch does with these headers, and where the
        // plaintext key used to surface: the runtime throws a TypeError whose
        // message embeds the WHOLE header value — i.e. the key — into logs and
        // stack traces.
        new Headers(init!.headers as Record<string, string>);
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      },
    });
  }

  test("a mid-value CR throws, and the message never contains the key", async () => {
    let fetchCalls = 0;
    const client = transportWithKey(`AAAA\r${PLAINTEXT}`, () => {
      fetchCalls += 1;
    });

    let thrown: unknown;
    try {
      await client.get("/items");
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(CredentialResolutionError);
    expect((thrown as Error).message).not.toContain(PLAINTEXT);
    // The value is rejected BEFORE anything is handed to fetch, so there is no
    // header for a runtime to quote back.
    expect(fetchCalls).toBe(0);
  });

  test("the rejection names the source instead of the value", async () => {
    const client = transportWithKey(`AAAA\r${PLAINTEXT}`, () => {});

    await expect(client.get("/items")).rejects.toThrow(/explicit apiKey option/);
  });

  test("a NUL byte in an explicit key is rejected too, not just CR", async () => {
    const client = transportWithKey(`AAAA\u0000${PLAINTEXT}`, () => {});

    let thrown: unknown;
    try {
      await client.get("/items");
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(CredentialResolutionError);
    expect((thrown as Error).message).not.toContain(PLAINTEXT);
  });

  test("a clean explicit key still works and is still sent", async () => {
    const seen: string[] = [];
    const client = createHasnaHttpTransport({
      name: "todos",
      baseUrl: "https://todos.your-deployment.example/v1",
      apiKey: PLAINTEXT,
      fetchImpl: async (_url, init) => {
        seen.push(String((init!.headers as Record<string, string>)["x-api-key"]));
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      },
    });

    await client.get("/items");
    expect(seen).toEqual([PLAINTEXT]);
  });

  test("the explicit-string credential is sealed, so a 401 report cannot serialize it", async () => {
    const client = createHasnaHttpTransport({
      name: "todos",
      baseUrl: "https://todos.your-deployment.example/v1",
      apiKey: PLAINTEXT,
      retry: false,
      fetchImpl: async () => new Response("", { status: 401 }),
    });

    let thrown: unknown;
    try {
      await client.get("/items");
    } catch (error) {
      thrown = error;
    }

    expect(JSON.stringify(thrown)).not.toContain(PLAINTEXT);
    expect((thrown as Error).message).not.toContain(PLAINTEXT);
  });
});

// ---------------------------------------------------------------------------
// P0 — CONTRACT.md §3a and `sealCredential`'s own comment promise that
// `console.log` cannot spill the key. Under Bun — the declared engine — it can:
// non-enumerability does NOT hide an own property from Bun's inspector, so
// `console.log(resolved)` printed `apiKey: "..."` verbatim. A normative
// guarantee the runtime does not honour is worse than no guarantee.
// ---------------------------------------------------------------------------

describe("the inspector cannot spill the key either", () => {
  test("Bun.inspect of a resolved credential excludes the key", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${SECRET}\n`);

    const resolved = resolveCredential("accounts", { HOME: home })!;

    expect(Bun.inspect(resolved)).not.toContain(SECRET);
  });

  test("console.log of a resolved credential excludes the key", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${SECRET}\n`);
    const resolved = resolveCredential("accounts", { HOME: home })!;

    const written: string[] = [];
    const original = console.log;
    console.log = (...args: unknown[]) => {
      written.push(args.map((arg) => (typeof arg === "string" ? arg : Bun.inspect(arg))).join(" "));
    };
    try {
      console.log(resolved);
    } finally {
      console.log = original;
    }

    expect(written.join("\n")).not.toContain(SECRET);
  });

  test("nesting the credential inside another object does not defeat the hook", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${SECRET}\n`);
    const resolved = resolveCredential("accounts", { HOME: home })!;

    expect(Bun.inspect({ credential: resolved, note: "diagnostic dump" })).not.toContain(SECRET);
  });

  test("the redacted form still names the tier and source, so it stays diagnostic", () => {
    const home = makeHome();
    const diskPath = writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${SECRET}\n`);
    const resolved = resolveCredential("accounts", { HOME: home })!;

    const rendered = Bun.inspect(resolved);
    expect(rendered).toContain("disk");
    expect(rendered).toContain(diskPath);
  });

  test("the inspect hook stays invisible to Object.keys, spreads, and property access", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${SECRET}\n`);
    const resolved = resolveCredential("accounts", { HOME: home })!;

    expect(Object.keys(resolved)).not.toContain("apiKey");
    expect(Object.keys({ ...resolved })).toEqual(Object.keys(resolved));
    // And the secret is still readable by the code that legitimately needs it.
    expect(resolved.apiKey).toBe(SECRET);
  });
});
