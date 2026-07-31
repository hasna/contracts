// Credential provider chain — behaviour tests.
//
// The measured failure this suite exists to kill: a shell started BEFORE a key
// rotation holds the stale `HASNA_<SVC>_API_KEY` for its whole life, so every
// command from that shell 401s while a fresh login shell on the same machine in
// the same second succeeds. The credential on disk was correct throughout; only
// the process env was stale.

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

const STALE_ENV_KEY = "hasna_accounts_STALE-revoked-key";
const FRESH_DISK_KEY = "hasna_accounts_FRESH-on-disk-key";

const homes: string[] = [];

function makeHome(): string {
  const home = mkdtempSync(join(tmpdir(), "hasna-cred-"));
  homes.push(home);
  return home;
}

/** Write `~/.hasna/cloud/<app>.env`. Path is composed from segments on purpose. */
function writeCloudEnv(home: string, app: string, body: string): string {
  const dir = join(home, ".hasna", "cloud");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${app}.env`);
  writeFileSync(path, body);
  return path;
}

/** Write the second on-disk layer, `~/.config/hasna/<app>-cloud.env`. */
function writeConfigEnv(home: string, app: string, body: string): string {
  const dir = join(home, ".config", "hasna");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${app}-cloud.env`);
  writeFileSync(path, body);
  return path;
}

afterEach(() => {
  __resetCredentialDeprecationNotices();
  while (homes.length > 0) {
    const home = homes.pop()!;
    rmSync(home, { recursive: true, force: true });
  }
});

describe("the measured failure: a stale shell must not outrank the disk", () => {
  test("a stale env key loses to a valid disk credential", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${FRESH_DISK_KEY}\n`);

    const resolved = resolveCredential("accounts", {
      HOME: home,
      HASNA_ACCOUNTS_API_KEY: STALE_ENV_KEY,
    });

    expect(resolved).not.toBeNull();
    expect(resolved!.apiKey).toBe(FRESH_DISK_KEY);
    expect(resolved!.tier).toBe("disk");
  });

  test("the disk is re-read on every call, so a rotation heals without a new process", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=key-before-rotation\n");
    const env = { HOME: home, HASNA_ACCOUNTS_API_KEY: STALE_ENV_KEY };

    expect(resolveCredential("accounts", env)!.apiKey).toBe("key-before-rotation");

    // The rotation lands on disk. The process env is untouched and still stale.
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=key-after-rotation\n");

    expect(resolveCredential("accounts", env)!.apiKey).toBe("key-after-rotation");
  });
});

describe("tier 1 — an explicit argument", () => {
  test("an explicit apiKey outranks the override, the disk, and the legacy env", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${FRESH_DISK_KEY}\n`);

    const resolved = resolveCredential(
      "accounts",
      {
        HOME: home,
        HASNA_ACCOUNTS_API_KEY: STALE_ENV_KEY,
        HASNA_ACCOUNTS_API_KEY_OVERRIDE: "override-key",
      },
      { apiKey: "explicit-flag-key" },
    );

    expect(resolved!.apiKey).toBe("explicit-flag-key");
    expect(resolved!.tier).toBe("argument");
    expect(resolved!.deliberate).toBe(true);
  });
});

describe("tier 2 — a deliberate override never falls through to another identity", () => {
  test("the override wins even when a different, valid credential sits on disk", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${FRESH_DISK_KEY}\n`);

    const resolved = resolveCredential("accounts", {
      HOME: home,
      HASNA_ACCOUNTS_API_KEY_OVERRIDE: "deliberate-tenant-x-key",
    });

    expect(resolved!.apiKey).toBe("deliberate-tenant-x-key");
    expect(resolved!.tier).toBe("override");
    expect(resolved!.deliberate).toBe(true);
    expect(resolved!.source).toBe("HASNA_ACCOUNTS_API_KEY_OVERRIDE");
  });

  test("a blank override throws instead of silently resolving to the disk identity", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${FRESH_DISK_KEY}\n`);

    expect(() =>
      resolveCredential("accounts", {
        HOME: home,
        HASNA_ACCOUNTS_API_KEY_OVERRIDE: "   ",
      }),
    ).toThrow(CredentialResolutionError);
  });

  test("a HASNA_PROFILE pointer resolves the profile's own disk file", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${FRESH_DISK_KEY}\n`);
    const dir = join(home, ".hasna", "cloud");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "accounts.staging.env"), "HASNA_ACCOUNTS_API_KEY=staging-key\n");

    const resolved = resolveCredential("accounts", { HOME: home, HASNA_PROFILE: "staging" });

    expect(resolved!.apiKey).toBe("staging-key");
    expect(resolved!.tier).toBe("profile");
    expect(resolved!.deliberate).toBe(true);
  });

  test("a HASNA_PROFILE naming a profile with no credential throws and names the paths tried", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${FRESH_DISK_KEY}\n`);

    let caught: unknown;
    try {
      resolveCredential("accounts", { HOME: home, HASNA_PROFILE: "no-such-profile" });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(CredentialResolutionError);
    const message = (caught as Error).message;
    expect(message).toContain("no-such-profile");
    // It must NOT have quietly used the default identity that is sitting right there.
    expect(message).not.toContain(FRESH_DISK_KEY);
  });

  test("the per-service override outranks the global profile pointer", () => {
    const home = makeHome();
    const dir = join(home, ".hasna", "cloud");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "accounts.staging.env"), "HASNA_ACCOUNTS_API_KEY=staging-key\n");

    const resolved = resolveCredential("accounts", {
      HOME: home,
      HASNA_PROFILE: "staging",
      HASNA_ACCOUNTS_API_KEY_OVERRIDE: "override-key",
    });

    expect(resolved!.tier).toBe("override");
    expect(resolved!.apiKey).toBe("override-key");
  });
});

describe("tier 3 — disk", () => {
  test("the primary cloud file outranks the secondary config file", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=primary-key\n");
    writeConfigEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=secondary-key\n");

    const resolved = resolveCredential("accounts", { HOME: home });

    expect(resolved!.apiKey).toBe("primary-key");
    expect(resolved!.tier).toBe("disk");
  });

  test("two disk layers holding DIFFERENT keys produce a split-brain warning with no key material", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=primary-key\n");
    writeConfigEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=secondary-key\n");

    const resolved = resolveCredential("accounts", { HOME: home });

    expect(resolved!.warning).toContain("disagree");
    expect(resolved!.warning).not.toContain("primary-key");
    expect(resolved!.warning).not.toContain("secondary-key");
  });

  test("two disk layers holding the SAME key produce no warning", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=same-key\n");
    writeConfigEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=same-key\n");

    expect(resolveCredential("accounts", { HOME: home })!.warning).toBeNull();
  });

  test("the `export KEY=\"value\"` file shape is parsed", () => {
    const home = makeHome();
    writeCloudEnv(home, "knowledge", 'export HASNA_KNOWLEDGE_API_KEY="quoted-exported-key"\n');

    expect(resolveCredential("knowledge", { HOME: home })!.apiKey).toBe("quoted-exported-key");
  });

  test("comments, blank lines, and trailing whitespace are ignored", () => {
    const home = makeHome();
    writeCloudEnv(
      home,
      "accounts",
      "# a comment\n\n  HASNA_ACCOUNTS_API_KEY=spaced-key  \n# HASNA_ACCOUNTS_API_KEY=commented-out\n",
    );

    expect(resolveCredential("accounts", { HOME: home })!.apiKey).toBe("spaced-key");
  });

  test("rotated-out sibling files are never read", () => {
    const home = makeHome();
    const dir = join(home, ".hasna", "cloud");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "accounts.env.bak-20260101"), "HASNA_ACCOUNTS_API_KEY=backup-key\n");
    writeFileSync(join(dir, "accounts.env.pre-flip-1"), "HASNA_ACCOUNTS_API_KEY=preflip-key\n");

    expect(resolveCredential("accounts", { HOME: home })).toBeNull();
  });

  test("the unprefixed <APP>_API_KEY alias is honoured, but only after the canonical name", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", "ACCOUNTS_API_KEY=alias-key\n");
    expect(resolveCredential("accounts", { HOME: home })!.apiKey).toBe("alias-key");

    writeCloudEnv(home, "accounts", "ACCOUNTS_API_KEY=alias-key\nHASNA_ACCOUNTS_API_KEY=canonical-key\n");
    expect(resolveCredential("accounts", { HOME: home })!.apiKey).toBe("canonical-key");
  });

  test("a malformed file yields no credential and leaks no file content into the result", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", "this is not an env file at all\x00\xff\n");

    expect(resolveCredential("accounts", { HOME: home })).toBeNull();
  });

  test("an unreadable disk path is not fatal — resolution continues to the legacy tier", () => {
    const home = makeHome();
    // `~/.hasna/cloud/accounts.env` is a DIRECTORY, so reading it throws EISDIR.
    mkdirSync(join(home, ".hasna", "cloud", "accounts.env"), { recursive: true });

    const resolved = resolveCredential(
      "accounts",
      { HOME: home, HASNA_ACCOUNTS_API_KEY: STALE_ENV_KEY },
      { onDeprecation: () => {} },
    );

    expect(resolved!.tier).toBe("legacy-env");
  });
});

describe("tier 4 — the legacy process env is a fallback, not a default", () => {
  test("legacy env is used only when the disk yields nothing", () => {
    const home = makeHome();
    const resolved = resolveCredential(
      "accounts",
      { HOME: home, HASNA_ACCOUNTS_API_KEY: STALE_ENV_KEY },
      { onDeprecation: () => {} },
    );

    expect(resolved!.apiKey).toBe(STALE_ENV_KEY);
    expect(resolved!.tier).toBe("legacy-env");
    expect(resolved!.deprecated).toBe(true);
  });

  test("the deprecation names the env key AND the disk path that replaces it", () => {
    const home = makeHome();
    const messages: string[] = [];
    resolveCredential(
      "accounts",
      { HOME: home, HASNA_ACCOUNTS_API_KEY: STALE_ENV_KEY },
      { onDeprecation: (message) => messages.push(message) },
    );

    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain("HASNA_ACCOUNTS_API_KEY");
    expect(messages[0]).toContain(join(home, ".hasna", "cloud", "accounts.env"));
    expect(messages[0]).not.toContain(STALE_ENV_KEY);
  });

  test("the deprecation is emitted once per app, not once per call", () => {
    const home = makeHome();
    const messages: string[] = [];
    const env = { HOME: home, HASNA_ACCOUNTS_API_KEY: STALE_ENV_KEY };
    const options = { onDeprecation: (message: string) => messages.push(message) };

    resolveCredential("accounts", env, options);
    resolveCredential("accounts", env, options);
    resolveCredential("accounts", env, options);

    expect(messages).toHaveLength(1);
  });

  test("a second app emits its own deprecation", () => {
    const home = makeHome();
    const messages: string[] = [];
    const options = { onDeprecation: (message: string) => messages.push(message) };

    resolveCredential("accounts", { HOME: home, HASNA_ACCOUNTS_API_KEY: "a" }, options);
    resolveCredential("knowledge", { HOME: home, HASNA_KNOWLEDGE_API_KEY: "k" }, options);

    expect(messages).toHaveLength(2);
  });
});

describe("precedence holds across all four tiers", () => {
  test("removing each tier in turn falls to exactly the next one", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", "HASNA_ACCOUNTS_API_KEY=disk-key\n");
    const base = {
      HOME: home,
      HASNA_ACCOUNTS_API_KEY: "legacy-key",
      HASNA_ACCOUNTS_API_KEY_OVERRIDE: "override-key",
    };
    const silent = { onDeprecation: () => {} };

    expect(resolveCredential("accounts", base, { ...silent, apiKey: "argument-key" })!.tier).toBe("argument");
    expect(resolveCredential("accounts", base, silent)!.tier).toBe("override");

    const { HASNA_ACCOUNTS_API_KEY_OVERRIDE: _dropped, ...noOverride } = base;
    expect(resolveCredential("accounts", noOverride, silent)!.tier).toBe("disk");

    rmSync(join(home, ".hasna", "cloud", "accounts.env"));
    expect(resolveCredential("accounts", noOverride, silent)!.tier).toBe("legacy-env");

    const { HASNA_ACCOUNTS_API_KEY: _alsoDropped, ...nothing } = noOverride;
    expect(resolveCredential("accounts", nothing, silent)).toBeNull();
  });
});

describe("the disk tier is hermetic: it reads only the HOME it is given", () => {
  test("an env with no HOME performs no disk read at all", () => {
    expect(credentialDiskSources("accounts", {})).toEqual([]);
    expect(resolveCredential("accounts", {})).toBeNull();
  });

  test("credentialDiskSources reports both layers for a given HOME", () => {
    const home = makeHome();
    expect(credentialDiskSources("accounts", { HOME: home })).toEqual([
      join(home, ".hasna", "cloud", "accounts.env"),
      join(home, ".config", "hasna", "accounts-cloud.env"),
    ]);
  });
});

describe("no key material ever escapes into diagnostics", () => {
  test("the resolution's source and warning never contain the secret", () => {
    const home = makeHome();
    writeCloudEnv(home, "accounts", `HASNA_ACCOUNTS_API_KEY=${FRESH_DISK_KEY}\n`);

    const resolved = resolveCredential("accounts", { HOME: home })!;

    expect(resolved.source).not.toContain(FRESH_DISK_KEY);
    expect(resolved.warning ?? "").not.toContain(FRESH_DISK_KEY);
  });
});
