// Regression suite for the deployment-mode removal (owner directive 2026-07-29).
//
// The deployment-placement axis (`local | self_hosted | cloud`, plus the
// `remote` / `hybrid` / `self-hosted` aliases) is gone from the contract
// surface. What remains is a single data-backend switch:
//
//   server backend : `sqlite | postgresql` (storage.backend)
//   client seam    : `sqlite | http`      (resolveClientTransport)
//
// The load-bearing guarantee — the reason this file exists — is that a
// manifest carrying `deploymentMode`/`deploymentModes` FAILS validation. A
// schema that merely ignored the field would have removed the word and kept
// the hole.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  SCHEMA_IDS,
  SERVICE_CONTRACT_VERSION,
  SERVICE_CONTRACT_JSON_SCHEMA,
  SERVER_DATA_BACKENDS,
  STORAGE_ENGINES,
  validateServiceContractManifest,
  resolveServerDataBackend,
  resolveClientTransport,
} from "../src";
import * as contractsExports from "../src";

const repoRoot = join(import.meta.dir, "..");

const REMOVED_MODE_WORDS = [
  "local",
  "cloud",
  "self_hosted",
  "self-hosted",
  "remote",
  "hybrid",
] as const;

const validManifest = {
  schema: SCHEMA_IDS.serviceContract,
  name: "todos",
  class: "cli-with-store",
  contractVersion: SERVICE_CONTRACT_VERSION,
  kitVersion: "0.8.4",
  bins: ["todos", "todos-mcp"],
  storage: {
    backend: "sqlite",
    sqlitePath: "~/.hasna/todos/todos.db",
  },
} as const;

describe("deployment-mode axis is rejected, not ignored", () => {
  test("positive control: the base manifest without deploymentModes is valid", () => {
    expect(validateServiceContractManifest(validManifest).success).toBe(true);
  });

  test("a manifest carrying deploymentModes fails validation", () => {
    const result = validateServiceContractManifest({
      ...validManifest,
      deploymentModes: ["local", "self_hosted"],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(JSON.stringify(result.error.issues)).toContain("deploymentModes");
    }
  });

  test("a manifest carrying singular deploymentMode fails validation", () => {
    for (const value of ["local", "self_hosted", "self-hosted", "cloud"]) {
      const result = validateServiceContractManifest({
        ...validManifest,
        deploymentMode: value,
      });
      expect(result.success, `deploymentMode: ${value} must fail`).toBe(false);
    }
  });

  test("both placement spellings fail as deploymentModes values", () => {
    for (const value of ["self_hosted", "self-hosted"]) {
      const result = validateServiceContractManifest({
        ...validManifest,
        deploymentModes: [value],
      });
      expect(result.success, `deploymentModes: [${value}] must fail`).toBe(false);
    }
  });

  // Direction 1 of the inversion. The old schema REQUIRED deploymentModes on
  // every service surface (`.min(1)`), so a manifest omitting it FAILED. Both
  // directions must flip: omission validates (this test), carriage fails (the
  // next one). This test is red against pre-removal main.
  test("a service surface omitting deploymentModes validates", () => {
    const result = validateServiceContractManifest({
      ...validManifest,
      bins: ["todos", "todos-serve"],
      serviceSurfaces: [
        {
          name: "api",
          kind: "api",
          status: "deferred",
          authMode: "api-key",
          deferReason: "pending",
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  test("a service surface carrying deploymentModes fails validation", () => {
    const result = validateServiceContractManifest({
      ...validManifest,
      bins: ["todos", "todos-serve"],
      serviceSurfaces: [
        {
          name: "api",
          kind: "api",
          status: "deferred",
          authMode: "api-key",
          deferReason: "pending",
          deploymentModes: ["local"],
        },
      ],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(JSON.stringify(result.error.issues)).toContain("deploymentModes");
    }
  });

  test("the deployment-mode exports are gone from the package surface", () => {
    const surface = contractsExports as Record<string, unknown>;
    for (const name of [
      "DEPLOYMENT_MODES",
      "DEPRECATED_DEPLOYMENT_MODE_ALIASES",
      "DeploymentModeSchema",
      "DEPRECATED_STORAGE_MODE_ALIASES",
    ]) {
      expect(surface[name], `${name} must no longer be exported`).toBeUndefined();
    }
  });
});

/** Collect every property key reachable in a JSON-schema-like object. */
function walkKeys(node: unknown, keys: string[] = []): string[] {
  if (Array.isArray(node)) {
    for (const item of node) walkKeys(item, keys);
    return keys;
  }
  if (node && typeof node === "object") {
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      keys.push(key);
      walkKeys(value, keys);
    }
  }
  return keys;
}

describe("JSON Schema copies reject the field structurally", () => {
  test("walkKeys positive control: sees a planted deploymentModes key", () => {
    expect(walkKeys({ nested: [{ deploymentModes: { type: "array" } }] })).toContain(
      "deploymentModes",
    );
  });

  for (const [label, schema] of [
    ["exported SERVICE_CONTRACT_JSON_SCHEMA", SERVICE_CONTRACT_JSON_SCHEMA],
    [
      "shipped src/hasna.contract.schema.json",
      JSON.parse(readFileSync(join(repoRoot, "src", "hasna.contract.schema.json"), "utf8")),
    ],
  ] as const) {
    test(`${label} carries no deploymentModes and stays closed`, () => {
      const keys = walkKeys(schema);
      expect(keys).not.toContain("deploymentModes");
      expect(keys).not.toContain("deploymentMode");
      // additionalProperties: false is what turns "field removed" into
      // "field rejected" for JSON-Schema validators.
      expect((schema as { additionalProperties?: boolean }).additionalProperties).toBe(false);
      const surfaceItems = (schema as any).properties?.serviceSurfaces?.items;
      expect(surfaceItems?.additionalProperties).toBe(false);
      // The placement words must not survive as enum values anywhere — and
      // the field name must not survive as a VALUE either (the old schema
      // listed "deploymentModes" in `required` arrays, where it is a string
      // value, invisible to a key walk).
      const text = JSON.stringify(schema);
      expect(text).not.toContain("deploymentMode");
      expect(text).not.toContain("self_hosted");
      expect(text).not.toContain("self-hosted");
    });
  }
});

describe("server data backend is sqlite|postgresql", () => {
  test("server backend matches the engine vocabulary", () => {
    expect(SERVER_DATA_BACKENDS).toEqual(["sqlite", "postgresql"]);
    expect(STORAGE_ENGINES).toEqual(["sqlite", "postgresql"]);
  });

  test("DATABASE_URL is the only server backend selector", () => {
    expect(resolveServerDataBackend("demo", {}).backend).toBe("sqlite");
    expect(resolveServerDataBackend("demo", {
      HASNA_DEMO_DATABASE_URL: "postgres://user@host/db",
    }).backend).toBe("postgresql");
  });

  test("retired server mode variables fail closed with migration guidance", () => {
    for (const word of ["", "   ", "sqlite", "postgres", ...REMOVED_MODE_WORDS]) {
      expect(
        () => resolveServerDataBackend("demo", { HASNA_DEMO_STORAGE_MODE: word }),
        `${word} must throw`,
      ).toThrow(/HASNA_DEMO_DATABASE_URL|removed/i);
    }
  });

  test("manifest storage.backend rejects placement words and retired storage.mode", () => {
    expect(
      validateServiceContractManifest({
        ...validManifest,
        storage: { backend: "local", sqlitePath: "~/.hasna/todos/todos.db" },
      }).success,
    ).toBe(false);
    expect(
      validateServiceContractManifest({
        ...validManifest,
        storage: { mode: "postgresql" },
      }).success,
    ).toBe(false);
  });
});

describe("client seam is sqlite|http, never placement words", () => {
  test("removed mode words in the client env throw", () => {
    for (const word of ["", "   ", "local", "cloud", "self_hosted", "self-hosted", "remote", "hybrid"]) {
      expect(
        () => resolveClientTransport("demo", { HASNA_DEMO_STORAGE_MODE: word }),
        `${word} must throw`,
      ).toThrow();
    }
  });

  test("URL + key select HTTP without a separate mode", () => {
    const resolved = resolveClientTransport("demo", {
      HASNA_DEMO_API_URL: "https://demo.example.com",
      HASNA_DEMO_API_KEY: "test-key-not-a-secret",
    });
    expect(resolved.transport).toBe("http");
    expect(resolved.baseUrl).toBe("https://demo.example.com/v1");
    expect(resolved.transportSource).toBe("HASNA_DEMO_API_URL");
  });

  test("a server DATABASE_URL never makes the client open PostgreSQL", () => {
    const resolved = resolveClientTransport("demo", {
      HASNA_DEMO_DATABASE_URL: "postgres://user@host/db",
    });
    expect(resolved.transport).toBe("sqlite");
    expect(resolved.baseUrl).toBeNull();
  });

  test("retired client mode variables fail closed even for old valid values", () => {
    for (const value of ["sqlite", "postgres"]) {
      expect(() => resolveClientTransport("demo", {
        HASNA_DEMO_STORAGE_MODE: value,
      })).toThrow(/HASNA_DEMO_API_URL|removed/i);
    }
  });
});

// ---------------------------------------------------------------------------
// Vocabulary boundary: the deployment-mode words must not survive anywhere in
// the shipped source, manifests, templates, or live docs. Tests are excluded
// (they must keep naming the words to prove rejection), and CHANGELOG.md is
// history, not instruction.
// ---------------------------------------------------------------------------

const FORBIDDEN_PATTERNS: readonly [string, RegExp][] = [
  ["deploymentMode(s)", /deploymentModes?/],
  ["deployment mode prose", /deployment[ -]modes?/i],
  ["self_hosted", /self_hosted/i],
  ["self-hosted", /self-hosted/i],
  ["hybrid", /\bhybrid(?:\b|_)/i],
];

// A line carrying a 64-hex digest cell is a hash-anchored evidence row — a
// quoted artifact of record whose text must stay verbatim (rewording it would
// falsify the recorded digest). Exactly those lines are exempt from the
// vocabulary scan; everything else in the same file is still scanned.
const DIGEST_ANCHORED_LINE = /`[0-9a-f]{64}`/;

function scanForForbidden(content: string): string[] {
  const scannable = content
    .split("\n")
    .filter((line) => !DIGEST_ANCHORED_LINE.test(line))
    .join("\n");
  return FORBIDDEN_PATTERNS.filter(([, pattern]) => pattern.test(scannable)).map(
    ([label]) => label,
  );
}

function trackedFiles(): string[] {
  const result = Bun.spawnSync(["git", "ls-files", "-z"], { cwd: repoRoot, stdout: "pipe" });
  if (result.exitCode !== 0) throw new Error("git ls-files failed");
  return new TextDecoder()
    .decode(result.stdout)
    .split("\0")
    .filter((path) => path.length > 0);
}

describe("no mode vocabulary survives in shipped source or live docs", () => {
  test("scanner positive control: detects a planted token", () => {
    expect(scanForForbidden('x = { "deploymentModes": ["self-hosted"] }')).toEqual([
      "deploymentMode(s)",
      "self-hosted",
    ]);
    expect(scanForForbidden("a hybrid runtime")).toEqual(["hybrid"]);
    expect(scanForForbidden("hybrid_local_cache")).toEqual(["hybrid"]);
    expect(scanForForbidden("nothing to see")).toEqual([]);
  });

  test("digest-anchored evidence rows are exempt, and ONLY those", () => {
    const digest = "a".repeat(64);
    // Positive control pair: the same token is ignored on a digest row and
    // caught on a plain line — proving the exemption is line-scoped.
    expect(scanForForbidden(`| 1 | "self-hosted plane" | \`${digest}\` |`)).toEqual([]);
    expect(
      scanForForbidden(`| 1 | "self-hosted plane" | \`${digest}\` |\na self_hosted claim`),
    ).toEqual(["self_hosted"]);
  });

  test("src, manifests, examples, templates, and docs are clean", () => {
    const files = trackedFiles().filter((path) => {
      if (path.endsWith(".test.ts")) return false;
      if (path === "CHANGELOG.md") return false;
      if (path.startsWith("tests/")) return false;
      return (
        path.startsWith("src/") ||
        path.startsWith("docs/") ||
        path.startsWith("examples/") ||
        path === "hasna.contract.json" ||
        path === "CONTRACT.md" ||
        path === "README.md"
      );
    });
    // The scan must actually cover the surfaces it claims to cover.
    expect(files).toContain("src/schemas.ts");
    expect(files).toContain("src/kit/templates/backend.ts");
    expect(files).toContain("hasna.contract.json");
    expect(files.length).toBeGreaterThan(40);

    const offenders: string[] = [];
    for (const path of files) {
      const hits = scanForForbidden(readFileSync(join(repoRoot, path), "utf8"));
      if (hits.length > 0) offenders.push(`${path}: ${hits.join(", ")}`);
    }
    expect(offenders).toEqual([]);
  });
});
