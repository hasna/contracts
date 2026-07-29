// Regressions from the adversarial review of 331e550, conformance-rule half.
//
// The gate was red on compliant code in 7 of 24 fleet repos, and — worse —
// green on the largest real bypass class. Both are represented here.

import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanCredentialSeam } from "../src/credential-seam";

const roots: string[] = [];

function repo(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "hasna-seam-review-"));
  roots.push(root);
  for (const [path, body] of Object.entries(files)) {
    const full = join(root, path);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, body);
  }
  return root;
}

function scan(files: Record<string, string>, appName = "accounts") {
  return scanCredentialSeam(repo(files), { appName });
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("a server reading the key it expects INBOUND is not a client bypass", () => {
  // Each path below is a real fleet file that the first version of this rule
  // flagged. All four compare the value against a caller-supplied header.
  const inboundSurfaces = [
    "src/api/index.ts",
    "src/http/auth.ts",
    "src/server/serve.ts",
    "src/mcp/http.ts",
  ];

  for (const path of inboundSurfaces) {
    test(`${path} is not a finding`, () => {
      const result = scan({
        [path]: [
          "const expected = process.env.HASNA_ACCOUNTS_API_KEY;",
          "export const ok = (presented: string) => secureCompare(presented, expected);",
        ].join("\n"),
      });
      expect(result.findings).toEqual([]);
    });
  }

  test("a client bypass in ordinary source is still caught alongside them", () => {
    const result = scan({
      "src/server/serve.ts": "const expected = process.env.HASNA_ACCOUNTS_API_KEY;\n",
      "src/lib/cloud.ts": "const key = process.env.HASNA_ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.path).toBe("src/lib/cloud.ts");
  });
});

describe("the unprefixed alias is not policed, because it collides with third-party keys", () => {
  test("a third-party key that happens to match the app name is not a finding", () => {
    // Real case: open-recordings reads RECORDINGS_API_KEY and assigns it to
    // config.openai_api_key. It is an OpenAI key, not a Hasna client credential.
    const result = scan(
      { "src/lib/config.ts": "const k = process.env.RECORDINGS_API_KEY;\n" },
      "recordings",
    );
    expect(result.findings).toEqual([]);
  });

  test("but the canonical name on the same line is still caught", () => {
    const result = scan({
      "src/lib/cloud.ts": "const k = env.HASNA_ACCOUNTS_API_KEY || env.ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.variable).toBe("HASNA_ACCOUNTS_API_KEY");
  });
});

describe("a comment-masking mistake cannot propagate past its own line", () => {
  test("an apostrophe inside a template literal does not unmask later comments", () => {
    // This exact construct broke the first masker: whole-file quote tracking
    // mis-paired the apostrophe in `service's`, leaving every following line
    // unmasked, and the rule then reported a key named only in a COMMENT.
    const result = scan({
      "src/report.ts": [
        "const message = `belongs to another service. Use that service's client`;",
        "// canonical name on the same line (`env.HASNA_ACCOUNTS_API_KEY || env.ACCOUNTS_API_KEY`)",
        "export const x = 1;",
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
  });

  test("a real read on the line AFTER such a template is still caught", () => {
    const result = scan({
      "src/report.ts": [
        "const message = `that service's client`;",
        "const k = process.env.HASNA_ACCOUNTS_API_KEY;",
      ].join("\n"),
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.line).toBe(2);
  });

  test("a multi-line block comment stays masked across lines", () => {
    const result = scan({
      "src/report.ts": [
        "/*",
        " * const k = process.env.HASNA_ACCOUNTS_API_KEY;",
        " */",
        "export const x = 1;",
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
  });

  test("code after a block comment CLOSES is still scanned", () => {
    const result = scan({
      "src/report.ts": "/* note */ const k = process.env.HASNA_ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toHaveLength(1);
  });

  test("this repo's own scanner source passes its own rule", () => {
    // The regression that motivated all of the above: the gate reported a
    // finding in `src/credential-seam.ts` itself.
    const root = join(import.meta.dir, "..");
    const result = scanCredentialSeam(root, { appName: "contracts" });
    expect(result.findings).toEqual([]);
  });
});

describe("dev and proof scripts are not shipped behaviour", () => {
  test("scripts/ is excluded like tests/", () => {
    const result = scan({
      "scripts/proof-roundtrip.ts": "const k = process.env.HASNA_ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toEqual([]);
  });
});

describe("a vendored fork of the seam is the loudest bypass, not a clean repo", () => {
  test("defining resolveClientTransport locally is a finding", () => {
    // A fork builds its key names by template and reads them through a computed
    // loop, so NO literal name appears and a name-based rule sees nothing. This
    // is how a repo shipping a complete copy of the defect scored zero findings.
    const result = scan({
      "src/store/contracts-client/transport.ts": [
        "export function resolveClientTransport(name, env = process.env) {",
        "  const keys = { apiKeyKeys: [`HASNA_${envToken(name)}_API_KEY`] };",
        "  for (const key of keys.apiKeyKeys) { const v = env[key]; if (v) return v; }",
        "}",
      ].join("\n"),
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.message).toContain("vendored copy");
  });

  test("each vendored entry point is reported", () => {
    const result = scan({
      "src/generated/storage-client/transport.ts": [
        "export function createHasnaHttpTransport(options) { return null; }",
        "export const createClientTransport = (name, env) => null;",
        "export function resolveStorageClient(name, env) { return null; }",
      ].join("\n"),
    });
    expect(result.findings).toHaveLength(3);
  });

  test("IMPORTING and CALLING the seam is compliant and never a finding", () => {
    const result = scan({
      "src/store/index.ts": [
        'import { resolveStorageClient, createClientTransport } from "@hasna/contracts/client/storage";',
        'export const store = (env: any) => resolveStorageClient("accounts", env);',
        'export const other = (env: any) => createClientTransport("accounts", env);',
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
  });

  test("the package that DEFINES the seam is allowed to define it", () => {
    const root = repo({
      "package.json": JSON.stringify({ name: "@hasna/contracts" }),
      "src/client/transport.ts": "export function resolveClientTransport(name, env) { return null; }\n",
    });
    expect(scanCredentialSeam(root, { appName: "contracts" }).findings).toEqual([]);
  });

  test("a DIFFERENT package defining it is still a finding", () => {
    const root = repo({
      "package.json": JSON.stringify({ name: "@hasna/telephony" }),
      "src/generated/transport.ts": "export function resolveClientTransport(name, env) { return null; }\n",
    });
    expect(scanCredentialSeam(root, { appName: "telephony" }).findings).toHaveLength(1);
  });
});
