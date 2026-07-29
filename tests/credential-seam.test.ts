// The conformance rule that keeps credential-resolution bypassers from regrowing.
//
// Half of this file is the rule finding real bypasses. The other half is the
// rule NOT firing on the legitimate code that surrounds them, because a
// mandatory gate that fails compliant repos gets switched off — and then it
// protects nothing, which is the same end state as a check that cannot fail.
// Every "must not fire" case below was taken from real fleet source.

import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanCredentialSeam } from "../src/credential-seam";

const roots: string[] = [];

function repo(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "hasna-seam-scan-"));
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

describe("the rule fails a package that resolves a credential by hand", () => {
  test("a member read of its own key is a finding", () => {
    const result = scan({
      "src/store.ts": "export const key = process.env.HASNA_ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.variable).toBe("HASNA_ACCOUNTS_API_KEY");
    expect(result.findings[0]!.line).toBe(1);
  });

  test("an index read of its own key is a finding", () => {
    const result = scan({
      "src/store.ts": 'export const key = process.env["HASNA_ACCOUNTS_API_KEY"];\n',
    });
    expect(result.findings).toHaveLength(1);
  });

  test("a read off a plain `env` parameter is a finding", () => {
    const result = scan({
      "src/store.ts": "export const pick = (env: any) => env.HASNA_ACCOUNTS_API_KEY || env.ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toHaveLength(1);
  });

  test("the unprefixed alias is a finding", () => {
    // The seam resolves `<APP>_API_KEY` as well as `HASNA_<APP>_API_KEY`, so a
    // hand-read of the alias is the same defect. A third-party key that happens
    // to wear an app's name clears through a waiver, not through the whole class
    // going unpoliced — see the review regression suite.
    const result = scan({ "src/store.ts": "const k = process.env.ACCOUNTS_API_KEY;\n" });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.variable).toBe("ACCOUNTS_API_KEY");
  });

  test("destructuring the key out of process.env is a finding", () => {
    const result = scan({
      "src/store.ts": "const { HASNA_ACCOUNTS_API_KEY } = process.env;\n",
    });
    expect(result.findings).toHaveLength(1);
  });

  test("reading ANOTHER service's client key is a finding", () => {
    const result = scan({
      "src/store.ts": "const k = process.env.HASNA_TODOS_API_KEY;\n",
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.message).toContain("another service");
  });

  test("a computed HASNA_${x}_API_KEY read is a finding", () => {
    const result = scan({
      "src/store.ts": "const k = process.env[`HASNA_${token}_API_KEY`];\n",
    });
    expect(result.findings).toHaveLength(1);
  });

  test("findings report the real line number in a multi-line file", () => {
    const result = scan({
      "src/store.ts": ["// header", "", "const a = 1;", "const k = process.env.HASNA_ACCOUNTS_API_KEY;"].join("\n"),
    });
    expect(result.findings[0]!.line).toBe(4);
  });
});

describe("the rule passes code that uses the seam", () => {
  test("a package resolving through @hasna/contracts/client is clean", () => {
    const result = scan({
      "src/store.ts": [
        'import { resolveStorageClient } from "@hasna/contracts/client/storage";',
        'export const store = (env: any) => resolveStorageClient("accounts", env);',
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
  });

  test("the seam's own variable-indexed reads are not findings", () => {
    // This is how `src/client/transport.ts` and `credentials.ts` read the env:
    // through a key list, never a literal. It needs no allowlist entry.
    const result = scan({
      "src/client/transport.ts": [
        "const keys = clientTransportEnvKeys(name);",
        "for (const key of keys.apiKeyKeys) { const v = env[key]; if (v) return v; }",
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
  });
});

describe("the rule does not fire on legitimate code", () => {
  test("WRITING the variable is not a read", () => {
    const result = scan({
      "src/flip.ts": [
        "process.env.HASNA_ACCOUNTS_API_KEY = minted;",
        'const child = { env: { HASNA_ACCOUNTS_API_KEY: minted } };',
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
  });

  test("re-injecting into a derived env object is not a finding on the write half", () => {
    const result = scan({
      "src/derive.ts": "const next = { ...env, HASNA_ACCOUNTS_API_KEY: trimmed };\n",
    });
    expect(result.findings).toEqual([]);
  });

  test("naming the variable in an error message is not a read", () => {
    const result = scan({
      "src/errors.ts": 'throw new Error("Unset HASNA_ACCOUNTS_API_URL/HASNA_ACCOUNTS_API_KEY to go local");\n',
    });
    expect(result.findings).toEqual([]);
  });

  test("a name-only constant list is not a read", () => {
    const result = scan({
      "src/mode.ts": 'const API_KEY_ENV_KEYS = ["HASNA_ACCOUNTS_API_KEY"] as const;\n',
    });
    expect(result.findings).toEqual([]);
  });

  test("a redaction allowlist that strips the key is not a read", () => {
    const result = scan({
      "src/redact.ts": [
        "const SENSITIVE = new Set([",
        '  "HASNA_ACCOUNTS_API_KEY",',
        '  "HASNA_TODOS_API_KEY",',
        "]);",
        "export const clean = (env: any) => Object.keys(env).filter((k) => !SENSITIVE.has(k));",
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
  });

  test("a JSDoc usage example is not a read", () => {
    const result = scan({
      "src/sdk.ts": [
        "/**",
        " * Usage:",
        " *   const c = new Client(process.env.HASNA_ACCOUNTS_API_KEY!);",
        " */",
        "export const version = 1;",
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
  });

  test("a line comment is not a read", () => {
    const result = scan({
      "src/sdk.ts": "// legacy: we used to read process.env.HASNA_ACCOUNTS_API_KEY here\nexport const x = 1;\n",
    });
    expect(result.findings).toEqual([]);
  });

  test("a `//` inside a string does not mask the rest of the line", () => {
    // If the comment masker treated this `//` as a comment start it would blind
    // the scanner to the real read that follows.
    const result = scan({
      "src/sdk.ts": 'const url = "https://accounts.example"; const k = process.env.HASNA_ACCOUNTS_API_KEY;\n',
    });
    expect(result.findings).toHaveLength(1);
  });

  test("test files are excluded", () => {
    const result = scan({
      "src/store.test.ts": "const env = { HASNA_ACCOUNTS_API_KEY: 'x' }; const k = process.env.HASNA_ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toEqual([]);
  });

  test("build output and shipped bundles are excluded", () => {
    const result = scan({
      "dist/store.js": "const k = process.env.HASNA_ACCOUNTS_API_KEY;\n",
      "bin/accounts.js": "const k = process.env.HASNA_ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toEqual([]);
  });

  test("a server reading the key it expects INBOUND is outside the client grammar", () => {
    const result = scan(
      {
        "src/server/auth.ts": [
          "const expected = process.env.HASNA_SKILLS_BOOTSTRAP_API_KEY;",
          "const serve = process.env.HASNA_CALENDAR_SERVE_API_KEY;",
        ].join("\n"),
      },
      "skills",
    );
    expect(result.findings).toEqual([]);
  });

  test("third-party provider keys wearing the HASNA_ prefix are not ours to resolve", () => {
    const result = scan(
      {
        "src/providers.ts": [
          "const a = process.env.HASNA_BRAIN_ANTHROPIC_API_KEY;",
          "const b = process.env.HASNA_CEREBRAS_LIVE_API_KEY;",
          "const c = process.env.HASNA_SANDBOXES_E2B_API_KEY;",
        ].join("\n"),
      },
      "brain",
    );
    expect(result.findings).toEqual([]);
  });

  test("an unrelated third-party key is never in scope", () => {
    const result = scan({ "src/llm.ts": "const k = process.env.OPENAI_API_KEY;\n" });
    expect(result.findings).toEqual([]);
  });
});

describe("waivers are explicit, justified, and reported", () => {
  test("a waiver with a real reason clears the finding and is recorded", () => {
    const result = scan({
      "src/lib/legacy-resolver.ts": [
        "// hasna-credential-seam-waiver: server-side validation of the inbound key, not a client resolve",
        "const expected = process.env.HASNA_ACCOUNTS_API_KEY;",
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
    expect(result.waivers).toHaveLength(1);
    expect(result.waivers[0]!.reason).toContain("server-side validation");
  });

  test("a same-line waiver also applies", () => {
    const result = scan({
      "src/lib/legacy-resolver.ts":
        "const expected = process.env.HASNA_ACCOUNTS_API_KEY; // hasna-credential-seam-waiver: inbound key validation for the serve bin\n",
    });
    expect(result.findings).toEqual([]);
    expect(result.waivers).toHaveLength(1);
  });

  test("a waiver that justifies nothing is rejected rather than honoured", () => {
    const result = scan({
      "src/lib/legacy-resolver.ts": [
        "// hasna-credential-seam-waiver: TODO",
        "const expected = process.env.HASNA_ACCOUNTS_API_KEY;",
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
    expect(result.waivers).toEqual([]);
    expect(result.invalidWaivers).toHaveLength(1);
  });

  test("a waiver two lines above does NOT apply to the read", () => {
    const result = scan({
      "src/lib/legacy-resolver.ts": [
        "// hasna-credential-seam-waiver: this justification is nowhere near the read it claims to cover",
        "const unrelated = 1;",
        "const expected = process.env.HASNA_ACCOUNTS_API_KEY;",
      ].join("\n"),
    });
    expect(result.findings).toHaveLength(1);
  });
});

describe("the scan proves it actually looked at something", () => {
  test("filesScanned counts the source files inspected", () => {
    const result = scan({ "src/a.ts": "export const a = 1;\n", "src/b.ts": "export const b = 2;\n" });
    expect(result.filesScanned).toBe(2);
  });

  test("an empty repo scans zero files, so a passing report there asserts nothing", () => {
    const result = scan({});
    expect(result.filesScanned).toBe(0);
  });
});
