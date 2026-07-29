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

describe("a third-party key wearing an app's name is a waiver case, not an unpoliced class", () => {
  // This block originally asserted that the bare alias was not policed at all.
  // That exclusion was reverted: see "the app's own bare alias is policed"
  // below for why, and for the waiver that covers the measured open-recordings
  // case without opening a fleet-wide hole.

  test("the canonical name on the same line is caught", () => {
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

// ---------------------------------------------------------------------------
// P0 — the SECOND review round. Three gate-WEAKENING changes rode in under a
// commit titled `test: pin the credential-seam review findings`, with no stated
// finding behind them. The most serious made the documented exclusion and the
// implemented one disagree in the UNSAFE direction.
// ---------------------------------------------------------------------------

describe("the inbound-surface exclusion is TOP-LEVEL, exactly as CONTRACT.md documents it", () => {
  // CONTRACT.md says the excluded surfaces are `src/server/`, `src/http/`,
  // `src/api/`, `src/mcp/` — top-level directories. The implementation matched
  // ANY path segment at ANY depth, so `src/client/api/client.ts` was silently
  // exempt. That is the single most likely place someone would actually put a
  // client bypass, and doc and impl disagreed in the direction that lets one
  // through.
  //
  // The four fleet files that motivated the exclusion are all top-level
  // (`src/api/index.ts`, `src/http/auth.ts`, `src/server/serve.ts`,
  // `src/mcp/http.ts`), so nothing measured is given up by narrowing it.

  test("a nested api/ under a CLIENT directory is policed again", () => {
    const result = scan({
      "src/client/api/client.ts": "const key = process.env.HASNA_ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.path).toBe("src/client/api/client.ts");
  });

  test("a top-level src/api/ read stays excluded", () => {
    const result = scan({
      "src/api/client.ts": "const expected = process.env.HASNA_ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toEqual([]);
  });

  for (const path of [
    "src/lib/server/pool.ts",
    "src/client/http/fetcher.ts",
    "src/features/mcp/bridge.ts",
  ]) {
    test(`${path} is policed — the excluded segment is not at the top level`, () => {
      const result = scan({ [path]: "const key = process.env.HASNA_ACCOUNTS_API_KEY;\n" });
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]!.path).toBe(path);
    });
  }

  test("the exclusion covers the whole subtree under a top-level surface", () => {
    // `src/server/**` is one inbound surface however deeply it is organised —
    // the narrowing is about WHERE the surface directory sits, not how far the
    // files beneath it nest.
    const result = scan({
      "src/server/routes/api/items.ts": "const expected = process.env.HASNA_ACCOUNTS_API_KEY;\n",
    });
    expect(result.findings).toEqual([]);
  });

  test("a directory merely NAMED like a surface outside src/ is policed", () => {
    const result = scan({ "api/client.ts": "const key = process.env.HASNA_ACCOUNTS_API_KEY;\n" });
    expect(result.findings).toHaveLength(1);
  });
});

describe("the app's own bare alias is policed, because the seam honours it", () => {
  // `clientTransportEnvKeys()` returns BOTH `HASNA_<APP>_API_KEY` and the bare
  // `<APP>_API_KEY`, and the transport resolves both. This rule justifies its
  // own soundness by asking that function for the names it polices "rather than
  // approximating them, so the rule and the seam cannot drift apart" — so
  // filtering its answer down to the prefixed half reintroduces exactly the
  // drift that sentence forbids, on the app's own canonical alias.
  //
  // The collision with third-party keys that share an app's name is real, but
  // the remedy for a measured exception is the waiver this rule already ships
  // and echoes into the report, not a silent fleet-wide de-policing.

  test("the unprefixed alias is a finding", () => {
    const result = scan({ "src/store.ts": "const k = process.env.ACCOUNTS_API_KEY;\n" });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.variable).toBe("ACCOUNTS_API_KEY");
  });

  test("a third-party key wearing the app's name clears with an auditable waiver", () => {
    // The measured case: open-recordings reads RECORDINGS_API_KEY into
    // config.openai_api_key. A waiver states that in the report where a
    // reviewer sees it, instead of the class disappearing fleet-wide.
    const result = scan(
      {
        "src/lib/config.ts": [
          "// hasna-credential-seam-waiver: RECORDINGS_API_KEY holds an OpenAI key here, not a Hasna client credential",
          "const k = process.env.RECORDINGS_API_KEY;",
        ].join("\n"),
      },
      "recordings",
    );
    expect(result.findings).toEqual([]);
    expect(result.waivers).toHaveLength(1);
  });

  test("another service's bare alias is still NOT policed", () => {
    // Only the scanned app's own keys come from `clientTransportEnvKeys()`. A
    // bare name belonging to some other service has no namespace to identify it
    // by, so it stays out of scope — this narrowing is about the OWN app key.
    const result = scan({ "src/lib/cloud.ts": "const k = process.env.TODOS_API_KEY;\n" });
    expect(result.findings).toEqual([]);
  });
});
