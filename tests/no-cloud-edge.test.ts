// The no-cloud gate, tested in BOTH directions.
//
// Every test here is a pair or has a pair elsewhere in the file: the shape
// that must pass, and the shape that must still fail. A rule that only ever
// gets the passing half tested is how a gate ends up protecting nothing, and
// this repo has been burned by that enough times to stop writing one-sided
// tests.
//
// The reference cases are real. `@hasna/connectors@1.4.0` is the one repo
// already remediated and published; it failed this gate on a JSDoc comment and
// on the guard test the remediation pattern itself mandates. `hasna/logs`
// failed on a lockfile entry that resolves nothing. `hasnaxyz/iapp-files`
// failed on two functions it defines itself. All four shapes are below.

import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanNoCloudTarget } from "../src/no-cloud";
import { isLinkedResolution, lockfileEdges, manifestEdges, nameFromResolutionId, parseLooseJson } from "../src/dependency-edge";
import { importedBindings, importsModule, maskComments, maskCommentsForPath } from "../src/source-text";

/** The retired runtime, spelled in pieces so this file does not trip its own gate. */
const RETIRED = ["@hasna/", "cloud"].join("");

interface Fixture {
  files: Record<string, string>;
  name?: string;
}

function withRepo(fixture: Fixture, assert: (verdict: ReturnType<typeof scanNoCloudTarget>) => void) {
  const dir = mkdtempSync(join(tmpdir(), "no-cloud-edge-"));
  try {
    const manifest = fixture.files["package.json"] ?? JSON.stringify({ name: fixture.name ?? "@hasna/subject", version: "1.0.0" });
    for (const [path, text] of Object.entries({ ...fixture.files, "package.json": manifest })) {
      const full = join(dir, path);
      mkdirSync(join(full, ".."), { recursive: true });
      writeFileSync(full, text);
    }
    assert(scanNoCloudTarget(dir));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function patterns(report: ReturnType<typeof scanNoCloudTarget>): string[] {
  return report.findings.map((finding) => `${finding.path ?? "<manifest>"}:${finding.pattern}`);
}

describe("no-cloud gate: comments are prose, not edges", () => {
  test("a JSDoc block recording the removal does not fail the scan", () => {
    // Verbatim shape of connectors' src/db/sqlite-adapter.ts, the file that
    // failed the published 1.4.0 release.
    withRepo(
      {
        files: {
          "src/sqlite-adapter.ts":
            "/**\n * Thin synchronous wrapper over `bun:sqlite`.\n *\n" +
            ` * This is the local-only storage engine. It was previously imported from \`${RETIRED}\`,\n` +
            " * which is retired and unsupported; the class is kept API-compatible.\n */\n" +
            "export class SqliteAdapter {}\n",
        },
      },
      (report) => {
        expect(patterns(report)).toEqual([]);
        expect(report.verdict).toBe("passed");
      },
    );
  });

  test("a line comment does not fail the scan, but the same text as code does", () => {
    withRepo({ files: { "src/a.ts": `// migrated off ${RETIRED} in 1.4.0\nexport const ok = true;\n` } }, (report) => {
      expect(report.verdict).toBe("passed");
    });
    withRepo({ files: { "src/a.ts": `export const runtime = "${RETIRED}";\n` } }, (report) => {
      expect(report.verdict).toBe("failed");
      expect(patterns(report)).toContain(`src/a.ts:${RETIRED}`);
    });
  });

  test("a hash comment is prose in yaml, toml and env files alike", () => {
    withRepo(
      {
        files: {
          "src/deploy.yaml": `# no longer installs ${RETIRED}\nname: app\n`,
          "src/app.toml": `# ${RETIRED} was dropped\nname = "app"\n`,
          ".env.example": `# HASNA_CLOUD_URL is retired\nAPP_URL=https://app.invalid\n`,
        },
      },
      (report) => {
        expect(patterns(report)).toEqual([]);
      },
    );
    withRepo({ files: { "src/deploy.yaml": `install: ${RETIRED}\n` } }, (report) => {
      expect(patterns(report)).toContain(`src/deploy.yaml:${RETIRED}`);
    });
  });

  test("a URL in a string is not a line comment", () => {
    // The false-negative trap: a naive `//` stripper truncates here and the
    // reference disappears. It must not.
    withRepo({ files: { "src/a.ts": `export const url = "https://registry.invalid/${RETIRED}";\n` } }, (report) => {
      expect(report.verdict).toBe("failed");
      expect(patterns(report)).toContain(`src/a.ts:${RETIRED}`);
    });
  });

  test("a `#` inside a quoted yaml scalar is not a comment", () => {
    withRepo({ files: { "src/deploy.yaml": `note: "a # ${RETIRED}"\n` } }, (report) => {
      expect(patterns(report)).toContain(`src/deploy.yaml:${RETIRED}`);
    });
  });

  test("a `#` with no whitespace before it is a URL fragment, not a yaml comment", () => {
    // YAML opens a comment only at line start or after whitespace. Treating
    // every `#` as a comment would mask the rest of this line — and with it a
    // real reference.
    withRepo({ files: { "src/deploy.yaml": `registry: https://npm.invalid/p#${RETIRED}\n` } }, (report) => {
      expect(patterns(report)).toContain(`src/deploy.yaml:${RETIRED}`);
    });
  });

  test("json has no comments, so `//` inside a json string hides nothing", () => {
    withRepo({ files: { "src/config.json": `{ "registry": "https://x.invalid/${RETIRED}" }\n` } }, (report) => {
      expect(patterns(report)).toContain(`src/config.json:${RETIRED}`);
    });
  });

  test("a `//` line in a .json file is scanned, because JSON comment support is ambiguous", () => {
    // Strict JSON has no comments; JSONC does. Guessing wrong hides a real
    // reference in the one format that carries dependency edges, so `.json`
    // is masked as nothing at all.
    withRepo({ files: { "src/tsconfig.json": `{\n  // pinned for ${RETIRED}\n  "strict": true\n}\n` } }, (report) => {
      expect(patterns(report)).toContain(`src/tsconfig.json:${RETIRED}`);
    });
  });
});

describe("no-cloud gate: the mandated guard test", () => {
  const guardTest =
    "const FORBIDDEN_PACKAGE = " +
    `"${RETIRED}";\n` +
    'const FORBIDDEN_IMPORT = new RegExp(String.raw`from ["\']${FORBIDDEN_PACKAGE}["\']`);\n' +
    'const symbols = ["registerCloudTools", "registerCloudCommands"];\n' +
    "export { FORBIDDEN_IMPORT, symbols };\n";

  test("the guard test the remediation pattern mandates does not fail the gate", () => {
    withRepo({ files: { "src/no-cloud-boundary.test.ts": guardTest } }, (report) => {
      expect(patterns(report)).toEqual([]);
      expect(report.verdict).toBe("passed");
    });
  });

  test("the allowlist covers mentions only — a real import in the guard test still fails", () => {
    withRepo(
      { files: { "src/no-cloud-boundary.test.ts": `import { thing } from "${RETIRED}";\n${guardTest}` } },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report)).toContain(`src/no-cloud-boundary.test.ts:${RETIRED}`);
      },
    );
  });

  test("the allowlist is that exact filename, not any test file", () => {
    withRepo({ files: { "src/my-boundary.test.ts": guardTest } }, (report) => {
      expect(report.verdict).toBe("failed");
    });
  });
});

describe("no-cloud gate: symbols are scoped to their import", () => {
  // iapp-files' real shape: defined locally, routed at the self-hosted service.
  const localDefinition =
    'import type { Command } from "commander";\n' +
    "export function registerCloudTools(register: unknown): void { void register; }\n" +
    "export function registerCloudCommands(program: Command): void { void program; }\n";

  test("locally defined registerCloudTools/registerCloudCommands are not the retired surface", () => {
    withRepo({ files: { "src/cloud-tools.ts": localDefinition } }, (report) => {
      expect(patterns(report)).toEqual([]);
      expect(report.verdict).toBe("passed");
    });
  });

  test("a local import of the same names is still local", () => {
    withRepo(
      {
        files: {
          "src/cloud-tools.ts": localDefinition,
          "src/index.ts": 'import { registerCloudTools } from "./cloud-tools.js";\nregisterCloudTools(null);\n',
        },
      },
      (report) => {
        expect(report.verdict).toBe("passed");
      },
    );
  });

  test("importing the same names from the retired runtime fails", () => {
    withRepo({ files: { "src/index.ts": `import { registerCloudTools } from "${RETIRED}";\nregisterCloudTools(null);\n` } }, (report) => {
      expect(report.verdict).toBe("failed");
      expect(patterns(report)).toContain("src/index.ts:registerCloudTools");
    });
  });

  test("a renamed import binds the local name and is still caught", () => {
    withRepo(
      { files: { "src/index.ts": `import { setup as registerCloudCommands } from "${RETIRED}";\nregisterCloudCommands(null);\n` } },
      (report) => {
        expect(patterns(report)).toContain("src/index.ts:registerCloudCommands");
      },
    );
  });

  test("a require of the retired runtime binds the same way an import does", () => {
    withRepo({ files: { "src/index.js": `const { registerCloudTools } = require("${RETIRED}");\n` } }, (report) => {
      expect(patterns(report)).toContain("src/index.js:registerCloudTools");
    });
  });
});

describe("no-cloud gate: dependency edges from the manifest", () => {
  test("a direct production dependency is critical", () => {
    withRepo({ files: { "package.json": JSON.stringify({ name: "@hasna/subject", dependencies: { [RETIRED]: "0.1.41" } }) } }, (report) => {
      expect(report.verdict).toBe("failed");
      const finding = report.findings.find((entry) => entry.pattern === RETIRED && entry.kind === "package_manifest");
      expect(finding?.severity).toBe("critical");
    });
  });

  test("an overrides pin is an edge even when nothing declares the dependency", () => {
    withRepo({ files: { "package.json": JSON.stringify({ name: "@hasna/subject", overrides: { [RETIRED]: "0.1.41" } }) } }, (report) => {
      expect(report.verdict).toBe("failed");
    });
  });

  test("a trustedDependencies entry is an edge", () => {
    withRepo({ files: { "package.json": JSON.stringify({ name: "@hasna/subject", trustedDependencies: [RETIRED] }) } }, (report) => {
      expect(report.verdict).toBe("failed");
    });
  });

  test("manifestEdges reads every install-bearing section", () => {
    const sections = manifestEdges(
      {
        dependencies: { [RETIRED]: "1" },
        devDependencies: { "open-cloud": "1" },
        resolutions: { [RETIRED]: "1" },
        bundleDependencies: ["open-cloud"],
      },
      [RETIRED, "open-cloud"],
    ).map((edge) => edge.section);
    expect(new Set(sections)).toEqual(new Set(["dependencies", "devDependencies", "resolutions", "bundleDependencies"]));
  });
});

describe("no-cloud gate: dependency edges from bun.lock", () => {
  function lock(body: Record<string, unknown>): string {
    // Written with a trailing comma, exactly as bun emits it.
    return JSON.stringify({ lockfileVersion: 1, ...body }, null, 2).replace(/\}\n(\s*)\}/g, "},\n$1}");
  }

  // Both halves of this pair were MEASURED on bun 1.3.14, not assumed. See
  // `isLinkedResolution`. Getting them backwards is what made `hasna/logs`
  // look like a false positive when it has a real edge.
  test("a REGISTRY package's devDependencies are not installed, so they are not edges", () => {
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "@hasna/wrapper": "^1" } } },
      packages: {
        "@hasna/wrapper": ["@hasna/wrapper@1.0.0", { devDependencies: { [RETIRED]: "^0.1.41" } }],
        [`@hasna/wrapper/${RETIRED}`]: [`${RETIRED}@0.1.41`, {}],
      },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"], "@hasna/subject")).toEqual([]);
  });

  test("a LINKED package's devDependencies ARE installed, so they are edges", () => {
    // hasna/logs, exactly: `@hasna/agent-registry` is a file: dependency, so
    // its dev-only edge to the retired runtime really does land in the tree.
    const text = lock({
      workspaces: { "": { name: "@hasna/logs", devDependencies: { "@hasna/agent-registry": "file:../open-agent-registry" } } },
      packages: {
        "@hasna/agent-registry": ["@hasna/agent-registry@file:../open-agent-registry", { dependencies: { pg: "^8" }, devDependencies: { [RETIRED]: "file:../open-cloud" } }],
        [`@hasna/agent-registry/${RETIRED}`]: [`${RETIRED}@file:../open-cloud`, {}],
      },
    });
    const edges = lockfileEdges(text, [RETIRED, "open-cloud"], "@hasna/logs");
    expect(edges?.map((edge) => edge.packageName)).toEqual([RETIRED]);
    expect(edges?.[0]?.scope).toBe("development");
    expect(edges?.[0]?.path).toEqual(["@hasna/agent-registry", RETIRED]);
  });

  test("isLinkedResolution reads the specifier, scope sigil and all", () => {
    expect(isLinkedResolution(`${RETIRED}@file:../open-cloud`)).toBe(true);
    expect(isLinkedResolution("pkg-a@link:../pkg-a")).toBe(true);
    expect(isLinkedResolution("pkg-a@workspace:packages/a")).toBe(true);
    expect(isLinkedResolution("commander@13.1.0")).toBe(false);
    expect(isLinkedResolution(`${RETIRED}@0.1.41`)).toBe(false);
  });

  test("a development hop cannot be laundered into a production verdict", () => {
    // The seed is a PRODUCTION dependency, so `current.scope` is "production"
    // when the dev hop is taken. If the hop kept the incoming scope instead of
    // forcing development, a dev-only edge would be reported critical.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "@hasna/linked": "file:../linked" } } },
      packages: {
        "@hasna/linked": ["@hasna/linked@file:../linked", { devDependencies: { "@hasna/mid": "^1" } }],
        "@hasna/mid": ["@hasna/mid@1.0.0", { dependencies: { [RETIRED]: "^0.1.41" } }],
        [RETIRED]: [`${RETIRED}@0.1.41`, {}],
      },
    });
    const edges = lockfileEdges(text, [RETIRED, "open-cloud"], "@hasna/subject");
    expect(edges?.map((edge) => edge.packageName)).toEqual([RETIRED]);
    expect(edges?.[0]?.scope).toBe("development");
  });

  test("a transitive PRODUCTION dependency is an edge the manifest never names", () => {
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "@hasna/wrapper": "^1" } } },
      packages: {
        "@hasna/wrapper": ["@hasna/wrapper@1.0.0", { dependencies: { [RETIRED]: "^0.1.41" } }],
        [RETIRED]: [`${RETIRED}@0.1.41`, {}],
      },
    });
    const edges = lockfileEdges(text, [RETIRED, "open-cloud"], "@hasna/subject");
    expect(edges?.map((edge) => edge.scope)).toEqual(["production"]);
    expect(edges?.[0]?.path).toEqual(["@hasna/wrapper", RETIRED]);
  });

  test("the root's own devDependency IS installed, and is high not critical", () => {
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", devDependencies: { [RETIRED]: "^0.1.41" } } },
      packages: { [RETIRED]: [`${RETIRED}@0.1.41`, {}] },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"], "@hasna/subject")?.map((edge) => edge.scope)).toEqual(["development"]);
  });

  test("an unreadable lockfile falls back to the text scan rather than reporting clean", () => {
    expect(lockfileEdges("{ not json", [RETIRED], "@hasna/subject")).toBeNull();
    withRepo({ files: { "bun.lock": `{ not json ${RETIRED}` } }, (report) => {
      expect(report.verdict).toBe("failed");
    });
  });

  test("a lockfile with no workspace table falls back rather than reporting clean", () => {
    expect(lockfileEdges(JSON.stringify({ lockfileVersion: 1, packages: {} }), [RETIRED])).toBeNull();
  });

  test("a transitive production edge fails the whole scan end to end", () => {
    withRepo(
      {
        files: {
          "package.json": JSON.stringify({ name: "@hasna/subject", version: "1.0.0", dependencies: { "@hasna/wrapper": "^1" } }),
          "bun.lock": lock({
            workspaces: { "": { name: "@hasna/subject", dependencies: { "@hasna/wrapper": "^1" } } },
            packages: {
              "@hasna/wrapper": ["@hasna/wrapper@1.0.0", { dependencies: { [RETIRED]: "^0.1.41" } }],
              [RETIRED]: [`${RETIRED}@0.1.41`, {}],
            },
          }),
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
        const finding = report.findings.find((entry) => entry.path === "bun.lock");
        expect(finding?.severity).toBe("critical");
        expect(finding?.message).toContain("@hasna/wrapper");
      },
    );
  });

  test("parseLooseJson tolerates trailing commas without mangling string contents", () => {
    const parsed = parseLooseJson('{ "a": "x,]", "b": [1,2,], }') as Record<string, unknown>;
    expect(parsed.a).toBe("x,]");
    expect(parsed.b).toEqual([1, 2]);
  });

  test("nameFromResolutionId keeps the scope sigil", () => {
    expect(nameFromResolutionId(`${RETIRED}@file:../open-cloud`)).toBe(RETIRED);
    expect(nameFromResolutionId("pg@8.22.0")).toBe("pg");
  });
});

describe("source-text masking primitives", () => {
  test("masking preserves length and line numbering", () => {
    const text = "const a = 1; // note\nconst b = 2;\n";
    const masked = maskComments(text, "c-like");
    expect(masked.length).toBe(text.length);
    expect(masked.split("\n").length).toBe(text.split("\n").length);
    expect(masked).not.toContain("note");
    expect(masked).toContain("const b = 2;");
  });

  test("a regex literal containing a quote does not drag the file into string state", () => {
    const text = `const re = /["']/;\n// hidden ${RETIRED}\nconst kept = "${RETIRED}";\n`;
    const masked = maskCommentsForPath(text, "src/a.ts");
    expect(masked).toContain(`const kept = "${RETIRED}"`);
    expect(masked).not.toContain(`hidden ${RETIRED}`);
  });

  test("a template literal closes its frame, so later comments still mask", () => {
    const text = `const t = \`a\${1}b\`;\n// gone ${RETIRED}\n`;
    expect(maskComments(text, "c-like")).not.toContain(`gone ${RETIRED}`);
  });

  test("an unterminated block comment discards the WHOLE mask, not just its own tail", () => {
    // The reference sits in a comment that was masked correctly before the
    // parse fell over. Keeping that partial result would hide it. Losing the
    // thread anywhere means trusting the mask nowhere.
    const text = `// note ${RETIRED}\nconst kept = 1;\n/* unterminated\n`;
    expect(maskComments(text, "c-like")).toContain(RETIRED);
  });

  test("an unterminated string also fails closed", () => {
    const text = `const broken = "oops;\n// note ${RETIRED}\n`;
    expect(maskComments(text, "c-like")).toContain(RETIRED);
  });

  test("importsModule sees every import form, including deep paths", () => {
    for (const form of [
      `import x from "${RETIRED}";`,
      `import "${RETIRED}/register";`,
      `export { a } from "${RETIRED}";`,
      `const m = await import("${RETIRED}");`,
      `const m = require("${RETIRED}");`,
    ]) {
      expect(importsModule(form, RETIRED)).toBe(true);
    }
    expect(importsModule(`const name = "${RETIRED}";`, RETIRED)).toBe(false);
  });

  test("importedBindings resolves default, named, renamed and namespace clauses", () => {
    expect(importedBindings(`import a, { b, c as d } from "${RETIRED}";`, RETIRED)).toEqual(new Set(["b", "d", "a"]));
    expect(importedBindings(`import * as ns from "${RETIRED}";`, RETIRED)).toEqual(new Set(["ns"]));
    expect(importedBindings(`import { x } from "./local.js";`, RETIRED)).toEqual(new Set());
  });
});
