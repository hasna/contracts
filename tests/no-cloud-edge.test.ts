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
import { isLinkedResolution, lockfileEdges, manifestEdges, nameFromResolutionId, parseLooseJson, resolutionTarget } from "../src/dependency-edge";
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

describe("no-cloud gate: the masker cannot blank live code", () => {
  // Every case here is a FALSE NEGATIVE found by review: the branch exited 0
  // where the substring scanner exited 1. The masker believed it had parsed
  // cleanly, so the fail-open path never triggered.

  test("an emoji before a comment does not shift the mask onto the code after it", () => {
    // Code points vs UTF-16 units. One astral character was enough to leave
    // the comment intact and blank the require() below it instead.
    const menu = Array.from({ length: 40 }, (_, index) => `  { icon: "\u{1F916}", label: "i${index}" },`).join("\n");
    withRepo(
      { files: { "src/menu.ts": `export const MENU = [\n${menu}\n];\n// Load the runtime adapter\nexport const adapter = require("${RETIRED}");\n` } },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report)).toContain(`src/menu.ts:${RETIRED}`);
      },
    );
  });

  test("an emoji before a hash comment does not shift the yaml mask either", () => {
    withRepo(
      { files: { "src/deploy.yaml": `title: "\u{1F916} \u{1F680} app"\n# retired\ninstall: ${RETIRED}\n` } },
      (report) => {
        expect(patterns(report)).toContain(`src/deploy.yaml:${RETIRED}`);
      },
    );
  });

  test("maskComments never blanks a character outside a comment, emoji or not", () => {
    // The property, stated directly: a masked character must have been a
    // comment character. Length equality alone does not catch index drift.
    const text = `const a = "\u{1F916}\u{1F680}"; // note\nconst b = "${RETIRED}";\n`;
    const masked = maskComments(text, "c-like");
    expect(masked.length).toBe(text.length);
    const commentStart = text.indexOf("//");
    const commentEnd = text.indexOf("\n", commentStart);
    for (let index = 0; index < text.length; index += 1) {
      if (masked[index] === text[index]) continue;
      expect(index).toBeGreaterThanOrEqual(commentStart);
      expect(index).toBeLessThan(commentEnd);
    }
    expect(masked).toContain(`const b = "${RETIRED}"`);
  });

  test("a glob in JSX text does not open a block comment over the imports below", () => {
    withRepo(
      { files: { "src/Help.tsx": `export const Help = () => <code>src/*</code>;\nimport { thing } from "${RETIRED}";\n/** doc */\n` } },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report)).toContain(`src/Help.tsx:${RETIRED}`);
      },
    );
  });

  test("a URL in JSX text does not comment out the rest of its line", () => {
    withRepo(
      { files: { "src/Doc.jsx": `export const Doc = () => <p>docs at https://x.invalid</p>; const m = require("${RETIRED}");\n` } },
      (report) => {
        expect(patterns(report)).toContain(`src/Doc.jsx:${RETIRED}`);
      },
    );
  });

  test("the cost of not masking JSX is a false positive, which is the acceptable direction", () => {
    withRepo({ files: { "src/Note.tsx": `// removed ${RETIRED} in 1.4.0\nexport const Note = () => <p>ok</p>;\n` } }, (report) => {
      expect(report.verdict).toBe("failed");
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

  test("a dynamic import of a computed specifier withdraws the exemption", () => {
    // The smuggle: the guard test may NAME the package, but the moment it
    // loads a computed specifier the mention stops being a mention.
    withRepo(
      { files: { "src/no-cloud-boundary.test.ts": `const runtime = "${RETIRED}";\nexport const mod = import(runtime);\n` } },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report)).toContain(`src/no-cloud-boundary.test.ts:${RETIRED}`);
      },
    );
  });

  test("a genuine guard test builds import regexes without tripping the dynamic-load rule", () => {
    // Real guard tests write `require\\s*\\(` inside a regex source. That must
    // not read as a dynamic load, or the allowlist is worthless.
    withRepo(
      {
        files: {
          "src/no-cloud-boundary.test.ts":
            `const FORBIDDEN = "${RETIRED}";\n` +
            "const RE = new RegExp(String.raw`(?:\\bfrom\\s*|\\brequire\\s*\\(\\s*)[\"']` + FORBIDDEN);\nexport { RE };\n",
        },
      },
      (report) => {
        expect(patterns(report)).toEqual([]);
      },
    );
  });

  test("config patterns are never exempt, even in the guard test", () => {
    // These have no import to look for, so "it is only a test file" was the
    // whole argument for skipping them — and the file can be re-exported.
    withRepo(
      {
        files: {
          "src/no-cloud-boundary.test.ts":
            'export const endpoint = process.env.HASNA_CLOUD_ENDPOINT;\n' +
            'export const pw = process.env.HASNA_RDS_PASSWORD;\n' +
            'export const state = ".hasna/cloud/state.json";\n',
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
        const hit = patterns(report);
        expect(hit).toContain("src/no-cloud-boundary.test.ts:HASNA_CLOUD_");
        expect(hit).toContain("src/no-cloud-boundary.test.ts:HASNA_RDS_PASSWORD");
        expect(hit).toContain("src/no-cloud-boundary.test.ts:.hasna/cloud");
      },
    );
  });

  test("the allowlist is that exact filename, not any test file", () => {
    withRepo({ files: { "src/my-boundary.test.ts": guardTest } }, (report) => {
      expect(report.verdict).toBe("failed");
    });
  });

  test("the allowlist covers module names only — runtime config in the guard test still fails", () => {
    // A guard test asserts the runtime is absent by NAMING the package. It has
    // no reason to point the shared runtime's environment at anything, and the
    // file is claimed by path alone, so exempting config would hand every repo
    // a one-file bypass for `HASNA_CLOUD_*`, `.hasna/cloud` and the shared RDS
    // credential.
    withRepo(
      {
        files: {
          "src/no-cloud-boundary.test.ts":
            'process.env.HASNA_CLOUD_URL = "https://shared.invalid";\n' +
            'const dir = ".hasna/cloud";\n' +
            "const secret = process.env.HASNA_RDS_PASSWORD;\n" +
            "export { dir, secret };\n",
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report)).toContain("src/no-cloud-boundary.test.ts:HASNA_CLOUD_");
        expect(patterns(report)).toContain("src/no-cloud-boundary.test.ts:.hasna/cloud");
        expect(patterns(report)).toContain("src/no-cloud-boundary.test.ts:HASNA_RDS_PASSWORD");
      },
    );
  });

  test("a real import in the guard test fails whatever shape the specifier takes", () => {
    // Each of these is an edge the exemption used to swallow: the specifier
    // does not START with the pattern, or the `import` keyword is not followed
    // by a space.
    for (const statement of [
      'import { registerCloudTools } from "@hasna/open-cloud";',
      'import { x } from "../vendor/cloud-mcp/index.js";',
      `import"${RETIRED}/register";`,
    ]) {
      withRepo({ files: { "src/no-cloud-boundary.test.ts": `${statement}\n${guardTest}` } }, (report) => {
        expect(report.verdict).toBe("failed");
      });
    }
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
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])).toEqual([]);
  });

  test("a LINKED package's REGISTRY devDependencies are installed, so they are edges", () => {
    // Measured shape 2: root -> file:../pkg-a, pkg-a devDepends on a registry
    // package -> that package is hoisted to the root and really is on disk.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "@hasna/linked": "file:../linked" } } },
      packages: {
        "@hasna/linked": ["@hasna/linked@file:../linked", { devDependencies: { [RETIRED]: "^0.1.41" } }],
        [`@hasna/linked/${RETIRED}`]: [`${RETIRED}@0.1.41`, {}],
      },
    });
    const edges = lockfileEdges(text, [RETIRED, "open-cloud"]);
    expect(edges?.map((edge) => edge.packageName)).toEqual([RETIRED]);
    expect(edges?.[0]?.scope).toBe("development");
  });




  test("a WORKSPACE MEMBER's transitive production edge is walked", () => {
    // A monorepo install materialises every member's dependencies. Seeding
    // only from workspaces[""] made this invisible; platform-mailery and todos
    // on this fleet are both multi-workspace.
    const text = lock({
      workspaces: {
        "": { name: "@hasna/root" },
        "packages/api": { name: "@hasna/api", dependencies: { "@hasna/wrapper": "^1" } },
      },
      packages: {
        "@hasna/wrapper": ["@hasna/wrapper@1.0.0", { dependencies: { [RETIRED]: "^0.1.41" } }],
        [RETIRED]: [`${RETIRED}@0.1.41`, {}],
      },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.map((edge) => edge.packageName)).toEqual([RETIRED]);
  });

  test("an npm: alias is followed to the package it really resolves to", () => {
    // bun writes the ALIAS as the map key and the real name in the resolution
    // id. Keying the graph only by resolved name made every alias a dead end.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { mycloud: `npm:${RETIRED}@0.1.41` } } },
      packages: { mycloud: [`${RETIRED}@0.1.41`, {}] },
    });
    const edges = lockfileEdges(text, [RETIRED, "open-cloud"]);
    expect(edges?.map((edge) => edge.packageName)).toEqual([RETIRED]);
    expect(edges?.[0]?.path).toEqual(["mycloud", RETIRED]);
  });

  test("a transitive npm: alias is followed too", () => {
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "@hasna/wrapper": "^1" } } },
      packages: {
        "@hasna/wrapper": ["@hasna/wrapper@1.0.0", { dependencies: { mycloud: `npm:${RETIRED}@0.1.41` } }],
        mycloud: [`${RETIRED}@0.1.41`, {}],
      },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.map((edge) => edge.packageName)).toEqual([RETIRED]);
  });

  test("a transitive linked resolution counts as an edge, because absence cannot be proven", () => {
    // hasna/logs' exact shape. A clean-room install of its lockfile puts no
    // @hasna/cloud on disk in a FLAT layout — but the same chain under a
    // WORKSPACE layout does install, measured on the same bun. The lockfile
    // does not say which topology applies, so absence is not claimed. This is
    // a deliberate false positive; the alternative is going quiet on every
    // monorepo. See `isLinkedResolution`.
    const text = lock({
      workspaces: { "": { name: "@hasna/logs", devDependencies: { "@hasna/agent-registry": "file:../open-agent-registry" } } },
      packages: {
        "@hasna/agent-registry": ["@hasna/agent-registry@file:../open-agent-registry", { dependencies: { pg: "^8" }, devDependencies: { [RETIRED]: "file:../open-cloud" } }],
        [`@hasna/agent-registry/${RETIRED}`]: [`${RETIRED}@file:../open-cloud`, {}],
      },
    });
    const edges = lockfileEdges(text, [RETIRED, "open-cloud"]);
    expect(edges?.map((edge) => edge.packageName)).toEqual([RETIRED]);
    expect(edges?.[0]?.scope).toBe("development");
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
    const edges = lockfileEdges(text, [RETIRED, "open-cloud"]);
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
    const edges = lockfileEdges(text, [RETIRED, "open-cloud"]);
    expect(edges?.map((edge) => edge.scope)).toEqual(["production"]);
    expect(edges?.[0]?.path).toEqual(["@hasna/wrapper", RETIRED]);
  });

  // Verbatim output of `bun install` (bun 1.3.14) in a `workspaces` repo whose
  // root declares nothing, `packages/app` depends on a linked `wrapper`, and
  // `wrapper` depends on the retired runtime. Copied from a generated file, not
  // written by hand: the root entry carrying a NAME AND NOTHING ELSE is the
  // whole point, and a hand-written fixture would have invented dependencies
  // there and hidden the defect.
  const monorepoLock = `{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "mono-root",
    },
    "packages/app": {
      "name": "app",
      "version": "1.0.0",
      "dependencies": {
        "wrapper": "file:../../wrapper",
      },
    },
  },
  "packages": {
    "app": ["app@workspace:packages/app"],

    "app/wrapper": ["wrapper@file:wrapper", { "dependencies": { "${RETIRED}": "file:../retired" } }],

    "app/wrapper/${RETIRED}": ["${RETIRED}@file:retired", {}],
  }
}`;

  test("a MONOREPO lockfile seeds from every workspace, not just the root entry", () => {
    // bun writes the root workspace with no dependency sections at all, so
    // seeding from `workspaces[""]` produced zero seeds, never entered the
    // walk, and returned [] — a clean verdict, not the null that falls back to
    // the text scan — for a tree that installs the retired runtime.
    const edges = lockfileEdges(monorepoLock, [RETIRED, "open-cloud"]);
    expect(edges?.map((edge) => edge.packageName)).toEqual([RETIRED]);
    expect(edges?.[0]?.scope).toBe("production");
    expect(edges?.[0]?.path).toEqual(["app", "wrapper", RETIRED]);
  });

  test("a monorepo transitive edge fails the whole scan end to end", () => {
    withRepo(
      {
        files: {
          "package.json": JSON.stringify({ name: "mono-root", version: "1.0.0", private: true, workspaces: ["packages/*"] }),
          "bun.lock": monorepoLock,
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report)).toContain(`bun.lock:${RETIRED}`);
      },
    );
  });

  test("a forbidden runtime surface off the schema list is still an edge", () => {
    // `cloud-mcp` is a declared forbidden runtime surface that was never added
    // to FORBIDDEN_SHARED_CLOUD_RUNTIMES. Keying the walk on that constant
    // alone meant the lockfile stopped answering for it entirely.
    withRepo(
      {
        files: {
          "bun.lock": lock({
            workspaces: { "": { name: "@hasna/subject", dependencies: { wrapper: "^1" } } },
            packages: {
              wrapper: ["wrapper@1.0.0", { dependencies: { "cloud-mcp": "^2" } }],
              "cloud-mcp": ["cloud-mcp@2.0.0", {}],
            },
          }),
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report)).toContain("bun.lock:cloud-mcp");
      },
    );
  });

  test("the retired runtime linked under another name is still the retired runtime", () => {
    // Verbatim `bun install` output for a dependency declared as
    // `"@hasna/legacy": "file:../open-cloud"`. The key is on no list; the
    // resolution target is.
    const text = `{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "@hasna/subject",
      "dependencies": {
        "@hasna/legacy": "file:../open-cloud",
      },
    },
  },
  "packages": {
    "@hasna/legacy": ["@hasna/legacy@file:../open-cloud", {}],
  }
}`;
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.map((edge) => edge.packageName)).toEqual(["open-cloud"]);
    withRepo({ files: { "bun.lock": text } }, (report) => {
      expect(report.verdict).toBe("failed");
      expect(patterns(report)).toContain("bun.lock:open-cloud");
    });
  });

  test("a name that merely contains a forbidden one is a different package", () => {
    // The substring bug this module exists to remove, in the one place the
    // alias lookup could reintroduce it.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "@hasna/cloudflare-adapter": "^1", shim: "file:../open-cloud-shim" } } },
      packages: {
        "@hasna/cloudflare-adapter": ["@hasna/cloudflare-adapter@1.0.0", {}],
        shim: ["shim@file:../open-cloud-shim", {}],
      },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])).toEqual([]);
  });

  test("runtime config in bun.lock is still read as text, because no edge can carry it", () => {
    // The walk answers package names. `.hasna/cloud` is a directory, so
    // replacing the text scan with the walk went quiet on it.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "local-config": "file:../.hasna/cloud" } } },
      packages: { "local-config": ["local-config@file:../.hasna/cloud", {}] },
    });
    withRepo({ files: { "bun.lock": text } }, (report) => {
      expect(patterns(report)).toContain("bun.lock:.hasna/cloud");
    });
  });

  test("resolutionTarget reads the link target and is silent when there is none", () => {
    expect(resolutionTarget("@hasna/legacy@file:../open-cloud")).toBe("open-cloud");
    expect(resolutionTarget("legacy@npm:open-cloud@1.0.0")).toBe("open-cloud");
    expect(resolutionTarget(`${RETIRED}@file:retired`)).toBe("retired");
    expect(resolutionTarget("commander@13.1.0")).toBeNull();
    expect(resolutionTarget("wrapper@file:wrapper")).toBeNull();
  });

  test("the root's own devDependency IS installed, and is high not critical", () => {
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", devDependencies: { [RETIRED]: "^0.1.41" } } },
      packages: { [RETIRED]: [`${RETIRED}@0.1.41`, {}] },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.map((edge) => edge.scope)).toEqual(["development"]);
  });

  test("an unreadable lockfile falls back to the text scan rather than reporting clean", () => {
    expect(lockfileEdges("{ not json", [RETIRED])).toBeNull();
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

  test("the graph is authoritative only for the packages it models", () => {
    // Findings review caught being dropped once the graph parsed successfully:
    // a legacy bin name and an env variable in a lockfile are not nodes in any
    // dependency graph, so the graph's silence must not stand for them.
    // The lockfile here PARSES — that is the whole point, since the
    // unparseable path already falls back to a full text scan.
    withRepo(
      {
        files: {
          "bun.lock": JSON.stringify({
            lockfileVersion: 1,
            workspaces: { "": { name: "@hasna/subject", dependencies: {} } },
            packages: {},
            scripts: { postinstall: "HASNA_CLOUD_URL=x cloud-mcp setup" },
          }),
        },
      },
      (report) => {
        expect(lockfileEdges(JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "@hasna/subject" } }, packages: {} }), [RETIRED])).toEqual([]);
        const hit = patterns(report);
        // Package names are the graph's business; a config key is nobody's edge.
        expect(hit).toContain("bun.lock:HASNA_CLOUD_");
        expect(report.verdict).toBe("failed");
      },
    );
  });

  test("a symbol in a file with no imports to read is matched on its name", () => {
    // Import analysis needs code. A lockfile has no import statements, so
    // requiring a binding there means the name can never be evidence — which
    // silently drops the check rather than scoping it.
    withRepo({ files: { "yarn.lock": 'x "registerCloudTools"\n' } }, (report) => {
      expect(patterns(report)).toContain("yarn.lock:registerCloudTools");
    });
    // ...and in real code the binding rule still applies, so a local
    // definition of the same name stays clean.
    withRepo({ files: { "src/local.ts": "export function registerCloudTools() {}\n" } }, (report) => {
      expect(patterns(report)).toEqual([]);
    });
  });

  test("an unreachable packages{} entry is not an edge, because nothing installs it", () => {
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: {} } },
      packages: { [RETIRED]: [`${RETIRED}@0.1.41`, {}] },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])).toEqual([]);
  });

  test("a cyclic lockfile terminates", () => {
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { a: "^1" } } },
      packages: {
        a: ["a@1.0.0", { dependencies: { b: "^1" } }],
        b: ["b@1.0.0", { dependencies: { a: "^1", [RETIRED]: "^1" } }],
        [RETIRED]: [`${RETIRED}@0.1.41`, {}],
      },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.map((edge) => edge.packageName)).toEqual([RETIRED]);
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

  test("importsModule reads the whole specifier, not just its first segment", () => {
    // A re-scoped publish and a vendored copy are the same edge; anchoring the
    // name at the opening quote saw neither.
    expect(importsModule('import { a } from "@hasna/open-cloud";', "open-cloud")).toBe(true);
    expect(importsModule('import { a } from "../vendor/cloud-mcp/index.js";', "cloud-mcp")).toBe(true);
    expect(importsModule(`import"${RETIRED}/register";`, RETIRED)).toBe(true);
    // A path SEGMENT, not a substring: these are different packages.
    expect(importsModule('import { a } from "open-cloudy";', "open-cloud")).toBe(false);
    expect(importsModule('import { a } from "@acme/my-open-cloud";', "open-cloud")).toBe(false);
  });

  test("importedBindings follows the same specifier rule as importsModule", () => {
    expect(importedBindings('import { registerCloudTools } from "@hasna/open-cloud";', "open-cloud")).toEqual(
      new Set(["registerCloudTools"]),
    );
    expect(importedBindings('import { registerCloudTools } from "./cloud-tools.js";', "open-cloud")).toEqual(new Set());
  });

  test("importedBindings resolves default, named, renamed and namespace clauses", () => {
    expect(importedBindings(`import a, { b, c as d } from "${RETIRED}";`, RETIRED)).toEqual(new Set(["b", "d", "a"]));
    expect(importedBindings(`import * as ns from "${RETIRED}";`, RETIRED)).toEqual(new Set(["ns"]));
    expect(importedBindings(`import { x } from "./local.js";`, RETIRED)).toEqual(new Set());
  });
});
