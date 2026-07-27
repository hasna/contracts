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
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanNoCloudTarget } from "../src/no-cloud";
import {
  isLinkedResolution,
  lockfileEdges,
  lockfileWalk,
  manifestEdges,
  nameFromResolutionId,
  parseLooseJson,
  resolutionTarget
} from "../src/dependency-edge";
import {
  importedBindings,
  importsModule,
  inlineDataNodes,
  inlineDataRegions,
  loadCallMentions,
  maskComments,
  maskCommentsForPath,
  mentionsCannotLoad
} from "../src/source-text";

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

  test("a `/` after `if (…)` opens a regex, so a `//` inside its character class is not a comment", () => {
    // The third false negative of this kind. `regexCanStart` said "after `)`,
    // division", the lexer walked into the regex body, met the `//` inside
    // `[//]`, and blanked the rest of the line — taking a live require() of the
    // retired runtime with it. Executable code, `exit 0` under 0.8.1.
    const source = `const s = "q";\nif (s) /a[//]b/.test(s); const m = require("${RETIRED}");\nexport { m };\n`;
    withRepo({ files: { "src/index.ts": source } }, (report) => {
      expect(report.verdict).toBe("failed");
      expect(patterns(report)).toContain(`src/index.ts:${RETIRED}`);
    });
    // At the masker, so the rule is pinned and not just its consequence.
    expect(maskCommentsForPath(source, "src/index.ts")).toContain(`require("${RETIRED}")`);
    for (const head of ["if (s)", "while (s)", "for (const x of [s])", "switch (s)", "catch (s)"]) {
      const text = `${head} /a[//]b/.test(s); const m = require("${RETIRED}");\n`;
      expect(maskCommentsForPath(text, "src/a.ts"), head).toContain(`require("${RETIRED}")`);
    }
    // ...and a `/` after a CALL is still division, so a real line comment after
    // one is still masked. The fix must not buy the false negative back as a
    // blanket "always a regex".
    expect(maskCommentsForPath(`const n = f(1) / 2; // gone ${RETIRED}\n`, "src/a.ts")).not.toContain(`gone ${RETIRED}`);
  });

  test("a slash the lexer cannot classify discards the mask instead of blanking live code", () => {
    // The fail-open guarantee, at the one place it was not firing. Where the
    // two readings of a `/` mask DIFFERENT characters and nothing in the token
    // stream settles which is right, the mask is discarded and the caller scans
    // raw text — noisy, never blind.
    for (const source of [
      // A `)` with no `(` behind it: a parse we do not have.
      `foo) /a[//]b/; const m = require("${RETIRED}");\n`,
      // A `)` that closed a CALL, where reading the slash as a regex would
      // swallow a comment opener. Division is the better guess and still not
      // good enough to blank on.
      `const n = f(1) /a[//]b/; const m = require("${RETIRED}");\n`,
    ]) {
      expect(maskCommentsForPath(source, "src/a.ts"), source).toContain(RETIRED);
      withRepo({ files: { "src/a.ts": source } }, (report) => {
        expect(report.verdict, source).toBe("failed");
      });
    }
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
    // loads a computed specifier the mention stops being a mention. A template
    // literal is the same move with different punctuation, so it withdraws the
    // exemption on the same terms — reading the identifier and not the backtick
    // left the interpolated form loading the runtime against a clean scan.
    for (const load of ["import(runtime)", "import(`${runtime}`)", "require(`${runtime}/register`)"]) {
      withRepo(
        { files: { "src/no-cloud-boundary.test.ts": `const runtime = "${RETIRED}";\nexport const mod = ${load};\n` } },
        (report) => {
          expect(report.verdict).toBe("failed");
          expect(patterns(report)).toContain(`src/no-cloud-boundary.test.ts:${RETIRED}`);
        },
      );
    }
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

  test("a computed BACKTICK specifier withdraws the exemption", () => {
    // Isolates the exemption rule: the specifier is computed so importsModule
    // does not fire, and the only thing between the mention and a finding is
    // whether a backtick counts as "not a simple string literal".
    withRepo(
      {
        files: {
          "src/no-cloud-boundary.test.ts":
            `const RETIRED_NAME = "${RETIRED}";\nconst m = await import(\`\${prefix}\`);\nexport { RETIRED_NAME, m };\n`,
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report)).toContain(`src/no-cloud-boundary.test.ts:${RETIRED}`);
      },
    );
  });

  test("a concatenated specifier withdraws it as well", () => {
    withRepo(
      { files: { "src/no-cloud-boundary.test.ts": `const m = await import("${RETIRED}" + suffix);\nexport { m };\n` } },
      (report) => {
        expect(report.verdict).toBe("failed");
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

  // Every case below was proved to LOAD the package and to scan `exit 0`
  // under 0.8.1. The withdrawal test recognised `import(` and `require(` and
  // nothing else, so a resolver API was read as a mention and erased. Tests for
  // two shapes are what let the other five through, which is why these assert
  // the shapes AND the rule that generalises them.

  test("a resolver API in the guard test is a load, not a mention", () => {
    for (const load of [
      'import { createRequire } from "node:module";\nconst load = createRequire(import.meta.url);\n' +
        `export const live = load("${RETIRED}");`,
      `export const resolved = Bun.resolveSync("${RETIRED}", import.meta.dir);`,
      `export const p = require.resolve("${RETIRED}");`,
      `export const w = new Worker(new URL("${RETIRED}/worker.js", import.meta.url).href);`,
      `export const r = import.meta.resolve("${RETIRED}");`,
    ]) {
      withRepo({ files: { "src/no-cloud-boundary.test.ts": `${load}\n` } }, (report) => {
        expect(report.verdict, load).toBe("failed");
        expect(patterns(report), load).toContain(`src/no-cloud-boundary.test.ts:${RETIRED}`);
      });
    }
  });

  test("an unrecognised callee withdraws the exemption, so the next spelling fails closed", () => {
    // The property, not the enumeration. `smuggle` is on no denylist anywhere;
    // it is a call, its argument is the package name, and that is enough.
    withRepo({ files: { "src/no-cloud-boundary.test.ts": `export const m = smuggle("${RETIRED}");\n` } }, (report) => {
      expect(report.verdict).toBe("failed");
    });
  });

  test("mentionsCannotLoad reads the position, and fails closed on anything it cannot", () => {
    const path = "src/no-cloud-boundary.test.ts";
    // Inert: the shapes the mandated guard test actually writes.
    for (const source of [
      `const FORBIDDEN = "${RETIRED}";`,
      `const FORBIDDEN = ["${RETIRED}", "open-cloud"];`,
      `const map = { retired: "${RETIRED}" };`,
      `expect(pkg.dependencies).not.toContain("${RETIRED}");`,
      `test("${RETIRED} is absent", () => {});`,
      `const RE = new RegExp(String.raw\`["']${RETIRED}["']\`);`,
      // Path building. Turning a path into a module needs a resolver, and the
      // capability check answers for that independently.
      `existsSync(join(root, "node_modules", "${RETIRED}"));`,
      `if ("${RETIRED}" in pkg.dependencies) fail();`,
    ]) {
      expect(mentionsCannotLoad(source, path, RETIRED), source).toBe(true);
    }
    // Not inert: every one of these resolves the argument.
    for (const source of [
      `load("${RETIRED}");`,
      `Bun.resolveSync("${RETIRED}", dir);`,
      `require.resolve("${RETIRED}");`,
      `new URL("${RETIRED}/worker.js", import.meta.url);`,
      `const m = await import("${RETIRED}");`,
      // Immediately invoked, and indexed: the callee has no name to allowlist,
      // which is exactly why an unnameable one can never be inert.
      `createRequire(import.meta.url)("${RETIRED}");`,
      `loaders["cjs"]("${RETIRED}");`,
    ]) {
      expect(mentionsCannotLoad(source, path, RETIRED), source).toBe(false);
    }
    // A comment is prose either way.
    expect(mentionsCannotLoad(`// dropped ${RETIRED} in 1.4.0\nexport const ok = true;\n`, path, RETIRED)).toBe(true);
    // An interpolated template chunk is a specifier under construction.
    expect(mentionsCannotLoad("const s = `${prefix}" + RETIRED + "`;", path, RETIRED)).toBe(false);
    // JSX is not lexable without a real parser, so it cannot prove anything.
    expect(mentionsCannotLoad(`const F = "${RETIRED}";`, "src/no-cloud-boundary.test.tsx", RETIRED)).toBe(false);
  });

  test("module-resolution capability withdraws the exemption on its own", () => {
    // The audit reads where the NAME sits. This reads whether the file can
    // resolve at all, because the name can be assembled or escaped and never
    // reach the audit — `"@hasna/" + "cloud"` is exactly that.
    withRepo(
      {
        files: {
          "src/no-cloud-boundary.test.ts":
            `const FORBIDDEN = "${RETIRED}";\n` +
            'import { createRequire } from "node:module";\n' +
            'export const live = createRequire(import.meta.url)("@hasna/" + "cloud");\n',
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
      },
    );
  });

  test("the exemption is claimable at ONE path, not at the filename anywhere", () => {
    // 0.8.1 honoured this filename at any depth, which handed the exemption to
    // `dist/` — shipped build output — to the repo root, and to `config/`. All
    // four of these carry a real `createRequire` load.
    const load =
      'import { createRequire } from "node:module";\n' +
      `const load = createRequire(import.meta.url);\nexport const live = load("${RETIRED}");\n`;
    for (const path of [
      "src/deep/nested/no-cloud-boundary.test.ts",
      "dist/no-cloud-boundary.test.js",
      "no-cloud-boundary.test.ts",
      "config/no-cloud-boundary.test.ts",
    ]) {
      withRepo({ files: { [path]: load } }, (report) => {
        expect(report.verdict, path).toBe("failed");
      });
    }
    // And a plain MENTION at those paths is a finding too, because the file has
    // no standing there at all.
    for (const path of ["dist/no-cloud-boundary.test.js", "no-cloud-boundary.test.ts"]) {
      withRepo({ files: { [path]: `const FORBIDDEN = "${RETIRED}";\nexport { FORBIDDEN };\n` } }, (report) => {
        expect(report.verdict, path).toBe("failed");
      });
    }
  });

  test("the mutation control: one appended load turns a passing tree into a failing one", () => {
    // The pair that IS the gate. A negative control that fails on a
    // `package.json` dependency exercises none of the source-level logic, so it
    // reads two-sided while being one-sided. This mutates the guard test of an
    // otherwise clean tree and nothing else.
    const clean = `const FORBIDDEN_PACKAGE = "${RETIRED}";\nexport { FORBIDDEN_PACKAGE };\n`;
    withRepo({ files: { "src/no-cloud-boundary.test.ts": clean } }, (report) => {
      expect(patterns(report)).toEqual([]);
      expect(report.verdict).toBe("passed");
    });
    withRepo(
      {
        files: {
          "src/no-cloud-boundary.test.ts":
            `${clean}import { createRequire } from "node:module";\n` +
            `export const live = createRequire(import.meta.url)("${RETIRED}");\n`,
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report)).toContain(`src/no-cloud-boundary.test.ts:${RETIRED}`);
      },
    );
  });

  test("a real import in the guard test fails whatever shape the specifier takes", () => {
    // Each of these is an edge the exemption used to swallow: the specifier
    // does not START with the pattern, the `import` keyword is not followed by
    // a space, or the specifier is quoted with backticks rather than the two
    // quotes the specifier pattern used to know about. The last shape is the
    // one that mattered most: it is a working load of the retired runtime that
    // scanned clean, which is the gate going blind rather than merely noisy.
    for (const statement of [
      'import { registerCloudTools } from "@hasna/open-cloud";',
      'import { x } from "../vendor/cloud-mcp/index.js";',
      `import"${RETIRED}/register";`,
      `const mod = await import(\`${RETIRED}\`);`,
      `const legacy = require(\`${RETIRED}/register\`);`,
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

  test("a HOISTED install does not materialise a transitive linked resolution", () => {
    // hasna/logs, exactly. Single workspace entry means a hoisted layout, and
    // measured on bun 1.3.14 a transitive file:/link: resolution lands nowhere
    // there — dev edge and production edge alike. A clean-room install of logs'
    // own lockfile has no @hasna/cloud on disk.
    const text = lock({
      workspaces: { "": { name: "@hasna/logs", devDependencies: { "@hasna/agent-registry": "file:../open-agent-registry" } } },
      packages: {
        "@hasna/agent-registry": ["@hasna/agent-registry@file:../open-agent-registry", { dependencies: { pg: "^8" }, devDependencies: { [RETIRED]: "file:../open-cloud" } }],
        [`@hasna/agent-registry/${RETIRED}`]: [`${RETIRED}@file:../open-cloud`, {}],
      },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])).toEqual([]);
  });

  test("an ISOLATED install DOES, so a monorepo still reports the edge", () => {
    // More than one workspace entry means node_modules/.bun/, where the same
    // chain IS installed. Skipping it there would be a false negative on every
    // monorepo — which is what makes the workspace count the discriminator
    // rather than a blanket rule in either direction.
    const text = lock({
      workspaces: { "": { name: "mono-root" }, "packages/app": { name: "app", dependencies: { wrapper: "file:../../wrapper" } } },
      packages: {
        app: ["app@workspace:packages/app"],
        "app/wrapper": ["wrapper@file:wrapper", { dependencies: { [RETIRED]: "file:../retired" } }],
        [`app/wrapper/${RETIRED}`]: [`${RETIRED}@file:retired`, {}],
      },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.map((edge) => edge.packageName)).toEqual([RETIRED]);
  });

  test("the root's own linked dependency is installed in either layout", () => {
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { [RETIRED]: "file:../open-cloud" } } },
      packages: { [RETIRED]: [`${RETIRED}@file:../open-cloud`, {}] },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.[0]?.scope).toBe("production");
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

  test("the lockfile's own top-level install sections are edges", () => {
    // A bun install with an overrides block writes it at the TOP LEVEL of
    // bun.lock, outside every workspace record. Reading only `workspaces` left
    // it invisible, and because the walk still returned a list rather than null
    // the miss was signed off as clean. Confirmed against a real install.
    for (const [label, body] of [
      ["overrides", { overrides: { "open-cloud": "1.0.0" } }],
      ["trustedDependencies", { trustedDependencies: [RETIRED] }],
      ["patchedDependencies", { patchedDependencies: { [`${RETIRED}@0.1.41`]: "patches/x.patch" } }],
    ] as const) {
      const text = JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "@hasna/subject" } }, ...body, packages: {} });
      expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.length, label).toBeGreaterThan(0);
    }
  });

  test("a node's bundleDependencies are edges, the same as the manifest's", () => {
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { w: "^1" } } },
      packages: { w: ["w@1.0.0", { bundleDependencies: [RETIRED] }] },
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

  // The bun.lock text fallback, which module patterns lost when the graph walk
  // took over and config patterns kept. Both pins below are real installs that
  // name the package in plain text and scanned clean under 0.8.1.

  test("a NESTED overrides pin in bun.lock is an edge", () => {
    // npm nests one level per parent: `{ "left-pad": { "@hasna/cloud": "…" } }`.
    // `Object.keys` one level deep returns `left-pad` and compares it to
    // nothing.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "left-pad": "^1.3.0" } } },
      overrides: { "left-pad": { [RETIRED]: "0.1.41" } },
      packages: { "left-pad": ["left-pad@1.3.0", {}], [RETIRED]: [`${RETIRED}@0.1.41`, {}] },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.map((edge) => edge.packageName)).toEqual([RETIRED]);
    withRepo({ files: { "bun.lock": text } }, (report) => {
      expect(report.verdict).toBe("failed");
      expect(patterns(report)).toContain(`bun.lock:${RETIRED}`);
    });
  });

  test("a PATH-KEYED resolutions pin in bun.lock is an edge", () => {
    // yarn writes the whole path as one key, and a scoped name is spelled with
    // the same `/` that separates it.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "left-pad": "^1.3.0" } } },
      resolutions: { [`left-pad/${RETIRED}`]: "0.1.41" },
      packages: { "left-pad": ["left-pad@1.3.0", {}], [RETIRED]: [`${RETIRED}@0.1.41`, {}] },
    });
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])?.map((edge) => edge.packageName)).toEqual([RETIRED]);
    withRepo({ files: { "bun.lock": text } }, (report) => {
      expect(report.verdict).toBe("failed");
    });
  });

  test("pin keys are split on the path, the range and the glob, but not at the scope sigil", () => {
    const cases: Array<[string, string[]]> = [
      [RETIRED, [RETIRED]],
      [`left-pad/${RETIRED}`, ["left-pad", RETIRED]],
      [`left-pad@^1.3.0/${RETIRED}`, ["left-pad", RETIRED]],
      [`**/${RETIRED}`, [RETIRED]],
      [`${RETIRED}@0.1.41`, [RETIRED]],
    ];
    for (const [key, expected] of cases) {
      const edges = manifestEdges({ resolutions: { [key]: "1" } }, expected).map((edge) => edge.packageName);
      expect(new Set(edges), key).toEqual(new Set(expected));
    }
  });

  test("a module name bun.lock spells out that the walk never reached is still reported", () => {
    // The graph is authoritative for what it DECIDED, not for what it never
    // looked at. A stale `packages` entry names the retired runtime in plain
    // text; the walk returns a list, and a list read as a clean tree.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "left-pad": "^1.3.0" } } },
      packages: { "left-pad": ["left-pad@1.3.0", {}], [RETIRED]: [`${RETIRED}@0.1.41`, {}] },
    });
    // The walk itself still reports no EDGE — that part is correct and unchanged.
    expect(lockfileEdges(text, [RETIRED, "open-cloud"])).toEqual([]);
    withRepo({ files: { "bun.lock": text } }, (report) => {
      expect(report.verdict).toBe("failed");
      expect(patterns(report)).toContain(`bun.lock:${RETIRED}`);
    });
  });

  test("the MEASURED hoisted-layout clearance survives the text fallback", () => {
    // `hasna/logs`, and the one thing the fallback must not undo. A transitive
    // `file:` resolution in a single-workspace lockfile lands nowhere on disk —
    // probed on bun 1.3.14, `require()` of it fails. The name is in the text
    // twice, and the walk says it decided rather than skipped, so the fallback
    // stays quiet. Both spellings: the key's name AND the name it resolves to.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "pkg-a": "file:../pkg-a" } } },
      packages: {
        "pkg-a": ["pkg-a@file:../pkg-a", { dependencies: { [RETIRED]: "file:../open-cloud" } }],
        [RETIRED]: [`${RETIRED}@file:../open-cloud`, {}],
      },
    });
    const walk = lockfileWalk(text, [RETIRED, "open-cloud"]);
    expect(walk?.edges).toEqual([]);
    expect(new Set(walk?.clearedByLayout)).toEqual(new Set([RETIRED, "open-cloud"]));
    withRepo({ files: { "bun.lock": text } }, (report) => {
      expect(patterns(report)).toEqual([]);
      expect(report.verdict).toBe("passed");
    });
  });

  test("the text fallback is a lockfile TOKEN, not the substring the walk replaced", () => {
    // The one way this fallback could reintroduce the bug this module exists to
    // remove. `@hasna/cloudflare-adapter` and `../open-cloud-shim` are different
    // packages and must stay clean.
    const text = lock({
      workspaces: { "": { name: "@hasna/subject", dependencies: { "@hasna/cloudflare-adapter": "^1", shim: "file:../open-cloud-shim" } } },
      packages: {
        "@hasna/cloudflare-adapter": ["@hasna/cloudflare-adapter@1.0.0", {}],
        shim: ["shim@file:../open-cloud-shim", {}],
      },
    });
    withRepo({ files: { "bun.lock": text } }, (report) => {
      expect(patterns(report)).toEqual([]);
      expect(report.verdict).toBe("passed");
    });
  });
});

describe("no-cloud gate: what a passed verdict does NOT claim", () => {
  // Pinned, not merely documented. A `verdict: passed` is a statement about the
  // shapes this scan reads, and it is used to certify a twelve-repo remediation
  // — so the boundary of the claim has to be asserted somewhere that breaks when
  // it moves. Every case below is a REAL reference the scan does not report.
  // None of them is a defect introduced by the guard-test, masking or lockfile
  // fixes; all of them bound what those fixes prove.

  test("a path with no SOURCE_DIRS segment is not read at all", () => {
    for (const path of ["app/api/route.ts", "packages/core/index.ts", "apps/web/main.ts"]) {
      withRepo({ files: { [path]: `import { a } from "${RETIRED}";\n` } }, (report) => {
        expect(report.verdict, path).toBe("passed");
      });
    }
  });

  test("`tests/` is skipped, and `test/` singular is unscanned for a different reason", () => {
    // `tests` is in SKIP_DIRS. `test` is in NEITHER set, so it fails the
    // SOURCE_DIRS requirement instead — two routes to the same blind spot, and
    // two real guard tests on this fleet live at `test/no-cloud-boundary.test.ts`.
    for (const path of ["tests/a.ts", "test/a.ts"]) {
      withRepo({ files: { [path]: `import { a } from "${RETIRED}";\n` } }, (report) => {
        expect(report.verdict, path).toBe("passed");
      });
    }
  });

  test("an on-disk node_modules copy with no manifest entry is not seen", () => {
    withRepo(
      { files: { "node_modules/@hasna/cloud/package.json": JSON.stringify({ name: RETIRED, version: "0.1.41" }) } },
      (report) => {
        expect(report.verdict).toBe("passed");
      },
    );
  });

  test("Dockerfile, terraform and an extensionless bin script are outside the extension filter", () => {
    withRepo(
      {
        files: {
          Dockerfile: `RUN bun add ${RETIRED}\n`,
          "infra/main.tf": `variable "pkg" { default = "${RETIRED}" }\n`,
          "bin/deploy": `#!/bin/sh\nbun add ${RETIRED}\n`,
        },
      },
      (report) => {
        expect(report.verdict).toBe("passed");
      },
    );
  });

  test("an assembled or escaped specifier is not text-matchable", () => {
    for (const source of [
      `export const m = require("@hasna/" + "cloud");`,
      'export const m = require("\\u0040hasna/cloud");',
      'export const m = require("\\x40hasna/cloud");',
    ]) {
      withRepo({ files: { "src/a.ts": `${source}\n` } }, (report) => {
        expect(report.verdict, source).toBe("passed");
      });
    }
  });

  test("a git+ssh dependency installing under the package name is not matchable either", () => {
    withRepo(
      {
        files: {
          "package.json": JSON.stringify({
            name: "@hasna/subject",
            version: "1.0.0",
            dependencies: { retired: "git+ssh://git@example.invalid/legacy.git" },
          }),
        },
      },
      (report) => {
        expect(report.verdict).toBe("passed");
      },
    );
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
    // Backtick specifiers are real imports. End to end this is invisible — the
    // bare-mention fallback reports the same file either way — so the matcher
    // has to be asserted directly or the rule is untested.
    expect(importsModule("import x from `" + RETIRED + "`;", RETIRED)).toBe(true);
    expect(importsModule("const m = await import(`" + RETIRED + "/register`);", RETIRED)).toBe(true);
    expect(importsModule("const m = require(`" + RETIRED + "`);", RETIRED)).toBe(true);
  });

  test("a template-literal specifier is a specifier", () => {
    // A backtick is the third quote, and the loader treats it as one. Reading
    // only two of the three said "no import here" about a working load.
    for (const form of [
      `import x from \`${RETIRED}\`;`,
      `const m = await import(\`${RETIRED}\`);`,
      `const m = require(\`${RETIRED}/register\`);`,
    ]) {
      expect(importsModule(form, RETIRED)).toBe(true);
    }
    // Still a name in a string, not an edge.
    expect(importsModule(`const name = \`${RETIRED}\`;`, RETIRED)).toBe(false);
    // And still a path SEGMENT: neighbouring names stay out.
    expect(importsModule("import { a } from `open-cloudy`;", "open-cloud")).toBe(false);
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

// ---------------------------------------------------------------------------
// The scanner's own declaration, inlined into somebody else's build output.
//
// Every test here is a pair. The false positive this fixes and the true
// positives it must not touch are the SAME code path — a bare occurrence in
// build output — so a one-sided test would pass while a credential detector was
// off. That is precisely how the first two attempts at this failed review.
//
// The declaration text below is written out rather than imported. It is the
// signature the scanner recognises, so pinning it here is the point: change a
// message in `RUNTIME_PATTERNS` and these fail, which is the correct signal that
// the recognition signature moved.
// ---------------------------------------------------------------------------
describe("no-cloud gate: this package's inlined declaration is attributed, not exempted", () => {
  const OTHER = ["open-", "cloud"].join("");
  const LEGACY_MCP = ["cloud-", "mcp"].join("");
  const RDS = ["HASNA_RDS", "_PASSWORD"].join("");
  const CLOUD_ENV = ["HASNA_CLOUD", "_"].join("");
  const DOTDIR = [".hasna/", "cloud"].join("");

  /** What `bun build` emits when it inlines this package: the exact two shapes. */
  const DENYLIST_ARRAY = `var FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["${RETIRED}", "${OTHER}"];`;
  const PATTERN_ROWS =
    "var RUNTIME_PATTERNS = [\n" +
    `  { pattern: "${RETIRED}", kind: "module", message: "Shared ${RETIRED} runtime reference is forbidden" },\n` +
    `  { pattern: "${OTHER}", kind: "module", message: "Shared ${OTHER} runtime reference is forbidden" },\n` +
    `  { pattern: "${LEGACY_MCP}", kind: "module", message: "Legacy ${LEGACY_MCP} runtime surface is forbidden" },\n` +
    '  { pattern: "registerCloudTools", kind: "symbol", message: "Legacy registerCloudTools runtime surface is forbidden" },\n' +
    '  { pattern: "registerCloudCommands", kind: "symbol", message: "Legacy registerCloudCommands runtime surface is forbidden" },\n' +
    `  { pattern: "${DOTDIR}", kind: "config", checkKind: "runtime_config", message: "Legacy ${DOTDIR} runtime config is forbidden" },\n` +
    `  { pattern: "${CLOUD_ENV}", kind: "config", message: "Shared ${CLOUD_ENV}* runtime config is forbidden" },\n` +
    `  { pattern: "${RDS}", kind: "config", message: "Legacy shared RDS credential config is forbidden" }\n` +
    "];";
  const INLINED_DECLARATION = `${DENYLIST_ARRAY}\n${PATTERN_ROWS}\nexport { FORBIDDEN_SHARED_CLOUD_RUNTIMES, RUNTIME_PATTERNS };\n`;

  /** Scan a fixture as a PACKED TARBALL, where build-output findings are critical. */
  function withTarball(files: Record<string, string>, assert: (verdict: ReturnType<typeof scanNoCloudTarget>) => void) {
    const dir = mkdtempSync(join(tmpdir(), "no-cloud-pack-"));
    try {
      for (const [path, text] of Object.entries(files)) {
        const full = join(dir, "package", path);
        mkdirSync(join(full, ".."), { recursive: true });
        writeFileSync(full, text);
      }
      const archive = join(dir, "fixture.tgz");
      const packed = Bun.spawnSync(["tar", "-czf", archive, "-C", dir, "package"]);
      expect(packed.exitCode, new TextDecoder().decode(packed.stderr)).toBe(0);
      assert(scanNoCloudTarget(archive));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  test("PROOF: a consumer bundling this package without --external passes", () => {
    // The bug. Six findings in one `dist/index.js`, none of them removable by
    // the consumer, and `open-cloud` reported against a repo that never used it.
    withRepo({ name: "iapp-consumer", files: { "dist/index.js": INLINED_DECLARATION } }, (report) => {
      expect(patterns(report)).toEqual([]);
      expect(report.verdict).toBe("passed");
    });
  });

  test("PROOF: the same bundle plus one real load fails, in the __require form", () => {
    // The negative half, and the shape that matters: `bun build --external`
    // compiles `require("x")` to `__require("x")`. A matcher anchored on `\b`
    // cannot see it, so this must be recognised as an IMPORT, not merely as a
    // bare name that happened to survive.
    withRepo(
      { name: "iapp-consumer", files: { "dist/index.js": `${INLINED_DECLARATION}var live = __require("${RETIRED}");\n` } },
      (report) => {
        expect(report.verdict).toBe("failed");
        const finding = report.findings.find((entry) => entry.pattern === RETIRED);
        expect(finding?.message).toContain("module import");
      },
    );
  });

  test("PROOF: a planted credential in build output is still critical in a dist-only tarball", () => {
    // The measurement the first attempt failed. `files: ["dist"]` keeps the
    // source out of the tarball, so the compiled bare occurrence is the ONLY
    // detector these three config patterns have.
    withTarball(
      {
        "package.json": JSON.stringify({ name: "iapp-leaky", version: "1.0.0", files: ["dist"] }),
        "dist/index.js": "var config = {\n  password: process.env." + RDS + ",\n  endpoint: process.env." + CLOUD_ENV + "API_URL\n};\nexport { config };\n",
      },
      (report) => {
        expect(report.scanMode).toBe("packed_artifact");
        const critical = report.findings.filter((entry) => entry.severity === "critical").map((entry) => entry.pattern);
        expect(critical.sort()).toEqual([CLOUD_ENV, RDS]);
        expect(report.verdict).toBe("failed");
      },
    );
  });

  test("PROOF: a credential sitting NEXT TO the inlined declaration is still reported", () => {
    // Per-occurrence, not per-file. Both previous attempts returned early for
    // the whole file, which is what took the credential detectors with them.
    withTarball(
      {
        "package.json": JSON.stringify({ name: "iapp-consumer", version: "1.0.0", files: ["dist"] }),
        "dist/index.js": `${INLINED_DECLARATION}var leaked = process.env.${RDS};\nexport { leaked };\n`,
      },
      (report) => {
        expect(report.findings.map((entry) => entry.pattern)).toEqual([RDS]);
        expect(report.findings[0]?.severity).toBe("critical");
      },
    );
  });

  test("a row cannot pair a pattern with a message that is not that pattern's own", () => {
    // The hole in matching the SHAPE of a row rather than its content: a
    // three-key object would otherwise let any repo silence any pattern, and
    // carry an arbitrary string in the `message` slot while doing it.
    for (const row of [
      // An invented message.
      `var x = [{ pattern: "${RDS}", kind: "config", message: "nothing to see" }];`,
      // Another entry's message. (Spelled without naming a second pattern, or
      // the fixture would report that one too and say nothing about this rule.)
      `var x = [{ pattern: "${RDS}", kind: "config", message: "Legacy cloud-m" + "cp runtime surface is forbidden" }];`,
      // Its own message, under the wrong `kind`.
      `var x = [{ pattern: "${RDS}", kind: "module", message: "Legacy shared RDS credential config is forbidden" }];`,
      // Its own message and kind, but as a two-key row with no `pattern` key.
      `var x = [{ kind: "config", message: "Legacy shared RDS credential config is forbidden", name: "${RDS}" }];`,
    ]) {
      withRepo({ name: "iapp-consumer", files: { "dist/index.js": `${row}\nexport { x };\n` } }, (report) => {
        expect(patterns(report), row).toEqual([`dist/index.js:${RDS}`]);
      });
    }
    // And the row that IS this table's own row is attributed.
    withRepo(
      {
        name: "iapp-consumer",
        files: {
          "dist/index.js":
            `var x = [{ pattern: "${RDS}", kind: "config", message: "Legacy shared RDS credential config is forbidden" }];\nexport { x };\n`,
        },
      },
      (report) => {
        expect(patterns(report)).toEqual([]);
      },
    );
  });

  test("the denylist array must equal the constant element for element", () => {
    // A longer array, a shorter one, and a reordered one are all somebody
    // else's data. Only the constant this package declares is attributable.
    for (const array of [
      `["${RETIRED}", "${OTHER}", "left-pad"]`,
      `["${RETIRED}"]`,
      `["${OTHER}", "${RETIRED}"]`,
    ]) {
      withRepo({ name: "iapp-consumer", files: { "dist/index.js": `var deny = ${array};\nexport { deny };\n` } }, (report) => {
        expect(report.verdict, array).toBe("failed");
      });
    }
    withRepo(
      { name: "iapp-consumer", files: { "dist/index.js": `var deny = ["${RETIRED}", "${OTHER}"];\nexport { deny };\n` } },
      (report) => {
        expect(report.verdict).toBe("passed");
      },
    );
  });

  test("a copy of the denylist read in place is a load, not a declaration", () => {
    // `__require(["a","b"][0])` is a real load whose specifier never appears in
    // specifier position. Indexing, calling and member access all consume the
    // collection where it stands.
    for (const source of [
      `var m = __require(["${RETIRED}", "${OTHER}"][0]);`,
      `var m = ["${RETIRED}", "${OTHER}"].map((n) => __require(n));`,
      `var m = load(["${RETIRED}", "${OTHER}"]);`,
    ]) {
      withRepo({ name: "iapp-consumer", files: { "dist/index.js": `${source}\nexport { m };\n` } }, (report) => {
        expect(report.verdict, source).toBe("failed");
      });
    }
  });

  test("a copy of the denylist a load call names is a laundering route, not a declaration", () => {
    // Stored under a name, then indexed through the name. The collection is in
    // data position and nothing reads it on the spot, so only the name links the
    // two — which is why the name is checked.
    withRepo(
      {
        name: "iapp-consumer",
        files: { "dist/index.js": `var DENY = ["${RETIRED}", "${OTHER}"];\nvar m = __require(DENY[0]);\nexport { m };\n` },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
      },
    );
    // The pair: the same declaration with no load call naming it.
    withRepo(
      {
        name: "iapp-consumer",
        files: { "dist/index.js": `var DENY = ["${RETIRED}", "${OTHER}"];\nvar m = DENY.length;\nexport { m };\n` },
      },
      (report) => {
        expect(report.verdict).toBe("passed");
      },
    );
    // A NESTED CALL IN AN EARLIER ARGUMENT is still the same load call. The
    // argument capture used to stop at the first `)`, so `norm(base)` was the
    // whole of what the bound-name test ever saw and the declaration below it
    // was attributed and blanked — with the array in inert position, the name is
    // the only thing standing between it and a clean scan.
    withRepo(
      {
        name: "iapp-consumer",
        files: {
          "dist/index.js": `var DENY = ["${RETIRED}", "${OTHER}"];\nvar m = __require(norm(base), DENY[0]);\nexport { m };\n`,
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report).sort()).toEqual([`dist/index.js:${RETIRED}`, `dist/index.js:${OTHER}`].sort());
      },
    );
    // Its pair: the same nesting under a callee that resolves nothing.
    withRepo(
      {
        name: "iapp-consumer",
        files: {
          "dist/index.js": `var DENY = ["${RETIRED}", "${OTHER}"];\nvar m = harmless(norm(base), DENY[0]);\nexport { m };\n`,
        },
      },
      (report) => {
        expect(report.verdict).toBe("passed");
      },
    );
  });

  test("PROOF: an inlined package.json manifest is a true positive with zero specifiers", () => {
    // `import pkg from "../package.json" with { type: "json" }` makes the
    // bundler inline the whole manifest, `dependencies` included. Confirmed real
    // in `hasna/evals`' `dist/mcp/index.js`. This is the counterexample that
    // rules out "a bare mention with no import specifier is a false positive":
    // there is no specifier anywhere in this file.
    const inlinedManifest =
      "var package_default = {\n" +
      '  name: "iapp-tp-manifest",\n' +
      '  version: "1.0.0",\n' +
      `  dependencies: { "${RETIRED}": "0.1.24" }\n` +
      "};\nexport { package_default };\n";
    expect(inlinedManifest).not.toContain('from "');
    withTarball(
      {
        "package.json": JSON.stringify({ name: "iapp-tp-manifest", version: "1.0.0", files: ["dist"] }),
        "dist/mcp/index.js": inlinedManifest,
      },
      (report) => {
        expect(report.findings.map((entry) => entry.pattern)).toEqual([RETIRED]);
        expect(report.findings[0]?.severity).toBe("critical");
      },
    );
  });

  test("PROOF: the runtime-config detectors still fire in build output", () => {
    // The three patterns with no import to look for, each read out of a
    // `dist/` file, because those are the ones a path exemption silences.
    for (const [pattern, source] of [
      [CLOUD_ENV, `var url = process.env.${CLOUD_ENV}API_URL;\nexport { url };\n`],
      [RDS, `var secret = process.env.${RDS};\nexport { secret };\n`],
      [DOTDIR, `var home = join(homedir(), "${DOTDIR}");\nexport { home };\n`],
    ] as const) {
      withRepo({ name: "iapp-consumer", files: { "dist/index.js": source } }, (report) => {
        expect(patterns(report), pattern).toContain(`dist/index.js:${pattern}`);
      });
    }
  });

  test("no path is exempt, and no package identity is either", () => {
    // The two mechanisms this replaces. Attribution reads content, so the same
    // bytes get the same verdict at every path and under every package name —
    // and `git mv` cannot change a verdict.
    for (const path of ["src/gate.ts", "dist/index.js", "lib/gate.js", "bin/gate.js", "scripts/gate.ts"]) {
      withRepo({ name: "iapp-consumer", files: { [path]: INLINED_DECLARATION } }, (report) => {
        expect(report.verdict, path).toBe("passed");
      });
      withRepo(
        { name: "iapp-consumer", files: { [path]: `${INLINED_DECLARATION}var leaked = process.env.${RDS};\nexport { leaked };\n` } },
        (report) => {
          expect(patterns(report), path).toEqual([`${path}:${RDS}`]);
        },
      );
    }
    // Byte-identical file, only the package NAME differs. Published 0.8.1 and
    // 0.8.2 PASSED the first of these with zero findings and FAILED the second
    // with two criticals, because the exemption was claimed by package identity.
    const leak = `${DENYLIST_ARRAY}\nvar leaked = process.env.${RDS};\nexport { leaked };\n`;
    for (const name of ["@hasna/contracts", "iapp-not-contracts"]) {
      withRepo({ name, files: { "dist/no-cloud.js": leak } }, (report) => {
        expect(patterns(report), name).toEqual([`dist/no-cloud.js:${RDS}`]);
      });
    }
  });

  test("a manifest is never text-edited on the strength of a shape match", () => {
    // Attribution is for C-family source, because that is the only thing a
    // bundler inlines a JavaScript constant into. A `package.json` array that
    // happens to equal the denylist is the subject's own data in the subject's
    // own manifest, and the manifest is the one file the scan must read whole.
    withRepo(
      {
        files: {
          "package.json": JSON.stringify({ name: "iapp-consumer", version: "1.0.0", keywords: [RETIRED, OTHER] }),
        },
      },
      (report) => {
        expect(patterns(report).sort()).toEqual([`package.json:${RETIRED}`, `package.json:${OTHER}`].sort());
      },
    );
  });

  test("a file living at the legacy config dotdir is read as runtime config", () => {
    // `shouldReadPath` decides this off the pattern table. It used to re-spell
    // the dotdir, and that copy was code rather than data — so a bundler inlined
    // it into every consumer where nothing structural could explain it.
    withRepo({ name: "iapp-consumer", files: { ".hasna/cloud/state.json": '{ "token": "x" }\n' } }, (report) => {
      const finding = report.findings.find((entry) => entry.pattern === DOTDIR);
      expect(finding?.kind).toBe("runtime_config");
      expect(report.verdict).toBe("failed");
    });
  });

  test("this repo does not spell a forbidden name outside the pattern table", () => {
    // The two `.hasna/cloud` copies that used to sit at finding sites were CODE,
    // not data, so no structural rule could ever attribute them — and a bundler
    // inlined them into every consumer just the same. Reading them off the table
    // is what makes the consumer's artifact attributable end to end.
    const scanner = readFileSync(join(import.meta.dir, "..", "src", "no-cloud.ts"), "utf8");
    const table = scanner.slice(scanner.indexOf("const RUNTIME_PATTERNS = ["), scanner.indexOf("] as const satisfies"));
    const code = maskComments(scanner.replace(table, ""), "c-like");
    for (const pattern of [RETIRED, OTHER, LEGACY_MCP, DOTDIR, CLOUD_ENV, RDS]) {
      expect(code.includes(pattern), `${pattern} is spelled outside RUNTIME_PATTERNS`).toBe(false);
    }
    // Positive control: the table itself does contain them, so the slice above
    // is not silently empty.
    expect(table).toContain(RDS);
    expect(table).toContain(RETIRED);
  });
});

describe("source-text: inert data regions and load callees", () => {
  test("inlineDataRegions reads arrays, records and nesting, and refuses anything else", () => {
    const array = 'var deny = ["a", "b"];';
    const [region] = inlineDataRegions(array, ["a"]);
    expect(region?.boundName).toBe("deny");
    expect(region?.root.kind).toBe("array");
    expect(inlineDataNodes(region!.root).filter((node) => node.kind === "string").length).toBe(2);

    // Nesting: the OUTERMOST collection is the region, because it carries the
    // name a later load call would have to use.
    const nested = 'var rows = [{ pattern: "a", kind: "module" }];';
    const [outer] = inlineDataRegions(nested, ["a"]);
    expect(outer?.boundName).toBe("rows");
    expect(outer?.root.kind).toBe("array");

    // Anything that is not a constant ends the parse, so no region is produced.
    for (const source of [
      'var deny = ["a", compute()];',
      'var deny = ["a", NAME];',
      "var deny = [`a${x}`];",
      'var deny = { [key]: "a" };',
    ]) {
      expect(inlineDataRegions(source, ["a"]), source).toEqual([]);
    }
  });

  test("inlineDataRegions refuses a collection consumed on the spot or passed to a call", () => {
    for (const source of ['require(["a"][0]);', 'var m = ["a"].map(load);', "var m = load([\"a\"]);", 'var m = ["a"](0);']) {
      expect(inlineDataRegions(source, ["a"]), source).toEqual([]);
    }
    // `=` must be an assignment, not a comparison.
    expect(inlineDataRegions('var same = x === ["a"];', ["a"])).toEqual([]);
    // A control head's `(` calls nothing, so the argument rule does not reach it
    // — and a condition stores nothing either. This is the half of "a `(` after
    // an identifier" that the bracket stack cannot answer.
    expect(inlineDataRegions('while (["a"]) {}', ["a"])).toEqual([]);
  });

  test("a text the lexer cannot read yields no regions at all", () => {
    // Whether a collection is an ARGUMENT is a question about brackets, and the
    // lexer is what tracks them. When it loses the thread nothing is attributed,
    // so every occurrence in the file is reported — the same direction
    // `maskComments` fails in on the same text.
    expect(inlineDataRegions('var deny = ["a", "b"];\n/* unterminated\n', ["a"])).toEqual([]);
    // The pair: close the comment and the same declaration is a region again.
    expect(inlineDataRegions('var deny = ["a", "b"];\n/* terminated */\n', ["a"]).length).toBe(1);
  });

  test("loadCallMentions sees the bundler's require wrapper, not just require", () => {
    expect(loadCallMentions("var m = __require(DENY[0]);", "DENY")).toBe(true);
    expect(loadCallMentions("var m = require(DENY[0]);", "DENY")).toBe(true);
    expect(loadCallMentions("var m = await import(DENY[0]);", "DENY")).toBe(true);
    expect(loadCallMentions("var m = DENY.length;", "DENY")).toBe(false);
    // A name that merely CONTAINS the bound name is a different name.
    expect(loadCallMentions("var m = __require(DENYLIST[0]);", "DENY")).toBe(false);
  });

  test("loadCallMentions reads the WHOLE argument list, nested calls included", () => {
    // `[^)]*` stopped at the first `)`, so one nested call in an earlier argument
    // was enough to hide the name the load actually uses.
    expect(loadCallMentions("var m = __require(norm(base), DENY[0]);", "DENY")).toBe(true);
    expect(loadCallMentions("var m = __require(opts.get(k), DENY[0]);", "DENY")).toBe(true);
    expect(loadCallMentions("var m = require(resolveFrom(dir), DENY[0]);", "DENY")).toBe(true);
    expect(loadCallMentions("var m = Module._load(x(), DENY[0]);", "DENY")).toBe(true);
    // A `)` inside a string argument does not end the list either.
    expect(loadCallMentions('var m = __require("a)b", DENY[0]);', "DENY")).toBe(true);
    // THE PAIR. A callee that resolves nothing withdraws nothing, however its
    // arguments nest; and the name is still matched whole, not as a substring.
    expect(loadCallMentions("var m = harmless(norm(base), DENY[0]);", "DENY")).toBe(false);
    expect(loadCallMentions("var m = __require(norm(base), DENYLIST[0]);", "DENY")).toBe(false);
    // The list ends where its `)` does: a name AFTER the call is not an argument.
    expect(loadCallMentions("var m = __require(norm(base));\nvar n = DENY[0];", "DENY")).toBe(false);
  });

  test("importsModule recognises the __require form bun build --external emits", () => {
    expect(importsModule(`var legacy = __require("${RETIRED}");`, RETIRED)).toBe(true);
    expect(importsModule(`var legacy = require("${RETIRED}");`, RETIRED)).toBe(true);
    // Still a path SEGMENT, not a substring.
    expect(importsModule('var legacy = __require("open-cloudy");', "open-cloud")).toBe(false);
  });
});

describe("source-text: a tuple type is inert, but not when a member is read out of it", () => {
  test("the .d.ts shape tsc emits beside every bundle is attributable", () => {
    // `export declare const FORBIDDEN_SHARED_CLOUD_RUNTIMES: readonly ["…"];`
    // is emitted into `dist/schemas.d.ts` on every build, and the scanner failed
    // its own shipped artifact on it.
    const declaration = 'export declare const DENY: readonly ["a", "b"];';
    expect(inlineDataRegions(declaration, ["a"]).length).toBe(1);
    // But a member read out of a tuple type is still a read, and there is no
    // reason for the type keyword to buy an exemption the value form is denied.
    expect(inlineDataRegions('type T = readonly ["a", "b"][0];', ["a"])).toEqual([]);
  });
});

describe("no-cloud gate: attribution survives a minifier, and does not take the credential detector with it", () => {
  // Measured emission of `bun build --minify` on a consumer that imports this
  // package: whitespace gone, the variable renamed to `HA`, the string literals
  // untouched. Attribution matches on CONTENT, so the rename is irrelevant — and
  // a path or identifier rule would have had nothing left to key on.
  const RETIRED_NAME = ["@hasna/", "cloud"].join("");
  const OTHER_NAME = ["open-", "cloud"].join("");
  const RDS_KEY = ["HASNA_RDS", "_PASSWORD"].join("");
  const minified =
    `var SA={},HA=["${RETIRED_NAME}","${OTHER_NAME}"],qU=[{pattern:"${RDS_KEY}",kind:"config",message:"Legacy shared RDS credential config is forbidden"}];` +
    "export{HA,qU,SA};";

  test("a minified bundle of this package passes", () => {
    withRepo({ name: "iapp-consumer-min", files: { "dist/index.js": minified } }, (report) => {
      expect(patterns(report)).toEqual([]);
      expect(report.verdict).toBe("passed");
    });
  });

  test("the same minified bundle plus a planted credential fails on the credential", () => {
    withRepo(
      { name: "iapp-consumer-min", files: { "dist/index.js": `${minified}var leaked=process.env.${RDS_KEY};export{leaked};` } },
      (report) => {
        expect(patterns(report)).toEqual([`dist/index.js:${RDS_KEY}`]);
        expect(report.verdict).toBe("failed");
      },
    );
  });
});

describe("source-text: a collection must be STORED, not just written down somewhere", () => {
  // FOUND BY A GAP IN THE MUTATION AUDIT, not by reading the code. Narrowing the
  // audit to the test files that contain no self-conformance scan reported M79 —
  // "a collection handed to a call is an argument, not a stored constant" —
  // SURVIVED. It had been reading as `caught` because weakening it also makes the
  // repo fail its own gate, and that broad failure was the first one reported for
  // every mutation in the block.
  //
  // The shape it protects, and the reason it is not covered by the
  // consumed-in-place rule: `for (const m of [...])` puts the collection in no
  // binding at all, so there is no name for a load call to mention, and the
  // character after `]` is `)`, which consumes nothing. Only the position BEFORE
  // the `[` says this is not a stored constant.
  const RETIRED_MODULE = ["@hasna/", "cloud"].join("");
  const OTHER_MODULE = ["open-", "cloud"].join("");

  test("a collection in a non-storing position is not a declaration", () => {
    for (const source of [
      `for (const m of ["${RETIRED_MODULE}", "${OTHER_MODULE}"]) __require(m);`,
      `return ["${RETIRED_MODULE}", "${OTHER_MODULE}"];`,
      `yield ["${RETIRED_MODULE}", "${OTHER_MODULE}"];`,
      `typeof ["${RETIRED_MODULE}", "${OTHER_MODULE}"];`,
    ]) {
      expect(inlineDataRegions(source, [RETIRED_MODULE]), source).toEqual([]);
    }
  });

  test("the for-of shape is still a finding end to end", () => {
    withRepo(
      {
        name: "iapp-consumer",
        files: {
          "dist/index.js": `for (const m of ["${RETIRED_MODULE}", "${OTHER_MODULE}"]) __require(m);\nexport const ok = true;\n`,
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
        expect(patterns(report).sort()).toEqual(
          [`dist/index.js:${RETIRED_MODULE}`, `dist/index.js:${OTHER_MODULE}`].sort(),
        );
      },
    );
    // The pair: the same two names, stored, with nothing loading through them.
    withRepo(
      {
        name: "iapp-consumer",
        files: { "dist/index.js": `var DENY = ["${RETIRED_MODULE}", "${OTHER_MODULE}"];\nexport { DENY };\n` },
      },
      (report) => {
        expect(report.verdict).toBe("passed");
      },
    );
  });

  test("an argument is not a stored constant WHEREVER it sits in the list", () => {
    // The character before the `[` can only ever see the FIRST argument.
    // `load([...])` was rejected on the `(` while `load(cfg, [...])` landed on a
    // `,` and was read as a stored constant — attributed, blanked, and scanned
    // clean, which the base branch did not do. An argument is the callee's to do
    // what it likes with, and `list.forEach((m) => __require(m))` one module away
    // is the same load the for-of case above is rejected for.
    for (const source of [
      `var mods = registerAll(ctx, ["${RETIRED_MODULE}", "${OTHER_MODULE}"]);`,
      `var mods = load(1, 2, ["${RETIRED_MODULE}", "${OTHER_MODULE}"]);`,
      `var mods = register("app", ["${RETIRED_MODULE}", "${OTHER_MODULE}"]);`,
      `loadAll(cfg, ["${RETIRED_MODULE}", "${OTHER_MODULE}"]).then(run);`,
      // The immediately-invoked resolver, whose callee has no name to check.
      `var mods = createRequire(url)(ctx, ["${RETIRED_MODULE}", "${OTHER_MODULE}"]);`,
      // A ternary alternate ends on the same `:` a record key does, and stores
      // nothing either.
      `var mods = cond ? fallback : ["${RETIRED_MODULE}", "${OTHER_MODULE}"];`,
    ]) {
      expect(inlineDataRegions(source, [RETIRED_MODULE]), source).toEqual([]);
    }
    // THE PAIR, and the bound the argument rule needs. Only the INNERMOST
    // bracket decides: a constant declared inside a callback BODY sits under a
    // call frame too, and `__commonJS((exports) => { … })` is what a bundler
    // emits for every CommonJS module it wraps. Rejecting on any enclosing call
    // would unattribute all of them.
    const wrapped =
      `var mod = __commonJS((exports) => {\n  var DENY = ["${RETIRED_MODULE}", "${OTHER_MODULE}"];\n  exports.DENY = DENY;\n});`;
    expect(inlineDataRegions(wrapped, [RETIRED_MODULE]).length).toBe(1);
    // And a record entry is still a record entry: that `:` is a key's.
    expect(inlineDataRegions(`var t = { deny: ["${RETIRED_MODULE}"] };`, [RETIRED_MODULE]).length).toBe(1);
  });

  test("the argument shape is still a finding end to end, in src/ as well as dist/", () => {
    // The same fixture as the first-argument case above, with one leading
    // argument. Attribution consults no path, so both have to behave the same
    // way wherever they land.
    for (const path of ["src/boot.ts", "dist/boot.js"]) {
      withRepo(
        {
          name: "iapp-consumer",
          files: { [path]: `export const mods = registerAll(ctx, ["${RETIRED_MODULE}", "${OTHER_MODULE}"]);\n` },
        },
        (report) => {
          expect(report.verdict, path).toBe("failed");
          expect(patterns(report).sort(), path).toEqual(
            [`${path}:${RETIRED_MODULE}`, `${path}:${OTHER_MODULE}`].sort(),
          );
        },
      );
      // The pair: the same two names stored rather than handed to a call.
      withRepo(
        { name: "iapp-consumer", files: { [path]: `export const mods = ["${RETIRED_MODULE}", "${OTHER_MODULE}"];\n` } },
        (report) => {
          expect(report.verdict, path).toBe("passed");
        },
      );
    }
  });
});

describe("no-cloud gate: a blanked span may carry nothing but the row this table emits", () => {
  // THE BLOCKING DEFECT A REVIEW FOUND, and it is the same shape as the rejection
  // that killed the first attempt at this fix. `isOwnPatternDeclaration` checked
  // three keys and ignored the rest of the key set, while
  // `withoutInlinedDeclarations` blanks the WHOLE record. So a verbatim
  // `{pattern, kind, message}` triple plus one more key smuggled anything at all
  // through the blanked span — and the three `config` patterns have no second
  // detector, so blanking a span is the only thing standing between them and a
  // clean scan.
  //
  // Measured before the key-set bound existed, as a tarball under a third-party
  // package name: the forge scored EXIT=0 with zero findings while the identical
  // credential string WITHOUT a triple around it scored EXIT=1. In authored
  // `src/` as well as in build output.
  const RETIRED_ROW = ["@hasna/", "cloud"].join("");
  const CONFIG_ROW = ["HASNA_CLOUD", "_"].join("");
  const CREDENTIAL = ["HASNA_RDS", "_PASSWORD"].join("");
  const DOTDIR_ROW = [".hasna/", "cloud"].join("");
  const verbatimRow =
    `{ pattern: "${RETIRED_ROW}", kind: "module", message: "Shared ${RETIRED_ROW} runtime reference is forbidden" }`;

  test("the row this table emits is attributed", () => {
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${verbatimRow}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report)).toEqual([]);
      expect(report.verdict).toBe("passed");
    });
  });

  test("a verbatim row plus ONE extra key is not that row, and the extra key is read", () => {
    const forged = verbatimRow.replace(
      " }",
      `, note: "${CREDENTIAL}=placeholder-not-a-real-value" }`,
    );
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${forged}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report), "the smuggled credential must be reported").toContain(`dist/bundle.js:${CREDENTIAL}`);
      expect(report.verdict).toBe("failed");
    });
  });

  test("checkKind is a FREE SLOT unless its value is compared too", () => {
    // F1b, the second review blocker, and the reason the record rule is now full
    // equality rather than another narrowing. `checkKind` is declared on exactly
    // one table row, but bounding the key set to a union over ALL rows admitted it
    // on all eight — and the check was that it held A string, never the RIGHT one.
    // A backtick literal then made the blanked span multi-line and arbitrarily
    // long. Measured before entry-for-entry equality, as tarballs under a
    // third-party package name:
    //
    //   verbatim module row + checkKind holding a credential  EXIT=0, 0 findings
    //     control: the same string with no triple             EXIT=1, 1 critical
    //   verbatim config row + backtick checkKind, four
    //     patterns over five lines                            EXIT=0, 0 findings
    //   the same slot in hand-authored src/table.ts           EXIT=0, 0 findings
    const forged =
      `{ pattern: "${RETIRED_ROW}", kind: "module", checkKind: "${CREDENTIAL}=placeholder", ` +
      `message: "Shared ${RETIRED_ROW} runtime reference is forbidden" }`;
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${forged}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report), "a module row never carries checkKind, so this is not that row").toContain(
        `dist/bundle.js:${CREDENTIAL}`,
      );
      expect(report.verdict).toBe("failed");
    });
    // A backtick value, so the span it would have blanked runs over five lines.
    const multiline =
      `{ pattern: "${CONFIG_ROW}", kind: "config", checkKind: \`\n  ${CREDENTIAL}\n  ${DOTDIR_ROW}\n\`, ` +
      `message: "Shared ${CONFIG_ROW}* runtime config is forbidden" }`;
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${multiline}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report)).toContain(`dist/bundle.js:${CREDENTIAL}`);
    });
    // THE PAIR: the genuine `.hasna/cloud` row, which really does carry
    // `checkKind`, with its own value. Four keys, all equal — attributed.
    const genuine =
      `{ pattern: "${DOTDIR_ROW}", kind: "config", checkKind: "runtime_config", ` +
      `message: "Legacy ${DOTDIR_ROW} runtime config is forbidden" }`;
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${genuine}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report), "the one row that really carries checkKind must still be attributed").toEqual([]);
      expect(report.verdict).toBe("passed");
    });
    // And that same row with checkKind holding somebody else's string is not it.
    const wrongValue = genuine.replace('"runtime_config"', `"${CREDENTIAL}"`);
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${wrongValue}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report)).toContain(`dist/bundle.js:${CREDENTIAL}`);
    });
  });

  test("a REPEATED key is a FREE SLOT unless the parser refuses the record", () => {
    // F1c, the third review blocker, and the one that survived entry-for-entry
    // equality. Duplicate property names are legal JavaScript that a bundler
    // preserves, and `parseInlineData` used to build the entries with `Map.set` —
    // which keeps the LAST value and shrinks the count. So a record repeating
    // `message` arrived at `isOwnPatternDeclaration` as a THREE-entry record whose
    // every entry equalled a module row, and `withoutInlinedDeclarations` blanked
    // the whole span including the shadowed value nothing had compared.
    //
    // Measured before the parser refused it, as tarballs under a third-party
    // package name, each against a control that fails:
    //
    //   verbatim module row + shadowed `message` holding a
    //     credential env key                                  EXIT=0, 0 findings
    //     control: the same credential with no record          EXIT=1, 1 critical
    //   the same slot carrying three config patterns at once   EXIT=0, 0 findings
    //   a backtick in the shadowed slot, span over five lines  EXIT=0, 0 findings
    //
    // The `config` patterns have no import to look for, so the bare-mention
    // detector is their only one and a blanked span is the whole of what stands
    // between them and a clean scan. The fix is in `parseInlineData`, not here: a
    // duplicate key means the text is not the inert constant this package emits,
    // so refusing to describe it is the fail-open direction.
    const shadowed =
      `{ pattern: "${RETIRED_ROW}", kind: "module", message: "${CREDENTIAL}=placeholder-not-a-real-value", ` +
      `message: "Shared ${RETIRED_ROW} runtime reference is forbidden" }`;
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${shadowed}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report), "the credential in the shadowed entry must be reported").toContain(
        `dist/bundle.js:${CREDENTIAL}`,
      );
      expect(report.verdict).toBe("failed");
    });
    // One shadowed slot hid the credential AND all three config patterns at once,
    // on a plain assignment with no aliasing.
    const manyPatterns = shadowed.replace(
      `"${CREDENTIAL}=placeholder-not-a-real-value"`,
      `"${CREDENTIAL} ${DOTDIR_ROW} ${CONFIG_ROW}"`,
    );
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${manyPatterns}];\nexport { t };\n` } }, (report) => {
      for (const pattern of [CREDENTIAL, DOTDIR_ROW, CONFIG_ROW]) {
        expect(patterns(report), pattern).toContain(`dist/bundle.js:${pattern}`);
      }
      expect(report.verdict).toBe("failed");
    });
    // A backtick in the shadowed slot, so the span it would have blanked is
    // multi-line and arbitrarily long.
    const multiline = shadowed.replace(
      `"${CREDENTIAL}=placeholder-not-a-real-value"`,
      `\`\n  ${CREDENTIAL}\n  ${DOTDIR_ROW}\n\``,
    );
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${multiline}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report)).toContain(`dist/bundle.js:${CREDENTIAL}`);
      expect(report.verdict).toBe("failed");
    });
    // The record as the region ROOT, not just as an element of one.
    withRepo({ name: "@acme/consumer-app", files: { "src/table.ts": `export const t = ${shadowed};\n` } }, (report) => {
      expect(patterns(report), "hand-authored source, same content, same verdict").toContain(
        `src/table.ts:${CREDENTIAL}`,
      );
    });
    // THE PAIR, both arities: the genuine three-entry module row and the genuine
    // four-entry config row repeat no key, and must still be attributed.
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${verbatimRow}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report), "the 3-key row this table emits must still be attributed").toEqual([]);
      expect(report.verdict).toBe("passed");
    });
    const genuineFourKey =
      `{ pattern: "${DOTDIR_ROW}", kind: "config", checkKind: "runtime_config", ` +
      `message: "Legacy ${DOTDIR_ROW} runtime config is forbidden" }`;
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${genuineFourKey}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report), "the 4-key row this table emits must still be attributed").toEqual([]);
      expect(report.verdict).toBe("passed");
    });
  });

  test("the parser refuses a duplicate-key record outright", () => {
    // The rule lives in `parseInlineData`, so it is tested where it lives as well
    // as end to end: a record with a repeated key describes nothing, and neither
    // does any collection around it, so no span is ever blanked on its strength.
    const duplicate = `var t = [{ pattern: "${RETIRED_ROW}", kind: "module", message: "a", message: "b" }];`;
    expect(inlineDataRegions(duplicate, [RETIRED_ROW])).toEqual([]);
    // A quoted key shadowing a bare one is the same key, and is refused too.
    const quotedDuplicate = `var t = [{ pattern: "${RETIRED_ROW}", kind: "module", "kind": "config", message: "b" }];`;
    expect(inlineDataRegions(quotedDuplicate, [RETIRED_ROW])).toEqual([]);
    // The pair: distinct keys still parse, and the region is still found.
    const distinct = `var t = [{ pattern: "${RETIRED_ROW}", kind: "module", message: "b" }];`;
    expect(inlineDataRegions(distinct, [RETIRED_ROW]).length).toBe(1);
  });

  test("an accepted key cannot hold a nested collection", () => {
    // Bounding the keys is not enough on its own: one key holding an object hides
    // a whole table inside the blanked span. Entry-for-entry equality covers this
    // as a side effect — a nested value is not equal to a string — but it is
    // tested separately because the two rules can be broken independently.
    const nested =
      `{ pattern: "${DOTDIR_ROW}", kind: "config", checkKind: { a: "${CREDENTIAL}", b: "registerCloudTools" }, ` +
      `message: "Legacy ${DOTDIR_ROW} runtime config is forbidden" }`;
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${nested}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report), "the credential nested under an accepted key must be reported").toContain(
        `dist/bundle.js:${CREDENTIAL}`,
      );
      expect(report.verdict).toBe("failed");
    });
  });

  test("the bound holds in hand-authored source, not only in build output", () => {
    // Attribution reads content and consults no path, so the forge and its
    // rejection have to behave identically wherever they land. This is also the
    // half a build-output path scope could never have covered.
    const forged = verbatimRow.replace(" }", `, note: "${CREDENTIAL}=placeholder" }`);
    for (const path of ["src/table.ts", "dist/bundle.js", "lib/table.js"]) {
      withRepo({ name: "@acme/consumer-app", files: { [path]: `export const t = [${forged}];\n` } }, (report) => {
        expect(patterns(report), path).toContain(`${path}:${CREDENTIAL}`);
      });
      withRepo({ name: "@acme/consumer-app", files: { [path]: `export const t = [${verbatimRow}];\n` } }, (report) => {
        expect(patterns(report), path).toEqual([]);
      });
    }
  });

  test("the compared key set is the MATCHED row's, not a union over all rows", () => {
    // The union was cause #1 of F1b: `checkKind` is declared on one row and the
    // union admitted it on eight. Keys now come from the row being compared, so a
    // module row carrying `checkKind` matches nothing — and the config row that
    // really carries it still matches.
    const moduleRowWithCheckKind =
      `{ pattern: "${RETIRED_ROW}", kind: "module", checkKind: "runtime_config", ` +
      `message: "Shared ${RETIRED_ROW} runtime reference is forbidden" }`;
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${moduleRowWithCheckKind}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report)).toContain(`dist/bundle.js:${RETIRED_ROW}`);
    });
    // A key that is in no row at all is rejected even holding an inert value.
    const strangeKey =
      `{ pattern: "${DOTDIR_ROW}", kind: "config", checkKind: "runtime_config", severity: "high", ` +
      `message: "Legacy ${DOTDIR_ROW} runtime config is forbidden" }`;
    withRepo({ name: "@acme/consumer-app", files: { "dist/bundle.js": `var t = [${strangeKey}];\nexport { t };\n` } }, (report) => {
      expect(patterns(report)).toContain(`dist/bundle.js:${DOTDIR_ROW}`);
    });
  });
});

describe("source-text: resolver callees the underscore rule cannot reach", () => {
  // A review reached a copy of the denylist through `Module._load(DENY[0])` and
  // through a function returned by `createRequire`. The first is a member name, so
  // `_*` never applies to it; the second has no word boundary before `Require` and
  // differs in case. Both are spelled out in `LOAD_CALLEE` now.
  //
  // Only ONE of the two is actually closed by naming the callee, and the comment
  // in `LOAD_CALLEE` says which: `Module._load(DENY[0])` names the array, so the
  // bound-name check sees it. `var r = createRequire(…); r(DENY[0])` calls `r`,
  // and no list of callee names can catch a name the caller chose — that route is
  // conceded in the scope block at the top of `src/no-cloud.ts` rather than
  // claimed here.
  const DENY_A = ["@hasna/", "cloud"].join("");
  const DENY_B = ["open-", "cloud"].join("");

  test("Module._load counts as a load call", () => {
    expect(loadCallMentions("var m = Module._load(DENY[0]);", "DENY")).toBe(true);
    expect(loadCallMentions("var r = createRequire(DENY[0]);", "DENY")).toBe(true);
    // Still a whole identifier, and still not just any call.
    expect(loadCallMentions("var m = Module._loader(DENYLIST[0]);", "DENY")).toBe(false);
    expect(loadCallMentions("var m = harmless(DENY[0]);", "DENY")).toBe(false);
  });

  test("a denylist copy loaded through Module._load is a finding", () => {
    withRepo(
      {
        name: "@acme/consumer-app",
        files: {
          "dist/bundle.js": `var DENY = ["${DENY_A}", "${DENY_B}"];\nvar m = Module._load(DENY[0]);\nexport { m };\n`,
        },
      },
      (report) => {
        expect(report.verdict).toBe("failed");
      },
    );
    // The pair: the same copy with a call that resolves nothing.
    withRepo(
      {
        name: "@acme/consumer-app",
        files: { "dist/bundle.js": `var DENY = ["${DENY_A}", "${DENY_B}"];\nvar m = harmless(DENY[0]);\nexport { m };\n` },
      },
      (report) => {
        expect(report.verdict).toBe("passed");
      },
    );
  });
});
