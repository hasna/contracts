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
import {
  isLinkedResolution,
  lockfileEdges,
  lockfileWalk,
  manifestEdges,
  nameFromResolutionId,
  parseLooseJson,
  resolutionTarget
} from "../src/dependency-edge";
import { importedBindings, importsModule, maskComments, maskCommentsForPath, mentionsCannotLoad } from "../src/source-text";

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
