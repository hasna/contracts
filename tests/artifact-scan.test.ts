import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEFAULT_INVENTORY_THRESHOLDS,
  decodeEscapes,
  formatArtifactScanReport,
  inventoryCounts,
  registrableDomain,
  resolveAssetInventoryWaivers,
  scanPublishedArtifact,
  MAX_INVENTORY_THRESHOLDS,
} from "../src/artifact-scan";
import { IANA_TLD_SNAPSHOT, PROGRAMMING_COLLISION_TLDS, RECOGNIZED_TLDS, isRecognizedTld } from "../src/tlds";
import { runRepoConformance } from "../src/conformance";

let workspace = "";

beforeAll(() => {
  workspace = mkdtempSync(join(tmpdir(), "contracts-artifact-scan-test-"));
});

afterAll(() => {
  if (workspace) rmSync(workspace, { recursive: true, force: true });
});

function tarball(name: string, files: Record<string, string>): string {
  const root = join(workspace, name);
  const pkg = join(root, "package");
  mkdirSync(pkg, { recursive: true });
  for (const [path, content] of Object.entries(files)) {
    const full = join(pkg, path);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  const archive = join(root, `${name}.tgz`);
  const result = Bun.spawnSync(["tar", "-czf", archive, "-C", root, "package"]);
  if (result.exitCode !== 0) throw new Error(`tar failed for ${name}`);
  return archive;
}

/** N distinct registrable domains, spread across real TLDs. */
function portfolio(count: number, prefix = "portfolio-brand"): string[] {
  const tlds = ["com", "net", "org", "co", "de", "fr", "nl", "se", "es", "it", "ca", "be"];
  return Array.from({ length: count }, (_, index) => `${prefix}-${index}.${tlds[index % tlds.length]}`);
}

// --- the incident, reproduced ---

describe("the failure this guard exists for", () => {
  test("catches a portfolio compiled into dist from a source file that never ships", () => {
    // @hasna/tenants@0.1.0: repo private, `files: ["dist"]`, 177 apex domains
    // inside dist/index.js. Every source-level review passed because the file
    // holding the list was excluded from the tarball while the list was not.
    const archive = tarball("incident", {
      "package.json": JSON.stringify({ name: "victim", version: "0.1.0", files: ["dist"] }),
      "dist/index.js": `var DEFAULT_ALLOWED_EMAIL_DOMAINS=${JSON.stringify(portfolio(177))};export{DEFAULT_ALLOWED_EMAIL_DOMAINS};`,
    });

    const report = scanPublishedArtifact(archive);
    expect(report.ok).toBe(false);
    expect(report.membersScanned).toBeGreaterThan(0);
    const finding = report.findings.find((entry) => entry.kind === "domain");
    expect(finding?.path).toBe("dist/index.js");
    expect(finding?.count).toBe(177);
  });

  test("the same package passes once the inventory is gone", () => {
    const archive = tarball("incident-remediated", {
      "package.json": JSON.stringify({ name: "victim", version: "0.1.1", files: ["dist"] }),
      "dist/index.js": "export const DEFAULT_ALLOWED_EMAIL_DOMAINS=[];",
    });
    expect(scanPublishedArtifact(archive).ok).toBe(true);
  });

  test("a report leaks neither brand, length, nor TLD", () => {
    // The previous mask emitted two characters of the brand, its exact length,
    // and the full TLD (`ha***.agency`). Against a one-brand portfolio three
    // samples of that form name the brand and three of its registrations.
    // Asserting `toContain("*")` accepted any masking at all; it could catch
    // NO masking but never BAD masking.
    const portfolio = oneBrandPortfolio(40);
    const archive = tarball("redaction-strict", {
      "package.json": JSON.stringify({ name: "victim", version: "1.0.0" }),
      "dist/index.js": JSON.stringify(portfolio),
    });
    const report = scanPublishedArtifact(archive);
    const text = formatArtifactScanReport(report);

    // The brand itself, in whole or in part.
    expect(text).not.toContain("acme-widgets");
    expect(text.toLowerCase()).not.toContain("acme");
    // Any TLD it is registered under.
    for (const domain of portfolio) {
      const tld = domain.slice(domain.lastIndexOf(".") + 1);
      expect(text, `must not disclose .${tld}`).not.toContain(`.${tld}`);
      expect(text, `must not disclose ${domain}`).not.toContain(domain);
    }
    // And no length tell: every sample must be the same width.
    const samples = report.findings.flatMap((finding) => finding.sample);
    expect(samples.length).toBeGreaterThan(0);
    expect(new Set(samples.map((sample) => sample.length)).size).toBe(1);
  });

  test("a report never republishes what it found", () => {
    const archive = tarball("redaction", {
      "package.json": JSON.stringify({ name: "victim", version: "0.1.0" }),
      "dist/index.js": JSON.stringify(portfolio(40, "secret-brand")),
    });
    const report = scanPublishedArtifact(archive);
    const text = formatArtifactScanReport(report);
    // The report is pasted into tasks, channels, and CI logs. A guard that
    // prints the inventory it just found has disclosed it a second time.
    expect(text).not.toContain("secret-brand-0.com");
    // Samples name a KIND and a per-report digest, never a fragment of the value.
    expect(text).toMatch(/<(?:domain|host|ip|email):[0-9a-f]{8}>/);
    // And the kind is the FINDING's, not one guessed from the value's shape:
    // reinstating label-by-shape made a `domain` finding print `<host:…>` and
    // survived the whole suite.
    for (const finding of report.findings) {
      for (const sample of finding.sample) {
        expect(sample.startsWith(`<${finding.kind}:`), `${finding.kind} sample ${sample}`).toBe(true);
      }
    }
    expect(report.findings.every((finding) => finding.sample.length <= 3)).toBe(true);
  });
});

/**
 * THE REAL INCIDENT SHAPE: one brand, many TLDs.
 *
 * Every other fixture in this file generates a distinct brand per entry
 * (`brand-0.com`, `brand-1.net`, …), which is the OPPOSITE structure. The real
 * disclosed portfolio is a single brand label registered across 177 TLDs — so
 * no many-brand fixture ever reaches `isMemberAccessRun`, the branch that keys
 * on `firstLabels.size !== 1`. The collision that dropped detection from 94.4%
 * to 29.2% was invisible to the entire suite for exactly that reason.
 */
function oneBrandPortfolio(count: number): string[] {
  const tlds = [
    "academy", "agency", "art", "cafe", "care", "chat", "city", "club", "coach", "coffee",
    "company", "design", "digital", "expert", "farm", "finance", "gallery", "games", "global",
    "gold", "green", "group", "guide", "guru", "holdings", "homes", "house", "institute",
    "international", "land", "legal", "life", "live", "market", "media", "money", "network",
    "news", "ninja", "partners",
  ];
  return tlds.slice(0, count).map((tld) => `acme-widgets.${tld}`);
}

describe("the real incident structure: one brand across many TLDs", () => {
  test("a quoted one-brand portfolio is detected", () => {
    // Removing the `quoted` short-circuit in `isMemberAccessRun` makes THIS
    // test fail. Nothing else in the suite notices, because nothing else uses
    // the real shape.
    const counts = inventoryCounts(JSON.stringify(oneBrandPortfolio(40)));
    expect(counts.domain.length).toBe(40);
  });

  test("the packed artifact form is detected end to end", () => {
    const archive = tarball("one-brand-incident", {
      "package.json": JSON.stringify({ name: "victim", version: "0.1.0", files: ["dist"] }),
      "dist/index.js": `var ALLOWED = ${JSON.stringify(oneBrandPortfolio(40))};export{ALLOWED};`,
    });
    const report = scanPublishedArtifact(archive);
    expect(report.ok).toBe(false);
    expect(report.findings.some((finding) => finding.kind === "domain")).toBe(true);
  });

  test("and in every unquoted list layout a human would actually write", () => {
    // Measured before the fix: markdown 0, numbered 0, YAML 0 — while the
    // many-brand equivalent of each scored 40. The guard is a CODE rule and was
    // being applied to prose.
    const portfolio = oneBrandPortfolio(40);
    const layouts: Array<[string, string]> = [
      ["markdown bullets", portfolio.map((domain) => `- ${domain}`).join("\n")],
      ["numbered list", portfolio.map((domain, index) => `${index + 1}. ${domain}`).join("\n")],
      ["yaml sequence", portfolio.map((domain) => `  - host: ${domain}`).join("\n")],
      ["bare lines", portfolio.join("\n")],
    ];
    for (const [label, text] of layouts) {
      const counts = inventoryCounts(text, { codeLike: false });
      expect(counts.domain.length + counts.host.length, label).toBeGreaterThanOrEqual(38);
    }
  });

  test("but a locale barrel in CODE is still member access, not a portfolio", () => {
    // The counterweight. Every ISO language code is a ccTLD, so a per-line rule
    // reads this as a ten-domain portfolio. Both halves have to hold at once.
    const locales = ["vi", "ua", "tr", "th", "sv", "ru", "pl", "no", "it", "id"]
      .map((locale) => `  exports.${locale},`)
      .join("\n");
    const counts = inventoryCounts(locales, { codeLike: true });
    expect(counts.domain).toEqual([]);
    expect(counts.host).toEqual([]);
  });
});

// --- the evasions an adversarial review actually landed ---

describe("evasions that previously walked past this guard", () => {
  const portfolioOf = (count: number) => portfolio(count);

  test("MIXED CASE is the same inventory — DNS is case-insensitive", () => {
    const mixed = portfolioOf(40).map((domain, index) =>
      index % 2 === 0 ? domain.toUpperCase() : domain.replace(/^./, (c) => c.toUpperCase()),
    );
    const counts = inventoryCounts(JSON.stringify(mixed));
    expect(counts.domain.length).toBe(40);
    // And the cased forms collapse onto the lowercase ones rather than doubling.
    expect(inventoryCounts(JSON.stringify([...mixed, ...portfolioOf(40)])).domain.length).toBe(40);
  });

  test("UNQUOTED prose and tabular data are read", () => {
    // A .csv or a markdown list has no string literals at all. Quote-anchoring
    // alone missed every one of these, and a .csv of domains discloses exactly
    // as well as a JS array of them.
    const csv = tarball("unquoted-csv", {
      "package.json": JSON.stringify({ name: "unquoted", version: "1.0.0" }),
      "data/portfolio.csv": portfolioOf(40).map((domain, index) => `${index},${domain}`).join("\n"),
    });
    expect(scanPublishedArtifact(csv).ok).toBe(false);

    const markdown = tarball("unquoted-md", {
      "package.json": JSON.stringify({ name: "unquoted", version: "1.0.0" }),
      "docs/assets.md": portfolioOf(40).map((domain) => `- ${domain}`).join("\n"),
    });
    expect(scanPublishedArtifact(markdown).ok).toBe(false);
  });

  test("dotted property access is never counted as a domain", () => {
    // The counterweight to the rule above: reading bare tokens in code reported
    // `array.map`, `cls.name` and `issues.map` and failed on this repo's own
    // bundle. Code is read through its string literals.
    const code = [
      "const a = input.data;", "const b = items.map;", "const c = cls.name;",
      "const d = actor.id;", "const e = tasks.next;", "const f = service.health;",
      "const g = commander.help;", "const h = current.repair;",
    ].join("\n");
    expect(inventoryCounts(code).domain).toEqual([]);
  });

  test("ONE long delimited string is a list, not one unmatched blob", () => {
    const packed = portfolioOf(40).join(",");
    expect(inventoryCounts(`const DOMAINS = "${packed}".split(",");`).domain.length).toBe(40);
  });

  test("escaped and encoded forms are decoded before counting", () => {
    const domains = portfolioOf(30);
    // \u002e for the dot — a one-character change walked past literal matching.
    const escaped = domains.map((d) => `"${d.replace(/\./g, "\\u002e")}"`).join(",");
    expect(inventoryCounts(`[${escaped}]`).domain.length).toBe(30);

    // Percent-encoding, as a URL-shaped disclosure would carry.
    const percent = domains.map((d) => `"${d.replace(/\./g, "%2e")}"`).join(",");
    expect(inventoryCounts(`[${percent}]`).domain.length).toBe(30);

    // A base64 blob, as a build step or an obfuscator would produce.
    const blob = Buffer.from(domains.join(",")).toString("base64");
    expect(inventoryCounts(`const D = atob("${blob}");`).domain.length).toBe(30);
  });

  test("a source map's original source is read IN THE SHAPE BUNDLERS EMIT", () => {
    // The earlier fixture was `JSON.stringify(list)` — one line, no newline
    // escapes — and passed while the real thing scanned clean. Every bundler
    // emits `sourcesContent` as ONE JSON string with the file's newlines
    // escaped, so the glue between entries is `,\n  `, which contains a
    // literal backslash. `LITERAL_RUN_GLUE` excludes backslash, so the run
    // broke at every element and a realistic `.map` carrying a full portfolio
    // reported ok.
    const portfolio = oneBrandPortfolio(40);
    const original = `export const ALLOWED = [\n${portfolio.map((d) => `  "${d}",`).join("\n")}\n];\n`;
    const map = JSON.stringify({
      version: 3,
      file: "index.js",
      sources: ["../src/policy.ts"],
      sourcesContent: [original],
      names: [],
      mappings: "AAAA",
    });
    // The escaped form is what lands on disk.
    expect(map).toContain("\\n");
    expect(inventoryCounts(map).domain.length).toBeGreaterThanOrEqual(38);

    const archive = tarball("sourcemap-multiline", {
      "package.json": JSON.stringify({ name: "mapped", version: "1.0.0", files: ["dist"] }),
      "dist/index.js": "export const ALLOWED=[];\n//# sourceMappingURL=index.js.map\n",
      "dist/index.js.map": map,
    });
    const report = scanPublishedArtifact(archive);
    expect(report.ok).toBe(false);
    expect(report.findings.some((finding) => finding.kind === "domain")).toBe(true);
  });

  test("a JSON-escaped source map's original source is read", () => {
    // `sourcesContent` embeds the ORIGINAL source with every quote escaped —
    // which is exactly how the incident's excluded source file could still ship.
    const inner = JSON.stringify(portfolioOf(40));
    const map = JSON.stringify({ version: 3, sources: ["policy.ts"], sourcesContent: [`const D = ${inner};`] });
    const archive = tarball("sourcemap", {
      "package.json": JSON.stringify({ name: "mapped", version: "1.0.0", files: ["dist"] }),
      "dist/index.js.map": map,
    });
    expect(scanPublishedArtifact(archive).ok).toBe(false);
  });

  test("SPLITTING the list across files does not defeat the threshold", () => {
    // Ten files of eighteen beats any per-file threshold, and the clause is
    // about what the ARTIFACT discloses, not what one file does.
    const domains = portfolioOf(180);
    const files: Record<string, string> = { "package.json": JSON.stringify({ name: "split", version: "1.0.0" }) };
    for (let index = 0; index < 10; index++) {
      files[`dist/chunk-${index}.js`] = JSON.stringify(domains.slice(index * 18, index * 18 + 18));
    }
    const report = scanPublishedArtifact(tarball("split", files));
    expect(report.ok).toBe(false);
    // No single file trips it; the aggregate does.
    expect(report.findings.every((finding) => finding.path === "<artifact>")).toBe(true);
    expect(report.aggregateFindings?.[0]?.count).toBe(180);
  });

  test("a trailing-dot FQDN is the same name", () => {
    const fqdn = portfolioOf(40).map((domain) => `"${domain}."`).join(",");
    expect(inventoryCounts(`[${fqdn}]`).domain.length).toBe(40);
  });

  test("URL authorities count — that is what an endpoint catalogue is", () => {
    const urls = portfolioOf(40).map((domain) => `"https://api.${domain}/v1/health"`).join(",");
    const counts = inventoryCounts(`[${urls}]`);
    expect(counts.domain.length).toBe(40);
  });
});

// --- vacuity ---

describe("it cannot pass by having nothing to check", () => {
  test("an archive with no readable members THROWS rather than reporting clean", () => {
    const root = join(workspace, "empty");
    mkdirSync(join(root, "nothing"), { recursive: true });
    const archive = join(root, "empty.tgz");
    Bun.spawnSync(["tar", "-czf", archive, "-C", join(root, "nothing"), "."]);
    expect(() => scanPublishedArtifact(archive)).toThrow(/zero members/);
  });

  test("a member with a NUL byte is SCANNED, not skipped", () => {
    // The previous version dropped any member with a NUL in its first 8 KB, so
    // one NUL in a leading comment removed a file from the scan and produced a
    // clean verdict — a one-character evasion of the whole guard.
    const withNul = `/*${String.fromCharCode(0)}*/\n` + JSON.stringify(portfolio(40));
    const archive = tarball("nul-byte", {
      "package.json": JSON.stringify({ name: "nul", version: "1.0.0" }),
      "dist/index.js": withNul,
    });
    const report = scanPublishedArtifact(archive);
    expect(report.membersSkipped).toBe(0);
    expect(report.ok).toBe(false);
  });

  test("an UNREAD member fails the scan — ok is not `no findings`", () => {
    // A scan that skipped the member holding the inventory has not cleared the
    // artifact, it has failed to look at it.
    const archive = tarball("ignored", {
      "package.json": JSON.stringify({ name: "ignored", version: "1.0.0" }),
      "dist/index.js": "export const a = 1;",
    });
    const clean = scanPublishedArtifact(archive);
    expect(clean.ok).toBe(true);

    // An unread member is not a clean member: the scan has not cleared the
    // artifact, it has failed to look at it.
    // One member readable, one over the limit: the scan runs, finds nothing,
    // and still must NOT report ok — an unread member is not a clean member.
    const mixed = tarball("partially-unreadable", {
      "package.json": JSON.stringify({ name: "mixed", version: "1.0.0" }),
      "dist/small.js": "export const a = 1;",
      "dist/big.js": `export const pad = "${"x".repeat(4000)}";`,
    });
    const oversize = scanPublishedArtifact(mixed, { maxMemberBytes: 1000 });
    expect(oversize.findings).toEqual([]);
    expect(oversize.membersScanned).toBeGreaterThan(0);
    expect(oversize.unreadable.length).toBeGreaterThan(0);
    expect(oversize.ok).toBe(false);

    // And when EVERY member is excluded, there is no verdict to give at all.
    expect(() => scanPublishedArtifact(archive, { ignorePaths: ["package.json", "dist/index.js"] })).toThrow(
      /zero members/,
    );
  });

  test("a real scan reports how many members it actually read", () => {
    const archive = tarball("counted", {
      "package.json": JSON.stringify({ name: "counted", version: "1.0.0" }),
      "dist/a.js": "export const a = 1;",
      "dist/b.js": "export const b = 2;",
    });
    expect(scanPublishedArtifact(archive).membersScanned).toBe(3);
  });

  test("the BIGGEST member is read, not skipped — a 6 MB bundle is where the list lives", () => {
    // The incident's inventory shipped inside `dist/index.js`. A scanner with a
    // 5 MB ceiling declines to read exactly the file most likely to be carrying
    // it, and bundles and `.map` files routinely run past any such cap.
    const archive = tarball("oversize", {
      "package.json": JSON.stringify({ name: "victim", version: "0.1.0", files: ["dist"] }),
      "dist/index.js": `var D=${JSON.stringify(portfolio(177))};\n//${"x".repeat(6 * 1024 * 1024)}\n`,
    });
    const report = scanPublishedArtifact(archive);
    expect(report.ok).toBe(false);
    expect(report.unreadable).toEqual([]);
    const finding = report.findings.find((entry) => entry.kind === "domain");
    expect(finding?.path).toBe("dist/index.js");
    expect(finding?.count).toBe(177);
  }, 120_000);

  test("a member that could NOT be read fails the scan instead of being a footnote", () => {
    // Same vacuity rule, one member at a time: an undecoded file has not been
    // cleared, so it cannot contribute to a clean verdict.
    const archive = tarball("unreadable", {
      "package.json": JSON.stringify({ name: "victim", version: "0.1.0" }),
      "dist/index.js": `var D=${JSON.stringify(portfolio(177))};`,
    });
    const report = scanPublishedArtifact(archive, { maxMemberBytes: 512 });
    expect(report.ok).toBe(false);
    expect(report.findings).toEqual([]);
    expect(report.unreadable.map((member) => member.path)).toContain("dist/index.js");
    const text = formatArtifactScanReport(report);
    expect(text).toContain("FAIL");
    expect(text).toContain("could not be read");
  });
});

// --- precision ---

describe("it does not cry wolf on ordinary code", () => {
  test("dotted identifiers and member access are not domains", () => {
    // The first draft of this guard reported every one of these and failed on
    // the contracts repo itself. A mandatory gate that fires on compliant repos
    // gets switched off, which protects exactly as much as a gate that cannot
    // fail.
    const source = [
      "agents.list", "agents.get", "agents.heartbeat", "config.replace",
      "pool.connectionTimeoutMillis", "manifest.kitVersion", "value.toUpperCase",
      "index.ts", "README.md", "schema.json", "styles.css", "run.sh",
    ]
      .map((identifier) => `"${identifier}"`)
      .join(",");
    const counts = inventoryCounts(`const surface = [${source}];`);
    expect(counts.domain).toEqual([]);
    expect(counts.host).toEqual([]);
  });

  test("specification-reserved names are excluded by rule", () => {
    const reserved = [
      ...Array.from({ length: 30 }, (_, i) => `host-${i}.example.com`),
      ...Array.from({ length: 30 }, (_, i) => `host-${i}.test`),
      ...Array.from({ length: 30 }, (_, i) => `svc-${i}.localhost`),
    ]
      .map((name) => `"${name}"`)
      .join(",");
    const counts = inventoryCounts(`[${reserved}]`);
    expect(counts.domain).toEqual([]);
    expect(counts.host).toEqual([]);
  });

  test("private, loopback, and documentation IP space is excluded BY RULE", () => {
    // This test used to prove nothing: the fixture was bare unquoted tokens and
    // `inventoryCounts` defaults to `codeLike: true`, which reads no bare
    // tokens at all — so the count was 0 whatever the reservation rule did.
    // Stubbing `isReservedIpv4` to `return false` left the file green.
    //
    // It now reads them from a position the scanner actually counts, and it
    // carries a POSITIVE CONTROL in the identical shape, so the assertion
    // distinguishes the rule from the plumbing.
    const reserved = [
      ...Array.from({ length: 8 }, (_, i) => `10.0.0.${i}`),
      ...Array.from({ length: 8 }, (_, i) => `192.168.1.${i}`),
      ...Array.from({ length: 8 }, (_, i) => `127.0.0.${i}`),
      ...Array.from({ length: 8 }, (_, i) => `192.0.2.${i}`), // RFC 5737 TEST-NET-1
      ...Array.from({ length: 8 }, (_, i) => `203.0.113.${i}`), // TEST-NET-3
      ...Array.from({ length: 8 }, (_, i) => `169.254.1.${i}`), // link-local
      ...Array.from({ length: 8 }, (_, i) => `172.16.0.${i}`), // private
    ];
    const public_ = Array.from({ length: 40 }, (_, i) => `51.15.${i}.10`);

    for (const [label, options] of [
      ["quoted, code member", { codeLike: true }],
      ["bare, prose member", { codeLike: false }],
    ] as const) {
      const render = (list: string[]) =>
        options.codeLike ? `const fleet=[${list.map((a) => `"${a}"`).join(",")}];` : list.join("\n");

      // The rule under test.
      expect(inventoryCounts(render(reserved), options).ip, `reserved / ${label}`).toEqual([]);
      // The positive control: same shape, same position, public addresses.
      expect(inventoryCounts(render(public_), options).ip.length, `public / ${label}`).toBe(40);
    }
  });

  test("member access on a real TLD is not a domain portfolio", () => {
    // `.name`, `.host`, `.info` and every ISO language code are real TLDs, so a
    // rule that counts any dotted lowercase run reports `node.name` as a
    // domain. Measured over node_modules, such a rule finds 139 distinct
    // "domains" in TypeScript's bundle and 25 in one zod locale file — a
    // mandatory gate that fires on every compliant repo gets switched off.
    const receivers = ["node", "callee", "property", "method", "option", "state", "spec", "exports", "inst", "def"];
    const properties = ["name", "host", "info", "email", "store", "int", "in", "is", "at", "to"];
    const expressions = receivers.flatMap((receiver) =>
      properties.map((property) => `      return ${receiver}.${property}\n`),
    );
    const locales = ["vi", "ua", "tr", "th", "sv", "ru", "pl", "no", "it", "id"].map(
      (locale) => `  exports.${locale},\n`,
    );
    const counts = inventoryCounts([...expressions, ...locales].join(""));
    expect(counts.domain).toEqual([]);
    expect(counts.host).toEqual([]);
  });

  test("this repository's own packed artifact passes", () => {
    // Dogfooding, and the reason the registry-suffix table is stored by label:
    // written as dotted strings it was itself a 40-entry domain inventory.
    const packed = Bun.spawnSync(
      ["bun", "pm", "pack", "--destination", workspace, "--ignore-scripts", "--quiet"],
      { cwd: join(import.meta.dir, ".."), stdout: "pipe", stderr: "pipe" },
    );
    expect(packed.exitCode).toBe(0);
    const name = new TextDecoder().decode(packed.stdout).trim();
    const report = scanPublishedArtifact(name.startsWith("/") ? name : join(workspace, name));
    expect(formatArtifactScanReport(report)).toContain("pass");
    expect(report.findings).toEqual([]);
    // Bounded low deliberately: `verify:release` packs after `rm -rf dist`, so
    // the member count legitimately differs between a bare pack and a full one.
    // The anti-vacuity property is that it read the artifact at all, and the
    // empty-archive test above is what pins that.
    expect(report.membersScanned).toBeGreaterThan(20);
  }, 120_000);
});

// --- detectors ---

describe("asset kinds", () => {
  test("hosts count machine names, not the domain itself — one list is not two findings", () => {
    const hosts = Array.from({ length: 40 }, (_, i) => `"node-${i}.fleet-example-corp.com"`).join(",");
    const counts = inventoryCounts(`[${hosts}]`);
    expect(counts.host.length).toBe(40);
    expect(counts.domain).toEqual(["fleet-example-corp.com"]);
  });

  test("an email inventory is counted once, not also as a domain inventory", () => {
    const emails = Array.from({ length: 30 }, (_, i) => `"person${i}@customer-list-corp.com"`).join(",");
    const counts = inventoryCounts(`[${emails}]`);
    expect(counts.email.length).toBe(30);
    // The address's own domain is not independent evidence; counting it again
    // would let one contact list trip two detectors.
    expect(counts.domain).toEqual([]);
    expect(counts.host).toEqual([]);
  });

  test("public IP inventories are detected", () => {
    const archive = tarball("machines", {
      "package.json": JSON.stringify({ name: "machines", version: "1.0.0" }),
      "dist/fleet.js": Array.from({ length: 30 }, (_, i) => `"51.15.${i}.10"`).join(","),
    });
    const report = scanPublishedArtifact(archive);
    expect(report.findings.some((finding) => finding.kind === "ip")).toBe(true);
  });

  test("registrableDomain collapses subdomains and respects registry second levels", () => {
    expect(registrableDomain("a.b.brand-example.com")).toBe("brand-example.com");
    expect(registrableDomain("shop.brand-example.co.uk")).toBe("brand-example.co.uk");
  });

  test("the TLD table is IANA's full list, not a hand-picked sample", () => {
    // The first version enumerated ~310 TLDs by hand and recognized 40 of the
    // 177 domains in the real disclosed artifact (22.6%). A guard against
    // disclosure cannot rest on a guessed subset of the namespace.
    expect(RECOGNIZED_TLDS.size).toBeGreaterThan(1300);
    expect(IANA_TLD_SNAPSHOT).toMatch(/^\d{10}$/);

    // Breadth: TLDs the hand-written list omitted and the portfolio used.
    for (const tld of ["com", "net", "org", "uk", "de", "io", "xyz", "cloud", "academy", "agency", "art", "cafe", "care", "chat", "city", "club", "coach", "coffee"]) {
      expect(isRecognizedTld(tld), tld).toBe(true);
    }
    // Case-insensitive: DNS is, and requiring lowercase let one capital letter
    // per entry defeat the guard.
    expect(isRecognizedTld("COM")).toBe(true);

    // Not TLDs at all — no exclusion needed.
    for (const word of ["list", "get", "json", "ts", "js", "css"]) {
      expect(isRecognizedTld(word), word).toBe(false);
    }
  });

  test("every collision exclusion is a REAL TLD, deliberately given up", () => {
    // The first version's exclusion list was largely fiction: most entries were
    // never delegated, so "excluding" them changed nothing while reading as a
    // considered trade-off. Each entry here is a real TLD this guard chooses
    // not to count, and that choice is a stated blind spot.
    expect(PROGRAMMING_COLLISION_TLDS.size).toBeGreaterThan(0);
    for (const tld of PROGRAMMING_COLLISION_TLDS) {
      expect(isRecognizedTld(tld), `${tld} must be excluded, not merely absent`).toBe(false);
    }
    // Measured collisions from Hasna's own `<noun>.<verb>` operation grammar.
    for (const tld of ["read", "next", "health", "post", "id", "map", "link"]) {
      expect(PROGRAMMING_COLLISION_TLDS.has(tld), tld).toBe(true);
    }
  });
});

// --- encodings ---

describe("an inventory is not made invisible by how it is written", () => {
  test("a joined string literal is still a list", () => {
    // `"a.com,b.com,…".split(",")` is the same 177 domains as the array
    // literal, and a rule that only recognised a literal which IS a hostname
    // could not see any of them.
    const joined = portfolio(177).join(",");
    expect(inventoryCounts(`var D="${joined}".split(",");`).domain.length).toBe(177);
    // One line, so only the literal rule can see this one.
    expect(inventoryCounts(`var D=\`${portfolio(40).join(" ")}\`.split(" ");`).domain.length).toBe(40);
  });

  test("a literal that MENTIONS an asset in a sentence is not a list", () => {
    const sentence = `"Contact us about ${portfolio(1)[0]} before renewal"`;
    expect(inventoryCounts(sentence).domain).toEqual([]);
  });

  test("an unquoted markdown table is still a list", () => {
    const rows = portfolio(60).map((domain, index) => `| ${domain} | Registrar ${index} | 2027 |`);
    const table = ["| Domain | Registrar | Renewal |", "|---|---|---|", ...rows].join("\n");
    const archive = tarball("markdown-inventory", {
      "package.json": JSON.stringify({ name: "docs", version: "1.0.0" }),
      "docs/portfolio.md": table,
    });
    const report = scanPublishedArtifact(archive);
    expect(report.ok).toBe(false);
    expect(report.findings.find((finding) => finding.kind === "domain")?.path).toBe("docs/portfolio.md");
  });

  test("a CSV column is still a list", () => {
    const csv = ["domain,owner,expires", ...portfolio(60).map((domain, index) => `${domain},team-${index},2027`)].join(
      "\n",
    );
    const archive = tarball("csv-inventory", {
      "package.json": JSON.stringify({ name: "data", version: "1.0.0" }),
      "data/assets.csv": csv,
    });
    const report = scanPublishedArtifact(archive);
    expect(report.ok).toBe(false);
    expect(report.findings.find((finding) => finding.kind === "domain")?.path).toBe("data/assets.csv");
  });

  test("one asset per line is still a list", () => {
    expect(inventoryCounts(portfolio(40).join("\n")).domain.length).toBe(40);
  });

  test("a handful of rows is a coincidence, not a column", () => {
    // A column is what makes a table a table. Below that, an ordinary file that
    // happens to line up two or three names is not reporting a portfolio.
    expect(inventoryCounts(portfolio(3).join("\n")).domain).toEqual([]);
  });
});

// --- a mention is not a list, however many mentions a file makes ---

describe("scattered mentions do not aggregate into an inventory", () => {
  /** What a validator's fixture file looks like: one asset per assertion. */
  function assertions(count: number): string {
    return Array.from({ length: count }, (_, i) => `  expect(isEmail("user${i}@mailtest-${i}.com")).toBe(true);`).join(
      "\n",
    );
  }

  test("a shipped test file of distinct fixture emails passes the gate", () => {
    // Measured on real packages, not imagined: counting a lone quoted asset as
    // a list made `zod@4.4.3` fail on 23 and 24 ordinary validator fixtures in
    // `src/**/tests/string.test.ts`, and `email-validator@2.0.4` on 22 in
    // `test.js`. Clause C makes this gate mandatory and blocking on prepack, so
    // that is `npm publish` refused on a compliant repo with no remedy but a
    // whole-artifact `email` waiver — the gate getting switched off.
    const archive = tarball("fixture-emails", {
      "package.json": JSON.stringify({ name: "validator-ish", version: "1.0.0" }),
      "src/is-email.test.ts": `describe("isEmail", () => {\n${assertions(30)}\n});\n`,
    });
    const report = scanPublishedArtifact(archive);
    expect(report.findings).toEqual([]);
    expect(report.ok).toBe(true);
    expect(inventoryCounts(assertions(30)).email).toEqual([]);
  });

  test("a lone quoted asset does not join the other lone assets in its file", () => {
    const mentions = portfolio(40).map((domain) => `const client = connect("${domain}");`).join("\n");
    expect(inventoryCounts(mentions).domain).toEqual([]);
    expect(inventoryCounts(`const primary = "${portfolio(1)[0]}";`).domain).toEqual([]);
  });

  test("but the SAME entries written as a list are still a list", () => {
    // The fix is "require the list shape", not "stop counting". An array of the
    // very entries the assertions mentioned is an inventory, before and after.
    const emails = Array.from({ length: 30 }, (_, i) => `user${i}@mailtest-${i}.com`);
    expect(inventoryCounts(JSON.stringify(emails)).email.length).toBe(30);
    expect(inventoryCounts(portfolio(40).map((domain) => `"${domain}"`).join(",\n")).domain.length).toBe(40);
  });

  test("a run of sibling literals is what makes an array an array", () => {
    // Five in a row is a list; the same five spread across five expressions is
    // five mentions. The boundary is stated rather than emergent.
    const five = portfolio(5, "run-brand");
    expect(inventoryCounts(`[${five.map((domain) => `"${domain}"`).join(",")}]`).domain.length).toBe(5);
    expect(inventoryCounts(five.map((domain) => `use("${domain}");`).join("\n")).domain).toEqual([]);
  });
});

// --- clause B names endpoint catalogues, so endpoints have to be visible ---

describe("an endpoint catalogue is not hidden by writing it as endpoints", () => {
  const endpoints = Array.from({ length: 100 }, (_, i) => `svc-${i}.fleet-example-corp.com`);

  test("URL, scheme-relative, host:port and userinfo forms all count the host", () => {
    // An endpoint catalogue is written as endpoints. Counting only the bare
    // name let the whole category — named in clause B — ship undetected: 100
    // `https://…/api/v1` entries counted zero while the same 100 bare names
    // counted 100.
    const forms: Record<string, string[]> = {
      bare: endpoints,
      url: endpoints.map((host) => `https://${host}/api/v1`),
      schemeRelative: endpoints.map((host) => `//${host}/api/v1`),
      hostPort: endpoints.map((host) => `${host}:443`),
      userinfo: endpoints.map((host) => `https://svc:token@${host}:8443/v1?trace=1#top`),
    };
    for (const [form, entries] of Object.entries(forms)) {
      expect(inventoryCounts(JSON.stringify(entries)).host.length, `${form} (array)`).toBe(100);
      expect(inventoryCounts(entries.join("\n")).host.length, `${form} (one per line)`).toBe(100);
    }
  });

  test("a packed artifact carrying a URL catalogue fails the scan", () => {
    const archive = tarball("endpoint-catalogue", {
      "package.json": JSON.stringify({ name: "fleet", version: "1.0.0", files: ["dist"] }),
      "dist/index.js": `var E=${JSON.stringify(endpoints.map((host) => `https://${host}/api/v1`))};export{E};`,
    });
    const report = scanPublishedArtifact(archive);
    expect(report.ok).toBe(false);
    const finding = report.findings.find((entry) => entry.kind === "host");
    expect(finding?.path).toBe("dist/index.js");
    expect(finding?.count).toBe(100);
  });

  test("a catalogue written as keyed records is still one list", () => {
    // `{"edge-1": {"description": "…", "host": "…", "port": 443}, …}` is the
    // shape a service table actually takes. The keys and the descriptions sit
    // between the entries; they are labels, and a list of pairs is one list.
    const table = Object.fromEntries(
      endpoints.map((host, index) => [`edge-${index}`, { description: `Edge node ${index}`, host, port: 443 }]),
    );
    expect(inventoryCounts(JSON.stringify(table, null, 2)).host.length).toBe(100);
  });

  test("a path is only stripped where a scheme says the piece is a URL", () => {
    // This fixture was doubly incapable of firing: FOUR quoted literals against
    // a MIN_LITERAL_RUN of 5, so no run could form, and none of its last labels
    // (`list`, `replace`, `json`, `md`) is a recognized TLD. Mutating
    // `hostComponent` to strip paths unconditionally passed the whole suite.
    //
    // It now uses six entries under a REAL TLD, so the only thing standing
    // between it and a finding is the rule under test.
    const memberAccess = [
      "agents.wiki/get", "config.wiki/all", "schema.wiki/definitions",
      "records.wiki/list", "session.wiki/close", "tenant.wiki/create",
    ]
      .map((identifier) => `"${identifier}"`)
      .join(",");
    const counts = inventoryCounts(`const surface = [${memberAccess}];`);
    expect(counts.domain).toEqual([]);
    expect(counts.host).toEqual([]);

    // POSITIVE CONTROL: the same six with a scheme ARE endpoints, and the path
    // is stripped. Without this the assertion above cannot tell the rule from
    // the plumbing.
    const endpoints = [
      "https://agents.wiki/get", "https://config.wiki/all", "https://schema.wiki/definitions",
      "https://records.wiki/list", "https://session.wiki/close", "https://tenant.wiki/create",
    ]
      .map((url) => `"${url}"`)
      .join(",");
    expect(inventoryCounts(`const surface = [${endpoints}];`).domain.length).toBeGreaterThanOrEqual(5);
  });
});

describe("thresholds and waivers", () => {
  test("a mention is not an inventory", () => {
    const few = portfolio(DEFAULT_INVENTORY_THRESHOLDS.domain - 1)
      .map((domain) => `"${domain}"`)
      .join(",");
    expect(inventoryCounts(`[${few}]`).domain.length).toBeLessThan(DEFAULT_INVENTORY_THRESHOLDS.domain);
    const archive = tarball("mention", {
      "package.json": JSON.stringify({ name: "mention", version: "1.0.0" }),
      "docs/partners.md": few,
    });
    expect(scanPublishedArtifact(archive).ok).toBe(true);
  });

  test("a waiver suppresses the failure but keeps the finding on the record", () => {
    const archive = tarball("waived", {
      "package.json": JSON.stringify({ name: "waived", version: "1.0.0" }),
      "dist/suffixes.js": JSON.stringify(portfolio(50)),
    });
    const report = scanPublishedArtifact(archive, { waivedKinds: ["domain"] });
    expect(report.findings.some((finding) => finding.kind === "domain")).toBe(false);
    // Suppressed, never erased: a waiver that hid the evidence would make the
    // audit trail worse than no waiver at all.
    expect(report.waived.some((finding) => finding.kind === "domain")).toBe(true);
    expect(formatArtifactScanReport(report)).toContain("waived");
  });

  test("an EXPIRED waiver excuses nothing", () => {
    const future = new Date(Date.now() + 86_400_000).toISOString();
    const past = new Date(Date.now() - 86_400_000).toISOString();
    const dir = join(workspace, "waiver-manifest");
    mkdirSync(dir, { recursive: true });
    const manifestPath = join(dir, "hasna.contract.json");
    writeFileSync(
      manifestPath,
      JSON.stringify({
        metadata: {
          conformance: {
            waivedAssetInventories: [
              { kind: "domain", reason: "Public suffix list.", reviewedBy: "platform", expiresAt: future },
              { kind: "email", reason: "Sample contacts.", reviewedBy: "platform", expiresAt: past },
            ],
          },
        },
      }),
    );
    const resolved = resolveAssetInventoryWaivers(manifestPath);
    expect(resolved.kinds).toEqual(["domain"]);
    // The refusal stays on the record rather than vanishing.
    expect(resolved.notes.join(" ")).toMatch(/email/);
  });

  test("a lowered threshold makes an otherwise-clean artifact fail", () => {
    const archive = tarball("threshold", {
      "package.json": JSON.stringify({ name: "threshold", version: "1.0.0" }),
      "docs/partners.md": portfolio(5).map((domain) => `"${domain}"`).join(","),
    });
    expect(scanPublishedArtifact(archive).ok).toBe(true);
    expect(scanPublishedArtifact(archive, { thresholds: { domain: 3 } }).ok).toBe(false);
  });

  // The manifest field, CONTRACT.md's instructions, and the enforcement have to
  // be the same waiver. A documented escape hatch nothing reads leaves a repo
  // that legitimately ships public reference data no recourse but to unwire the
  // gate — the failure clause C exists to prevent.
  function manifestWith(name: string, waivers: unknown[]): string {
    const root = join(workspace, name);
    mkdirSync(root, { recursive: true });
    const file = join(root, "hasna.contract.json");
    writeFileSync(file, JSON.stringify({ metadata: { conformance: { waivedAssetInventories: waivers } } }));
    return file;
  }

  const publicData = { kind: "domain", reason: "Ships the ICANN public-suffix table.", reviewedBy: "release-review" };

  test("a manifest-declared, unexpired waiver moves the finding onto the record", () => {
    const manifest = manifestWith("waiver-live", [{ ...publicData, expiresAt: "2999-01-01T00:00:00Z" }]);
    const resolved = resolveAssetInventoryWaivers(manifest);
    expect(resolved.kinds).toEqual(["domain"]);
    expect(resolved.notes.join(" ")).toContain("reviewed by release-review");

    const archive = tarball("waiver-live-artifact", {
      "package.json": JSON.stringify({ name: "reference-data", version: "1.0.0" }),
      "dist/suffixes.js": JSON.stringify(portfolio(50)),
    });
    const report = scanPublishedArtifact(archive, { waivedKinds: resolved.kinds });
    expect(report.ok).toBe(true);
    expect(report.waived.some((finding) => finding.kind === "domain")).toBe(true);
  });

  test("an expired waiver stops applying on its own", () => {
    const manifest = manifestWith("waiver-expired", [{ ...publicData, expiresAt: "2020-01-01T00:00:00Z" }]);
    const resolved = resolveAssetInventoryWaivers(manifest);
    expect(resolved.kinds).toEqual([]);
    expect(resolved.notes.join(" ")).toContain("expired");

    const archive = tarball("waiver-expired-artifact", {
      "package.json": JSON.stringify({ name: "reference-data", version: "1.0.1" }),
      "dist/suffixes.js": JSON.stringify(portfolio(50)),
    });
    expect(scanPublishedArtifact(archive, { waivedKinds: resolved.kinds }).ok).toBe(false);
  });

  test("a waiver nobody reviewed is not a reviewed exception", () => {
    const manifest = manifestWith("waiver-unsigned", [
      { kind: "domain", reason: "Ships the ICANN public-suffix table.", expiresAt: "2999-01-01T00:00:00Z" },
    ]);
    const resolved = resolveAssetInventoryWaivers(manifest);
    expect(resolved.kinds).toEqual([]);
    expect(resolved.notes.join(" ")).toContain("no reviewer");
  });

  test("a repo with no manifest simply has no waivers", () => {
    expect(resolveAssetInventoryWaivers(join(workspace, "absent", "hasna.contract.json"))).toEqual({
      kinds: [],
      notes: [],
    });
  });

  test("the CLI reads the waiver the contract tells a repo to declare", () => {
    // End to end: `contracts artifact-scan <tarball> --manifest <file>` is what
    // a repo's `scan:artifact` script runs from prepack.
    const archive = tarball("waiver-cli-artifact", {
      "package.json": JSON.stringify({ name: "reference-data", version: "1.0.2" }),
      "dist/suffixes.js": JSON.stringify(portfolio(50)),
    });
    const live = manifestWith("waiver-cli-live", [{ ...publicData, expiresAt: "2999-01-01T00:00:00Z" }]);
    const expired = manifestWith("waiver-cli-expired", [{ ...publicData, expiresAt: "2020-01-01T00:00:00Z" }]);

    const run = (manifest: string) =>
      Bun.spawnSync(["bun", "run", "src/cli/index.ts", "artifact-scan", archive, "--manifest", manifest, "--json"], {
        cwd: join(import.meta.dir, ".."),
        stdout: "pipe",
        stderr: "pipe",
      });

    const waived = run(live);
    expect(waived.exitCode).toBe(0);
    const waivedReport = JSON.parse(waived.stdout.toString());
    expect(waivedReport.ok).toBe(true);
    expect(waivedReport.waived.some((finding: { kind: string }) => finding.kind === "domain")).toBe(true);

    const enforced = run(expired);
    expect(enforced.exitCode).toBe(1);
    const enforcedReport = JSON.parse(enforced.stdout.toString());
    expect(enforcedReport.ok).toBe(false);
    expect(enforcedReport.waiverNotes.join(" ")).toContain("expired");
  }, 60_000);
});

describe("fixes that had no regression coverage", () => {
  test("thresholds are CLAMPED — the gate cannot be switched off through its own flags", () => {
    // `--domain-threshold 1000000` returned exit 0 on the real leaked artifact
    // while `published_artifact_gate` still passed, because the gate inspects
    // the script graph and never the flags.
    const archive = tarball("threshold-ceiling", {
      "package.json": JSON.stringify({ name: "ceiling", version: "1.0.0" }),
      "dist/index.js": JSON.stringify(oneBrandPortfolio(40)),
    });
    expect(scanPublishedArtifact(archive).ok).toBe(false);

    // Over the ceiling: refused by name.
    for (const domain of [1_000_000, 41, 1e9]) {
      expect(() => scanPublishedArtifact(archive, { thresholds: { domain } }), String(domain)).toThrow(
        /ceiling/,
      );
    }
    // Not a usable number at all: refused before the ceiling is consulted.
    for (const domain of [Number.POSITIVE_INFINITY, Number.NaN, 0, -1]) {
      expect(() => scanPublishedArtifact(archive, { thresholds: { domain } }), String(domain)).toThrow(
        /positive number/,
      );
    }
    // Tightening is always allowed; only loosening past the ceiling is refused.
    expect(() => scanPublishedArtifact(archive, { thresholds: { domain: 5 } })).not.toThrow();
    // Twice the default, not five times it: clause C never inspects the flags,
    // so a repo can bake a loosened threshold into its scan script and still
    // pass conformance. 2x leaves room to tune; it leaves none to switch off.
    expect(MAX_INVENTORY_THRESHOLDS.domain).toBe(2 * DEFAULT_INVENTORY_THRESHOLDS.domain);
    expect(MAX_INVENTORY_THRESHOLDS.domain).toBe(40);
  });

  test("the redaction salt is PER RUN, not a constant", () => {
    // A fixed salt makes every digest a stable identifier for the value across
    // every report ever published — a rainbow table over candidate names, and
    // the same finding correlatable between two artifacts. The salt must differ per
    // process, so the same input digests differently in a separate run.
    const archive = tarball("salt-per-run", {
      "package.json": JSON.stringify({ name: "salted", version: "1.0.0" }),
      "dist/index.js": JSON.stringify(oneBrandPortfolio(40)),
    });
    const here = scanPublishedArtifact(archive).findings.flatMap((finding) => finding.sample);
    expect(here.length).toBeGreaterThan(0);

    const script = `
      const { scanPublishedArtifact } = await import(${JSON.stringify(join(import.meta.dir, "..", "src", "artifact-scan.ts"))});
      const report = scanPublishedArtifact(${JSON.stringify(archive)});
      console.log(JSON.stringify(report.findings.flatMap((f) => f.sample)));
    `;
    const scriptPath = join(workspace, "salt-probe.ts");
    writeFileSync(scriptPath, script);
    const other = Bun.spawnSync(["bun", "run", scriptPath], { stdout: "pipe", stderr: "pipe" });
    expect(other.exitCode).toBe(0);
    const elsewhere = JSON.parse(new TextDecoder().decode(other.stdout).trim()) as string[];

    // Same shape, different digests: nothing about the value survives the run.
    expect(elsewhere.length).toBe(here.length);
    expect(elsewhere).not.toEqual(here);
    for (const sample of [...here, ...elsewhere]) expect(sample).toMatch(/^<(?:domain|host|ip|email):[0-9a-f]{8}>$/);
  });

  test("a SHORT quoted token does not break the run", () => {
    // `{3,}` left a 2-character key unmatched, its quotes fell into the run
    // glue (which excludes `"`), and the run broke at every element.
    const portfolio = oneBrandPortfolio(40);
    for (const key of ["id", "x", "idx", "ключ"]) {
      const rows = portfolio.map((domain, index) => `{"${key}":${index},"domain":"${domain}"}`).join(",");
      expect(inventoryCounts(`[${rows}]`).domain.length, `key "${key}"`).toBeGreaterThanOrEqual(38);
    }
  });

  test("a four-component VERSION string is not an address", () => {
    // Round 3 removed only the bare-token path; the quoted path kept the exact
    // same false-positive class. Real packages bundling browserslist or
    // node-releases data (playwright: 44, node-releases: 50) failed their own
    // mandatory prepack gate with a finding nobody could action.
    // 244+i stays inside 0-255 for all 30, so every one of these is a valid
    // dotted quad. An earlier version ran to 273 and silently lost 18 of them
    // to `isReservedIpv4`, overstating the fixture's strength 2.5x.
    const versions = Array.from({ length: 30 }, (_, i) => `{"v8":"11.0.${200 + i}.1"}`).join(",");
    expect(inventoryCounts(`[${versions}]`).ip).toEqual([]);
    // `node` included deliberately: node-releases keys its version table on it.
    for (const key of ["version", "node", "chrome", "electron", "engine", "v8"]) {
      const rows = Array.from({ length: 30 }, (_, i) => `{"${key}":"11.0.${200 + i}.1"}`).join(",");
      expect(inventoryCounts(`[${rows}]`).ip, key).toEqual([]);
    }

    // Compound address spellings must all still count. An exact-match address
    // WHITELIST silently dropped every one of these, so a 40-record EC2
    // `describe-instances` export scanned clean.
    for (const key of [
      "ipAddress", "ip_address", "public_ip", "publicIp", "PublicIpAddress",
      "privateIp", "host_ip", "ansible_host", "tailscale_ip", "ips", "addresses", "v4",
    ]) {
      const rows = Array.from({ length: 30 }, (_, i) => `{"${key}":"51.15.${i}.10"}`).join(",");
      expect(inventoryCounts(`[${rows}]`).ip.length, key).toBe(30);
    }

    // A hostname->IP map counts on BOTH kinds. Under the whitelist it scored
    // zero on all four, because each address broke the hostname run as well as
    // being suppressed itself.
    const hostMap: Record<string, string> = {};
    for (let index = 0; index < 30; index += 1) {
      hostMap[`node-${index}.fleet-example-corp.com`] = `51.15.${index}.10`;
    }
    const mapCounts = inventoryCounts(JSON.stringify(hostMap));
    expect(mapCounts.ip.length).toBe(30);
    expect(mapCounts.host.length).toBe(30);

    // But an address under an ADDRESS key, or with no key at all, still counts:
    // a bare array is the shape a fleet list actually takes.
    const bare = Array.from({ length: 30 }, (_, i) => `"51.15.${i}.10"`).join(",");
    expect(inventoryCounts(`const fleet=[${bare}];`).ip.length).toBe(30);
    const keyed = Array.from({ length: 30 }, (_, i) => `{"ip":"51.15.${i}.10"}`).join(",");
    expect(inventoryCounts(`[${keyed}]`).ip.length).toBe(30);
  });

  test("a dotted quad with LEADING ZEROS is not presentation format", () => {
    // Binary members are decoded as latin1 and scanned, which is correct for
    // domains — they need a real TLD, so noise cannot reach a finding. It was
    // never true for IPs: a 135 MB native addon produced 153 "addresses", 147
    // of them zero-padded, and the exposure scaled with binary size.
    const padded = Array.from({ length: 30 }, (_, i) => `"01.52.0${i % 10}.53"`).join(",");
    expect(inventoryCounts(`const x=[${padded}];`).ip).toEqual([]);
    expect(inventoryCounts(Array.from({ length: 30 }, (_, i) => `011.012.012.1${i}`).join("\n"), { codeLike: false }).ip).toEqual([]);

    // The same addresses without padding are ordinary public addresses.
    const clean = Array.from({ length: 30 }, (_, i) => `"1.52.${i}.53"`).join(",");
    expect(inventoryCounts(`const x=[${clean}];`).ip.length).toBe(30);
  });

  test("IPv4 is read from VALUES only — not from SVG path data in a bundle", () => {
    // `@hasna/tables` failed on 26 coordinate pairs in a minified Vite bundle.
    // The comment claiming a dotted quad "cannot be confused with code" was
    // measurably false, and every app shipping an icon set would have hit it.
    // Real path data: coordinate runs delimited by spaces, which is what makes
    // them look like dotted quads to a `\b`-anchored matcher. (An earlier
    // fixture wrote `M12.3.5.7` with no delimiter — `\b` never matched after
    // `M`, so it reproduced nothing.)
    const svg = Array.from(
      { length: 30 },
      (_, index) => `c ${index + 10}.${index + 2}.${index + 4}.${index + 6} 1 2`,
    ).join(" ");
    const bundle = `const icons=[${JSON.stringify(svg)}];export{icons};`;
    expect(inventoryCounts(bundle, { codeLike: true }).ip).toEqual([]);
    // The fixture really does look like addresses to a bare-token matcher —
    // otherwise this test would pass for the wrong reason.
    expect(inventoryCounts(bundle, { codeLike: false }).ip.length).toBeGreaterThanOrEqual(25);

    // A genuine address inventory is still caught, in a value position.
    const real = Array.from({ length: 30 }, (_, index) => `"51.15.${index}.10"`).join(",");
    expect(inventoryCounts(`const fleet=[${real}];`, { codeLike: true }).ip.length).toBe(30);
  });
});

describe("escape decoding", () => {
  const B = "\\";

  test("13 shapes decode exactly, with no over-decoding", () => {
    // Every branch of the decoder, including the ones only `\n` used to pin.
    // Over-decoding is the failure that matters as much as under-decoding: if
    // `\\n` became a newline, a scanner would read structure that the runtime
    // never sees.
    const cases: Array<[string, string, string]> = [
      ["newline", `a${B}nb`, "a\nb"],
      ["escaped backslash stays literal", `a${B}${B}nb`, `a${B}nb`],
      ["four backslashes become two", `a${B}${B}${B}${B}b`, `a${B}${B}b`],
      ["escaped quote", `a${B}"b`, 'a"b'],
      ["escaped apostrophe", `a${B}'b`, "a'b"],
      ["escaped backtick", `a${B}\`b`, "a`b"],
      ["tab", `a${B}tb`, "a\tb"],
      ["carriage return", `a${B}rb`, "a\rb"],
      ["unknown escape passes through", `a${B}qb`, `a${B}qb`],
      ["trailing lone backslash", `ab${B}`, `ab${B}`],
      ["\\uXXXX", `a${B}u002eb`, "a.b"],
      ["\\u{...}", `a${B}u{2e}b`, "a.b"],
      ["\\xXX", `a${B}x2eb`, "a.b"],
    ];
    for (const [label, input, expected] of cases) {
      expect(decodeEscapes(input), label).toBe(expected);
    }
  });

  test("percent and HTML entities decode independently of backslashes", () => {
    expect(decodeEscapes("a%2eb")).toBe("a.b");
    expect(decodeEscapes("a&#x2e;b")).toBe("a.b");
    expect(decodeEscapes("a&#46;b")).toBe("a.b");
    // An out-of-range code point is left alone rather than throwing.
    expect(decodeEscapes("a&#1114112;b")).toBe("a&#1114112;b");
  });
});

// --- clause C: the prepack gate ---

function conformanceRepo(name: string, pkg: Record<string, unknown>, manifestExtra: Record<string, unknown> = {}): string {
  const root = join(workspace, name);
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: "widget", version: "1.0.0", bin: { widget: "d.js" }, ...pkg }));
  writeFileSync(join(root, "d.js"), "");
  writeFileSync(
    join(root, "hasna.contract.json"),
    JSON.stringify({
      schema: "hasna.service_contract.v1",
      name: "widget",
      class: "library",
      contractVersion: "v1",
      kitVersion: "0.8.0",
      description: "Test fixture",
      bins: ["widget"],
      hosting: ["user-hosted"],
      serviceSurfaces: [
        { name: "sdk", kind: "sdk", status: "supported", authMode: "none", exportSubpath: "." },
        { name: "cli", kind: "cli", status: "supported", bin: "widget", authMode: "local-only" },
      ],
      metadata: {
        conformance: {
          waivedSurfaces: [
            { kind: "api", reason: "Test fixture has no HTTP boundary." },
            { kind: "mcp", reason: "Test fixture has no MCP boundary." },
          ],
        },
        ...manifestExtra,
      },
    }),
  );
  return root;
}

function gate(root: string) {
  const report = runRepoConformance(root, { skipNoCloudScan: true, env: {} });
  return report.checks.find((check) => check.id === "published_artifact_gate")!;
}

describe("published_artifact_gate (clause C)", () => {
  const release = { release: { artifactScan: { script: "scan:artifact" } } };

  test("passes when prepack transitively reaches the declared scan", () => {
    const root = conformanceRepo(
      "gate-pass",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run verify:release", "verify:release": "bun test && bun run scan:artifact", "scan:artifact": "contracts artifact-scan" } },
      release,
    );
    const check = gate(root);
    expect(check.status).toBe("pass");
    expect(check.detail).toContain("scan:artifact");
  });

  test("FAILS when the scan exists but prepack never reaches it", () => {
    // "A hook bypassable by publishing directly is not a hook." A scan wired
    // only into a custom script runs when someone remembers to call it.
    const root = conformanceRepo(
      "gate-orphan",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun test", "scan:artifact": "contracts artifact-scan" } },
      release,
    );
    const check = gate(root);
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("does not reach");
  });

  test("FAILS when there is no prepack at all", () => {
    const root = conformanceRepo(
      "gate-no-prepack",
      { exports: { ".": "./d.js" }, scripts: { "verify:release": "bun run scan:artifact", "scan:artifact": "contracts artifact-scan" } },
      release,
    );
    expect(gate(root).status).toBe("fail");
  });

  test("FAILS when the manifest declares a script that does not exist", () => {
    const root = conformanceRepo(
      "gate-ghost",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact" } },
      release,
    );
    const check = gate(root);
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("not a package script");
  });

  test("FAILS when a published package declares no scan at all", () => {
    const root = conformanceRepo("gate-undeclared", { exports: { ".": "./d.js" }, scripts: { prepack: "bun test" } });
    const check = gate(root);
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("metadata.release.artifactScan.script");
  });

  test("FAILS when the gate invokes bunx/npx without a version pin", () => {
    // An unpinned invocation resolves to whatever is newest at publish time, so
    // the gate's own behaviour is not reproducible, and a resolution failure
    // becomes a silent non-run.
    const root = conformanceRepo(
      "gate-unpinned",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": "bunx @hasna/contracts artifact-scan ./pack.tgz" } },
      release,
    );
    const check = gate(root);
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("version pin");

    const pinned = conformanceRepo(
      "gate-pinned",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": "bunx @hasna/contracts@0.8.0 artifact-scan ./pack.tgz" } },
      release,
    );
    expect(gate(pinned).status).toBe("pass");
  });

  test("FAILS when the declared script is a NO-OP", () => {
    // `"scan:artifact": "true"` satisfied every structural condition while
    // scanning nothing — the exact bypass this clause exists to close.
    for (const body of ["true", ":", "exit 0", "echo scanning", "  "]) {
      const root = conformanceRepo(
        `gate-noop-${body.trim().replace(/\W+/g, "-") || "blank"}`,
        { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": body } },
        release,
      );
      const check = gate(root);
      expect(check.status, body).toBe("fail");
      expect(check.detail).toContain("no-op");
    }
  });

  test("a no-op is rejected however it is SPELLED", () => {
    // The earlier pattern matched only bare forms, so appending ` # scan` — or
    // writing `/bin/true` — restored a switched-off gate while still reading
    // as deliberate.
    const noops = [
      "true", "true # scan", ": # scan", "exit 0 # ok", "/bin/true", "/usr/bin/true # x",
      "command true", "builtin :", "echo scanned", "  ", "exec /bin/true",
    ];
    for (const body of noops) {
      const root = conformanceRepo(
        `gate-noop-${Buffer.from(body).toString("hex").slice(0, 10)}`,
        { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": body } },
        release,
      );
      const check = gate(root);
      expect(check.status, JSON.stringify(body)).toBe("fail");
      expect(check.detail).toContain("no-op");
    }

    // A script that is ONLY a comment does nothing. Without comment stripping
    // the head token is `#`, which is not a recognised no-op command, so the
    // script would read as real work.
    const commentOnly = conformanceRepo(
      "gate-comment-only",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": "# TODO: wire the scan" } },
      release,
    );
    expect(gate(commentOnly).status).toBe("fail");
    expect(gate(commentOnly).detail).toContain("no-op");

    // Newline-separated segments: a multi-line script is no-op only if EVERY
    // line is. This branch (`\n` in the split) had no coverage.
    const multilineNoop = conformanceRepo(
      "gate-noop-multiline",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": "true\n: # nothing\nexit 0" } },
      release,
    );
    expect(gate(multilineNoop).status).toBe("fail");

    const multilineReal = conformanceRepo(
      "gate-real-multiline",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": "echo start\ncontracts artifact-scan p.tgz" } },
      release,
    );
    expect(gate(multilineReal).status).toBe("pass");

    // A `#` INSIDE quotes is not a comment. Stripping it would turn a real
    // command into an apparent no-op and fail a compliant repo.
    const quotedHash = conformanceRepo(
      "gate-quoted-hash",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": "contracts artifact-scan './pkg#1.tgz'" } },
      release,
    );
    expect(gate(quotedHash).status).toBe("pass");

    // Real work is still accepted, including work that merely mentions echo.
    for (const body of [
      "contracts artifact-scan p.tgz",
      "bun scripts/scan-artifact.ts",
      "echo scanning && contracts artifact-scan p.tgz",
    ]) {
      const root = conformanceRepo(
        `gate-real-${Buffer.from(body).toString("hex").slice(0, 10)}`,
        { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": body } },
        release,
      );
      expect(gate(root).status, JSON.stringify(body)).toBe("pass");
    }
  });

  test("follows run-s / npm-run-all and npm's implicit pre/post hooks", () => {
    // A resolver that knew only `bun run` reported "does not reach" for
    // conventional layouts that plainly do reach it — and a gate that fails
    // compliant repos gets switched off.
    const viaRunS = conformanceRepo(
      "gate-run-s",
      { exports: { ".": "./d.js" }, scripts: { prepack: "run-s typecheck scan:artifact", typecheck: "tsc --noEmit", "scan:artifact": "contracts artifact-scan p.tgz" } },
      release,
    );
    expect(gate(viaRunS).status).toBe("pass");

    const viaLifecycle = conformanceRepo(
      "gate-prepack-hook",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun test", prepreapck: "noop", preprepack: "bun run scan:artifact", "scan:artifact": "contracts artifact-scan p.tgz" } },
      release,
    );
    expect(gate(viaLifecycle).status).toBe("pass");
  });

  test("the unpinned-bunx check reads the package spec, not the whole line", () => {
    // The previous regex used a line-wide lookahead for `@<digit>`, so a
    // tarball named `pkg@1.tgz` suppressed the finding for an unpinned runner.
    const masked = conformanceRepo(
      "gate-masked",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": "bunx @hasna/contracts artifact-scan pkg@1.tgz" } },
      release,
    );
    const check = gate(masked);
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("version pin");

    const pinned = conformanceRepo(
      "gate-pinned-with-at",
      { exports: { ".": "./d.js" }, scripts: { prepack: "bun run scan:artifact", "scan:artifact": "bunx @hasna/contracts@0.8.0 artifact-scan pkg@1.tgz" } },
      release,
    );
    expect(gate(pinned).status).toBe("pass");
  });

  test("SKIPS a private package — the predicate is 'this repo publishes'", () => {
    const root = conformanceRepo("gate-private", { private: true, exports: { ".": "./d.js" }, scripts: {} });
    const check = gate(root);
    expect(check.status).toBe("skip");
    expect(check.detail).toContain("private");
  });
});
