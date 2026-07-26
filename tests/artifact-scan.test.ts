import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEFAULT_INVENTORY_THRESHOLDS,
  formatArtifactScanReport,
  inventoryCounts,
  registrableDomain,
  resolveAssetInventoryWaivers,
  scanPublishedArtifact,
} from "../src/artifact-scan";
import { isRecognizedTld } from "../src/tlds";
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
    expect(text).toContain("*");
    expect(report.findings.every((finding) => finding.sample.length <= 3)).toBe(true);
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

  test("private, loopback, and documentation IP space is excluded by rule", () => {
    const addresses = [
      ...Array.from({ length: 30 }, (_, i) => `10.0.0.${i}`),
      ...Array.from({ length: 30 }, (_, i) => `192.168.1.${i}`),
      ...Array.from({ length: 30 }, (_, i) => `127.0.0.${i}`),
      ...Array.from({ length: 30 }, (_, i) => `192.0.2.${i}`), // RFC 5737 TEST-NET-1
      ...Array.from({ length: 30 }, (_, i) => `203.0.113.${i}`), // TEST-NET-3
    ].join(" ");
    expect(inventoryCounts(addresses).ip).toEqual([]);
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

  test("an email inventory is counted once, not also as a host inventory", () => {
    const emails = Array.from({ length: 30 }, (_, i) => `"person${i}@customer-list-corp.com"`).join(",");
    const counts = inventoryCounts(`[${emails}]`);
    expect(counts.email.length).toBe(30);
    expect(counts.host).toEqual([]);
  });

  test("public IP inventories are detected", () => {
    const archive = tarball("machines", {
      "package.json": JSON.stringify({ name: "machines", version: "1.0.0" }),
      "dist/fleet.js": Array.from({ length: 30 }, (_, i) => `51.15.${i}.10`).join(","),
    });
    const report = scanPublishedArtifact(archive);
    expect(report.findings.some((finding) => finding.kind === "ip")).toBe(true);
  });

  test("registrableDomain collapses subdomains and respects registry second levels", () => {
    expect(registrableDomain("a.b.brand-example.com")).toBe("brand-example.com");
    expect(registrableDomain("shop.brand-example.co.uk")).toBe("brand-example.co.uk");
  });

  test("the TLD table recognizes real TLDs and rejects programming vocabulary", () => {
    for (const tld of ["com", "net", "org", "uk", "de", "io", "xyz", "cloud"]) {
      expect(isRecognizedTld(tld), tld).toBe(true);
    }
    for (const word of ["list", "map", "get", "json", "ts", "js", "md", "app", "dev"]) {
      expect(isRecognizedTld(word), word).toBe(false);
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
      deploymentModes: ["local"],
      serviceSurfaces: [
        { name: "sdk", kind: "sdk", status: "supported", authMode: "none", deploymentModes: ["local"], exportSubpath: "." },
        { name: "cli", kind: "cli", status: "supported", bin: "widget", authMode: "local-only", deploymentModes: ["local"] },
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

  test("SKIPS a private package — the predicate is 'this repo publishes'", () => {
    const root = conformanceRepo("gate-private", { private: true, exports: { ".": "./d.js" }, scripts: {} });
    const check = gate(root);
    expect(check.status).toBe("skip");
    expect(check.detail).toContain("private");
  });
});
