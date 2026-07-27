// The mutation audit for the clause B/C guard, enumerated and runnable.
//
// WHY THIS IS IN THE REPO. A claim of "N of N mutations caught" is not evidence
// unless the N are written down and anyone can re-run them. An earlier round of
// this work reported 11/11 with the list living only in a scratch file, and a
// reviewer running an 18-mutation superset found two rules unprotected — a
// number that may have been literally true while leaving real holes.
//
// Each entry names a rule, the edit that removes it, and the test that must
// then fail. `bun scripts/mutation-audit.ts` applies each in turn against a
// pristine copy of the tree, runs the suite, and restores.
//
// A mutation that leaves the suite green is a rule with no test. That is a
// defect in this file's terms, not a curiosity.

import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

interface Mutation {
  /** Short id used in reports. */
  id: string;
  /** The rule this removes, in one line. */
  rule: string;
  file: string;
  from: string;
  to: string;
}

const MUTATIONS: Mutation[] = [
  {
    id: "M1-threshold-ceiling",
    rule: "a caller cannot loosen a threshold past 2x the default",
    file: "src/artifact-scan.ts",
    from: "    if (value > MAX_INVENTORY_THRESHOLDS[kind]) {",
    to: "    if (false) {",
  },
  {
    id: "M2-per-run-salt",
    rule: "redaction digests cannot be correlated across reports",
    file: "src/artifact-scan.ts",
    from: "const REPORT_SALT = randomBytes(16);",
    to: 'const REPORT_SALT = Buffer.from("fixed-salt");',
  },
  {
    id: "M3-short-token-run",
    rule: "a 1- or 2-character quoted token does not break a run",
    file: "src/artifact-scan.ts",
    from: 'const QUOTED_LITERAL_PATTERN = /"((?:[^"\\\\\\n]|\\\\.)*)"',
    to: 'const QUOTED_LITERAL_PATTERN = /"((?:[^"\\\\\\n]|\\\\.){3,})"',
  },
  {
    id: "M4-ipv4-value-position",
    rule: "IPv4 is read from value positions, not bare tokens in code",
    file: "src/artifact-scan.ts",
    from: "  if (!codeLike) {",
    to: "  if (true) {",
  },
  {
    id: "M5-decode-newline",
    rule: "backslash-n is decoded, so source maps are readable",
    file: "src/artifact-scan.ts",
    from: 'n: "\\n", r: "\\r", t: "\\t",',
    to: 'r: "\\r", t: "\\t",',
  },
  {
    id: "M6-decode-no-overreach",
    rule: "an unknown escape is passed through, never invented",
    file: "src/artifact-scan.ts",
    from: "      return single !== undefined ? SIMPLE[single] ?? match : match;",
    to: "      return single !== undefined ? SIMPLE[single] ?? single : match;",
  },
  {
    id: "M7-version-key-suppression",
    rule: "a quad under a version key is a version, not an address",
    file: "src/artifact-scan.ts",
    from: "      if (key !== null && isVersionKey(key)) continue;",
    to: "      if (false) continue;",
  },
  {
    id: "M8-hostname-key-is-not-a-version-key",
    rule: "a hostname key never suppresses its address value",
    file: "src/artifact-scan.ts",
    from: "  if (isCountableHostname(key.toLowerCase())) return false;",
    to: "  if (false) return false;",
  },
  {
    id: "M9-presentation-format",
    rule: "a zero-padded quad is binary noise, not an address",
    file: "src/artifact-scan.ts",
    from: "const IPV4_LITERAL = /^(?:(?:0|[1-9]\\d{0,2})\\.){3}(?:0|[1-9]\\d{0,2})$/;",
    to: "const IPV4_LITERAL = /^(?:\\d{1,3}\\.){3}\\d{1,3}$/;",
  },
  {
    id: "M10-reserved-ip-space",
    rule: "private, loopback and documentation space is not an inventory",
    file: "src/artifact-scan.ts",
    from: "function isReservedIpv4(value: string): boolean {",
    to: "function isReservedIpv4(value: string): boolean {\n  if (true) return false;",
  },
  {
    id: "M11-address-does-not-break-host-run",
    rule: "an address between hostnames does not end the hostname run",
    file: "src/artifact-scan.ts",
    from: "      if (IPV4_LITERAL.test(literal)) continue;",
    to: "      if (false) continue;",
  },
  {
    id: "M12-url-path-stripping",
    rule: "a path is stripped only where a scheme marks the piece a URL",
    file: "src/artifact-scan.ts",
    from: "  if (!prefix) return piece.replace(HOST_PORT_SUFFIX, \"\").replace(/\\.$/, \"\");",
    to: "  if (!prefix) return piece.split(\"/\")[0]!.replace(HOST_PORT_SUFFIX, \"\").replace(/\\.$/, \"\");",
  },
  {
    id: "M13-redact-by-finding-kind",
    rule: "a sample is labelled by the finding's kind, not the value's shape",
    file: "src/artifact-scan.ts",
    from: "function redact(entry: string, kind: AssetInventoryKind): string {",
    to:
      "function redact(entry: string, _kind: AssetInventoryKind): string {\n" +
      '  const kind = entry.includes("@") ? "email" : /^[0-9.]+$/.test(entry) ? "ip" : "host";',
  },
  {
    id: "M14-member-access-is-code-only",
    rule: "the member-access guard applies to code members only",
    file: "src/artifact-scan.ts",
    from: "!(codeLike && isMemberAccessRun(run))",
    to: "!isMemberAccessRun(run)",
  },
  {
    id: "M15-unread-member-fails",
    rule: "a member that could not be read fails the scan",
    file: "src/artifact-scan.ts",
    from: "    ok: findings.length === 0 && unreadable.length === 0,",
    to: "    ok: findings.length === 0,",
  },
  {
    id: "M16-scanned-not-seen",
    rule: "a scan that read nothing gives no verdict",
    file: "src/artifact-scan.ts",
    from: "  if (scanned === 0) {",
    to: "  if (seen === 0) {",
  },
  {
    id: "M17-no-op-spellings",
    rule: "a no-op is rejected however it is spelled",
    file: "src/conformance.ts",
    from: "const NO_OP_COMMAND = /^(?:(?:\\/usr)?\\/bin\\/)?(?::|true)$/;",
    to: "const NO_OP_COMMAND = /^(?::|true)$/;",
  },
  {
    id: "M18-no-op-comment-stripping",
    rule: "a comment-only script is a no-op",
    file: "src/conformance.ts",
    from: "  const text = withoutComment(segment).trim();",
    to: "  const text = segment.trim();",
  },
];

const repoRoot = join(import.meta.dir, "..");

function runSuite(): { pass: number; fail: number; failed: string[] } {
  const result = Bun.spawnSync(["bun", "test"], { cwd: repoRoot, stdout: "pipe", stderr: "pipe" });
  const blob = new TextDecoder().decode(result.stdout) + new TextDecoder().decode(result.stderr);
  const pass = Number(/^\s*(\d+) pass$/m.exec(blob)?.[1] ?? "0");
  const fail = Number(/^\s*(\d+) fail$/m.exec(blob)?.[1] ?? "0");
  const failed = [...blob.matchAll(/^\(fail\) (.+?) \[/gm)].map((match) => match[1]!);
  return { pass, fail, failed };
}

const only = process.argv[2];
const selected = only ? MUTATIONS.filter((mutation) => mutation.id.includes(only)) : MUTATIONS;
if (selected.length === 0) {
  console.error(`No mutation matches '${only}'. Known ids:\n  ${MUTATIONS.map((m) => m.id).join("\n  ")}`);
  process.exit(2);
}

const baseline = runSuite();
console.log(`baseline: ${baseline.pass} pass / ${baseline.fail} fail\n`);
if (baseline.fail !== 0) {
  console.error("Refusing to audit against a red suite.");
  process.exit(2);
}

let survivors = 0;
for (const mutation of selected) {
  const path = join(repoRoot, mutation.file);
  const original = readFileSync(path, "utf8");
  if (!original.includes(mutation.from)) {
    console.log(`${mutation.id.padEnd(38)} STALE — anchor not found`);
    survivors += 1;
    continue;
  }
  writeFileSync(path, original.replace(mutation.from, mutation.to));
  const result = runSuite();
  writeFileSync(path, original);
  const caught = result.fail > 0;
  if (!caught) survivors += 1;
  console.log(
    `${mutation.id.padEnd(38)} ${caught ? "caught " : "SURVIVED"} ${result.pass}/${result.fail}` +
      (caught ? `  -> ${result.failed[0]?.slice(0, 60) ?? ""}` : `  (rule: ${mutation.rule})`),
  );
}

console.log(`\n${selected.length - survivors}/${selected.length} caught`);
process.exit(survivors === 0 ? 0 : 1);
