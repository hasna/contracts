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

  // ---------------------------------------------------------------------
  // The no-cloud gate: dependency edges and real imports, not substrings.
  //
  // Filter to these with `bun scripts/mutation-audit.ts nocloud`.
  //
  // These pin the fix for the gate that failed `@hasna/connectors@1.4.0` — the
  // one repo already remediated and published — on a JSDoc comment and on the
  // guard test the remediation pattern itself mandates.
  // ---------------------------------------------------------------------
  {
    id: "M19-nocloud-comments-are-not-code",
    rule: "a comment is prose; only code is an edge",
    file: "src/no-cloud.ts",
    from: "  const masked = maskCommentsForPath(file.text, file.path);",
    to: "  const masked = file.text;",
  },
  {
    id: "M20-nocloud-symbol-needs-an-import",
    rule: "registerCloud* is the retired surface only when imported from it",
    file: "src/no-cloud.ts",
    from: "      const bound = MODULE_PATTERNS.some((module) => importedBindings(masked, module.pattern).has(pattern));",
    to: "      const bound = masked.includes(pattern);",
  },
  {
    id: "M21-nocloud-guard-test-allowlisted",
    rule: "the mandated guard test may name what it forbids",
    file: "src/no-cloud.ts",
    from: "  return NO_CLOUD_GUARD_TEST.test(path.replaceAll(\"\\\\\", \"/\"));",
    to: "  return false;",
  },
  {
    id: "M22-nocloud-allowlist-is-not-a-bypass",
    rule: "the allowlist covers mentions, never a real import",
    file: "src/no-cloud.ts",
    from: "  return NO_CLOUD_GUARD_TEST.test(path.replaceAll(\"\\\\\", \"/\"));",
    to: "  return /\\.test\\.[cm]?[jt]sx?$/.test(path.replaceAll(\"\\\\\", \"/\"));",
  },
  {
    id: "M23-nocloud-lockfile-is-a-graph",
    rule: "bun.lock is walked as a graph, not grepped",
    file: "src/no-cloud.ts",
    from: "  if (basename(file.path) !== BUN_LOCKFILE) return textFindings(file, severity, packageName);",
    to: "  return textFindings(file, severity, packageName);\n  if (basename(file.path) !== BUN_LOCKFILE) return textFindings(file, severity, packageName);",
  },
  {
    id: "M24-nocloud-unreadable-lockfile",
    rule: "a lockfile we cannot parse is scanned, not passed",
    file: "src/dependency-edge.ts",
    from: "  if (roots.length === 0) return null;",
    to: "  if (roots.length === 0) return [];",
  },
  {
    id: "M25-nocloud-linked-dev-is-installed",
    rule: "a linked package's devDependencies land in the tree and are edges",
    file: "src/dependency-edge.ts",
    from: "      if (node.linked) {",
    to: "      if (false) {",
  },
  {
    id: "M25b-nocloud-registry-dev-is-not-installed",
    rule: "a registry package's devDependencies are not installed and not edges",
    file: "src/dependency-edge.ts",
    from: "      if (node.linked) {",
    to: "      if (true) {",
  },
  {
    id: "M25c-nocloud-linked-is-read-from-the-specifier",
    rule: "file:/link:/workspace: is what marks a resolution linked",
    file: "src/dependency-edge.ts",
    from: "  return /^(?:file|link|workspace):/.test(id.slice(name.length + 1));",
    to: "  return false;",
  },
  {
    id: "M26-nocloud-transitive-production-edge",
    rule: "a transitive production dependency is still an edge",
    file: "src/dependency-edge.ts",
    from: "    for (const node of reachable) {",
    to: "    for (const node of []) {",
  },
  {
    id: "M27-nocloud-pin-sections-are-edges",
    rule: "overrides and resolutions pull a package in",
    file: "src/dependency-edge.ts",
    from: 'export const PIN_SECTIONS = ["overrides", "resolutions"] as const;',
    to: "export const PIN_SECTIONS = [] as unknown as readonly [\"overrides\", \"resolutions\"];",
  },
  {
    id: "M28-nocloud-name-list-sections-are-edges",
    rule: "bundleDependencies and trustedDependencies are arrays of names",
    file: "src/dependency-edge.ts",
    from: '  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string");',
    to: "  if (Array.isArray(value)) return [];",
  },
  {
    id: "M29-nocloud-strings-are-not-comments",
    rule: "`//` inside a string literal does not start a comment",
    file: "src/source-text.ts",
    from: "    if (character === '\"' || character === \"'\") {",
    to: "    if (false) {",
  },
  {
    id: "M30-nocloud-yaml-hash-needs-space",
    rule: "`#` opens a YAML comment only at line start or after whitespace",
    file: "src/source-text.ts",
    from: "        if (previous === \"\" || /\\s/.test(previous)) {",
    to: "        if (true) {",
  },
  {
    id: "M32-nocloud-template-frame-closes",
    rule: "a closed template pops its frame, so later comments still mask",
    file: "src/source-text.ts",
    from: "      if (chunk.closed) templateDepths.pop();",
    to: "      if (false) templateDepths.pop();",
  },
  {
    id: "M33-nocloud-regex-literal-tracking",
    rule: "a quote inside a regex literal does not open a string",
    file: "src/source-text.ts",
    from: "    if (character === \"/\" && regexCanStart(text.slice(Math.max(0, index - 64), index))) {",
    to: "    if (false) {",
  },
  {
    id: "M34-nocloud-unterminated-masks-nothing",
    rule: "a parse we lost the thread on masks nothing, and fails closed",
    file: "src/source-text.ts",
    from: "      const end = text.indexOf(\"*/\", index + 2);\n      if (end === -1) return null;",
    to: "      const end = text.indexOf(\"*/\", index + 2);\n      if (end === -1) return chars.join(\"\");",
  },
  {
    id: "M35-nocloud-rename-binds-the-local-name",
    rule: "`x as y` binds y, the name actually in scope",
    file: "src/source-text.ts",
    from: '      const name = (pieces[pieces.length - 1] ?? "").trim();',
    to: '      const name = (pieces[0] ?? "").trim();',
  },
  {
    id: "M36-nocloud-deep-imports-count",
    // Spelled without the package name on purpose: a string literal naming it
    // is a source reference, and this repo's own gate is right to say so.
    rule: "a deep import path is the same edge as the bare specifier",
    file: "src/source-text.ts",
    from: "  return `${SPECIFIER_QUOTE}(?:${SPECIFIER_CHAR}*/)?${escapeRegex(moduleName)}(?:/${SPECIFIER_CHAR}*)?${SPECIFIER_QUOTE}`;",
    to: "  return `${SPECIFIER_QUOTE}(?:${SPECIFIER_CHAR}*/)?${escapeRegex(moduleName)}${SPECIFIER_QUOTE}`;",
  },
  {
    id: "M37-nocloud-every-workspace-is-a-seed",
    rule: "a monorepo's member workspaces seed the walk, not just the root entry",
    file: "src/dependency-edge.ts",
    from: "  const roots = installRoots(lock);",
    to: "  const roots = installRoots(lock).filter((root) => root.label === null);",
  },
  {
    id: "M38-nocloud-alias-is-the-package-it-installs",
    rule: "a linked or npm-aliased resolution is the package it resolves to",
    file: "src/dependency-edge.ts",
    from: "    if (node.alias !== null && forbidden.includes(node.alias)) return node.alias;",
    to: "    if (false) return node.alias;",
  },
  {
    id: "M38b-nocloud-alias-is-not-a-substring",
    rule: "an alias lookup matches a whole name, never a substring",
    file: "src/dependency-edge.ts",
    from: "    if (node.alias !== null && forbidden.includes(node.alias)) return node.alias;",
    to: "    if (node.alias !== null && forbidden.some((entry) => node.alias!.includes(entry))) return node.alias;",
  },
  {
    id: "M39-nocloud-lockfile-walks-every-module-pattern",
    rule: "the lockfile walk covers every forbidden module name, not one constant",
    file: "src/no-cloud.ts",
    from: "  const edges = lockfileEdges(file.text, FORBIDDEN_LOCKFILE_PACKAGES);",
    to: "  const edges = lockfileEdges(file.text, FORBIDDEN_SHARED_CLOUD_RUNTIMES);",
  },
  {
    id: "M40-nocloud-allowlist-is-module-names-only",
    rule: "the guard-test allowlist never exempts runtime config",
    file: "src/no-cloud.ts",
    from: '    } else if (!(guardTest && kind === "module") && masked.includes(pattern)) {',
    to: "    } else if (!guardTest && masked.includes(pattern)) {",
  },
  {
    id: "M41-nocloud-specifier-is-matched-anywhere",
    rule: "a re-scoped or vendored specifier is the same import",
    file: "src/source-text.ts",
    from: "  return `${SPECIFIER_QUOTE}(?:${SPECIFIER_CHAR}*/)?${escapeRegex(moduleName)}(?:/${SPECIFIER_CHAR}*)?${SPECIFIER_QUOTE}`;",
    to: "  return `${SPECIFIER_QUOTE}${escapeRegex(moduleName)}(?:/${SPECIFIER_CHAR}*)?${SPECIFIER_QUOTE}`;",
  },
  {
    id: "M42-nocloud-bare-import-needs-no-space",
    rule: "`import\"x\"` is the same side-effect import as `import \"x\"`",
    file: "src/source-text.ts",
    from: "    String.raw`(?:\\bfrom\\s*|\\bimport\\s*\\(\\s*|\\brequire\\s*\\(\\s*|\\bimport\\s*)` + moduleSpecifier(moduleName),",
    to: "    String.raw`(?:\\bfrom\\s*|\\bimport\\s*\\(\\s*|\\brequire\\s*\\(\\s*|\\bimport\\s+)` + moduleSpecifier(moduleName),",
  },
  {
    id: "M43-nocloud-lockfile-config-is-still-read",
    rule: "config patterns no edge can carry are still read out of bun.lock",
    file: "src/no-cloud.ts",
    from: '  return [...edges.map((edge) => edgeFinding(edge, file.path, "lockfile", packageName)), ...lockfileTextFindings(file, severity)];',
    to: '  return edges.map((edge) => edgeFinding(edge, file.path, "lockfile", packageName));',
  },
  {
    id: "M50-nocloud-utf16-index-alignment",
    rule: "the mask is addressed in UTF-16 units, the same as the offsets it uses",
    file: "src/source-text.ts",
    from: "  return text.split(\"\");\n}",
    to: "  return [...text];\n}",
  },
  {
    id: "M51-nocloud-json-and-jsx-are-not-masked",
    rule: "JSON and JSX are scanned raw, because guessing their comments hides code",
    file: "src/source-text.ts",
    from: "const C_LIKE_EXTENSIONS = /\\.(?:[cm]?[jt]s)$/i;",
    to: "const C_LIKE_EXTENSIONS = /\\.(?:[cm]?[jt]sx?|json)$/i;",
  },
  {
    id: "M52-nocloud-dev-hop-is-not-laundered",
    rule: "a production hop after a dev hop is still a dev edge",
    file: "src/dependency-edge.ts",
    from: '        for (const name of node.development) next.push({ name, scope: "development" });',
    to: "        for (const name of node.development) next.push({ name, scope: current.scope });",
  },
  {
    id: "M53-nocloud-key-alias-is-registered",
    rule: "an entry is findable by the name a dependent wrote, not only by what it resolves to",
    file: "src/dependency-edge.ts",
    from: "    for (const lookup of new Set([name, aliasFromKey(key, keys)])) {",
    to: "    for (const lookup of new Set([name])) {",
  },
  {
    id: "M54-nocloud-identity-reads-the-resolved-name",
    rule: "an aliased KEY is judged by the package its resolution names",
    file: "src/dependency-edge.ts",
    from: "    if (forbidden.includes(node.name)) return node.name;",
    to: "    if (false) return node.name;",
  },
  {
    id: "M55-nocloud-dynamic-load-withdraws-exemption",
    rule: "a computed import in the guard test is a load, not a mention",
    file: "src/no-cloud.ts",
    from: "  const guardTest = isNoCloudGuardTest(file.path) && !DYNAMIC_MODULE_LOAD.test(masked);",
    to: "  const guardTest = isNoCloudGuardTest(file.path);",
  },
  {
    id: "M56-nocloud-symbols-need-code-to-read",
    rule: "import analysis applies where there is code; elsewhere the name is the evidence",
    file: "src/no-cloud.ts",
    from: '  const codeLike = file.kind === "source_import" || file.kind === "packed_artifact";',
    to: "  const codeLike = true;",
  },
  {
    id: "M57-nocloud-backtick-is-a-quote",
    rule: "a template-literal specifier is a specifier, so its load is an import",
    file: "src/source-text.ts",
    from: "const SPECIFIER_QUOTE = \"[\\\"'`]\";",
    to: "const SPECIFIER_QUOTE = \"[\\\"']\";",
  },
  {
    id: "M58-nocloud-backtick-load-withdraws-exemption",
    rule: "an interpolated specifier in the guard test is a load, not a mention",
    file: "src/no-cloud.ts",
    from: "const DYNAMIC_MODULE_LOAD = /\\b(?:import|require)\\s*\\(\\s*[A-Za-z_$`]/;",
    to: "const DYNAMIC_MODULE_LOAD = /\\b(?:import|require)\\s*\\(\\s*[A-Za-z_$]/;",
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
  let result = runSuite();
  // A suite that reported NOTHING did not survive the mutation — it failed to
  // run at all, which under load looks identical to a survivor and is why a
  // review saw `M21 SURVIVED 0/0` that re-ran clean in isolation. Retry once,
  // then say "no result" rather than blame the rule.
  if (result.pass === 0 && result.fail === 0) result = runSuite();
  writeFileSync(path, original);
  const ranAtAll = result.pass > 0 || result.fail > 0;
  const caught = result.fail > 0;
  if (!caught) survivors += 1;
  const verdict = !ranAtAll ? "NO-RESULT" : caught ? "caught " : "SURVIVED";
  console.log(
    `${mutation.id.padEnd(38)} ${verdict} ${result.pass}/${result.fail}` +
      (caught ? `  -> ${result.failed[0]?.slice(0, 60) ?? ""}` : `  (rule: ${mutation.rule})`),
  );
}

console.log(`\n${selected.length - survivors}/${selected.length} caught`);
process.exit(survivors === 0 ? 0 : 1);
