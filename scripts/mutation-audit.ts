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

import { copyFileSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
    from: "  const masked = withoutInlinedDeclarations(maskCommentsForPath(file.text, file.path), file.path);",
    to: "  const masked = withoutInlinedDeclarations(file.text, file.path);",
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
    from: "  if (basename(file.path) !== BUN_LOCKFILE) return textFindings(file, severity);",
    to: "  return textFindings(file, severity);\n  if (basename(file.path) !== BUN_LOCKFILE) return textFindings(file, severity);",
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
    from: "      if (opensRegex) {",
    to: "      if (false) {",
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
    rule: "a deep import path is the same edge as the bare specifier",
    file: "src/source-text.ts",
    from: "${escapeRegex(moduleName)}(?:/${SPECIFIER_CHAR}*)?${SPECIFIER_QUOTE}",
    to: "${escapeRegex(moduleName)}${SPECIFIER_QUOTE}",
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
    from: "    if (node.alias !== null && forbidden.includes(node.alias)) found.add(node.alias);",
    to: "    if (false) found.add(node.alias);",
  },
  {
    id: "M38b-nocloud-alias-is-not-a-substring",
    rule: "an alias lookup matches a whole name, never a substring",
    file: "src/dependency-edge.ts",
    from: "    if (node.alias !== null && forbidden.includes(node.alias)) found.add(node.alias);",
    to: "    if (node.alias !== null && forbidden.some((entry) => node.alias!.includes(entry))) found.add(node.alias);",
  },
  {
    id: "M39-nocloud-lockfile-walks-every-module-pattern",
    rule: "the lockfile walk covers every forbidden module name, not one constant",
    file: "src/no-cloud.ts",
    from: "  const walk = lockfileWalk(file.text, FORBIDDEN_LOCKFILE_PACKAGES);",
    to: "  const walk = lockfileWalk(file.text, FORBIDDEN_SHARED_CLOUD_RUNTIMES);",
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
    rule: "the module name is matched as a path segment, not anchored at the quote",
    file: "src/source-text.ts",
    from: "(?:${SPECIFIER_CHAR}*/)?${escapeRegex(moduleName)}",
    to: "${escapeRegex(moduleName)}",
  },
  {
    id: "M42-nocloud-bare-import-needs-no-space",
    rule: "`import\"x\"` is the same side-effect import as `import \"x\"`",
    file: "src/source-text.ts",
    from: "    String.raw`(?:\\bfrom\\s*|${LOAD_CALLEE}\\s*\\(\\s*|\\bimport\\s*)` + moduleSpecifier(moduleName),",
    to: "    String.raw`(?:\\bfrom\\s*|${LOAD_CALLEE}\\s*\\(\\s*|\\bimport\\s+)` + moduleSpecifier(moduleName),",
  },
  {
    id: "M43-nocloud-lockfile-config-is-still-read",
    rule: "config patterns no edge can carry are still read out of bun.lock",
    file: "src/no-cloud.ts",
    from: "    ...lockfileTextFindings(file, severity)\n  ];",
    to: "  ];",
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
    from: "    if (forbidden.includes(node.name)) found.add(node.name);",
    to: "    if (false) found.add(node.name);",
  },
  {
    id: "M55-nocloud-dynamic-load-withdraws-exemption",
    rule: "a computed import in the guard test is a load, not a mention",
    file: "src/no-cloud.ts",
    from: "  if (DYNAMIC_MODULE_LOAD.test(masked)) return false;",
    to: "  if (false) return false;",
  },
  {
    id: "M56-nocloud-symbols-need-code-to-read",
    rule: "import analysis applies where there is code; elsewhere the name is the evidence",
    file: "src/no-cloud.ts",
    from: '  const codeLike = file.kind === "source_import" || file.kind === "packed_artifact";',
    to: "  const codeLike = true;",
  },
  {
    id: "M57-nocloud-lockfile-top-level-sections",
    rule: "the lockfile's own overrides/trusted/patched sections are install-bearing",
    file: "src/dependency-edge.ts",
    from: "  if (Object.keys(topLevel).length > 0) roots.push({ label: null, record: topLevel });",
    to: "  if (false) roots.push({ label: null, record: topLevel });",
  },
  {
    id: "M58-nocloud-patched-key-carries-a-version",
    rule: "a patchedDependencies key is name@version, not a bare name",
    file: "src/dependency-edge.ts",
    from: "      .map((key) => nameFromResolutionId(key) ?? key)",
    to: "      .map((key) => key)",
  },
  {
    id: "M59-nocloud-node-name-lists-are-edges",
    rule: "a node's bundleDependencies pull a package in, same as the manifest's",
    file: "src/dependency-edge.ts",
    from: "      production: meta ? [...PRODUCTION_SECTIONS, ...PIN_SECTIONS, ...NAME_LIST_SECTIONS].flatMap((section) => namesInSection(meta, section)) : [],",
    to: "      production: meta ? [...PRODUCTION_SECTIONS].flatMap((section) => namesInSection(meta, section)) : [],",
  },
  {
    id: "M60-nocloud-dynamic-load-is-a-negative",
    rule: "anything but one complete simple string literal withdraws the exemption",
    file: "src/no-cloud.ts",
    from: "\\s*(?!([\"'])[^\"'\\n]*\\1\\s*\\))/;",
    to: "\\s*[A-Za-z_$]/;",
  },
  {
    id: "M61-nocloud-backtick-is-a-specifier",
    rule: "a template-literal specifier is a real import",
    file: "src/source-text.ts",
    from: "const SPECIFIER_QUOTE = \"[\\\"'`]\";",
    to: "const SPECIFIER_QUOTE = \"[\\\"']\";",
  },
  {
    id: "M62-nocloud-hoisted-skips-transitive-links",
    rule: "a hoisted install does not materialise a transitive linked resolution",
    file: "src/dependency-edge.ts",
    from: "    const reachable = hoisted ? known.filter((node) => current.root || !node.linked) : known;",
    to: "    const reachable = known;",
  },
  {
    id: "M63-nocloud-isolated-keeps-transitive-links",
    rule: "an isolated (monorepo) install DOES materialise them, so they stay edges",
    file: "src/dependency-edge.ts",
    from: "    const reachable = hoisted ? known.filter((node) => current.root || !node.linked) : known;",
    to: "    const reachable = known.filter((node) => current.root || !node.linked);",
  },
  {
    id: "M64-nocloud-workspace-count-is-the-discriminator",
    rule: "the workspace count is what tells hoisted from isolated",
    file: "src/dependency-edge.ts",
    from: "  return Object.values(workspaces).filter(isRecord).length <= 1;",
    to: "  return true;",
  },

  // ---------------------------------------------------------------------
  // The gate no longer scores its own inlined declaration as the consumer's
  // breach — and every detector still runs on everything else in that file.
  //
  // Filter to these with `bun scripts/mutation-audit.ts attrib` — every id in
  // this block carries that tag, which is what makes the filter usable.
  //
  // TWO DIRECTIONS, because this rule has failed review twice in the SAME
  // direction. M71/M72/M80 revert the fix, so the false positive returns.
  // Everything else pushes it TOO FAR — that is where a false-positive fix
  // actually causes harm, and where the two rejected attempts landed: both
  // returned early for a whole FILE and took the credential detectors with them.
  // ---------------------------------------------------------------------
  {
    id: "M71-attrib-happens-at-all",
    rule: "a consumer that bundles this package's own declaration is not in breach of it",
    file: "src/no-cloud.ts",
    from: "  const masked = withoutInlinedDeclarations(maskCommentsForPath(file.text, file.path), file.path);",
    to: "  const masked = maskCommentsForPath(file.text, file.path);",
  },
  {
    id: "M72-attrib-recognised-by-content",
    rule: "the declaration is recognised, not merely parsed",
    file: "src/no-cloud.ts",
    from: "      if (isOwnPatternDeclaration(node)) spans.push({ start: node.start, end: node.end });",
    to: "      if (false) spans.push({ start: node.start, end: node.end });",
  },
  {
    id: "M73-attrib-is-per-occurrence-not-per-file",
    rule: "attribution drops the declaration's own characters, never the whole file",
    file: "src/no-cloud.ts",
    from: "  return blankSpans(masked, spans);",
    to: '  return spans.length > 0 ? "" : masked;',
  },
  {
    id: "M74-attrib-array-must-match-length",
    rule: "an array holding a SUBSET or SUPERSET of the denylist is somebody else's data",
    file: "src/no-cloud.ts",
    from: "      node.items.length === FORBIDDEN_SHARED_CLOUD_RUNTIMES.length &&",
    to: "      true &&",
  },
  {
    id: "M75-attrib-array-must-match-members",
    rule: "an array of the right length but the wrong names is not the denylist",
    file: "src/no-cloud.ts",
    from: '      node.items.every((item, index) => item.kind === "string" && item.value === FORBIDDEN_SHARED_CLOUD_RUNTIMES[index])',
    to: '      node.items.every((item) => item.kind === "string")',
  },
  {
    id: "M76-attrib-row-must-match-its-own-message",
    rule: "a row cannot pair a forbidden name with a message that is not that name's own",
    file: "src/no-cloud.ts",
    from: "    (entry) => entry.pattern === pattern.value && entry.kind === kind.value && entry.message === message.value",
    to: "    (entry) => entry.pattern === pattern.value",
  },
  {
    id: "M77-attrib-row-shape-alone-is-not-enough",
    rule: "a three-key row that names no known pattern is not this table's row",
    file: "src/no-cloud.ts",
    from: "  return RUNTIME_PATTERNS.some(",
    to: "  return true || RUNTIME_PATTERNS.some(",
  },
  {
    id: "M78-attrib-not-read-in-place",
    rule: "indexing, calling or member-accessing a collection is a load, not a declaration",
    file: "src/source-text.ts",
    from: '  if (next.startsWith("[") || next.startsWith("(") || next.startsWith(".") || next.startsWith("?.")) return false;',
    to: "  if (false) return false;",
  },
  {
    id: "M79-attrib-must-sit-in-data-position",
    rule: "a collection handed to a call is an argument, not a stored constant",
    file: "src/source-text.ts",
    from: '    if (!typePosition && !(last === "=" || last === "[" || last === "," || last === ":" || last === "(")) return false;',
    to: "    if (false) return false;",
  },
  {
    id: "M79b-attrib-call-argument-is-not-a-declaration",
    rule: "a `(` that follows an identifier is a CALL, and its argument is not a declaration",
    file: "src/source-text.ts",
    from: '    if (last === "(" && IDENTIFIER_TAIL.test(before.slice(0, -1))) return false;',
    to: "    if (false) return false;",
  },
  {
    id: "M80-attrib-bound-name-in-a-load-call-withdraws-it",
    rule: "a declaration stored under a name a load call names is a laundering route",
    file: "src/no-cloud.ts",
    from: "    if (region.boundName !== null && loadCallMentions(masked, region.boundName)) continue;",
    to: "    if (false) continue;",
  },
  {
    id: "M81-attrib-load-callee-includes-the-bundler-wrapper",
    rule: "`__require` is a load: bun build --external emits it and `\\b` cannot see it",
    file: "src/source-text.ts",
    from: "const LOAD_CALLEE = String.raw`(?:^|[^\\w$])_*(?:import|require)`;",
    to: "const LOAD_CALLEE = String.raw`\\b(?:import|require)`;",
  },
  {
    id: "M82-attrib-load-call-name-is-a-whole-identifier",
    rule: "`DENYLIST` is not `DENY`, so a bound-name check cannot match a substring",
    file: "src/source-text.ts",
    from: "  const bounded = new RegExp(`[^\\\\w$]${escapeRegex(name)}(?![\\\\w$])`);",
    to: "  const bounded = new RegExp(escapeRegex(name));",
  },
  {
    id: "M83-attrib-enclosure-checked-before-the-seen-set",
    rule: "an unrelated region recorded upstream does not end the search for this occurrence",
    file: "src/source-text.ts",
    from:
      "        if (!(root.start <= at && at + needle.length <= root.end)) continue;\n" +
      "        // Enclosing, so it is the answer for this occurrence either way.\n" +
      "        if (seen.has(opener)) break;",
    to:
      "        if (seen.has(opener)) break;\n" +
      "        if (!(root.start <= at && at + needle.length <= root.end)) continue;",
  },
  {
    id: "M84-attrib-c-family-source-only",
    rule: "a manifest is read structurally; its text is not edited on a shape match",
    file: "src/no-cloud.ts",
    from: '  if (commentSyntaxForPath(path) !== "c-like") return masked;',
    to: "  if (false) return masked;",
  },
  {
    id: "M85-attrib-a-constant-is-only-string-literals",
    rule: "a collection holding a call or an identifier is code, and code is never attributed",
    file: "src/source-text.ts",
    from: "      const item = parseInlineData(text, index);\n      if (item === null) return null;",
    to: "      const item = parseInlineData(text, index);\n      if (item === null) { index = skipSpace(text, index + 1); continue; }",
  },
  {
    id: "M86-attrib-names-spelled-once-in-the-table",
    rule: "no finding site re-spells a forbidden name, because a re-spelling is code a bundler inlines",
    file: "src/no-cloud.ts",
    from: '      kind: "checkKind" in entry ? entry.checkKind : file.kind,',
    // Spelled in pieces so this file does not carry a literal the gate forbids.
    to: '      kind: entry.pattern === ".hasna/' + 'cloud" ? "runtime_config" : file.kind,',
  },
  {
    id: "M87-attrib-path-config-read-off-the-table",
    rule: "a legacy config dotdir path is runtime config, decided from the table not a literal",
    file: "src/no-cloud.ts",
    from: "  for (const entry of PATH_CONFIG_PATTERNS) {\n    if (path.includes(entry.pattern)) return entry.checkKind;\n  }",
    to: "  for (const entry of PATH_CONFIG_PATTERNS) {\n    if (false) return entry.checkKind;\n  }",
  },
];

const repoRoot = join(import.meta.dir, "..");

/**
 * Long enough that machine load cannot manufacture a failure.
 *
 * `tests/published-package-security.test.ts` runs a full `bun run build` and a
 * `bun pm pack` in `beforeAll`. Measured on this machine at load ~85 that hook
 * takes ~39 s, and the default timeout aborted it at 30 s — which reads as a red
 * suite, and a red baseline makes this script refuse to audit at all. A timeout
 * that trips under load turns every run into a coin flip.
 */
const SUITE_TIMEOUT_MS = 180_000;

/**
 * CSI escape sequences, so a coloured suite still parses.
 *
 * Written as `\x1b` rather than a literal escape byte: a raw control character
 * in source is invisible in review and easy for an editor to eat. Anchoring on
 * ESC also matters — matching a bare `[...]` would eat ordinary text, and a test
 * named `handles [1m] input` would lose part of its name.
 */
const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;

/**
 * `--suite <file>…` — narrow which test files decide "caught".
 *
 * WHY THIS EXISTS, and it is not for speed. Run whole, this suite contains
 * `open-contracts passes conformance against itself`, which scans this repo with
 * its own scanner. Weakening almost anything in `src/no-cloud.ts` makes that one
 * test fail, so it is the FIRST failure reported for every no-cloud mutation and
 * it hides whether the rule has a test of its own. Eighteen rules reported
 * `caught` behind one broad test.
 *
 * Narrowing to the files that contain no self-scan answers the sharper question:
 * is this rule pinned by a test somebody wrote FOR IT. Asked that way, M79 —
 * "a collection handed to a call is an argument, not a stored constant" — came
 * back SURVIVED, and it had been reading as caught all along. Its test exists
 * now; the flag is what found the gap, so it stays.
 *
 *   bun scripts/mutation-audit.ts attrib --suite tests/no-cloud-edge.test.ts tests/cli.test.ts
 *
 * The narrowed run is WEAKER evidence than the whole suite and is not a
 * substitute for it: a rule can legitimately be pinned by a test in another file.
 * Read the two together.
 */
/**
 * One pass over argv, because two independent passes disagreed.
 *
 * `--suite` takes bare words as VALUES, and the id filter is also a bare word,
 * so neither can be found by scanning for "the first thing without dashes" —
 * `--print-json attrib` selected all 78 mutations, silently, while reporting a
 * filter was applied. Parse once, and let `--suite` claim its own values.
 */
const cli = (() => {
  const flags = new Set<string>();
  const suite: string[] = [];
  let only: string | undefined;
  let collectingSuite = false;
  for (const argument of process.argv.slice(2)) {
    if (argument.startsWith("--")) {
      flags.add(argument);
      collectingSuite = argument === "--suite";
      continue;
    }
    if (collectingSuite) suite.push(argument);
    else if (only === undefined) only = argument;
  }
  return { flags, suite, only };
})();
const suiteFilter = cli.suite;

function runSuite(): { pass: number; fail: number; failed: string[] } {
  const result = Bun.spawnSync(["bun", "test", ...suiteFilter, "--timeout", String(SUITE_TIMEOUT_MS)], {
    cwd: repoRoot,
    stdout: "pipe",
    stderr: "pipe",
    // `bun test` drops colour when stdout is a pipe, EXCEPT when something in
    // the environment forces it. `FORCE_COLOR=3` is set by some terminals and
    // agent harnesses, and then every count arrives wrapped in escapes,
    // `/^\s*(\d+) pass$/m` matches nothing, and the audit reports NO-RESULT for
    // mutations the suite actually caught. Ask for plain output, then strip
    // escapes anyway, because the env is not ours to rely on.
    env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" },
  });
  const blob = (new TextDecoder().decode(result.stdout) + new TextDecoder().decode(result.stderr)).replace(ANSI, "");
  const pass = Number(/^\s*(\d+) pass$/m.exec(blob)?.[1] ?? "0");
  const fail = Number(/^\s*(\d+) fail$/m.exec(blob)?.[1] ?? "0");
  const failed = [...blob.matchAll(/^\(fail\) (.+?) \[/gm)].map((match) => match[1]!);
  return { pass, fail, failed };
}

/**
 * Crash-surviving record of the file currently holding a mutation.
 *
 * WHY THIS EXISTS. This script edits tracked source in place and restores it on
 * the next line. Anything that stops the process between those two lines leaves
 * the mutation on disk looking exactly like someone's edit — that is how
 * `if (false) roots.push(...)` reached a commit in this repo.
 *
 * SIGNAL HANDLERS DO NOT CLOSE IT, and the reason is specific to this script
 * rather than general: it spends essentially all of its life inside a blocking
 * `Bun.spawnSync`, which does not yield to the event loop, so a queued handler
 * gets no turn until the suite returns. Measured during this change — SIGTERM to
 * the audit process was delivered and the process kept going through two more
 * mutations with the handler never running. SIGKILL cannot be caught at all.
 *
 * So the original text is ALSO written to disk before the mutation, and the next
 * run repairs from it. That path is the one that works, and it was verified the
 * only honest way: SIGKILL the audit mid-mutation, confirm the mutation is left
 * on disk, then confirm the next run prints RECOVERED and restores the file. The
 * handlers below are kept as a cheap best effort for the idle case, not as the
 * guarantee.
 *
 * The sentinel lives in the repo root, gitignored, so a human or agent looking
 * at a confusing diff can SEE it.
 */
const SENTINEL = join(repoRoot, ".mutation-audit-inflight.json");

let inFlight: { path: string; original: string } | null = null;

function beginMutation(path: string, original: string): void {
  inFlight = { path, original };
  writeFileSync(SENTINEL, JSON.stringify({ path, original }));
}

function endMutation(): void {
  if (inFlight) {
    const { path, original } = inFlight;
    inFlight = null;
    writeFileSync(path, original);
  }
  if (existsSync(SENTINEL)) rmSync(SENTINEL, { force: true });
}

/** Repair a previous run that was killed before it could restore. */
function recoverAbandonedMutation(): void {
  if (!existsSync(SENTINEL)) return;
  const record = JSON.parse(readFileSync(SENTINEL, "utf8")) as { path: string; original: string };
  if (readFileSync(record.path, "utf8") !== record.original) {
    writeFileSync(record.path, record.original);
    console.error(`RECOVERED: a previous run left ${record.path} mutated. Restored it.`);
  }
  rmSync(SENTINEL, { force: true });
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"] as const) {
  process.on(signal, () => {
    endMutation();
    console.error(`\n${signal} — restored the mutated file before exiting.`);
    process.exit(130);
  });
}
process.on("uncaughtException", (error) => {
  endMutation();
  console.error(error);
  process.exit(1);
});
process.on("exit", endMutation);

recoverAbandonedMutation();

// Flags are not filters. `bun scripts/mutation-audit.ts --anchors` used to be
// read as "select mutations whose id contains `--anchors`", i.e. none of them.
const only = cli.only;
const selected = only ? MUTATIONS.filter((mutation) => mutation.id.includes(only)) : MUTATIONS;
if (selected.length === 0) {
  console.error(`No mutation matches '${only}'. Known ids:\n  ${MUTATIONS.map((m) => m.id).join("\n  ")}`);
  process.exit(2);
}

/**
 * `--print-json` — the selected mutations, as data.
 *
 * The list is the evidence, so anything that wants to check a property of it
 * should read it from here rather than re-parsing this file. Re-parsing was
 * tried and is a trap: `from` and `to` are TypeScript string literals, some of
 * them concatenated across lines and full of escaped regex, so a text scraper
 * gets them subtly wrong and reports on mutations that do not exist.
 */
if (cli.flags.has("--print-json")) {
  console.log(JSON.stringify(selected, null, 2));
  process.exit(0);
}

/**
 * `--anchors` — check every `from` still exists, without running anything.
 *
 * A STALE anchor is scored a survivor, which is correct but expensive to learn:
 * the audit only says so after a full suite run per mutation. Refactoring
 * `src/` silently staled four entries in this list, and nobody found out until
 * an audit that costs an hour reported them. This is the cheap way to ask.
 */
if (cli.flags.has("--anchors")) {
  let stale = 0;
  const cache = new Map<string, string>();
  for (const mutation of MUTATIONS) {
    if (!cache.has(mutation.file)) cache.set(mutation.file, readFileSync(join(repoRoot, mutation.file), "utf8"));
    if (!cache.get(mutation.file)!.includes(mutation.from)) {
      console.log(`STALE ${mutation.id.padEnd(46)} ${mutation.file}`);
      stale += 1;
    }
  }
  console.log(`\n${MUTATIONS.length - stale}/${MUTATIONS.length} anchors present`);
  process.exit(stale === 0 ? 0 : 1);
}

const baseline = runSuite();
console.log(`baseline: ${baseline.pass} pass / ${baseline.fail} fail\n`);
// A baseline of zero passes is not a green suite, it is no reading at all — the
// suite failed to start, or its output could not be parsed. Continuing from it
// scores every mutation NO-RESULT and prints a clean-looking audit that proves
// nothing, which is the exact failure this file exists to prevent. Fatal, not a
// warning.
if (baseline.pass === 0) {
  console.error("Refusing to audit: the baseline suite reported no passing tests, so nothing here can be measured.");
  process.exit(2);
}
if (baseline.fail !== 0) {
  console.error(`Refusing to audit against a red suite. Failing: ${baseline.failed.join(", ")}`);
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
  beginMutation(path, original);
  writeFileSync(path, original.replace(mutation.from, mutation.to));
  let result = runSuite();
  // A suite that reported NOTHING did not survive the mutation — it failed to
  // run at all, which under load looks identical to a survivor and is why a
  // review saw `M21 SURVIVED 0/0` that re-ran clean in isolation. Retry once,
  // then say "no result" rather than blame the rule.
  if (result.pass === 0 && result.fail === 0) result = runSuite();
  endMutation();
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
