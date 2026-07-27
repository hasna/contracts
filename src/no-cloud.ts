import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import { lockfileWalk, manifestEdges, type DependencyEdge, type LockfileWalk } from "./dependency-edge";
import {
  commonArchiveRoot,
  isPackedArtifactPath,
  listArchiveEntries,
  normalizeArchiveEntry,
  readArchiveMemberText
} from "./packed-artifact";
import { importedBindings, importsModule, maskCommentsForPath, mentionsCannotLoad } from "./source-text";
import {
  FORBIDDEN_SHARED_CLOUD_RUNTIMES,
  AppCloudManifestSchema,
  NoCloudEvidencePackSchema,
  SCHEMA_IDS,
  type NoCloudCheckKind,
  type NoCloudCheckResult,
  type NoCloudEvidencePack,
  type NoCloudFinding,
  type NoCloudFindingSeverity
} from "./schemas";

export interface NoCloudScanOptions {
  id?: string;
  now?: string;
  manifest?: unknown;
  generatedBy?: NoCloudEvidencePack["generatedBy"];
}

interface ScanFile {
  path: string;
  text: string;
  kind: NoCloudCheckKind;
}

/**
 * WHAT `verdict: passed` DOES NOT CLAIM.
 *
 * This scan reads an allowlist of directories and extensions. It is a gate on
 * the shapes below, not a proof that no reference to the retired runtime exists
 * anywhere in the tree, and the difference is load-bearing when the verdict is
 * used to certify a remediation. Each of these is pinned by a test in
 * `tests/no-cloud-edge.test.ts` so closing one cannot happen silently:
 *
 *   - a path with NO `SOURCE_DIRS` segment is not read at all: `app/api/…`,
 *     `packages/…`, `apps/…`. `shouldReadPath` requires one.
 *   - `tests/` is in `SKIP_DIRS`, and `test/` SINGULAR is in neither set — so a
 *     `test/` tree is unscanned for the same reason but by a different route.
 *   - a bare `node_modules/@hasna/cloud` on disk with no manifest or lockfile
 *     entry: `node_modules` is skipped, and nothing else looks at disk.
 *   - `Dockerfile`, `.tf` and an extensionless `bin/` script: the extension
 *     filter excludes them.
 *   - an assembled name — `"@hasna/" + "cloud"` — and an escaped specifier —
 *     `"@hasna/cloud"`, `"\x40hasna/cloud"`. Text matching sees neither.
 *     In the guard test `MODULE_RESOLUTION_CAPABILITY` covers the load; nowhere
 *     else does.
 *   - a `git+ssh:` dependency that installs UNDER the package name without the
 *     name appearing in the specifier.
 */
const SKIP_DIRS = new Set([".git", "node_modules", ".cache", ".next", ".turbo", "coverage", "docs", "examples", "tests"]);
const LOCKFILES = new Set(["bun.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"]);
const SOURCE_DIRS = new Set(["src", "bin", "cli", "mcp", "server", "lib", "scripts", "config", "infra", "hooks", ".github", "dist"]);
const MAX_TEXT_BYTES = 5 * 1024 * 1024;

/**
 * What a pattern IS, which decides what evidence counts as a hit.
 *
 * - `module`  — a package name. An import of it is an edge; a mention of it in
 *   code is a lead worth failing on; a mention in a comment is prose.
 * - `symbol`  — an export of the retired runtime. The NAME alone proves
 *   nothing: `iapp-files` defines its own `registerCloudTools` in
 *   `src/mcp/cloud-tools.ts` and routes it at the self-hosted files service.
 *   Only an import binding from a forbidden module makes it a breach.
 * - `config`  — an env or dotdir key. There is no import to look for, so any
 *   occurrence outside a comment counts.
 */
type RuntimePatternKind = "module" | "symbol" | "config";

const RUNTIME_PATTERNS = [
  { pattern: "@hasna/cloud", kind: "module", message: "Shared @hasna/cloud runtime reference is forbidden" },
  { pattern: "open-cloud", kind: "module", message: "Shared open-cloud runtime reference is forbidden" },
  { pattern: "cloud-mcp", kind: "module", message: "Legacy cloud-mcp runtime surface is forbidden" },
  { pattern: "registerCloudTools", kind: "symbol", message: "Legacy registerCloudTools runtime surface is forbidden" },
  { pattern: "registerCloudCommands", kind: "symbol", message: "Legacy registerCloudCommands runtime surface is forbidden" },
  { pattern: ".hasna/cloud", kind: "config", message: "Legacy .hasna/cloud runtime config is forbidden" },
  { pattern: "HASNA_CLOUD_", kind: "config", message: "Shared HASNA_CLOUD_* runtime config is forbidden" },
  { pattern: "HASNA_RDS_PASSWORD", kind: "config", message: "Legacy shared RDS credential config is forbidden" }
] as const satisfies ReadonlyArray<{ pattern: string; kind: RuntimePatternKind; message: string }>;

const MODULE_PATTERNS = RUNTIME_PATTERNS.filter((entry) => entry.kind === "module");

/**
 * Package names a lockfile edge is forbidden to reach.
 *
 * `FORBIDDEN_SHARED_CLOUD_RUNTIMES` is the schema-level list and it is not the
 * whole answer: `cloud-mcp` is a declared forbidden runtime surface that was
 * never added to that constant, so keying the lockfile walk on the constant
 * alone stopped reporting `cloud-mcp` edges at all. Every module-kind pattern
 * is a package name, so every one of them is an edge worth walking to.
 */
const FORBIDDEN_LOCKFILE_PACKAGES: readonly string[] = [
  ...new Set<string>([...FORBIDDEN_SHARED_CLOUD_RUNTIMES, ...MODULE_PATTERNS.map((entry) => entry.pattern)])
];

/**
 * Patterns no dependency edge can carry, because they are env keys and dotdirs
 * rather than package names. The graph walk cannot answer them, so `bun.lock`
 * is still read as text for these — going quiet on them once the walk succeeds
 * would trade one blind spot for another.
 */
const LOCKFILE_TEXT_PATTERNS = RUNTIME_PATTERNS.filter((entry) => entry.kind === "config");

/**
 * A package name spelled as a lockfile TOKEN, not as a substring.
 *
 * The same argument as `LOCKFILE_TEXT_PATTERNS`, applied to the half it was
 * never applied to. Module patterns lost their text fallback entirely when the
 * graph walk took over `bun.lock`, so a pin the walk could not read —
 * `"overrides": { "left-pad": { "@hasna/cloud": "0.1.41" } }` — named the
 * package in plain text and scanned clean.
 *
 * Bounded to a token so this cannot become the substring check the walk
 * replaced: a lockfile name is opened by a quote or a `/` and closed by a
 * quote, an `@` (a resolution id) or a `/`. `@hasna/cloudflare-adapter` and
 * `../open-cloud-shim` are different packages and stay out.
 */
function lockfileNamesPackage(text: string, packageName: string): boolean {
  return new RegExp(`(?:^|["/])${packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=["@/])`).test(text);
}

/**
 * The guard test every remediated repo is required to ship.
 *
 * It exists to assert the retired runtime is absent, which it can only do by
 * naming it. Scoring those assertions as breaches meant the sanctioned fix
 * tripped the gate meant to certify it — `@hasna/connectors@1.4.0` failed on
 * its own guard test three times over. Allowlisting it here, once, is what
 * stops every repo in the remediation wave from inventing a local exemption.
 *
 * ONE path, anchored. The previous spelling matched the filename at ANY depth,
 * which meant the exemption was claimable from `dist/no-cloud-boundary.test.js`
 * — shipped build output — from the repo root, from `config/`, and from
 * `src/deep/nested/`. A file that only asserts absence has no reason to live
 * anywhere but next to the source it guards, and every extra location was a
 * place to put a real load and have it erased.
 *
 * Measured on this fleet at the time of the change: fourteen
 * `no-cloud-boundary.test.*` files exist, TEN at this exact path, two under
 * `test/` singular — which is unscanned for an unrelated reason, see the scope
 * block above `SKIP_DIRS` — and two `dist/*.d.ts` stubs containing `export {};`
 * whose extension does not match this pattern at all. So anchoring here costs
 * nothing that is live today, which is the only claim worth making.
 *
 * Deliberately NOT read from the scanned repo's own manifest: the repo under
 * audit writes that manifest, so a declared path is a path the subject chooses,
 * and `dist/` is one of the things it could choose. A constant here is strictly
 * narrower than anything self-declared.
 *
 * The exemption covers MENTIONS OF A MODULE NAME only:
 *
 *   - a real load is still a finding, whatever shape it takes — see
 *     `guardTestMentionsOnly`, which decides this by ALLOWLIST;
 *   - runtime CONFIG — `HASNA_CLOUD_*`, `.hasna/cloud`, `HASNA_RDS_PASSWORD` —
 *     is still a finding, because a guard test asserts absence by naming a
 *     package, never by setting the shared runtime's environment;
 *   - the file cannot create an install edge without `package.json` or
 *     `bun.lock` showing it, and both are checked separately.
 */
const NO_CLOUD_GUARD_TEST = /^src\/no-cloud-boundary\.test\.(?:[cm]?[jt]sx?|[cm]ts)$/;

/**
 * `import(` or `require(` whose argument is not ONE complete, simple string
 * literal.
 *
 * Stated as a negative on purpose. The first version enumerated the shapes it
 * considered computed — an identifier start — and a review walked past it with
 * a template literal. Listing what is dangerous is how you miss the next
 * spelling; listing the one safe shape is not.
 *
 * So anything that is not `("literal")` or `('literal')` withdraws the
 * guard-test exemption: a backtick specifier, a computed template, an
 * identifier, and `"a" + "b"` alike.
 *
 * A genuine guard test builds regex SOURCE like `require\s*\(\s*`, where the
 * character after `(` is a backslash inside a string literal — the lookahead
 * sees a complete literal, and the exemption stands.
 */
const DYNAMIC_MODULE_LOAD = /\b(?:import|require)\s*\(\s*(?!(["'])[^"'\n]*\1\s*\))/;

/**
 * Module-resolution capability, present at all.
 *
 * The mention audit in `guardTestMentionsOnly` reads where the package NAME
 * sits. This reads whether the file can resolve a module at all, whatever it
 * resolves — because the name can be assembled (`"@hasna/" + "cloud"`), escaped
 * (`"\x40hasna/cloud"`), or read from a fixture, and none of those spellings
 * reach the audit. A file whose only job is to assert absence needs none of
 * these APIs, so their presence alone withdraws the exemption.
 *
 * Verified against all fourteen `no-cloud-boundary.test.*` files on this fleet:
 * none of them uses any of these.
 */
const MODULE_RESOLUTION_CAPABILITY =
  /\b(?:createRequire|resolveSync|process\.binding|dlopen|eval|Function)\s*\(|\brequire\s*\.\s*resolve\b|\bimport\s*\.\s*meta\s*\.\s*resolve\b|\bBun\s*\.\s*plugin\b|\bnew\s+(?:URL|Worker|SharedWorker|Function)\s*\(/;

function isNoCloudGuardTest(path: string): boolean {
  return NO_CLOUD_GUARD_TEST.test(path.replaceAll("\\", "/"));
}

/**
 * Does this guard test only MENTION the retired runtimes?
 *
 * Three independent withdrawals, because the failure this replaces was a single
 * check that knew about two shapes:
 *
 *   1. it resolves modules at all (`MODULE_RESOLUTION_CAPABILITY`);
 *   2. it loads a computed specifier (`DYNAMIC_MODULE_LOAD`);
 *   3. any literal mention of a forbidden module sits somewhere that could
 *      resolve it (`mentionsCannotLoad`, an allowlist of inert positions).
 *
 * `masked` is for the shape checks, which must not fire on prose. The mention
 * audit gets RAW text because it lexes, and it recognises comments itself.
 */
function guardTestMentionsOnly(file: ScanFile, masked: string): boolean {
  if (!isNoCloudGuardTest(file.path)) return false;
  if (MODULE_RESOLUTION_CAPABILITY.test(masked)) return false;
  if (DYNAMIC_MODULE_LOAD.test(masked)) return false;
  return MODULE_PATTERNS.every((module) => mentionsCannotLoad(file.text, file.path, module.pattern));
}

const DECLARATION_FILE_MARKERS = [
  "FORBIDDEN_SHARED_CLOUD_RUNTIMES",
  "RUNTIME_PATTERNS",
  "hasna.app_cloud_manifest.v1",
  "hasna.no_cloud_evidence_pack.v1"
] as const;
const CONTRACTS_DECLARATION_PATHS = new Set([
  "src/no-cloud.ts",
  "src/schemas.ts",
  "dist/no-cloud.js",
  "dist/schemas.js",
  "dist/validators.js",
  "dist/index.js",
  "dist/mode.js",
  "dist/service-contract.js",
  "dist/secure-local-store.js",
  "dist/conformance.js",
  "dist/client/transport.js",
  "dist/client/storage.js",
  "dist/cli/index.js",
  "dist/no-cloud.d.ts",
  "dist/schemas.d.ts",
  "dist/mode.d.ts",
  "dist/service-contract.d.ts",
  "dist/secure-local-store.d.ts",
  "dist/conformance.d.ts"
]);

function stableId(input: string) {
  let hash = 0;
  for (let index = 0; index < input.length; index += 1) {
    hash = Math.imul(31, hash) + input.charCodeAt(index);
  }
  return Math.abs(hash >>> 0).toString(36);
}

function readJson(text: string): unknown | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function packageVersionFromPackageJson(text: string): { name?: string; version?: string } {
  const parsed = readJson(text);
  if (!isRecord(parsed)) return {};
  const record = parsed as { name?: unknown; version?: unknown };
  const packageInfo: { name?: string; version?: string } = {};
  if (typeof record.name === "string") packageInfo.name = record.name;
  if (typeof record.version === "string") packageInfo.version = record.version;
  return packageInfo;
}

function malformedPackageJsonFinding(file: ScanFile): NoCloudFinding | null {
  if (isRecord(readJson(file.text))) return null;
  return {
    id: `finding_${stableId(`${file.path}:malformed`)}`,
    kind: "package_manifest",
    severity: "critical",
    path: file.path,
    pattern: "package.json",
    message: "package.json must be valid JSON object before no-cloud dependency checks can pass",
    evidenceRefs: []
  };
}

function missingPackageJsonFinding(): NoCloudFinding {
  return {
    id: "finding_package_manifest_missing",
    kind: "package_manifest",
    severity: "critical",
    pattern: "package.json",
    message: "No-cloud scan target must include a package.json manifest",
    evidenceRefs: []
  };
}

function dependencyFindings(file: ScanFile): NoCloudFinding[] {
  const parsed = readJson(file.text);
  if (!isRecord(parsed)) {
    const malformed = malformedPackageJsonFinding(file);
    return malformed ? [malformed] : [];
  }
  const pkg = parsed;
  const packageName = typeof pkg.name === "string" ? pkg.name : undefined;
  const findings: NoCloudFinding[] = [];

  if (packageName && FORBIDDEN_SHARED_CLOUD_RUNTIMES.includes(packageName as (typeof FORBIDDEN_SHARED_CLOUD_RUNTIMES)[number])) {
    findings.push({
      id: `finding_${stableId(`${file.path}:name:${packageName}`)}`,
      kind: "package_manifest",
      severity: "critical",
      path: file.path,
      packageName,
      pattern: packageName,
      message: "Package identity is a forbidden shared cloud runtime",
      evidenceRefs: []
    });
  }

  // Every section that can pull the package into an install, not just the four
  // version maps: `overrides`/`resolutions` pin a package without naming it as
  // a dependency, and `bundleDependencies`/`trustedDependencies` are arrays of
  // names. All of them are edges; only some of them were being read.
  for (const edge of manifestEdges(pkg, FORBIDDEN_SHARED_CLOUD_RUNTIMES)) {
    findings.push({
      id: `finding_${stableId(`${file.path}:${edge.section}:${edge.packageName}`)}`,
      kind: "package_manifest",
      severity: edge.scope === "production" ? "critical" : "high",
      path: file.path,
      packageName,
      pattern: edge.packageName,
      message: `Forbidden shared cloud runtime dependency in ${edge.section}`,
      evidenceRefs: []
    });
  }

  return findings;
}

function isAppCloudManifestDocument(file: ScanFile): boolean {
  if (!file.path.endsWith(".json")) return false;
  const parsed = readJson(file.text);
  return isRecord(parsed) && parsed.schema === SCHEMA_IDS.appCloudManifest;
}

function isNoCloudDeclarationFile(file: ScanFile, packageName?: string): boolean {
  if (packageName !== "@hasna/contracts") return false;
  const normalized = file.path.replaceAll("\\", "/");
  if (!CONTRACTS_DECLARATION_PATHS.has(normalized)) return false;
  if (!/\.(cjs|cts|js|jsx|mjs|mts|ts|tsx)$/i.test(normalized)) return false;
  const markerCount = DECLARATION_FILE_MARKERS.filter((marker) => file.text.includes(marker)).length;
  return markerCount >= 2;
}

/**
 * Directories whose contents are BUILD OUTPUT — emitted by a bundler rather than
 * written by anyone.
 *
 * `lib` is deliberately absent even though `SOURCE_DIRS` lists it: plenty of
 * repos author directly in `lib/`, and mistaking authored code for output buys a
 * false negative. Erring toward noise is the correct direction here.
 */
const GENERATED_OUTPUT_DIRS = new Set(["bin", "dist", "build", "out", ".output"]);

/**
 * What a bundler EMITS: a JavaScript or TypeScript module, `.d.ts` included.
 *
 * Sitting in `bin/` is not on its own enough to call a file generated. `bin/`
 * and `build/` routinely hold hand-written shell scripts, and `shouldReadPath`
 * reads `.sh`, `.yml`, `.toml` and `.env` too. A `bin/deploy.sh` exporting
 * `HASNA_CLOUD_*` is somebody's decision, not a byte a bundler copied.
 */
const BUNDLED_ARTIFACT_FILE = /\.(?:[cm]?[jt]sx?)$/i;

/**
 * Directories nobody generates INTO — where a `dist` segment underneath is a
 * folder somebody named, not a build.
 *
 * Without this, `src/dist/loader.ts` counted as build output, which is a
 * self-service exemption: a repo could park authored code one directory deep and
 * be exempt. Measured before this clause existed — that exact path scanned clean.
 * Ordering is what separates the two: build output nested under authored source
 * is authored, while authored-looking structure nested under build output —
 * `dist/src/index.js`, which `tsc --rootDir .` really does emit — is still
 * output.
 *
 * Kept to the three names that are never a package folder. `app` is deliberately
 * absent: `app/dist/index.js` is a real build path in a monorepo, and listing it
 * would trade this bypass back for the false positive #34 is about. Verified
 * against every build-output file carrying a hit on this fleet — none has a `src`
 * or `lib` segment above its output directory.
 */
const AUTHORED_SOURCE_DIRS = new Set(["src", "lib", "source"]);

/**
 * Is this path a bundler-emitted module inside build output?
 *
 * Directory segments only for the directory test — the basename is excluded so a
 * FILE called `dist.ts` is still read as the source it is.
 */
function isGeneratedOutputPath(path: string): boolean {
  const normalized = path.replaceAll("\\", "/");
  if (!BUNDLED_ARTIFACT_FILE.test(normalized)) return false;
  const dirs = normalized.split("/").slice(0, -1);
  const output = dirs.findIndex((segment) => GENERATED_OUTPUT_DIRS.has(segment));
  if (output === -1) return false;
  return !dirs.slice(0, output).some((segment) => AUTHORED_SOURCE_DIRS.has(segment));
}

/**
 * An assigned, single-line ARRAY LITERAL — captured by its VALUE, not by the
 * name it is assigned to.
 *
 * WHY BY VALUE. This scanner's own denylist is a pair of string literals, so any
 * repo that bundles `@hasna/contracts` without externalising it gets
 * `["@hasna/cloud", "open-cloud"]` inlined into its output, and the scanner then
 * read its own denylist back out of the consumer's artifact and scored it as the
 * consumer's breach. The tell was `open-cloud` reported against repos that never
 * used it.
 *
 * Keying on the identifier `FORBIDDEN_SHARED_CLOUD_RUNTIMES` plus a
 * `const|let|var` prefix does NOT recognise what bundlers actually emit, and was
 * measured missing both real shapes on this fleet:
 *
 *   - bun's lazy `__esm` wrapper HOISTS the declaration and emits a bare
 *     assignment: `  FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["@hasna/cloud", …];`
 *     with no keyword anywhere near it;
 *   - `--minify-identifiers` RENAMES it and folds it into a comma sequence:
 *     `…,Ob=["@hasna/cloud","open-cloud"],pG=…` — no keyword, no original name,
 *     no trailing `;`.
 *
 * The value is the part a bundler cannot rewrite, so the value is what this
 * matches. Sweep over 1656 build-output files in 41 consumer repos: 18 of 18
 * files whose only hits were the two module names are cleared by this; the
 * remaining 4 are `registerCloudTools`/`registerCloudCommands` in a repo that
 * defines its own, which is a `symbol` pattern and never reached this branch.
 *
 * TWO NARROWINGS, both load-bearing:
 *
 *   - `=` immediately before the literal, so it is a VALUE BEING STORED. A
 *     literal passed straight into a call — `loadAll(["@hasna/cloud", …])` — is
 *     not a declaration and stays visible. The lookbehind rejects `==`, `===`,
 *     `!==`, `<=`, `>=`; `=>` cannot match because `>` is not whitespace.
 *   - nothing may be INVOKED on the literal. `[…].map((name) => require(name))`
 *     and `[…][0]` turn the array into a load, which is the one move that makes
 *     these strings live again, so `.`, `(` and `[` after the closing bracket
 *     withdraw the mask.
 */
const ASSIGNED_ARRAY_LITERAL = /(?<![=!<>])=[^\S\r\n]*\[([^[\]\r\n]*)\](?![^\S\r\n]*[.(\[])/g;

/** The literal's elements, or `null` for any element that is not a plain string literal. */
function arrayLiteralStrings(elements: string): (string | null)[] {
  return elements.split(",").map((element) => {
    const literal = element.trim();
    const quote = literal[0];
    if ((quote !== '"' && quote !== "'") || literal.at(-1) !== quote || literal.length < 2) return null;
    return literal.slice(1, -1);
  });
}

/**
 * Blank out inlined copies of this package's denylist, in place.
 *
 * Same-length spaces, so every other byte keeps its offset and no two tokens
 * merge: a second mention, or a real import, elsewhere on the same minified line
 * stays exactly where the scanner can still see it.
 */
function maskVendoredDenylistLiterals(text: string): string {
  return text.replace(ASSIGNED_ARRAY_LITERAL, (assignment, elements: string) => {
    const values = arrayLiteralStrings(elements);
    const isVendoredDenylist =
      values.length === FORBIDDEN_SHARED_CLOUD_RUNTIMES.length &&
      values.every((value, index) => value === FORBIDDEN_SHARED_CLOUD_RUNTIMES[index]);
    return isVendoredDenylist ? assignment.replace(/[^\r\n]/g, " ") : assignment;
  });
}

function pathFindings(file: ScanFile, severity: NoCloudFindingSeverity): NoCloudFinding[] {
  const findings: NoCloudFinding[] = [];
  for (const { pattern, message } of RUNTIME_PATTERNS) {
    if (!file.path.includes(pattern)) continue;
    findings.push({
      id: `finding_${stableId(`${file.path}:path:${pattern}`)}`,
      kind: pattern === ".hasna/cloud" ? "runtime_config" : file.kind,
      severity,
      path: file.path,
      pattern,
      message: `${message} in path`,
      evidenceRefs: []
    });
  }
  return findings;
}

/**
 * Runtime-pattern findings for one file, read as source rather than as a byte
 * stream.
 *
 * Comments are masked first. That single change is what clears
 * `@hasna/connectors@1.4.0`, whose only `@hasna/cloud` reference in `src/` is
 * the JSDoc line recording that the import was REMOVED.
 *
 * Each pattern yields at most one finding, and the reason is recorded in the
 * message so a reviewer can tell an import from a mention without re-running
 * anything.
 */
function textFindings(file: ScanFile, severity: NoCloudFindingSeverity, packageName?: string): NoCloudFinding[] {
  if (isAppCloudManifestDocument(file)) return [];
  if (isNoCloudDeclarationFile(file, packageName)) return [];
  const masked = maskCommentsForPath(file.text, file.path);
  // The exemption is withdrawn from a "guard test" that can load a module at
  // all — the one move that turns a mention into a real load, and the one thing
  // a genuine guard test never does.
  const guardTest = guardTestMentionsOnly(file, masked);
  // Reading imports only makes sense where there is code to read. A lockfile
  // or a dotenv file has no import statements, so requiring a binding there
  // drops the check rather than scoping it.
  const codeLike = file.kind === "source_import" || file.kind === "packed_artifact";
  /**
   * The text a BARE MENTION is read out of — the vendored denylist blanked, but
   * ONLY where a bundler could have put it there.
   *
   * Scoping this to build output is what stops a repo exempting itself: an
   * authored `src/loader.ts` that writes the same array and then loads through it
   * (`await import(NAMES[0])`) is unchanged here, so it stays a finding. Without
   * the path scope the mask is a self-service exemption in hand-written code.
   *
   * `importsModule` and `importedBindings` keep reading the ORIGINAL bytes: an
   * externalised `import { connect } from "@hasna/cloud"` survives bundling
   * verbatim and is still critical in `dist/`, as are dependency edges, which
   * `package.json` and `bun.lock` answer separately.
   */
  const bareMentionText = codeLike && isGeneratedOutputPath(file.path) ? maskVendoredDenylistLiterals(masked) : masked;
  const findings: NoCloudFinding[] = [];

  for (const { pattern, kind, message } of RUNTIME_PATTERNS) {
    let reason: string | null = null;
    if (kind === "symbol" && codeLike) {
      // Bound from a forbidden module, or it is somebody else's function.
      const bound = MODULE_PATTERNS.some((module) => importedBindings(masked, module.pattern).has(pattern));
      if (bound) reason = "imported binding";
    } else if (kind === "module" && importsModule(masked, pattern)) {
      reason = "module import";
    } else if (!(guardTest && kind === "module") && bareMentionText.includes(pattern)) {
      reason = "source reference";
    }
    if (!reason) continue;
    findings.push({
      id: `finding_${stableId(`${file.path}:${pattern}`)}`,
      kind: file.kind,
      severity,
      path: file.path,
      pattern,
      message: `${message} (${reason})`,
      evidenceRefs: []
    });
  }
  return findings;
}

/** A dependency edge, rendered as a finding. */
function edgeFinding(edge: DependencyEdge, path: string, kind: NoCloudCheckKind, packageName?: string): NoCloudFinding {
  const via = edge.path.length > 1 ? ` via ${edge.path.join(" -> ")}` : "";
  const where = edge.section ? ` (root ${edge.section})` : "";
  return {
    id: `finding_${stableId(`${path}:edge:${edge.scope}:${edge.packageName}`)}`,
    kind,
    severity: edge.scope === "production" ? "critical" : "high",
    path,
    ...(packageName ? { packageName } : {}),
    pattern: edge.packageName,
    message: `Forbidden shared cloud runtime is a reachable ${edge.scope} dependency${via}${where}`,
    evidenceRefs: []
  };
}

const BUN_LOCKFILE = "bun.lock";

/** Env keys and dotdirs spelled out in a lockfile, which no dependency edge can express. */
function lockfileTextFindings(file: ScanFile, severity: NoCloudFindingSeverity): NoCloudFinding[] {
  const findings: NoCloudFinding[] = [];
  for (const { pattern, message } of LOCKFILE_TEXT_PATTERNS) {
    if (!file.text.includes(pattern)) continue;
    findings.push({
      id: `finding_${stableId(`${file.path}:${pattern}`)}`,
      kind: file.kind,
      severity,
      path: file.path,
      pattern,
      message: `${message} (source reference)`,
      evidenceRefs: []
    });
  }
  return findings;
}

/**
 * Module names this `bun.lock` spells out that the walk neither reported as an
 * edge nor proved absent.
 *
 * The walk is authoritative for what it decided, not for what it never looked
 * at. A pin shape it cannot read, a stale `packages` entry, a future lockfile
 * layout — all of them name the package in plain text while the walk returns a
 * list and the list reads as a clean tree. `clearedByLayout` is the one
 * exception, and it is a measurement rather than an assumption: a transitive
 * `file:`/`link:` resolution in a hoisted install lands nowhere on disk, which
 * is what clears `hasna/logs` and must keep clearing it.
 *
 * So: report the difference, and over-approximate in the direction that costs
 * noise rather than blindness.
 */
function lockfileUnwalkedNameFindings(
  file: ScanFile,
  severity: NoCloudFindingSeverity,
  walk: LockfileWalk
): NoCloudFinding[] {
  const explained = new Set<string>([...walk.edges.map((edge) => edge.packageName), ...walk.clearedByLayout]);
  const findings: NoCloudFinding[] = [];
  for (const { pattern, message } of MODULE_PATTERNS) {
    if (explained.has(pattern)) continue;
    if (!lockfileNamesPackage(file.text, pattern)) continue;
    findings.push({
      id: `finding_${stableId(`${file.path}:${pattern}`)}`,
      kind: file.kind,
      severity,
      path: file.path,
      pattern,
      message: `${message} (lockfile names it outside any edge the walk could read)`,
      evidenceRefs: []
    });
  }
  return findings;
}

/**
 * Lockfile findings.
 *
 * `bun.lock` is walked as a graph — see `src/dependency-edge.ts` for why a
 * substring is not the same question as an edge. The walk answers PACKAGE
 * NAMES, so the config patterns are still read as text and unioned in;
 * replacing the whole scan with the walk dropped them silently. Module names
 * are unioned back on the same terms, minus the ones the walk actively cleared
 * — the asymmetry between the two halves was the whole bug. Any other lockfile
 * keeps the old text scan, because we have no parser for it and going quiet on
 * an unparsed lockfile is the failure mode this change exists to remove.
 */
function lockfileFindings(file: ScanFile, severity: NoCloudFindingSeverity, packageName?: string): NoCloudFinding[] {
  if (basename(file.path) !== BUN_LOCKFILE) return textFindings(file, severity, packageName);
  const walk = lockfileWalk(file.text, FORBIDDEN_LOCKFILE_PACKAGES);
  if (walk === null) return textFindings(file, severity, packageName);
  return [
    ...walk.edges.map((edge) => edgeFinding(edge, file.path, "lockfile", packageName)),
    ...lockfileUnwalkedNameFindings(file, severity, walk),
    ...lockfileTextFindings(file, severity)
  ];
}

function scanFindings(file: ScanFile, severity: NoCloudFindingSeverity, packageName?: string): NoCloudFinding[] {
  if (file.kind === "package_manifest") {
    return [...dependencyFindings(file), ...pathFindings(file, severity), ...textFindings(file, "high", packageName)];
  }
  if (file.kind === "lockfile") {
    return [...pathFindings(file, severity), ...lockfileFindings(file, severity, packageName)];
  }
  return [...pathFindings(file, severity), ...textFindings(file, severity, packageName)];
}

function shouldReadPath(path: string): NoCloudCheckKind | null {
  if (path.includes(".hasna/cloud")) return "runtime_config";
  const name = basename(path);
  if (name === "package.json") return "package_manifest";
  if (LOCKFILES.has(name)) return "lockfile";
  if (name === ".env" || name.startsWith(".env.")) return "runtime_config";
  if (!/\.(cjs|cts|js|json|jsx|mjs|mts|sh|ts|tsx|toml|ya?ml)$/i.test(name)) return null;
  const parts = path.split(/[\\/]/);
  if (parts.length === 1) return "source_import";
  return parts.some((part) => SOURCE_DIRS.has(part)) ? "source_import" : null;
}

function collectDirectoryFiles(root: string): ScanFile[] {
  const files: ScanFile[] = [];

  function walk(dir: string): void {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const kind = shouldReadPath(relative(root, full).replaceAll("\\", "/"));
      if (!kind) continue;
      const stat = statSync(full);
      if (stat.size > MAX_TEXT_BYTES) continue;
      files.push({ path: relative(root, full).replaceAll("\\", "/"), text: readFileSync(full, "utf8"), kind });
    }
  }

  walk(root);
  return files;
}

function collectTarballFiles(target: string): ScanFile[] {
  const entries = listArchiveEntries(target);
  const archiveRoot = commonArchiveRoot(entries);
  const files: ScanFile[] = [];
  for (const entry of entries) {
    const normalized = normalizeArchiveEntry(entry, archiveRoot);
    if (!normalized) continue;
    // This guard reads SOURCE-SHAPED members only: it is looking for imports
    // and runtime config. The published-artifact guard reads everything, and
    // deliberately so — see src/artifact-scan.ts.
    const kind = shouldReadPath(normalized);
    if (!kind) continue;
    const text = readArchiveMemberText(target, entry);
    const artifactKind = kind === "package_manifest" || kind === "lockfile" ? kind : "packed_artifact";
    files.push({ path: normalized, text, kind: artifactKind });
  }
  return files;
}

function collectScanFiles(target: string): { files: ScanFile[]; scanMode: NoCloudEvidencePack["scanMode"] } {
  const stat = statSync(target);
  if (stat.isDirectory()) return { files: collectDirectoryFiles(target), scanMode: "source_tree" };
  if (stat.isFile() && isPackedArtifactPath(target)) return { files: collectTarballFiles(target), scanMode: "packed_artifact" };
  throw new Error("no-cloud scan target must be a directory, .tgz, or .tar.gz file");
}

function portableSubject(resolved: string, scanMode: NoCloudEvidencePack["scanMode"], packageName?: string) {
  if (scanMode === "packed_artifact") {
    const artifactName = basename(resolved);
    return {
      kind: "artifact" as const,
      id: artifactName,
      uri: `artifact://${artifactName}`
    };
  }

  const repoId = packageName ?? basename(resolved);
  return {
    kind: "repo" as const,
    id: repoId,
    uri: `repo://${repoId}`
  };
}

export function scanNoCloudTarget(target: string, options: NoCloudScanOptions = {}): NoCloudEvidencePack {
  const resolved = resolve(target);
  const { files, scanMode } = collectScanFiles(resolved);
  const packageFile = files.find((file) => file.path === "package.json") ?? files.find((file) => file.path.endsWith("/package.json"));
  const packageInfo = packageFile ? packageVersionFromPackageJson(packageFile.text) : {};
  const subject = portableSubject(resolved, scanMode, packageInfo.name);
  const targetRef = (checkId: string) => `${subject.uri}#${checkId}`;
  const findings = files.flatMap((file) => {
    if (file.kind === "lockfile") return scanFindings(file, "high", packageInfo.name);
    if (file.kind === "packed_artifact") return scanFindings(file, "critical", packageInfo.name);
    return scanFindings(file, "high", packageInfo.name);
  });
  const manifestProvided = Object.prototype.hasOwnProperty.call(options, "manifest") && options.manifest !== undefined;
  const manifestResult = manifestProvided ? AppCloudManifestSchema.safeParse(options.manifest) : null;
  const manifestFindings: NoCloudFinding[] = [];
  if (manifestResult && !manifestResult.success) {
    manifestFindings.push({
      id: "finding_app_cloud_manifest_invalid",
      kind: "app_cloud_manifest",
      severity: "critical",
      pattern: SCHEMA_IDS.appCloudManifest,
      message: manifestResult.error.issues.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`).join("; "),
      evidenceRefs: []
    });
  }
  if (manifestResult?.success && packageInfo.name && manifestResult.data.packageName !== packageInfo.name) {
    manifestFindings.push({
      id: "finding_app_cloud_manifest_package_mismatch",
      kind: "app_cloud_manifest",
      severity: "critical",
      pattern: "packageName",
      message: `App cloud manifest packageName ${manifestResult.data.packageName} does not match scanned package ${packageInfo.name}`,
      evidenceRefs: []
    });
  }
  if (manifestResult?.success && packageInfo.version && manifestResult.data.packageVersion && manifestResult.data.packageVersion !== packageInfo.version) {
    manifestFindings.push({
      id: "finding_app_cloud_manifest_version_mismatch",
      kind: "app_cloud_manifest",
      severity: "high",
      pattern: "packageVersion",
      message: `App cloud manifest packageVersion ${manifestResult.data.packageVersion} does not match scanned package ${packageInfo.version}`,
      evidenceRefs: []
    });
  }
  const packagePresenceFindings = packageFile ? [] : [missingPackageJsonFinding()];
  const allFindings: NoCloudFinding[] = [...packagePresenceFindings, ...findings, ...manifestFindings];

  const status = allFindings.some((finding) => finding.severity === "high" || finding.severity === "critical") ? "failed" : "succeeded";
  const packageChecks = [...packagePresenceFindings, ...files.filter((file) => file.kind === "package_manifest").flatMap((file) => scanFindings(file, "high", packageInfo.name))];
  const lockChecks = files.filter((file) => file.kind === "lockfile").flatMap((file) => scanFindings(file, "high", packageInfo.name));
  const sourceChecks = files
    .filter((file) => file.kind === "source_import" || file.kind === "runtime_config")
    .flatMap((file) => scanFindings(file, "high", packageInfo.name));
  const artifactChecks = files.filter((file) => file.kind === "packed_artifact").flatMap((file) => scanFindings(file, "critical", packageInfo.name));
  const checks: NoCloudCheckResult[] = [
    {
      id: "package_manifest",
      kind: "package_manifest" as const,
      status: packageChecks.length > 0 ? "failed" as const : "succeeded" as const,
      target: targetRef("package_manifest"),
      findings: packageChecks,
      evidenceRefs: []
    },
    {
      id: "lockfile",
      kind: "lockfile" as const,
      status: lockChecks.length > 0 ? "failed" as const : "succeeded" as const,
      target: targetRef("lockfile"),
      findings: lockChecks,
      evidenceRefs: []
    },
    {
      id: "source_runtime",
      kind: scanMode === "packed_artifact" ? "packed_artifact" as const : "source_import" as const,
      status: sourceChecks.length + artifactChecks.length > 0 ? "failed" as const : "succeeded" as const,
      target: targetRef("source_runtime"),
      findings: [...sourceChecks, ...artifactChecks],
      evidenceRefs: []
    }
  ];
  if (manifestProvided) {
    checks.push({
      id: "app_cloud_manifest",
      kind: "app_cloud_manifest",
      status: manifestResult?.success && manifestFindings.length === 0 ? "succeeded" : "failed",
      target: targetRef("app_cloud_manifest"),
      findings: manifestFindings,
      evidenceRefs: []
    });
  }

  return NoCloudEvidencePackSchema.parse({
    schema: SCHEMA_IDS.noCloudEvidencePack,
    id: options.id ?? `no_cloud_${stableId(`${subject.uri}:${packageInfo.version ?? ""}`)}`,
    createdAt: options.now ?? new Date().toISOString(),
    subject,
    packageName: packageInfo.name,
    packageVersion: packageInfo.version,
    generatedBy: options.generatedBy,
    scanMode,
    status,
    verdict: status === "succeeded" ? "passed" : "failed",
    appCloudManifest: manifestResult?.success ? manifestResult.data : undefined,
    checks,
    findings: allFindings
  });
}
