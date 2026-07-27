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
import {
  blankSpans,
  commentSyntaxForPath,
  importedBindings,
  importsModule,
  inlineDataRegions,
  loadCallMentions,
  maskCommentsForPath,
  mentionsCannotLoad,
  type InlineDataNode
} from "./source-text";
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
 *   - a copy of this scanner's own denylist reached through a SECOND binding, so
 *     the bound-name check never sees the name the load uses. Three routes were
 *     measured, each with a plain-`require` control that fails:
 *       * array destructuring — `var DENY = […]; var [a] = DENY; __require(a)`;
 *       * a function RETURNED by a resolver — `var r = createRequire(…); r(DENY[0])`,
 *         where the callee is `r` and no callee list can name it;
 *       * a two-file re-export — `export const DENY` in one module, the load in
 *         another. Single-file text matching cannot follow it, by construction.
 *     `Module._load(DENY[0])` was a fourth and is now closed — see `LOAD_CALLEE`.
 *     All three need a hand-built fake denylist; the assembled-name case above
 *     needs nothing. All three are MODULE-class: the equality rules in
 *     `isOwnPatternDeclaration` leave no slot for a `config` pattern or a
 *     credential env key to ride along.
 *
 *     Two measurements about the alternatives, so this is not read as a
 *     regression. The path-scoped predecessor on `main` did not close the
 *     two-file route either — it caught it in `lib/` only because it declined to
 *     attribute outside build output, and the same two files under `dist/`
 *     scanned clean there too. Published 0.8.2 DOES catch it, because it
 *     attributes nothing at all — which is the same property that makes it report
 *     six unremovable findings against every consumer that bundles this package.
 *     See `isOwnPatternDeclaration` for the trade.
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

/**
 * `checkKind` — the finding kind this pattern reports, when it is not the kind
 * of the file it was found in.
 *
 * Declared here rather than decided at the finding site, because the finding
 * site had to SPELL the pattern to decide it: `pattern === ".hasna/cloud"`. A
 * second literal copy of a forbidden name inside the scanner is a second thing
 * a bundler inlines into every consumer, and the copies at the finding sites
 * were not data — they were code, so nothing structural could ever explain them
 * away. Every forbidden name this file knows is now written exactly once, in
 * this table.
 */
const RUNTIME_PATTERNS = [
  { pattern: "@hasna/cloud", kind: "module", message: "Shared @hasna/cloud runtime reference is forbidden" },
  { pattern: "open-cloud", kind: "module", message: "Shared open-cloud runtime reference is forbidden" },
  { pattern: "cloud-mcp", kind: "module", message: "Legacy cloud-mcp runtime surface is forbidden" },
  { pattern: "registerCloudTools", kind: "symbol", message: "Legacy registerCloudTools runtime surface is forbidden" },
  { pattern: "registerCloudCommands", kind: "symbol", message: "Legacy registerCloudCommands runtime surface is forbidden" },
  { pattern: ".hasna/cloud", kind: "config", checkKind: "runtime_config", message: "Legacy .hasna/cloud runtime config is forbidden" },
  { pattern: "HASNA_CLOUD_", kind: "config", message: "Shared HASNA_CLOUD_* runtime config is forbidden" },
  { pattern: "HASNA_RDS_PASSWORD", kind: "config", message: "Legacy shared RDS credential config is forbidden" }
] as const satisfies ReadonlyArray<{ pattern: string; kind: RuntimePatternKind; checkKind?: NoCloudCheckKind; message: string }>;

/**
 * Patterns that are a PATH fragment, so a file living at one is runtime config
 * whatever its extension says. Read off the table instead of re-spelled.
 */
const PATH_CONFIG_PATTERNS = RUNTIME_PATTERNS.filter(
  (entry): entry is typeof entry & { checkKind: NoCloudCheckKind } => "checkKind" in entry
);

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

/**
 * THE INLINED-DECLARATION FALSE POSITIVE, AND WHY IT IS ANSWERED BY CONTENT.
 *
 * This scanner declares what it forbids as data:
 * `FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["@hasna/cloud", "open-cloud"]` and a
 * `RUNTIME_PATTERNS` row per pattern. A bundler that inlines `@hasna/contracts`
 * copies both into the consumer's output verbatim, and the scanner then read its
 * own denylist back out of the consumer's artifact and scored it as the
 * consumer's breach. Measured on a consumer that imports nothing but
 * `scanNoCloudTarget`: SIX findings in one `dist/index.js`, including
 * `HASNA_RDS_PASSWORD`, and nothing the consumer could delete to clear them. The
 * tell was `open-cloud` reported against a repo that never used it.
 *
 * WHAT WAS TRIED AND REJECTED, because the same idea will look attractive again:
 *
 *   - EXEMPT BUILD-OUTPUT PATHS (`dist/`, `bin/`, …). The three `config`
 *     patterns have no import to look for, so a bare occurrence is their only
 *     detector; exempting build output turns it off. Measured: a `dist`-only
 *     tarball leaking `HASNA_RDS_PASSWORD` scored two criticals before and zero
 *     after. A false-positive fix that opens a credential blind spot is worse
 *     than the bug.
 *   - EXEMPT THIS PACKAGE'S OWN FILE PATHS by name and package identity. Shipped,
 *     and it has the same defect in a smaller box: `textFindings` returned `[]`
 *     for the whole file, config patterns included. Measured against published
 *     0.8.1 and 0.8.2 with a byte-identical `dist/no-cloud.js` carrying a planted
 *     `HASNA_RDS_PASSWORD` — named `@hasna/contracts` it PASSED with zero
 *     findings; named anything else the same bytes scored two criticals. The one
 *     artifact whose credential detectors were off was this package's own
 *     release.
 *   - TREAT A BARE MENTION WITH NO IMPORT SPECIFIER AS A FALSE POSITIVE. Unsound
 *     in both directions. `bun build --external` emits `__require("…")`, which is
 *     a real load carrying no specifier the old matcher could see; and a source
 *     file doing `import pkg from "../package.json" with { type: "json" }` makes
 *     the bundler inline the whole manifest, so `"@hasna/cloud": "0.1.24"` sits
 *     in the artifact as a bare mention with zero specifiers anywhere — a
 *     confirmed true positive.
 *
 * WHAT IS ACTUALLY DIFFERENT about the copied declaration is not where it lives
 * and not what surrounds it in the file. It is that the text IS this scanner's
 * own constant, still in the inert data shape the scanner wrote it in. So that
 * is what gets matched, and only the characters it spans are dropped:
 *
 *   - the array must equal `FORBIDDEN_SHARED_CLOUD_RUNTIMES` element for
 *     element, so an array holding anything else is not it;
 *   - a row must equal one `RUNTIME_PATTERNS` row ENTRY FOR ENTRY — same key
 *     count, every value equal — which is the record analogue of the array rule
 *     above. Partial versions of this were tried twice and each left one free
 *     slot: comparing three keys left the rest of the key set uncompared, and
 *     bounding the key set to a union over all rows admitted `checkKind` on all
 *     eight while only ever checking it was A string, never the RIGHT one. Full
 *     equality removes the class rather than the instance;
 *   - the collection must sit where data sits and must not be read in place, and
 *     if it is bound to a name, no load call in the file may mention that name.
 *     That is what keeps `__require(DENY[0])` from becoming a way to launder a
 *     specifier through a copy of the denylist.
 *
 * The consequence that matters, and the wording has been wrong twice so it is
 * worth reading precisely: no detector is turned off for any occurrence OUTSIDE a
 * blanked span, and a blanked span holds nothing but an exact copy of something
 * this table declares — a record equal to a row entry for entry, or an array equal
 * to the denylist element for element. There is no admitted-but-uncompared slot
 * left for anything else to occupy, which is what finally makes the second half of
 * that sentence true.
 *
 * It was not true before. The first version of this comment claimed "NO DETECTOR
 * IS TURNED OFF ANYWHERE" while three keys were compared and the rest of the key
 * set was not. The second claimed "nothing but a row this table emits" while
 * `checkKind` was admitted on every row and never compared — a module row carrying
 * a `checkKind` is a row this table never emits, and it was attributed. Both
 * claims were caught by review rather than by a test, which is the argument for
 * writing the guarantee as narrowly as the code earns it.
 *
 * Each occurrence is judged on its own, so the same file keeps every check for
 * every other occurrence in it — a consumer that bundles `@hasna/contracts` and
 * also reads `HASNA_CLOUD_*`, or also loads the retired runtime, is still
 * reported. No path is consulted, so nothing is exempt for living in `dist/`, and
 * `git mv` cannot change a verdict.
 *
 * WHAT IT DOES NOT CLOSE, corrected after a review measured it: not one route
 * but THREE, and they are single-binding rather than two-step. Each reaches a copy
 * of the denylist through a name the bound-name check cannot see — array
 * destructuring, a function returned by `createRequire`, and a two-file
 * re-export. `Module._load` was a fourth and is closed. The scope block at the top
 * of this file enumerates them with the controls that fail.
 *
 * They are MODULE-CLASS ONLY, and that bound comes from the two equality rules
 * rather than from an argument: the only array ever attributed equals the
 * denylist, which holds package names and nothing else, and the only record ever
 * attributed equals a table row entry for entry, so it has no slot to carry a
 * value in. No `config` pattern and no credential env key can ride any of the
 * three.
 *
 * The earlier wording here said "bound to one name, rebound to a second", which
 * made the residual sound narrower and harder to reach than it is. Understating it
 * was wrong.
 *
 * THE TRADE, stated plainly, because "attribution is strictly better" would be the
 * comfortable version and it is not accurate. Published 0.8.2 attributes NOTHING,
 * so it catches the two-file re-export route that this concedes — and that same
 * property is why it reports six unremovable findings against every consumer that
 * bundles this package. 0.8.2 catches more and cries wolf; this cries less and
 * concedes three aliasing routes, all module-class. That is the exchange being
 * made, deliberately, and it is reversible: the array and record equality rules are
 * where to tighten if the exchange ever looks wrong.
 */
function isOwnPatternDeclaration(node: InlineDataNode): boolean {
  if (node.kind === "array") {
    return (
      node.items.length === FORBIDDEN_SHARED_CLOUD_RUNTIMES.length &&
      node.items.every((item, index) => item.kind === "string" && item.value === FORBIDDEN_SHARED_CLOUD_RUNTIMES[index])
    );
  }
  if (node.kind !== "record") return false;
  // A ROW MUST EQUAL ONE TABLE ROW ENTRY FOR ENTRY. Same key count, every value
  // equal. Nothing about the record is left uncompared.
  //
  // This is the record analogue of the array branch above, and it belongs beside
  // it: an array is attributed only when it matches ELEMENT FOR ELEMENT, and a
  // record only when it matches ENTRY FOR ENTRY. Two rounds of review were spent
  // arriving back at that symmetry, by two different partial versions of it:
  //
  //   1. compare three keys, ignore the rest of the key set. A verbatim
  //      `{pattern, kind, message}` triple plus one more key carried anything at
  //      all through the blanked span.
  //   2. bound the key set to the union of keys the table emits, and require
  //      every value to be a string. `checkKind` is declared on exactly ONE row,
  //      but a union admitted it on all eight — and being a string was all it had
  //      to be, never the right string. A backtick literal then made the span
  //      multi-line and arbitrarily long.
  //
  // Measured at the second version, as tarballs under a third-party package name,
  // each against a control that fails:
  //
  //   verbatim module row + `checkKind` holding a credential env key -> EXIT=0, 0 findings
  //     control: the same string with no triple around it            -> EXIT=1, 1 critical
  //   verbatim config row + backtick `checkKind`, four patterns
  //     spread over five lines                                      -> EXIT=0, 0 findings
  //     control: the same payload with no triple                    -> EXIT=1, 3 critical
  //   the same slot in hand-authored `src/table.ts`                  -> EXIT=0, 0 findings
  //
  // Each narrowing removed one free slot and left the next. Full equality removes
  // the CLASS: there is no slot left that is admitted but uncompared, so a future
  // field cannot become the next one. That is the property to preserve — if this
  // ever needs loosening, loosen the SHAPES matched, never the completeness of the
  // comparison.
  //
  // It costs nothing real: the build emits `{pattern, kind, message}` seven times
  // and `{pattern, kind, checkKind, message}` once, and full equality accepts
  // every one of them. The keys come from the MATCHED ROW rather than from a union
  // over all rows, so `checkKind` is admitted only on the row that declares it.
  return RUNTIME_PATTERNS.some((row) => {
    const keys = Object.keys(row) as ReadonlyArray<keyof typeof row>;
    if (keys.length !== node.entries.size) return false;
    return keys.every((key) => {
      const value = node.entries.get(key);
      return value?.kind === "string" && value.value === row[key];
    });
  });
}

/**
 * `masked`, with this package's own inlined declarations blanked out.
 *
 * Blanked rather than deleted, so every offset in the returned text still lines
 * up with the original — the invariant `maskComments` maintains, and the reason a
 * caller can mix the two.
 *
 * Restricted to C-family source because that is the only thing a bundler inlines
 * a JavaScript constant into. A `package.json` is read structurally by
 * `manifestEdges` and a lockfile by the graph walk, and neither should have its
 * text quietly edited on the strength of a shape match.
 */
function withoutInlinedDeclarations(masked: string, path: string): string {
  if (commentSyntaxForPath(path) !== "c-like") return masked;
  const spans: Array<{ start: number; end: number }> = [];
  for (const region of inlineDataRegions(masked, RUNTIME_PATTERNS.map((entry) => entry.pattern))) {
    // A collection stored under a name that a load call also names is a
    // laundering route, not a declaration. Withdraw the whole region.
    if (region.boundName !== null && loadCallMentions(masked, region.boundName)) continue;
    // The region ROOT, or a direct element of a root array — not an arbitrary
    // node anywhere inside it.
    //
    // This is what this package actually emits: the denylist is a bare assigned
    // array, and `RUNTIME_PATTERNS` is an assigned array whose ELEMENTS are the
    // rows. Nothing it emits buries either shape under a property key. Walking
    // the whole tree instead would have attributed
    // `var schema = { forbidden: ["…", "…"] };` — a consumer's own object, which
    // this package never writes. It is reachable only through `schema`, and the
    // bound-name check above already covers a load through that name, so the
    // looser rule was not unsafe so much as unearned. Claim the shapes we emit.
    for (const node of [region.root, ...(region.root.kind === "array" ? region.root.items : [])]) {
      if (isOwnPatternDeclaration(node)) spans.push({ start: node.start, end: node.end });
    }
  }
  return blankSpans(masked, spans);
}

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

function pathFindings(file: ScanFile, severity: NoCloudFindingSeverity): NoCloudFinding[] {
  const findings: NoCloudFinding[] = [];
  for (const entry of RUNTIME_PATTERNS) {
    if (!file.path.includes(entry.pattern)) continue;
    findings.push({
      id: `finding_${stableId(`${file.path}:path:${entry.pattern}`)}`,
      kind: "checkKind" in entry ? entry.checkKind : file.kind,
      severity,
      path: file.path,
      pattern: entry.pattern,
      message: `${entry.message} in path`,
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
 * Then this package's own inlined pattern declarations are blanked — see
 * `withoutInlinedDeclarations` for why that is decided by content and not by
 * path, and for the two path-shaped attempts it replaces. Both maskers preserve
 * offsets, so they compose.
 *
 * Each pattern yields at most one finding, and the reason is recorded in the
 * message so a reviewer can tell an import from a mention without re-running
 * anything.
 */
function textFindings(file: ScanFile, severity: NoCloudFindingSeverity): NoCloudFinding[] {
  if (isAppCloudManifestDocument(file)) return [];
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
   * The text a BARE MENTION is read out of, and ONLY a bare mention.
   *
   * `importsModule` and `importedBindings` below keep reading the ORIGINAL
   * masked bytes. That asymmetry is deliberate and it is the cheapest safety
   * margin available here: an externalised `import { connect } from "…"`, or a
   * `__require("…")`, survives bundling verbatim and is still reported even if
   * attribution were to over-mask. Dependency edges are answered separately again
   * by `package.json` and `bun.lock`. So the attributed text is used for exactly
   * one of four detectors, and the other three are untouched by it.
   */
  const bareMentionText = withoutInlinedDeclarations(masked, file.path);
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
  if (basename(file.path) !== BUN_LOCKFILE) return textFindings(file, severity);
  const walk = lockfileWalk(file.text, FORBIDDEN_LOCKFILE_PACKAGES);
  if (walk === null) return textFindings(file, severity);
  return [
    ...walk.edges.map((edge) => edgeFinding(edge, file.path, "lockfile", packageName)),
    ...lockfileUnwalkedNameFindings(file, severity, walk),
    ...lockfileTextFindings(file, severity)
  ];
}

function scanFindings(file: ScanFile, severity: NoCloudFindingSeverity, packageName?: string): NoCloudFinding[] {
  if (file.kind === "package_manifest") {
    return [...dependencyFindings(file), ...pathFindings(file, severity), ...textFindings(file, "high")];
  }
  if (file.kind === "lockfile") {
    return [...pathFindings(file, severity), ...lockfileFindings(file, severity, packageName)];
  }
  return [...pathFindings(file, severity), ...textFindings(file, severity)];
}

function shouldReadPath(path: string): NoCloudCheckKind | null {
  // Read off `RUNTIME_PATTERNS` rather than re-spelled here. A second literal
  // copy of a forbidden name inside this file is a second thing a bundler
  // inlines into every consumer, and unlike the table it is code, so nothing
  // structural can ever attribute it back to us.
  for (const entry of PATH_CONFIG_PATTERNS) {
    if (path.includes(entry.pattern)) return entry.checkKind;
  }
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
