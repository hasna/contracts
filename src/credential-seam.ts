// Conformance rule: nobody resolves a Hasna client credential by hand.
//
// The credential provider chain in `src/client/credentials.ts` only helps the
// consumers that actually go through it. A package that reaches into
// `process.env` for its own `HASNA_<NAME>_API_KEY` keeps the defect the chain
// exists to remove: an environment snapshot taken at process start, which goes
// stale the moment a key is rotated and stays stale for the life of the shell.
// Without a gate the bypassers regrow; with one, every adoption PR is a
// mechanical diff that flips a red check green.
//
// WHAT THIS RULE WILL NOT DO. A mandatory gate that fires on compliant code
// gets switched off, and then it protects nothing — the same end state as a
// check that cannot fail. So the rule is deliberately narrow:
//
//   * It asks `clientTransportEnvKeys()` for the names it polices, rather than
//     approximating them, so the rule and the seam cannot drift apart.
//   * It matches READ expressions only. Writing the variable, naming it in a
//     message, listing it in a redaction allowlist, or passing it to a child
//     process are all compliant — and are the overwhelming majority of the
//     mentions in the fleet.
//   * `HASNA_<APP>_SERVE_API_KEY` and `HASNA_<APP>_BOOTSTRAP_API_KEY` are a
//     SERVER reading the key it expects inbound, not a client resolving a
//     credential. Third-party keys that merely wear the prefix
//     (`HASNA_BRAIN_ANTHROPIC_API_KEY`, `HASNA_CEREBRAS_LIVE_API_KEY`) are not
//     ours to resolve either. Both fall outside the single-segment client-flip
//     grammar and are structurally excluded.
//   * Tests, build output, and shipped bundles are excluded.
//
// The pressure valve is an explicit, reasoned, auditable waiver comment. Every
// waiver is echoed into the conformance report, so a waiver is a thing a
// reviewer reads rather than a thing that disappears.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { clientTransportEnvKeys } from "./client/env-keys.js";

export interface CredentialSeamFinding {
  /** Repo-relative path. */
  path: string;
  /** 1-based line number. */
  line: number;
  /** The env variable being read. */
  variable: string;
  /** Why it is a finding. */
  message: string;
}

export interface CredentialSeamWaiver {
  path: string;
  line: number;
  reason: string;
}

export interface CredentialSeamScan {
  findings: CredentialSeamFinding[];
  waivers: CredentialSeamWaiver[];
  /** Waivers rejected for carrying no usable justification. */
  invalidWaivers: CredentialSeamWaiver[];
  /** Number of source files actually inspected. A zero here means the scan proved nothing. */
  filesScanned: number;
}

export interface CredentialSeamScanOptions {
  /** The app name from the manifest. Its own client-flip keys are the strictest case. */
  appName: string;
}

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  "bin",
  "coverage",
  ".next",
  ".turbo",
  ".cache",
  "tests",
  "test",
  "__tests__",
  "examples",
  "docs",
  // Dev and proof scripts are not shipped behaviour, for the same reason tests
  // are not. Measured: `open-identities/scripts/proof-roundtrip.ts` was the
  // only finding in that repo and it is a round-trip proof, not a client.
  "scripts",
]);

/**
 * Directories that serve INBOUND requests.
 *
 * A server reading its own `HASNA_<APP>_API_KEY` is reading the key it EXPECTS
 * a caller to present, then comparing the two — the opposite of resolving a
 * credential to send. The name is identical, so no grammar can separate them;
 * only location can.
 *
 * Measured across the fleet, every one of these is a constant-time comparison
 * against an inbound header: `iapp-factory/src/api/index.ts` (`secureCompare`),
 * `iapp-sandboxes/src/http/auth.ts` (`safeEqual`), `open-todos/src/server/serve.ts`
 * (`safeEqualStrings`), `open-machines/src/mcp/http.ts`. Flagging them made the
 * gate red on 7 of 24 repos on day one, and a gate that is red on compliant code
 * gets switched off.
 *
 * The trade is deliberate: a genuine client bypass hidden under a server
 * directory is missed. That is the safer direction — a missed finding leaves
 * the status quo, while a false finding removes the gate entirely.
 */
const INBOUND_SURFACE_DIRS = new Set(["server", "http", "api", "mcp"]);

const SOURCE_EXTENSIONS = /\.(?:[cm]?ts|[cm]?js|tsx|jsx)$/i;
const TEST_FILE = /\.(?:test|spec)\.[cm]?[jt]sx?$/i;
const MAX_FILE_BYTES = 2_000_000;

/** The waiver marker. Deliberately verbose: it should be greppable fleet-wide. */
const WAIVER_MARKER = /hasna-credential-seam-waiver:\s*(.+)$/i;
const MIN_WAIVER_REASON_LENGTH = 12;
/** Reasons that assert nothing. A waiver that says "todo" has not been reviewed. */
const EMPTY_REASONS = /^(?:todo|fixme|wip|n\/?a|later|temporary|temp|because|reasons?|legacy)\W*$/i;

/**
 * The client-flip credential grammar: `HASNA_<TOKEN>_API_KEY` where `<TOKEN>`
 * is a SINGLE segment.
 *
 * That single-segment requirement is the whole of the false-positive defence.
 * `envToken()` maps an app name to one token, so every real client-flip
 * variable has exactly one segment between the prefix and the suffix. Every
 * non-client key observed in the fleet has two or more —
 * `HASNA_SKILLS_BOOTSTRAP_API_KEY`, `HASNA_CALENDAR_SERVE_API_KEY`,
 * `HASNA_BRAIN_ANTHROPIC_API_KEY`, `HASNA_SANDBOXES_E2B_API_KEY` — and so is
 * excluded without an allowlist anyone has to maintain.
 */
const FOREIGN_CLIENT_KEY = /^HASNA_[A-Z0-9]+_API_KEY$/;

/**
 * Blank out comments while preserving byte offsets and line numbering.
 *
 * String literals are tracked so that a `//` inside a URL is not mistaken for a
 * comment — masking from there to end of line would hide real code behind it.
 */
function maskComments(text: string): string {
  const masked: string[] = [];
  let inBlockComment = false;

  for (const line of text.split("\n")) {
    const out = line.split("");
    // Quote state is reset at every line ON PURPOSE.
    //
    // An earlier version tracked quotes across the whole file and drifted: one
    // apostrophe whose parity it got wrong (`service's` inside a template
    // literal) left every following line unmasked, and the rule then reported a
    // key name mentioned in a COMMENT ninety lines later — on its own source.
    // A gate that fires on compliant code gets switched off, so the lexer must
    // fail LOCALLY. Resetting per line bounds any mistake to that one line; the
    // only thing given up is a string literal spanning lines, which cannot
    // contain a single-line env-read expression anyway.
    let quote: string | null = null;
    let index = 0;

    while (index < line.length) {
      const char = line[index]!;
      const next = line[index + 1];

      if (inBlockComment) {
        if (char === "*" && next === "/") {
          out[index] = " ";
          out[index + 1] = " ";
          index += 2;
          inBlockComment = false;
          continue;
        }
        out[index] = " ";
        index += 1;
        continue;
      }

      if (quote) {
        if (char === "\\") {
          index += 2;
          continue;
        }
        if (char === quote) quote = null;
        index += 1;
        continue;
      }

      if (char === '"' || char === "'" || char === "`") {
        quote = char;
        index += 1;
        continue;
      }

      if (char === "/" && next === "/") {
        while (index < line.length) {
          out[index] = " ";
          index += 1;
        }
        continue;
      }

      if (char === "/" && next === "*") {
        out[index] = " ";
        out[index + 1] = " ";
        index += 2;
        inBlockComment = true;
        continue;
      }

      index += 1;
    }

    masked.push(out.join(""));
  }

  return masked.join("\n");
}

function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Read expressions for one variable name.
 *
 * A read is `x.NAME` or `x["NAME"]`, or a destructure out of something called
 * `env`. An assignment to the same place is a WRITE and is excluded by the
 * trailing lookahead — `process.env.X = y` and `{ X: y }` both configure a
 * credential rather than consume one, and the fleet does far more of that than
 * it does reading.
 */
function readPatterns(variable: string): RegExp[] {
  const name = escapeForRegExp(variable);
  return [
    // `process.env.X`, `Bun.env.X`, `env.X`
    new RegExp(`\\.${name}\\b(?!\\s*=(?!=))`, "g"),
    // `process.env["X"]`, `env['X']` — the leading character class rejects a
    // bare array literal such as `["X"]`, which is a name list, not a read.
    new RegExp(`[\\w$)\\]]\\s*\\[\\s*(['"\`])${name}\\1\\s*\\](?!\\s*=(?!=))`, "g"),
    // `const { X } = process.env`
    new RegExp(`\\{[^{}]*\\b${name}\\b[^{}]*\\}\\s*=\\s*[\\w$.]*\\benv\\b`, "g"),
  ];
}

/** A computed client-flip read: ``env[`HASNA_${token}_API_KEY`]``. */
const COMPUTED_CLIENT_KEY_READ = /[\w$)\]]\s*\[\s*`HASNA_\$\{[^`]*\}_API_KEY`\s*\]/g;

/**
 * A local DEFINITION of one of the seam's entry points — i.e. a vendored fork.
 *
 * Matches a declaration, not a call: `function resolveClientTransport(`,
 * `export function createHasnaHttpTransport(`, `const createClientTransport = (`.
 * Importing and calling these is the compliant path and must not match.
 */
const SEAM_DEFINITION =
  /(?:^|\n)\s*(?:export\s+)?(?:async\s+)?(?:function\s+|const\s+|let\s+|var\s+)(resolveClientTransport|createClientTransport|createHasnaHttpTransport|resolveStorageClient)\s*(?:\(|=\s*(?:async\s*)?(?:\(|function))/g;

function lineNumberAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) {
    if (text[i] === "\n") line += 1;
  }
  return line;
}

function packageName(repoRoot: string): string | null {
  try {
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as { name?: unknown };
    return typeof pkg.name === "string" ? pkg.name : null;
  } catch {
    return null;
  }
}

function collectSourceFiles(root: string): string[] {
  const files: string[] = [];
  function walk(dir: string): void {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!SOURCE_EXTENSIONS.test(entry.name) || TEST_FILE.test(entry.name)) continue;
      try {
        if (statSync(full).size > MAX_FILE_BYTES) continue;
      } catch {
        continue;
      }
      files.push(full);
    }
  }
  walk(root);
  return files;
}

/**
 * Scan a repo for hand-rolled resolutions of a Hasna client credential.
 *
 * Own-app keys and other services' client-flip keys are both findings: reading
 * another service's credential directly bypasses the seam exactly as reading
 * your own does.
 */
export function scanCredentialSeam(repoRoot: string, options: CredentialSeamScanOptions): CredentialSeamScan {
  // ONLY the `HASNA_`-prefixed name is policed; the bare `<APP>_API_KEY` alias
  // is not.
  //
  // The alias has no namespace, so it collides with unrelated third-party
  // credentials that happen to share the app's name — `open-recordings` reads
  // `RECORDINGS_API_KEY` and assigns it to `config.openai_api_key`, which is an
  // OpenAI key and none of this rule's business. There is no structure in the
  // bare form to tell the two apart. The canonical name is what the fleet
  // actually uses, and a real bypass through the alias almost always reads the
  // canonical name on the same line (`env.HASNA_X_API_KEY || env.X_API_KEY`),
  // so it is still caught.
  const ownKeys = clientTransportEnvKeys(options.appName).apiKeyKeys.filter((key) =>
    key.startsWith("HASNA_"),
  );
  const ownKeySet = new Set(ownKeys);
  const findings: CredentialSeamFinding[] = [];
  const waivers: CredentialSeamWaiver[] = [];
  const invalidWaivers: CredentialSeamWaiver[] = [];
  const files = collectSourceFiles(repoRoot);
  // The package that DEFINES the seam is naturally the one package allowed to
  // define it. Read from package.json rather than an allowlist of paths.
  const isOwnPackage = packageName(repoRoot) === "@hasna/contracts";

  for (const file of files) {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }

    const path = relative(repoRoot, file).replaceAll("\\", "/");

    // A vendored copy of the seam is the LOUDEST possible bypass, and it is
    // invisible to a rule that looks for literal key names: a fork builds its
    // names by template (`HASNA_${token}_API_KEY`) and reads them through a
    // computed loop, so no literal ever appears. Measured: `iapp-telephony`
    // scored ZERO findings while shipping a complete copy of the pre-fix
    // resolver on its live storage path. Left unchecked, the cheapest way to
    // turn this gate green is to fork the transport — the gate would reward
    // exactly the thing it exists to prevent.
    if (!isOwnPackage) {
      for (const match of text.matchAll(SEAM_DEFINITION)) {
        findings.push({
          path,
          line: lineNumberAt(text, match.index ?? 0),
          variable: match[1]!,
          message:
            `${match[1]} is DEFINED here — this is a vendored copy of the @hasna/contracts client seam, ` +
            `not a use of it. A fork does not receive credential-resolution fixes, so it keeps resolving ` +
            `keys from the process environment however many times the shared package is corrected. ` +
            `Import it from @hasna/contracts/client instead.`,
        });
      }
    }

    if (!text.includes("API_KEY")) continue;
    // A directory that serves inbound requests reads its own key to COMPARE
    // against a caller's, which is the opposite of resolving one to send.
    if (path.split("/").some((segment) => INBOUND_SURFACE_DIRS.has(segment))) continue;
    const rawLines = text.split(/\r?\n/);
    const maskedLines = maskComments(text).split(/\r?\n/);

    // Every client-flip-shaped name that appears anywhere in this file, so a
    // repo reading a sibling service's credential is caught too.
    const candidates = new Set<string>(ownKeys);
    for (const match of text.matchAll(/\bHASNA_[A-Z0-9_]+_API_KEY\b/g)) {
      if (FOREIGN_CLIENT_KEY.test(match[0])) candidates.add(match[0]);
    }

    for (const [index, masked] of maskedLines.entries()) {
      if (!masked.includes("API_KEY")) continue;
      const lineNumber = index + 1;

      const waiverReason = waiverForLine(rawLines, index);
      const hit = firstReadOnLine(masked, candidates);
      if (!hit) continue;

      if (waiverReason !== null) {
        const waiver = { path, line: lineNumber, reason: waiverReason };
        const reason = waiverReason.trim();
        if (reason.length >= MIN_WAIVER_REASON_LENGTH && !EMPTY_REASONS.test(reason)) {
          waivers.push(waiver);
        } else {
          invalidWaivers.push(waiver);
        }
        continue;
      }

      findings.push({
        path,
        line: lineNumber,
        variable: hit,
        message: ownKeySet.has(hit)
          ? `${hit} is read straight from the process environment. Resolve it through @hasna/contracts/client instead ` +
            `(resolveClientTransport / createClientTransport / resolveCredential): an env read is a snapshot taken at ` +
            `process start, so it keeps serving a revoked key until the shell exits.`
          : `${hit} belongs to another service and is read straight from the process environment. Use that service's ` +
            `client through @hasna/contracts/client rather than resolving its credential by hand.`,
      });
    }
  }

  return { findings, waivers, invalidWaivers, filesScanned: files.length };
}

/** A waiver applies to its own line or to the line directly below it. */
function waiverForLine(rawLines: string[], index: number): string | null {
  for (const candidate of [rawLines[index], index > 0 ? rawLines[index - 1] : undefined]) {
    const match = candidate ? WAIVER_MARKER.exec(candidate) : null;
    if (match) return match[1]!.trim().replace(/\*\/\s*$/, "").trim();
  }
  return null;
}

function firstReadOnLine(masked: string, candidates: Set<string>): string | null {
  for (const variable of candidates) {
    if (!masked.includes(variable)) continue;
    for (const pattern of readPatterns(variable)) {
      pattern.lastIndex = 0;
      if (pattern.test(masked)) return variable;
    }
  }
  COMPUTED_CLIENT_KEY_READ.lastIndex = 0;
  if (COMPUTED_CLIENT_KEY_READ.test(masked)) return "HASNA_<APP>_API_KEY (computed)";
  return null;
}
