// Repo self-conformance for the Hasna Service Contract v1.
//
// A repo runs this against its own root to prove it satisfies the contract:
//   1. hasna.contract.json is present and valid (manifest + class rules).
//   2. Declared bins and SDK exports match package.json.
//   3. Required API/SDK/MCP/CLI surfaces are declared or explicitly waived.
//   4. Store-owning repos declare SQLite + PostgreSQL capability and a live-PG
//      gate, or carry an explicit, unexpired storage-engine waiver.
//   5. Public manifests do not expose private infrastructure references.
//   6. Env parsing follows the HASNA_<NAME>_STORAGE_MODE spec and any mode env
//      value normalizes to the sqlite|postgres backend enum (mode enum compliance).
//   7. If a `<name>-serve` bin exists, the health payload (when sampled) has the
//      { status, version, mode } shape.
//   8. No forbidden shared cloud runtimes (reuses the no-cloud guard).
//   9. Published packages bind a packed-artifact scan to `prepack` (clause C).

import { existsSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import {
  HealthResponseSchema,
  SERVICE_SURFACE_KINDS,
  STORAGE_ENGINES,
  WAIVABLE_STORAGE_ENGINES,
  allowedBinsForName,
  storageWaiverIneligibilityReason,
  type ServiceContractManifest,
  type ServiceSurfaceKind,
  type StorageEngine
} from "./schemas";
import { loadServiceContractManifest, type LoadServiceContractResult } from "./service-contract";
import { normalizeStorageMode, storageEnvKeys, type Env } from "./mode";
import { API_KEY_TOKEN_PATTERN } from "./auth/keys";
import { scanNoCloudTarget } from "./no-cloud";

export type ConformanceStatus = "pass" | "fail" | "skip";

export interface ConformanceCheck {
  id: string;
  status: ConformanceStatus;
  detail: string;
}

export interface RepoConformanceReport {
  ok: boolean;
  repoRoot: string;
  name: string | null;
  class: string | null;
  checks: ConformanceCheck[];
}

export interface RepoConformanceOptions {
  /** Environment to parse for mode-enum compliance (defaults to process.env). */
  env?: Env;
  /** Optional sampled `GET /health` payload to shape-check. */
  healthSample?: unknown;
  /** Skip the no-cloud scan (useful when a caller runs it separately). */
  skipNoCloudScan?: boolean;
  /** Public manifests are checked for private infrastructure references. */
  manifestTier?: "public" | "private";
  /** Clock used for time-boxed checks such as storage-waiver expiry. */
  now?: Date;
}

interface PackageJsonInfo {
  present: boolean;
  bins: string[];
  exportSubpaths: string[];
  exportTargets: Record<string, string[]>;
}

function collectExportTargets(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(collectExportTargets);
  if (!value || typeof value !== "object") return [];
  return Object.values(value as Record<string, unknown>).flatMap(collectExportTargets);
}

function packageExportTargets(value: unknown): Record<string, string[]> {
  if (typeof value === "string" || Array.isArray(value)) {
    return { ".": collectExportTargets(value) };
  }
  if (!value || typeof value !== "object") return {};

  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.some(([key]) => key.startsWith("."))) {
    return Object.fromEntries(
      entries
        .filter(([key]) => key.startsWith("."))
        .map(([key, target]) => [key, collectExportTargets(target)])
    );
  }
  return { ".": collectExportTargets(value) };
}

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function sourceCandidatesForExportTarget(target: string): string[] {
  if (!target.startsWith("./dist/")) return [];
  const relativeTarget = target.slice("./dist/".length);
  const sourceStem = relativeTarget
    .replace(/\.d\.(?:ts|mts|cts)$/i, "")
    .replace(/\.(?:js|mjs|cjs|json)$/i, "");
  return [
    `./src/${sourceStem}.ts`,
    `./src/${sourceStem}.tsx`,
    `./src/${sourceStem}.mts`,
    `./src/${sourceStem}.cts`,
    `./src/${sourceStem}.json`
  ];
}

function exportTargetExists(repoRoot: string, target: string): boolean {
  if (!target.startsWith("./")) return false;
  const resolved = join(repoRoot, target);
  if (relative(repoRoot, resolved).startsWith("..")) return false;
  if (isFile(resolved)) return true;
  return sourceCandidatesForExportTarget(target).some((candidate) => isFile(join(repoRoot, candidate)));
}

function packageJsonInfo(repoRoot: string): PackageJsonInfo {
  const path = join(repoRoot, "package.json");
  if (!existsSync(path)) return { present: false, bins: [], exportSubpaths: [], exportTargets: {} };
  try {
    const pkg = JSON.parse(readFileSync(path, "utf8")) as { name?: unknown; bin?: unknown; exports?: unknown };
    const defaultBinName =
      typeof pkg.name === "string" && pkg.name.length > 0 ? pkg.name.replace(/^@[^/]+\//, "") : "<default>";
    const bins =
      typeof pkg.bin === "string"
        ? [defaultBinName]
        : pkg.bin && typeof pkg.bin === "object"
          ? Object.keys(pkg.bin as Record<string, unknown>)
          : [];
    const exportTargets = packageExportTargets(pkg.exports);
    return { present: true, bins, exportSubpaths: Object.keys(exportTargets), exportTargets };
  } catch {
    return { present: true, bins: [], exportSubpaths: [], exportTargets: {} };
  }
}

function representedSurfaceKinds(manifest: ServiceContractManifest): Set<ServiceSurfaceKind> {
  const kinds = new Set<ServiceSurfaceKind>();
  for (const surface of manifest.serviceSurfaces) {
    if (surface.status !== "supported") continue;
    if (surface.kind) {
      kinds.add(surface.kind);
      continue;
    }
    // Compatibility inference for pre-kind manifests. One legacy entry could
    // represent both the HTTP and MCP bindings.
    if (surface.apiBasePath || surface.openApiPath || surface.health || surface.readiness || surface.version || surface.bin) {
      kinds.add("api");
    }
    if (surface.mcpBin) kinds.add("mcp");
  }
  return kinds;
}

interface PublicManifestFinding {
  path: string;
  category: "secret-ref" | "credential-ref" | "credential-value" | "internal-host" | "arn" | "account-id";
}

const SELF_HOST_ARTIFACTS = [
  "docker-compose.yml",
  "docker-compose.yaml",
  "compose.yml",
  "compose.yaml",
  "Dockerfile"
] as const;

function credentialKeyFinding(key: string): PublicManifestFinding["category"] | null {
  // Manifest metadata is open-ended, and producers use both nested objects and
  // flattened paths (`auth.credential.value`, `auth/token/reference`). Treat
  // every non-alphanumeric separator as a path boundary before matching so a
  // dotted key cannot bypass the same policy as its nested representation.
  const normalized = key.replace(/[^a-z0-9]/gi, "");
  if (/secretref$/i.test(normalized) || normalized === "databasedsnbindings") {
    return "secret-ref";
  }
  if (
    /(?:secret|secrets|credential|credentials|password|passphrase|privatekey|apikey|accesskey|token)(?:value|ref|reference|id|path|arn)?$/i.test(
      normalized
    ) ||
    /(?:databaseurl|dsn|connectionstring)$/i.test(normalized)
  ) {
    return /(?:ref|reference|id|path|arn)$/i.test(normalized) ? "credential-ref" : "credential-value";
  }
  return null;
}

/**
 * A leaked Hasna API key, derived from the token grammar in `src/auth/keys.ts`
 * rather than approximated.
 *
 * The previous pattern was `/\bhasna_[a-z0-9_]+_[A-Za-z0-9._-]{12,}\b/i` —
 * CASE-INSENSITIVE, and with no requirement for the signature segment. CONTRACT
 * section 3 mandates env keys of the form `HASNA_<NAME>_DATABASE_URL`, so
 * section 6 was flagging as a leaked credential the exact variable name section
 * 3 requires the manifest to use. Live on `open-loops`, `open-sessions`,
 * `iapp-sessions` and `iapp-domains`: `HASNA_LOOPS_DATABASE_URL` matched
 * because `DATABASE_URL` is exactly 12 characters.
 *
 * A mandatory gate that fires on compliant repos gets switched off, and then it
 * protects nothing — the same end state as a check that cannot fail. So this
 * pattern is now the real grammar: the namespace and app slug are LOWERCASE by
 * construction (`apiKeyPrefix()` builds them from `APP_SLUG_PATTERN`), and a
 * token always carries `.<signature>`. An upper-snake env name was never a
 * token, and this is strictly better at finding tokens that are.
 */
const HASNA_API_KEY_TOKEN_PATTERN = new RegExp(
  // Derived from the grammar itself, so the two cannot drift apart again.
  API_KEY_TOKEN_PATTERN.source.replace(/^\^/, "\\b").replace(/\$$/, "\\b")
);

function credentialValueFinding(value: string): PublicManifestFinding["category"] | null {
  const trimmed = value.trim();
  if (
    /^(?:vault|secret|credential|keychain|secretsmanager|aws-secretsmanager|ssm):(?:\/\/|[a-z0-9])/i.test(trimmed) ||
    /(?:^|\/)(?:secrets?|credentials?)(?:\/|:)[a-z0-9._-]+/i.test(trimmed)
  ) {
    return "credential-ref";
  }
  if (
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(trimmed) ||
    /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/.test(trimmed) ||
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/.test(trimmed) ||
    /\bgithub_pat_[A-Za-z0-9_]{20,}\b/.test(trimmed) ||
    /\bsk-[A-Za-z0-9_-]{16,}\b/.test(trimmed) ||
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/.test(trimmed) ||
    /\bBearer\s+[A-Za-z0-9._~+/-]{8,}\b/i.test(trimmed) ||
    /^[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^@\s]+@/i.test(trimmed) ||
    HASNA_API_KEY_TOKEN_PATTERN.test(trimmed) ||
    /\b(?:password|passphrase|api[_-]?key|access[_-]?key|token|secret)\s*[:=]\s*\S{8,}/i.test(trimmed) ||
    /(?:^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:$|[^A-Za-z0-9_-])/.test(
      trimmed
    )
  ) {
    return "credential-value";
  }
  return null;
}

/**
 * An upper-snake token with no scheme, no separator, and no punctuation beyond
 * `_` — the shape of an environment variable NAME.
 */
function isEnvVarName(value: unknown): boolean {
  return typeof value === "string" && /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value.trim());
}

/**
 * Keys whose value is understood to be the NAME of a variable rather than its
 * contents — `envVar`, `environmentVariable`, `...EnvName`, `envPrefix`.
 *
 * Section 3 requires manifests to reference `HASNA_<NAME>_DATABASE_URL` instead
 * of inlining a DSN, so those must not be findings. But the exemption has to be
 * anchored to keys that declare a variable name; applying it to any
 * credential-shaped key merely because the VALUE looked upper-snake let a real
 * secret through whenever it happened to be upper-snake.
 */
function namesAnEnvironmentVariable(path: string, value: unknown): boolean {
  if (!isEnvVarName(value)) return false;
  const leaf = path.slice(path.lastIndexOf(".") + 1).replace(/\[\d+\]$/, "");
  const normalized = leaf.replace(/[^a-z0-9]/gi, "").toLowerCase();
  return (
    /^env(?:var|variable|name|key|prefix)?$/.test(normalized) ||
    /(?:env|environment)(?:var|variable|name|key|prefix)$/.test(normalized) ||
    /^(?:environmentvariable|envvarname|envvariable)$/.test(normalized)
  );
}

function publicManifestFindings(value: unknown, path = "<root>"): PublicManifestFinding[] {
  const findings: PublicManifestFinding[] = [];
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      findings.push(...publicManifestFindings(item, `${path}[${index}]`));
    }
    return findings;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const childPath = path === "<root>" ? key : `${path}.${key}`;
      // Classify the full logical path, not only the immediate leaf. That makes
      // nested `{ api: { key: ... } }` equivalent to flattened `api.key`,
      // including dotted, slash, underscore, and hyphen separators.
      // A credential-shaped KEY whose value is plainly an ENV VAR NAME is the
      // contract working as specified, not a leak: section 3 requires manifests
      // to reference `HASNA_<NAME>_DATABASE_URL` rather than inline a DSN. The
      // key heuristic alone flagged exactly that, so section 3 required what
      // section 6 rejected. Naming the variable is the compliant behaviour;
      // only a value that looks like a credential is a finding.
      // The carve-out is scoped to keys that NAME a variable, not to every
      // credential-shaped key. Unscoped, `"apiKey": "PRODUCTION_KEY_MATERIAL"`
      // — an upper-snake value that IS the secret — passed silently.
      const keyFinding = namesAnEnvironmentVariable(childPath, child) ? null : credentialKeyFinding(childPath);
      if (keyFinding) findings.push({ path: childPath, category: keyFinding });
      findings.push(...publicManifestFindings(child, childPath));
    }
    return findings;
  }
  if (typeof value !== "string") return findings;

  if (/\bhasna\/oss\/[a-z0-9-]+(?:\/[a-z0-9._/-]+)?\b/i.test(value)) {
    findings.push({ path, category: "secret-ref" });
  }
  if (/\b(?:[a-z0-9-]+\.)*hasna\.xyz\b/i.test(value)) {
    findings.push({ path, category: "internal-host" });
  }
  if (/\barn:(?:aws|aws-us-gov|aws-cn):/i.test(value)) {
    findings.push({ path, category: "arn" });
  }
  if (/\b\d{12}\b/.test(value)) {
    findings.push({ path, category: "account-id" });
  }
  const credentialFinding = credentialValueFinding(value);
  if (credentialFinding) {
    findings.push({ path, category: credentialFinding });
  }
  return findings;
}

interface StorageWaiverAnalysis {
  /** Engines an eligible, unexpired waiver excuses from the capability matrix. */
  waivedEngines: Set<StorageEngine>;
  /**
   * Engines a waiver speaks for, valid or not. An expired waiver still
   * suppresses the "missing engine" and PostgreSQL-proof messages so the
   * report states one remedy — renew or declare — instead of also telling the
   * repo to build the support its waiver was about.
   */
  answeredEngines: Set<StorageEngine>;
  /** Pass-detail fragments such as `postgres explicitly waived: <reason>`. */
  summaries: string[];
  /** Failures raised by ineligible, unusable, or expired waivers. */
  failures: string[];
}

/**
 * A waiver is only auditable if its justification can be shown. Waiver prose
 * is echoed into the report detail, so prose carrying a private
 * infrastructure reference cannot be printed — and silently redacting it would
 * pass the gate with no recorded justification at all, which is worse than
 * failing. `public_manifest_safety` catches this too, but it is skipped for
 * private-tier callers.
 */
function unprintableWaiverFields(waiver: { reason: string; reviewedBy?: string | undefined }): string[] {
  const fields: string[] = [];
  if (publicManifestFindings(waiver.reason).length > 0) fields.push("reason");
  if (waiver.reviewedBy && publicManifestFindings(waiver.reviewedBy).length > 0) fields.push("reviewedBy");
  return fields;
}

/**
 * Resolve `metadata.conformance.waivedStorageEngines` into the engines the
 * storage gate may skip. Eligibility is shared with the manifest schema via
 * `storageWaiverIneligibilityReason`, only PostgreSQL is waivable, and a
 * waiver stops applying once it expires. A waiver for an engine the manifest
 * already declares is redundant, so the engine keeps its normal proof
 * obligations (notably `storage.pgTestGate`).
 */
function analyzeStorageWaivers(manifest: ServiceContractManifest, nowMs: number): StorageWaiverAnalysis {
  const declaredWaivers = manifest.metadata?.conformance?.waivedStorageEngines ?? [];
  const waivedEngines = new Set<StorageEngine>();
  const answeredEngines = new Set<StorageEngine>();
  const summaries: string[] = [];
  const failures: string[] = [];
  if (declaredWaivers.length === 0) return { waivedEngines, answeredEngines, summaries, failures };

  const ineligible = storageWaiverIneligibilityReason({
    class: manifest.class,
    name: manifest.name,
    bins: manifest.bins,
    hosting: manifest.hosting,
    storageMode: manifest.storage?.mode
  });
  if (ineligible) {
    failures.push(`${ineligible}: ${declaredWaivers.map((waiver) => waiver.engine).join(", ")}`);
    return { waivedEngines, answeredEngines, summaries, failures };
  }

  const declaredEngines = new Set(manifest.storage?.engines ?? []);
  for (const waiver of declaredWaivers) {
    // A waiver next to an engine the manifest declares is redundant: the
    // engine keeps its normal proof obligations.
    if (declaredEngines.has(waiver.engine)) continue;
    const unprintable = unprintableWaiverFields(waiver);
    if (unprintable.length > 0) {
      answeredEngines.add(waiver.engine);
      failures.push(
        `storage waiver for ${waiver.engine} cannot be recorded: ${unprintable.join(", ")} carries a private infrastructure reference; rewrite the waiver without secret refs, internal hosts, ARNs, or account ids`
      );
      continue;
    }
    if (waiver.expiresAt && Date.parse(waiver.expiresAt) <= nowMs) {
      answeredEngines.add(waiver.engine);
      failures.push(
        `storage waiver for ${waiver.engine} expired at ${waiver.expiresAt}; declare the engine or renew the waiver`
      );
      continue;
    }
    waivedEngines.add(waiver.engine);
    answeredEngines.add(waiver.engine);
    const annotations: string[] = [];
    if (waiver.reviewedBy) annotations.push(`reviewed by ${waiver.reviewedBy}`);
    if (waiver.expiresAt) annotations.push(`expires ${waiver.expiresAt}`);
    const annotated = annotations.length > 0 ? ` (${annotations.join("; ")})` : "";
    summaries.push(`${waiver.engine} explicitly waived: ${waiver.reason}${annotated}`);
  }
  return { waivedEngines, answeredEngines, summaries, failures };
}

/**
 * Every package script reachable from an entry, following the ways one script
 * actually invokes another.
 *
 * More than `bun run x`: npm runs `pre<name>` and `post<name>` around every
 * script, and `npm-run-all` / `run-s` / `run-p` take bare script names as
 * arguments. A resolver that knew only `bun run` reported "prepack does not
 * reach the scan" for conventional layouts that plainly do reach it — and a
 * gate that fails compliant repos gets switched off.
 */
function resolveScriptGraph(scripts: Record<string, string>, entry: string): Set<string> {
  const reached = new Set<string>();
  const queue = [entry];
  const enqueue = (name: string): void => {
    if (name in scripts) queue.push(name);
  };
  while (queue.length > 0) {
    const name = queue.shift()!;
    if (reached.has(name)) continue;
    reached.add(name);
    // npm's implicit lifecycle wrappers run without appearing in any body.
    enqueue(`pre${name}`);
    enqueue(`post${name}`);
    const body = scripts[name];
    if (!body) continue;
    for (const match of body.matchAll(/\b(?:bun|bunx|npm|pnpm|yarn)\s+(?:(?:--\S+|-\w)\s+)*(?:run\s+)?([a-zA-Z0-9_][\w:.-]*)/g)) {
      enqueue(match[1]!);
    }
    // `run-s a b c`, `npm-run-all --serial a b`, `concurrently "x" "y"`.
    for (const runner of body.matchAll(/\b(?:npm-run-all|run-s|run-p|concurrently)\b([^&|;]*)/g)) {
      for (const token of (runner[1] ?? "").split(/\s+/)) {
        const candidate = token.replace(/^["']|["']$/g, "");
        if (candidate && !candidate.startsWith("-")) enqueue(candidate);
      }
    }
  }
  return reached;
}

/**
 * Does this script body actually DO something?
 *
 * `"scan:artifact": "true"` satisfied every structural condition the gate
 * checked while scanning nothing at all — the single most important thing a
 * release gate must not accept, since the entire clause exists because a
 * bypassable hook is not a hook. This does not attempt to prove the script
 * scans correctly; it rejects the bodies that provably cannot.
 */
/**
 * Commands that do nothing, however they are spelled.
 *
 * `true`, `/bin/true`, `/usr/bin/true`, `command true`, `builtin true`, `:`,
 * `exit 0`, a bare `echo`. The earlier pattern matched only the bare forms, so
 * appending ` # scan` — or writing `/bin/true` — restored a switched-off gate
 * while still reading as deliberate.
 */
const NO_OP_COMMAND = /^(?:(?:\/usr)?\/bin\/)?(?::|true)$/;

/** Strip an unquoted trailing `# comment` from one command segment. */
function withoutComment(segment: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let index = 0; index < segment.length; index += 1) {
    const character = segment[index]!;
    if (character === "'" && !inDouble) inSingle = !inSingle;
    else if (character === '"' && !inSingle) inDouble = !inDouble;
    else if (character === "#" && !inSingle && !inDouble) return segment.slice(0, index);
  }
  return segment;
}

function segmentIsNoOp(segment: string): boolean {
  const text = withoutComment(segment).trim();
  if (text === "") return true;
  // `command`/`builtin`/`exec` are prefixes, not work.
  const tokens = text.split(/\s+/).filter((token) => !/^(?:command|builtin|exec|nohup)$/.test(token));
  const [head, ...rest] = tokens;
  if (head === undefined) return true;
  if (NO_OP_COMMAND.test(head)) return true;
  if (head === "exit" && (rest.length === 0 || rest[0] === "0")) return true;
  if (/^(?:(?:\/usr)?\/bin\/)?echo$/.test(head)) return true;
  return false;
}

function scriptIsNoOp(body: string): boolean {
  return body.split(/&&|\|\||;|\n/).every(segmentIsNoOp);
}

/**
 * Clause C: for every repo that publishes, scanning the PACKED artifact is a
 * hard release gate bound to `prepack`.
 *
 * `prepack`, not `verify:release`, and the distinction is the whole point: a
 * hook a publisher can step around by running `npm publish` directly is not a
 * hook. `prepack` is the one lifecycle script both `npm pack` and `npm publish`
 * always run.
 *
 * The gate is contract-driven — the manifest names its own scan script, and
 * this resolves the real script graph — rather than grepping `prepack` for a
 * blessed command name, which would pass for any repo that wrote the magic
 * string in a comment.
 */
/**
 * `bunx`/`npx` invocations whose package spec carries no `@version`.
 *
 * Walks the tokens after the runner, skipping its flags, and inspects the FIRST
 * package spec only — so a version-looking substring elsewhere on the line
 * cannot mask an unpinned invocation.
 */
function unpinnedPackageRunnerInvocations(body: string): string[] {
  const unpinned: string[] = [];
  for (const segment of body.split(/&&|\|\||;/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    for (const [index, token] of tokens.entries()) {
      if (token !== "bunx" && token !== "npx") continue;
      const spec = tokens.slice(index + 1).find((candidate) => !candidate.startsWith("-"));
      if (spec === undefined) continue;
      // `@scope/name@1.2.3` — the version `@` is the one after any scope.
      const versionAt = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
      if (versionAt === -1) unpinned.push(`${token} ${spec}`);
      break;
    }
  }
  return unpinned;
}

function publishedArtifactGateCheck(repoRoot: string, manifest: ServiceContractManifest): ConformanceCheck {
  const packagePath = join(repoRoot, "package.json");
  if (!existsSync(packagePath)) {
    return { id: "published_artifact_gate", status: "skip", detail: "no package.json found" };
  }
  let pkg: { private?: unknown; scripts?: unknown };
  try {
    pkg = JSON.parse(readFileSync(packagePath, "utf8")) as { private?: unknown; scripts?: unknown };
  } catch {
    return { id: "published_artifact_gate", status: "fail", detail: "package.json is not valid JSON" };
  }
  if (pkg.private === true) {
    // Predicate false: nothing is published, so there is nothing to gate.
    return { id: "published_artifact_gate", status: "skip", detail: "package is private; it publishes no artifact" };
  }

  const scripts: Record<string, string> = {};
  if (pkg.scripts && typeof pkg.scripts === "object") {
    for (const [name, body] of Object.entries(pkg.scripts as Record<string, unknown>)) {
      if (typeof body === "string") scripts[name] = body;
    }
  }

  const declared = manifest.metadata?.release?.artifactScan?.script;
  if (!declared) {
    return {
      id: "published_artifact_gate",
      status: "fail",
      detail:
        "metadata.release.artifactScan.script is required for a published package: name the script that scans the PACKED artifact, then wire it into prepack",
    };
  }
  const failures: string[] = [];
  if (!(declared in scripts)) {
    failures.push(`metadata.release.artifactScan.script names '${declared}', which is not a package script`);
  } else if (scriptIsNoOp(scripts[declared]!)) {
    failures.push(
      `'${declared}' is a no-op ('${scripts[declared]}'); a gate that runs nothing is the bypass this clause exists to close`
    );
  }
  if (!("prepack" in scripts)) {
    failures.push("no prepack script: a release gate bound only to a custom script can be bypassed by publishing directly");
  } else if (declared in scripts && !resolveScriptGraph(scripts, "prepack").has(declared)) {
    failures.push(`prepack does not reach '${declared}'; the scan runs only when someone remembers to call it`);
  }

  // An unpinned `bunx`/`npx` in a gate resolves to whatever is newest at
  // publish time, so the gate's own behaviour is not reproducible — and a
  // resolution failure silently becomes a non-run.
  //
  // Parsed rather than pattern-matched: the previous regex used a LINE-WIDE
  // negative lookahead for `@<digit>`, so an unrelated `@1` anywhere on the
  // line (a tarball named `pkg@1.tgz`) suppressed the finding entirely.
  for (const invocation of unpinnedPackageRunnerInvocations(scripts[declared] ?? "")) {
    failures.push(
      `'${declared}' invokes ${invocation} without a version pin; pin the kit version so the gate is reproducible`
    );
  }

  return failures.length === 0
    ? {
        id: "published_artifact_gate",
        status: "pass",
        detail: `prepack reaches the declared packed-artifact scan '${declared}'`,
      }
    : { id: "published_artifact_gate", status: "fail", detail: failures.join("; ") };
}

export function runRepoConformance(repoRoot: string, options: RepoConformanceOptions = {}): RepoConformanceReport {
  const checks: ConformanceCheck[] = [];
  const loaded: LoadServiceContractResult = loadServiceContractManifest(repoRoot);

  if (!loaded.ok) {
    const issueDetail = loaded.issues
      ? `: ${loaded.issues.map((issue) => `${issue.path.join(".") || "<root>"} ${issue.message}`).join("; ")}`
      : "";
    checks.push({ id: "manifest_valid", status: "fail", detail: `${loaded.error}${issueDetail}` });
    return { ok: false, repoRoot, name: null, class: null, checks };
  }

  const manifest = loaded.manifest;
  checks.push({ id: "manifest_valid", status: "pass", detail: `hasna.contract.json valid for ${manifest.name} (${manifest.class})` });

  // Check 2: bins declared vs package.json bin, and allowlist compliance.
  const allowed = new Set(allowedBinsForName(manifest.name));
  const outOfAllowlist = manifest.bins.filter((bin) => !allowed.has(bin));
  if (outOfAllowlist.length > 0) {
    checks.push({ id: "bins_allowlisted", status: "fail", detail: `bins outside allowlist: ${outOfAllowlist.join(", ")}` });
  } else {
    checks.push({ id: "bins_allowlisted", status: "pass", detail: `bins allowlisted: ${manifest.bins.join(", ") || "(none)"}` });
  }

  const pkg = packageJsonInfo(repoRoot);
  if (!pkg.present) {
    checks.push({ id: "bins_match_package", status: "skip", detail: "no package.json found" });
  } else {
    const declared = new Set(manifest.bins);
    const missing = manifest.bins.filter((bin) => !pkg.bins.includes(bin));
    const undeclared = pkg.bins.filter((bin) => !declared.has(bin));
    if (missing.length > 0 || undeclared.length > 0) {
      const parts: string[] = [];
      if (missing.length > 0) parts.push(`declared but missing from package.json: ${missing.join(", ")}`);
      if (undeclared.length > 0) parts.push(`in package.json but undeclared: ${undeclared.join(", ")}`);
      checks.push({ id: "bins_match_package", status: "fail", detail: parts.join("; ") });
    } else {
      checks.push({ id: "bins_match_package", status: "pass", detail: "declared bins match package.json bin" });
    }
  }

  // Check 3: four-surface declaration and package bindings.
  const hasServeBin = manifest.bins.includes(`${manifest.name}-serve`) || manifest.class === "service" || manifest.class === "saas";
  const requiresGeneratedServiceSdk =
    manifest.class === "service" ||
    manifest.class === "saas" ||
    (manifest.class === "cli-with-store" && manifest.bins.includes(`${manifest.name}-serve`));
  const representedKinds = representedSurfaceKinds(manifest);
  const waivers = manifest.metadata?.conformance?.waivedSurfaces ?? [];
  const waiverProfile = manifest.metadata?.conformance?.waiverProfile;
  const eligibleWaiverKinds =
    waiverProfile === "non-node-monorepo"
      ? new Set<ServiceSurfaceKind>(SERVICE_SURFACE_KINDS)
      : manifest.class === "library"
        ? new Set<ServiceSurfaceKind>(["api", "mcp"])
        : new Set<ServiceSurfaceKind>();
  const ineligibleWaivers = waivers.filter((waiver) => !eligibleWaiverKinds.has(waiver.kind));
  const waivedKinds = new Set(
    waivers.filter((waiver) => eligibleWaiverKinds.has(waiver.kind)).map((waiver) => waiver.kind)
  );
  const requiredSurfaceKinds: readonly ServiceSurfaceKind[] =
    manifest.class === "cli-with-store" && !hasServeBin
      ? ["cli"]
      : SERVICE_SURFACE_KINDS;
  const missingKinds = requiredSurfaceKinds.filter((kind) => !representedKinds.has(kind) && !waivedKinds.has(kind));
  if (missingKinds.length > 0 || ineligibleWaivers.length > 0) {
    const failures: string[] = [];
    if (missingKinds.length > 0) {
      failures.push(`missing supported surface declarations or eligible waivers: ${missingKinds.join(", ")}`);
    }
    if (ineligibleWaivers.length > 0) {
      failures.push(
        `waivers not permitted for class ${manifest.class}${waiverProfile ? ` with profile ${waiverProfile}` : ""}: ${ineligibleWaivers
          .map((waiver) => waiver.kind)
          .join(", ")}`
      );
    }
    checks.push({
      id: "surface_matrix",
      status: "fail",
      detail: failures.join("; ")
    });
  } else {
    checks.push({
      id: "surface_matrix",
      status: "pass",
      detail: `API, SDK, MCP, and CLI are declared or explicitly waived`
    });
  }

  const surfaceBindingFailures: string[] = [];
  const apiOpenApiPaths = new Set(
    manifest.serviceSurfaces
      .filter((surface) => surface.kind === "api" || (!surface.kind && Boolean(surface.openApiPath)))
      .map((surface) => surface.openApiPath)
      .filter((value): value is string => Boolean(value))
  );
  for (const [index, surface] of manifest.serviceSurfaces.entries()) {
    if (surface.bin && !pkg.bins.includes(surface.bin)) {
      surfaceBindingFailures.push(`serviceSurfaces[${index}].bin is not in package.json bin`);
    }
    if (surface.mcpBin && !pkg.bins.includes(surface.mcpBin)) {
      surfaceBindingFailures.push(`serviceSurfaces[${index}].mcpBin is not in package.json bin`);
    }
    if (surface.kind === "sdk" && surface.status === "supported") {
      if (!surface.exportSubpath || !pkg.exportSubpaths.includes(surface.exportSubpath)) {
        surfaceBindingFailures.push(`serviceSurfaces[${index}].exportSubpath is not in package.json exports`);
      } else {
        const targets = pkg.exportTargets[surface.exportSubpath] ?? [];
        const missingTargets = targets.filter((target) => !exportTargetExists(repoRoot, target));
        if (targets.length === 0) {
          surfaceBindingFailures.push(`serviceSurfaces[${index}].exportSubpath has no package export file target`);
        } else if (missingTargets.length > 0) {
          surfaceBindingFailures.push(
            `serviceSurfaces[${index}].exportSubpath targets missing files: ${missingTargets.join(", ")}`
          );
        }
      }
      if (requiresGeneratedServiceSdk && !surface.generatedFrom) {
        surfaceBindingFailures.push(`serviceSurfaces[${index}].generatedFrom is required for a supported service SDK`);
      } else if (surface.generatedFrom && !apiOpenApiPaths.has(surface.generatedFrom)) {
        surfaceBindingFailures.push(`serviceSurfaces[${index}].generatedFrom does not match a declared API openApiPath`);
      }
    }
  }
  checks.push({
    id: "surface_bindings",
    status: surfaceBindingFailures.length === 0 ? "pass" : "fail",
    detail: surfaceBindingFailures.length === 0 ? "declared surface bins and SDK exports match package.json" : surfaceBindingFailures.join("; ")
  });

  const apiTopologyFailures: string[] = [];
  if (requiresGeneratedServiceSdk) {
    const apiSurfaces = manifest.serviceSurfaces.filter(
      (surface) =>
        surface.status === "supported" &&
        (surface.kind === "api" ||
          (!surface.kind &&
            Boolean(surface.apiBasePath || surface.openApiPath || surface.health || surface.readiness || surface.version)))
    );
    if (apiSurfaces.length === 0) {
      apiTopologyFailures.push("a supported API surface is required");
    }
    for (const [index, surface] of apiSurfaces.entries()) {
      for (const [label, endpoint, path] of [
        ["health", surface.health, "/health"],
        ["readiness", surface.readiness, "/ready"],
        ["version", surface.version, "/version"]
      ] as const) {
        if (!endpoint || endpoint.method !== "GET" || endpoint.path !== path) {
          apiTopologyFailures.push(`supported API surface ${index} must declare GET ${path} (${label})`);
        }
      }
    }
  }
  checks.push({
    id: "service_api_topology",
    status: requiresGeneratedServiceSdk
      ? apiTopologyFailures.length === 0
        ? "pass"
        : "fail"
      : "skip",
    detail: requiresGeneratedServiceSdk
      ? apiTopologyFailures.length === 0
        ? "supported API declares GET /health, GET /ready, and GET /version"
        : apiTopologyFailures.join("; ")
      : `${manifest.class} repo has no required service API topology`
  });

  if (requiresGeneratedServiceSdk) {
    const presentArtifacts = SELF_HOST_ARTIFACTS.filter((artifact) => isFile(join(repoRoot, artifact)));
    checks.push({
      id: "self_host_artifact",
      status: presentArtifacts.length > 0 ? "pass" : "fail",
      detail:
        presentArtifacts.length > 0
          ? `self-host deployment artifact present: ${presentArtifacts.join(", ")}`
          : `service-class repos require one self-host deployment artifact: ${SELF_HOST_ARTIFACTS.join(", ")}`
    });
  } else {
    checks.push({
      id: "self_host_artifact",
      status: "skip",
      detail: `${manifest.class} repo has no required self-host service artifact`
    });
  }

  // Check 4: storage capability matrix and PostgreSQL runtime proof.
  const storageWaivers = analyzeStorageWaivers(manifest, (options.now ?? new Date()).getTime());
  if (manifest.class === "saas") {
    const failures = [...storageWaivers.failures];
    if (!manifest.storage?.envPrefix) failures.push("storage.envPrefix is required for the public SaaS DATABASE_URL contract");
    checks.push({
      id: "storage_capabilities",
      status: failures.length === 0 ? "pass" : "fail",
      detail: failures.length === 0 ? "SaaS PostgreSQL env contract declared" : failures.join("; ")
    });
  } else if (manifest.class !== "service" && manifest.class !== "cli-with-store") {
    checks.push({
      id: "storage_capabilities",
      status: storageWaivers.failures.length === 0 ? "skip" : "fail",
      detail:
        storageWaivers.failures.length === 0
          ? `${manifest.class} repo is outside the dual-storage core gate`
          : storageWaivers.failures.join("; ")
    });
  } else {
    const engines = manifest.storage?.engines ?? [];
    const declaredEngines = new Set(engines);
    const missingEngines = STORAGE_ENGINES.filter(
      (engine) => !declaredEngines.has(engine) && !storageWaivers.answeredEngines.has(engine)
    );
    const failures = [...storageWaivers.failures];
    if (missingEngines.length > 0) failures.push(`missing storage engines: ${missingEngines.join(", ")}`);
    // `storage.envPrefix` and `storage.pgTestGate` both exist to serve the
    // PostgreSQL contract: the DATABASE_URL derivation and the live-PG proof.
    // Neither is required while a waiver speaks for PostgreSQL, because there
    // is no PostgreSQL boundary to derive or prove; a rejected waiver already
    // reports its own single, actionable remedy.
    if (!storageWaivers.answeredEngines.has("postgres")) {
      if (!manifest.storage?.envPrefix) failures.push("storage.envPrefix is required for the PostgreSQL DATABASE_URL contract");
      if (!manifest.storage?.pgTestGate) failures.push("storage.pgTestGate is required to prove live PostgreSQL support");
    }
    const declaredDetail = engines.length > 0 ? `${engines.join(", ")} declared` : "no storage engines declared";
    checks.push({
      id: "storage_capabilities",
      status: failures.length === 0 ? "pass" : "fail",
      detail:
        failures.length > 0
          ? failures.join("; ")
          : storageWaivers.summaries.length > 0
            ? `${declaredDetail}; ${storageWaivers.summaries.join("; ")}`
            : "sqlite and postgres capabilities plus live-PG gate declared"
    });
  }

  // Check 5: public manifest safety and product hosting story.
  if ((options.manifestTier ?? "public") === "private") {
    checks.push({ id: "public_manifest_safety", status: "skip", detail: "private-tier manifest selected by caller" });
  } else {
    const findings = publicManifestFindings(manifest);
    const unique = [...new Map(findings.map((finding) => [`${finding.path}:${finding.category}`, finding])).values()];
    checks.push({
      id: "public_manifest_safety",
      status: unique.length === 0 ? "pass" : "fail",
      detail:
        unique.length === 0
          ? "no private secret or credential references, credential values, internal hosts, ARNs, or account IDs"
          : `private infrastructure references at ${unique.map((finding) => `${finding.path} (${finding.category})`).join(", ")}`
    });
  }

  const requiredHosting = manifest.class === "saas" ? "hasna-saas" : "user-hosted";
  checks.push({
    id: "hosting_story",
    status: manifest.hosting.includes(requiredHosting) ? "pass" : "fail",
    detail: manifest.hosting.includes(requiredHosting)
      ? manifest.class === "saas"
        ? `Hasna SaaS control-plane story declared${manifest.hosting.includes("user-hosted") ? " with user-hosted parity" : ""}`
        : `user-hosted product story declared${manifest.hosting.includes("hasna-saas") ? " with optional Hasna SaaS" : ""}`
      : manifest.class === "saas"
        ? "saas repos must declare the hasna-saas product story"
        : "public OSS cores must declare the user-hosted product story"
  });

  // Check 6: env parsing + storage mode enum compliance.
  const env = options.env ?? process.env;
  const { modeKeys } = storageEnvKeys(manifest.name);
  const modeEnvHit = modeKeys.map((key) => ({ key, value: env[key]?.trim() })).find((hit) => hit.value);
  if (!modeEnvHit || !modeEnvHit.value) {
    checks.push({ id: "mode_enum_compliance", status: "pass", detail: `no mode env set; defaults to sqlite (keys: ${modeKeys.join(", ")})` });
  } else {
    try {
      const { mode } = normalizeStorageMode(modeEnvHit.value);
      checks.push({ id: "mode_enum_compliance", status: "pass", detail: `${modeEnvHit.key} normalizes to '${mode}'` });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      checks.push({ id: "mode_enum_compliance", status: "fail", detail: `${modeEnvHit.key}: ${message}` });
    }
  }

  // Check 7: health shape when a serve bin exists.
  if (!hasServeBin) {
    checks.push({ id: "health_shape", status: "skip", detail: "no serve bin declared" });
  } else if (options.healthSample === undefined) {
    checks.push({ id: "health_shape", status: "skip", detail: "serve bin present; no health sample provided to shape-check" });
  } else {
    const result = HealthResponseSchema.safeParse(options.healthSample);
    if (result.success) {
      checks.push({ id: "health_shape", status: "pass", detail: "GET /health payload matches { status, version, mode }" });
    } else {
      checks.push({
        id: "health_shape",
        status: "fail",
        detail: `health payload invalid: ${result.error.issues.map((i) => `${i.path.join(".") || "<root>"} ${i.message}`).join("; ")}`
      });
    }
  }

  // Check 9: published-artifact scanning is bound to prepack (clause C).
  checks.push(publishedArtifactGateCheck(repoRoot, manifest));

  // Check 8: no forbidden shared cloud runtimes (reuse the no-cloud guard).
  if (options.skipNoCloudScan) {
    checks.push({ id: "no_cloud_guard", status: "skip", detail: "skipped by caller" });
  } else {
    try {
      const pack = scanNoCloudTarget(repoRoot);
      if (pack.verdict === "passed") {
        checks.push({ id: "no_cloud_guard", status: "pass", detail: "no forbidden shared cloud runtime edges" });
      } else {
        const top = pack.findings
          .filter((f) => f.severity === "high" || f.severity === "critical")
          .slice(0, 5)
          .map((f) => `${f.severity} ${f.path ?? "<manifest>"}: ${f.message}`)
          .join("; ");
        checks.push({ id: "no_cloud_guard", status: "fail", detail: top || "no-cloud scan failed" });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      checks.push({ id: "no_cloud_guard", status: "fail", detail: `no-cloud scan error: ${message}` });
    }
  }

  const ok = checks.every((check) => check.status !== "fail");
  return { ok, repoRoot, name: manifest.name, class: manifest.class, checks };
}
