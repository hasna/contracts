import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
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

const SKIP_DIRS = new Set([".git", "node_modules", ".cache", ".next", ".turbo", "coverage", "docs", "examples", "tests"]);
const LOCKFILES = new Set(["bun.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"]);
const SOURCE_DIRS = new Set(["src", "bin", "cli", "mcp", "server", "lib", "scripts", "config", "infra", "hooks", ".github", "dist"]);
const MAX_TEXT_BYTES = 5 * 1024 * 1024;

const RUNTIME_PATTERNS = [
  { pattern: "@hasna/cloud", message: "Shared @hasna/cloud runtime reference is forbidden" },
  { pattern: "open-cloud", message: "Shared open-cloud runtime reference is forbidden" },
  { pattern: "cloud-mcp", message: "Legacy cloud-mcp runtime surface is forbidden" },
  { pattern: "registerCloudTools", message: "Legacy registerCloudTools runtime surface is forbidden" },
  { pattern: "registerCloudCommands", message: "Legacy registerCloudCommands runtime surface is forbidden" },
  { pattern: ".hasna/cloud", message: "Legacy .hasna/cloud runtime config is forbidden" },
  { pattern: "HASNA_CLOUD_", message: "Shared HASNA_CLOUD_* runtime config is forbidden" },
  { pattern: "HASNA_RDS_PASSWORD", message: "Legacy shared RDS credential config is forbidden" }
] as const;

const DECLARATION_FILE_MARKERS = [
  "FORBIDDEN_SHARED_CLOUD_RUNTIMES",
  "RUNTIME_PATTERNS",
  "hasna.app_cloud_manifest.v1",
  "hasna.no_cloud_evidence_pack.v1"
] as const;
// The forbidden-runtime pattern strings legitimately live in exactly two source
// modules. Any file under dist/ is a build artifact derived from those sources;
// bundlers inline the declaration content into whichever entrypoints import it,
// so the exact set of dist files carrying it changes with the build config.
// Match the two sources explicitly and treat any dist/ artifact generically —
// the >= 2 declaration-marker gate below (plus the @hasna/contracts package gate)
// keeps downstream packages from bypassing the scan.
const CONTRACTS_DECLARATION_SOURCES = new Set(["src/no-cloud.ts", "src/schemas.ts"]);

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
  const sections = ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"];
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

  for (const section of sections) {
    const deps = pkg[section];
    if (!deps || typeof deps !== "object") continue;
    for (const runtime of FORBIDDEN_SHARED_CLOUD_RUNTIMES) {
      if (Object.prototype.hasOwnProperty.call(deps, runtime)) {
        findings.push({
          id: `finding_${stableId(`${file.path}:${section}:${runtime}`)}`,
          kind: "package_manifest",
          severity: section === "devDependencies" ? "high" : "critical",
          path: file.path,
          packageName,
          pattern: runtime,
          message: `Forbidden shared cloud runtime dependency in ${section}`,
          evidenceRefs: []
        });
      }
    }
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
  const isDeclarationSource = CONTRACTS_DECLARATION_SOURCES.has(normalized);
  const isBuildArtifact = normalized === "dist" || normalized.startsWith("dist/");
  if (!isDeclarationSource && !isBuildArtifact) return false;
  if (!/\.(cjs|cts|js|jsx|mjs|mts|ts|tsx)$/i.test(normalized)) return false;
  const markerCount = DECLARATION_FILE_MARKERS.filter((marker) => file.text.includes(marker)).length;
  return markerCount >= 2;
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

function textFindings(file: ScanFile, severity: NoCloudFindingSeverity, packageName?: string): NoCloudFinding[] {
  if (isAppCloudManifestDocument(file)) return [];
  if (isNoCloudDeclarationFile(file, packageName)) return [];
  const findings: NoCloudFinding[] = [];
  for (const { pattern, message } of RUNTIME_PATTERNS) {
    if (!file.text.includes(pattern)) continue;
    findings.push({
      id: `finding_${stableId(`${file.path}:${pattern}`)}`,
      kind: file.kind,
      severity,
      path: file.path,
      pattern,
      message,
      evidenceRefs: []
    });
  }
  return findings;
}

function scanFindings(file: ScanFile, severity: NoCloudFindingSeverity, packageName?: string): NoCloudFinding[] {
  if (file.kind === "package_manifest") {
    return [...dependencyFindings(file), ...pathFindings(file, severity), ...textFindings(file, "high", packageName)];
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

function normalizeArchiveEntry(entry: string, commonRoot: string | null): string | null {
  let normalized = entry.replace(/^\.\/+/, "").replace(/^\/+/, "");
  if (!normalized || normalized.endsWith("/")) return null;
  if (commonRoot && (normalized === commonRoot || normalized.startsWith(`${commonRoot}/`))) {
    normalized = normalized.slice(commonRoot.length).replace(/^\/+/, "");
  } else {
    normalized = normalized.replace(/^package\//, "");
  }
  return normalized || null;
}

function commonArchiveRoot(entries: string[]): string | null {
  const firstSegments = new Set<string>();
  for (const entry of entries) {
    const normalized = entry.replace(/^\.\/+/, "").replace(/^\/+/, "");
    if (!normalized || normalized.endsWith("/")) continue;
    const [first, ...rest] = normalized.split("/");
    if (!first || rest.length === 0) return null;
    firstSegments.add(first);
    if (firstSegments.size > 1) return null;
  }
  const [root] = [...firstSegments];
  return root ?? null;
}

function collectTarballFiles(target: string): ScanFile[] {
  const entries = execFileSync("tar", ["-tzf", target], { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 })
    .split("\n")
    .filter(Boolean);
  const archiveRoot = commonArchiveRoot(entries);
  const files: ScanFile[] = [];
  for (const entry of entries) {
    const normalized = normalizeArchiveEntry(entry, archiveRoot);
    if (!normalized) continue;
    const kind = shouldReadPath(normalized);
    if (!kind) continue;
    const text = execFileSync("tar", ["-xOzf", target, entry], {
      encoding: "utf8",
      maxBuffer: MAX_TEXT_BYTES
    });
    const artifactKind = kind === "package_manifest" || kind === "lockfile" ? kind : "packed_artifact";
    files.push({ path: normalized, text, kind: artifactKind });
  }
  return files;
}

function collectScanFiles(target: string): { files: ScanFile[]; scanMode: NoCloudEvidencePack["scanMode"] } {
  const stat = statSync(target);
  if (stat.isDirectory()) return { files: collectDirectoryFiles(target), scanMode: "source_tree" };
  if (stat.isFile() && /\.(tgz|tar\.gz)$/i.test(target)) return { files: collectTarballFiles(target), scanMode: "packed_artifact" };
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
