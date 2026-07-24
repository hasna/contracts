// Repo self-conformance for the Hasna Service Contract v1.
//
// A repo runs this against its own root to prove it satisfies the contract:
//   1. hasna.contract.json is present and valid (manifest + class rules).
//   2. Declared bins and SDK exports match package.json.
//   3. Required API/SDK/MCP/CLI surfaces are declared or explicitly waived.
//   4. Store-owning repos declare SQLite + PostgreSQL capability and a live-PG gate.
//   5. Public manifests do not expose private infrastructure references.
//   6. Env parsing follows the HASNA_<NAME>_STORAGE_MODE spec and any mode env
//      value normalizes to the local|cloud enum (mode enum compliance).
//   7. If a `<name>-serve` bin exists, the health payload (when sampled) has the
//      { status, version, mode } shape.
//   8. No forbidden shared cloud runtimes (reuses the no-cloud guard).

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  HealthResponseSchema,
  SERVICE_SURFACE_KINDS,
  allowedBinsForName,
  type ServiceContractManifest,
  type ServiceSurfaceKind
} from "./schemas";
import { loadServiceContractManifest, type LoadServiceContractResult } from "./service-contract";
import { normalizeStorageMode, storageEnvKeys, type Env } from "./mode";
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
}

interface PackageJsonInfo {
  present: boolean;
  bins: string[];
  exportSubpaths: string[];
}

function packageJsonInfo(repoRoot: string): PackageJsonInfo {
  const path = join(repoRoot, "package.json");
  if (!existsSync(path)) return { present: false, bins: [], exportSubpaths: [] };
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
    let exportSubpaths: string[] = [];
    if (typeof pkg.exports === "string" || Array.isArray(pkg.exports)) {
      exportSubpaths = ["."];
    } else if (pkg.exports && typeof pkg.exports === "object") {
      const keys = Object.keys(pkg.exports as Record<string, unknown>);
      exportSubpaths = keys.some((key) => key.startsWith(".")) ? keys.filter((key) => key.startsWith(".")) : ["."];
    }
    return { present: true, bins, exportSubpaths };
  } catch {
    return { present: true, bins: [], exportSubpaths: [] };
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
  category: "secret-ref" | "internal-host" | "arn" | "account-id";
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
      if (/secretRef$/i.test(key) || key === "databaseDsnBindings") {
        findings.push({ path: childPath, category: "secret-ref" });
      }
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
  return findings;
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
  const waivedKinds = new Set(manifest.metadata?.conformance?.waivedSurfaces?.map((waiver) => waiver.kind) ?? []);
  const missingKinds = SERVICE_SURFACE_KINDS.filter((kind) => !representedKinds.has(kind) && !waivedKinds.has(kind));
  if (missingKinds.length > 0) {
    checks.push({
      id: "surface_matrix",
      status: "fail",
      detail: `missing supported surface declarations or explicit waivers: ${missingKinds.join(", ")}`
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

  // Check 4: storage capability matrix and PostgreSQL runtime proof.
  if (manifest.class !== "service" && manifest.class !== "cli-with-store") {
    checks.push({ id: "storage_capabilities", status: "skip", detail: `${manifest.class} repo is outside the dual-storage core gate` });
  } else {
    const engines = new Set(manifest.storage?.engines ?? []);
    const missingEngines = ["sqlite", "postgres"].filter((engine) => !engines.has(engine as "sqlite" | "postgres"));
    const failures: string[] = [];
    if (missingEngines.length > 0) failures.push(`missing storage engines: ${missingEngines.join(", ")}`);
    if (!manifest.storage?.envPrefix) failures.push("storage.envPrefix is required for the PostgreSQL DATABASE_URL contract");
    if (!manifest.storage?.pgTestGate) failures.push("storage.pgTestGate is required to prove live PostgreSQL support");
    checks.push({
      id: "storage_capabilities",
      status: failures.length === 0 ? "pass" : "fail",
      detail: failures.length === 0 ? "sqlite and postgres capabilities plus live-PG gate declared" : failures.join("; ")
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
          ? "no private secret references, internal hosts, ARNs, or account IDs"
          : `private infrastructure references at ${unique.map((finding) => `${finding.path} (${finding.category})`).join(", ")}`
    });
  }

  checks.push({
    id: "hosting_story",
    status: manifest.hosting.includes("user-hosted") || manifest.class === "saas" ? "pass" : "fail",
    detail: manifest.hosting.includes("user-hosted")
      ? `user-hosted product story declared${manifest.hosting.includes("hasna-saas") ? " with optional Hasna SaaS" : ""}`
      : manifest.class === "saas"
        ? "Hasna SaaS control-plane story declared"
        : "public OSS cores must declare the user-hosted product story"
  });

  // Check 6: env parsing + storage mode enum compliance.
  const env = options.env ?? process.env;
  const { modeKeys } = storageEnvKeys(manifest.name);
  const modeEnvHit = modeKeys.map((key) => ({ key, value: env[key]?.trim() })).find((hit) => hit.value);
  if (!modeEnvHit || !modeEnvHit.value) {
    checks.push({ id: "mode_enum_compliance", status: "pass", detail: `no mode env set; defaults to local (keys: ${modeKeys.join(", ")})` });
  } else {
    try {
      const { mode, deprecatedAlias } = normalizeStorageMode(modeEnvHit.value);
      const alias = deprecatedAlias ? ` (deprecated alias '${deprecatedAlias}' -> cloud)` : "";
      checks.push({ id: "mode_enum_compliance", status: "pass", detail: `${modeEnvHit.key} normalizes to '${mode}'${alias}` });
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
