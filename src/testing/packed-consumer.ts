// The offline archive-extraction diagnostic for the isolated-consumer pack
// smoke, plus the policy and the provenance audit that go with it.
//
// `scripts/smoke-todos-pack.ts` proves one thing above all: the consumer loads
// what `npm publish` would ship, resolved the way a real consumer resolves it.
// Only `bun install` proves that, because only `bun install` exercises the
// package's declared dependency ranges. When the environment refuses that
// install — no reachable registry, read-only cache — the smoke does NOT get to
// report success. The gate is fail-closed: the run is UNVERIFIED and exits
// non-zero, so a package whose dependency ranges cannot resolve can never go
// green through an offline runner.
//
// The extraction fallback below is therefore an opt-in diagnostic, never a
// pass. It still exits non-zero; it exists only so an offline operator can see
// the export-map and import checks run.
//
// On the `bun install` path a single `lstat` carries the provenance proof — if
// the resolver linked back to the repo, `node_modules/@hasna/contracts` is a
// symlink. On the extraction path that check is tautological, because the
// fallback creates the directory itself, so the tree is audited against the
// archive's own entry list and any link that could reach back out of it is
// rejected.

import { cpSync, lstatSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join, relative, sep } from "node:path";

type Environment = Record<string, string | undefined>;

/**
 * Opt-in that lets the pack smoke run the offline archive-extraction
 * diagnostic when an isolated `bun install` is unavailable. It never turns a
 * degraded run into a pass: the diagnostic still exits with the UNVERIFIED
 * code, so `verify:release` — and with it `prepack`/`prepublishOnly` — fails.
 */
export const PACK_INSTALL_FALLBACK_ENV = "CONTRACTS_ALLOW_PACK_INSTALL_FALLBACK";

/**
 * Test seam: forces the pack smoke to treat the isolated `bun install` as
 * unavailable, so the fail-closed refusal stays reachable on a host that can in
 * fact install. It can only ever DENY the install — forcing a denial makes the
 * gate stricter, never laxer — so it cannot walk an unverified build past the
 * publish gate.
 */
export const PACK_INSTALL_DENY_ENV = "CONTRACTS_PACK_INSTALL_DENY";

export function packInstallFallbackAllowed(env: Environment = process.env): boolean {
  return env[PACK_INSTALL_FALLBACK_ENV] === "1";
}

export function packInstallDenied(env: Environment = process.env): boolean {
  return env[PACK_INSTALL_DENY_ENV] === "1";
}

// Bun reports a runtime that cannot reach a registry or cannot write its cache
// with these codes; they are what an offline or read-only runner always
// produces. Matching them only selects which refusal the operator is told
// about — a genuine resolution failure keeps its own message — and never
// selects success. Offline the two are not fully separable (an unresolvable
// range also surfaces as ConnectionRefused), which is safe precisely because
// neither branch can report a pass.
const ENVIRONMENT_RESTRICTED_INSTALL = /ReadOnlyFileSystem|ConnectionRefused|FailedToOpenSocket/;

export function isEnvironmentRestrictedInstall(output: string): boolean {
  return ENVIRONMENT_RESTRICTED_INSTALL.test(output);
}

export function packInstallUnavailableMessage(label: string, detail: string): string {
  return `${label} could not run an isolated \`bun install\` on this runtime: ${detail}. `
    + "This gate is fail-closed and will not report success without resolving the packed "
    + "package the way a real consumer does, because only that exercises the declared "
    + `dependency ranges. Set ${PACK_INSTALL_FALLBACK_ENV}=1 to run the offline `
    + "archive-extraction diagnostic instead; it still exits non-zero.";
}

export function packSmokeUnverifiedMessage(label: string, detail: string): string {
  return `todos pack smoke UNVERIFIED: ${label} did not resolve the packed package with an `
    + `isolated \`bun install\` (${detail}). The archive-extraction diagnostic never `
    + "resolves the package's dependency ranges, so this run does not clear the publish "
    + "gate.";
}

export interface PackedTreeAudit {
  readonly ok: boolean;
  readonly failures: readonly string[];
}

/** File entries of a packed archive listing, relative to the package root. */
export function archivePackageEntries(
  entries: Iterable<string>,
  prefix = "package/",
): string[] {
  const files: string[] = [];
  for (const entry of entries) {
    if (!entry.startsWith(prefix) || entry.endsWith("/")) continue;
    const relativePath = entry.slice(prefix.length);
    if (relativePath.length > 0) files.push(relativePath);
  }
  return files.sort();
}

export function auditExtractedPackage(
  packageRoot: string,
  expectedFiles: readonly string[],
): PackedTreeAudit {
  const failures: string[] = [];

  if (lstatSync(packageRoot).isSymbolicLink()) {
    failures.push("extracted package root is a symlink");
    return { ok: false, failures };
  }

  const found: string[] = [];
  const walk = (directory: string) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      const relativePath = relative(packageRoot, absolute).split(sep).join("/");
      if (entry.isSymbolicLink()) {
        failures.push(`extracted package contains a symlink: ${relativePath}`);
        continue;
      }
      if (entry.isDirectory()) {
        walk(absolute);
        continue;
      }
      if (entry.isFile()) {
        found.push(relativePath);
        continue;
      }
      failures.push(`extracted package contains an unsupported entry: ${relativePath}`);
    }
  };
  walk(packageRoot);

  const expected = new Set(expectedFiles);
  const actual = new Set(found);
  for (const missing of [...expected].filter((file) => !actual.has(file)).sort()) {
    failures.push(`extracted package is missing an archive entry: ${missing}`);
  }
  for (const extra of [...actual].filter((file) => !expected.has(file)).sort()) {
    failures.push(`extracted package carries an entry the archive does not: ${extra}`);
  }

  return { ok: failures.length === 0, failures };
}

export interface PackedConsumerInstallOptions {
  /** Tarball produced by `bun pm pack`. */
  readonly archivePath: string;
  /** Consumer workspace whose `node_modules` is (re)built from the archive. */
  readonly consumerRoot: string;
  /** Repository root the runtime dependencies are copied out of. */
  readonly repoRoot: string;
  /** Raw `tar -tzf` listing of the archive, used as the audit's expectation. */
  readonly archiveEntries: Iterable<string>;
  /** Runtime dependencies the consumer smoke imports. */
  readonly runtimeDependencies: readonly string[];
}

/**
 * Populate an isolated consumer tree from the packed archive and audit it
 * against the archive's own entry list. Throws when the extraction or the audit
 * fails; callers still have to treat a successful return as UNVERIFIED, because
 * nothing here resolves a dependency range.
 *
 * Returns the package root the consumer will resolve.
 */
export function installPackedConsumerFromArchive(
  options: PackedConsumerInstallOptions,
): string {
  const consumerNodeModules = join(options.consumerRoot, "node_modules");
  const packageRoot = join(consumerNodeModules, "@hasna", "contracts");
  rmSync(consumerNodeModules, { recursive: true, force: true });
  mkdirSync(packageRoot, { recursive: true });
  const extract = Bun.spawnSync(
    ["tar", "-xzf", options.archivePath, "-C", packageRoot, "--strip-components", "1"],
    {
      cwd: options.consumerRoot,
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  if (extract.exitCode !== 0) {
    const decoder = new TextDecoder();
    throw new Error(
      "archive extraction diagnostic failed\n"
      + `${decoder.decode(extract.stdout)}\n${decoder.decode(extract.stderr)}`,
    );
  }
  for (const dependency of options.runtimeDependencies) {
    cpSync(
      join(options.repoRoot, "node_modules", dependency),
      join(consumerNodeModules, dependency),
      { recursive: true, dereference: true },
    );
  }

  const audit = auditExtractedPackage(packageRoot, archivePackageEntries(options.archiveEntries));
  if (!audit.ok) {
    throw new Error(
      `isolated consumer tree does not match the packed archive\n${audit.failures.join("\n")}`,
    );
  }
  return packageRoot;
}
