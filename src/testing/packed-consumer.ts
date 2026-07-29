// Provenance audit for a consumer tree that was populated by extracting the
// packed tarball instead of by `bun install`.
//
// The isolated-consumer smoke proves one thing above all: the consumer loads
// what `npm publish` would ship, not the repo's own source tree. On the
// `bun install` path a single `lstat` carries that proof — if the resolver
// linked back to the repo, `node_modules/@hasna/contracts` is a symlink.
//
// On an extraction fallback that check is tautological: the fallback creates
// the directory itself, so it can never be a link. This audit restores the
// guarantee the symlink check was standing in for, by comparing the tree that
// the consumer will resolve against the archive's own entry list, and by
// rejecting any link that could reach back out of it.

import { lstatSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

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
