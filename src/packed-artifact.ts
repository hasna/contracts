// Reading what actually SHIPS, rather than what is in the repo.
//
// `files` negations mean the repo and the package diverge, and the divergence
// is exactly where disclosures hide: `@hasna/tenants@0.1.0` shipped a complete
// asset inventory compiled into `dist/` from a source file that `files` kept
// out of the tarball, so every source-level review passed. Two scanners now
// need to read a packed tarball — the no-cloud runtime guard and the
// published-artifact guard — so the archive plumbing lives here once.
//
// The two scanners deliberately select DIFFERENT members. The no-cloud guard
// reads source-shaped files, because it is looking for imports and config. The
// published-artifact guard reads everything text-decodable, because a leak has
// no preferred file extension — a `.map`, a `.md`, or a `.csv` discloses just
// as well as a `.js`. Only the archive mechanics are shared.

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/** Largest member the buffered readers decode by default. */
export const MAX_ARCHIVE_MEMBER_BYTES = 5 * 1024 * 1024;

/**
 * Ceiling for a scanner that is not allowed to decline.
 *
 * The published-artifact guard cannot have a working size limit. A member it
 * declines to read is a member that could be carrying the inventory, and the
 * biggest file in a tarball is exactly where a compiled-in list ends up:
 * bundles and `.map` files routinely run past any cap worth setting, and the
 * incident's own `dist/index.js` is the shape this guard exists for. This bound
 * is therefore a memory backstop for a corrupt or hostile archive, not a policy
 * knob — a member above it is reported as UNREADABLE, which FAILS the scan.
 */
export const MAX_SCANNED_MEMBER_BYTES = 512 * 1024 * 1024;

/** Is `target` a path this module can read as a packed artifact? */
export function isPackedArtifactPath(target: string): boolean {
  return /\.(tgz|tar\.gz)$/i.test(target);
}

/**
 * Extract the whole archive ONCE into a directory and return its path.
 *
 * The per-member `tar -xOzf <archive> <entry>` this replaces re-decompressed
 * the entire stream every time: measured at 0.243 s/member on a 20,414-member
 * package, i.e. **82 minutes**, against 4.9 s for the same content as a
 * directory — a ~1000x penalty on a mandatory, blocking `prepack` hook. A gate
 * that costs an hour is a gate that gets switched off, which is the failure
 * mode this module exists to argue against.
 *
 * Extraction to disk rather than to one buffer, deliberately: `tar -xzO` into a
 * single pipe truncates on large packages (`gzip: unexpected end of file`), and
 * a scan that silently reads a truncated stream is worse than a slow one. The
 * caller owns the returned directory and must remove it.
 */
export function extractArchive(target: string): string {
  const directory = mkdtempSync(join(tmpdir(), "hasna-artifact-scan-"));
  try {
    execFileSync("tar", ["-xzf", resolve(target), "-C", directory], { stdio: "pipe" });
  } catch (error) {
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
  return directory;
}

/** Raw member paths inside the archive, in archive order. */
export function listArchiveEntries(target: string): string[] {
  return execFileSync("tar", ["-tzf", target], { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 })
    .split("\n")
    .filter(Boolean);
}

/**
 * The single top-level directory every member sits under (npm's `package/`),
 * or `null` when members do not share one. Returning `null` rather than
 * guessing keeps a hand-rolled archive from having its paths rewritten.
 */
export function commonArchiveRoot(entries: string[]): string | null {
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

/** Strip the archive root and leading separators; `null` for directories. */
export function normalizeArchiveEntry(entry: string, commonRoot: string | null): string | null {
  let normalized = entry.replace(/^\.\/+/, "").replace(/^\/+/, "");
  if (!normalized || normalized.endsWith("/")) return null;
  if (commonRoot && (normalized === commonRoot || normalized.startsWith(`${commonRoot}/`))) {
    normalized = normalized.slice(commonRoot.length).replace(/^\/+/, "");
  } else {
    normalized = normalized.replace(/^package\//, "");
  }
  return normalized || null;
}

/**
 * Extract one member's bytes. Throws if the member exceeds `maxBytes`.
 *
 * The cap is a parameter because the two callers want opposite things from it:
 * the no-cloud guard reads source-shaped files and a big one is not its
 * problem, while the published-artifact guard must read whatever shipped and
 * treats an undecoded member as a failure rather than a footnote.
 */
export function readArchiveMemberBytes(
  target: string,
  entry: string,
  maxBytes: number = MAX_ARCHIVE_MEMBER_BYTES
): Buffer {
  return execFileSync("tar", ["-xOzf", target, entry], { maxBuffer: maxBytes });
}

/** Extract one member as UTF-8 text. Throws if the member exceeds the size cap. */
export function readArchiveMemberText(target: string, entry: string): string {
  return execFileSync("tar", ["-xOzf", target, entry], {
    encoding: "utf8",
    maxBuffer: MAX_ARCHIVE_MEMBER_BYTES,
  });
}
