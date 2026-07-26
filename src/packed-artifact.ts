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

/** Largest member this module will decode. Bigger members are reported, not read. */
export const MAX_ARCHIVE_MEMBER_BYTES = 5 * 1024 * 1024;

/** Is `target` a path this module can read as a packed artifact? */
export function isPackedArtifactPath(target: string): boolean {
  return /\.(tgz|tar\.gz)$/i.test(target);
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

/** Extract one member's bytes. Throws if the member exceeds the size cap. */
export function readArchiveMemberBytes(target: string, entry: string): Buffer {
  return execFileSync("tar", ["-xOzf", target, entry], { maxBuffer: MAX_ARCHIVE_MEMBER_BYTES });
}

/** Extract one member as UTF-8 text. Throws if the member exceeds the size cap. */
export function readArchiveMemberText(target: string, entry: string): string {
  return execFileSync("tar", ["-xOzf", target, entry], {
    encoding: "utf8",
    maxBuffer: MAX_ARCHIVE_MEMBER_BYTES,
  });
}
