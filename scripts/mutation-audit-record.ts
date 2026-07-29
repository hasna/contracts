// The mutation audit's crash-surviving in-flight record, on its own so it can be
// read, reasoned about, and TESTED without running an audit.
//
// WHY IT IS A SEPARATE FILE. `scripts/mutation-audit.ts` runs the whole suite on
// import — there is no `import.meta.main` guard to hide behind, because the file
// IS the run — so nothing could import it to check these rules, and the record
// handling shipped with no test of any kind. `scripts/check-todos-text-hygiene.ts`
// is imported by `tests/todos/text-hygiene.test.ts` exactly this way, and that is
// the shape copied here.
//
// REFUSALS THROW, they do not `process.exit(2)`. The caller turns a refusal into
// the rc=2 the runbook expects; a test asserts one in milliseconds instead of
// spawning a process and reading a number off stderr. The exit code is unchanged
// either way — see the `refuseWith` wrapper in `scripts/mutation-audit.ts`.

import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, isAbsolute, join, relative } from "node:path";

/**
 * A refusal, which is always "stop the run", never "carry on with a warning".
 *
 * Every condition below is one where continuing would either corrupt somebody's
 * tree or publish a coverage figure that is not real, so there is no degraded
 * mode to offer.
 */
export class MutationRecordRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MutationRecordRefusal";
  }
}

/** What is written to disk while a tracked file is held mutated. */
export interface InFlightRecord {
  pid?: number;
  path: string;
  original: string;
}

export interface InFlightRecordStore {
  /** Where this tree's record lives. Printed by the audit so a run is traceable. */
  readonly sentinel: string;
  /** The pre-relocation path, recovered from once and then deleted. */
  readonly legacySentinel: string;
  /** Record `path`'s pristine text, then let the caller mutate it. */
  begin(path: string, original: string): void;
  /** Restore whatever is held and drop the record. Safe to call repeatedly. */
  end(): void;
  /** Repair a killed run. Returns lines to print; throws `MutationRecordRefusal`. */
  recover(): string[];
}

/**
 * The directory the record lives in: per-user, not shared.
 *
 * WHY NOT THE SYSTEM TEMP DIR. A first cut put this under `os.tmpdir()`, which on
 * Linux is `/tmp` — mode 1777, readable and traversable by every local account.
 * Two things went wrong there and both were measured, not argued. The payload of
 * a record is the FULL pristine text of the file being mutated, so `/tmp` published
 * `src/no-cloud.ts` — the denylist itself — as a world-readable file with a
 * predictable name in a world-listable directory. And `mkdirSync(dir, {recursive:
 * true})` neither throws on nor tightens a pre-existing directory, so anyone who
 * created `/tmp/hasna-mutation-audit` mode 0777 first owned the path this script
 * would then read a record out of; that record's `path` and `original` went
 * straight into `writeFileSync`, which is an arbitrary-file-write with the auditing
 * user's rights. Even with nobody hostile, umask 0002 made the directory
 * group-writable, so every agent profile on a shared box already had it.
 *
 * `XDG_STATE_HOME` (default `~/.local/state`) rather than `~/.cache`, because
 * losing this file loses the ability to restore a mutated tracked file — it is
 * state that must survive, not a cache that may be swept. An `XDG_STATE_HOME` that
 * is not absolute is ignored, per the XDG spec.
 */
export function recordDirectoryPath(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.XDG_STATE_HOME?.trim();
  const base =
    configured !== undefined && configured !== "" && isAbsolute(configured)
      ? configured
      : join(env.HOME ?? homedir(), ".local", "state");
  return join(base, "hasna-mutation-audit");
}

/**
 * The record's filename for one tree.
 *
 * Keyed on the absolute repo root, so recovery finds the same file on the next run
 * in this tree and two worktrees of this repo never share one. The pid guard in
 * `recover` arbitrates concurrent runs against the SAME tree; it cannot arbitrate
 * two trees, where one run's recovery would restore the other's file mid-mutation.
 *
 * Pure, and takes an already-resolved root, so the derivation can be checked
 * against roots that do not exist on the machine running the test.
 */
export function sentinelPathFor(resolvedRepoRoot: string, recordDirectory: string): string {
  const key = createHash("sha256").update(resolvedRepoRoot).digest("hex").slice(0, 16);
  return join(recordDirectory, `${basename(resolvedRepoRoot)}-${key}.inflight.json`);
}

/** Is `candidate` the repo root or somewhere beneath it? */
function isWithin(resolvedRepoRoot: string, candidate: string): boolean {
  const within = relative(resolvedRepoRoot, candidate);
  return !within.startsWith("..") && !isAbsolute(within);
}

/**
 * THE RECORD MUST NOT LAND INSIDE THE SCANNED TREE, and that is not tidiness.
 *
 * It used to sit in the repo root as `.mutation-audit-inflight.json`, gitignored so
 * that a human looking at a confusing diff could SEE it. But `original` is the full
 * pristine text of the file being mutated, and for `src/no-cloud.ts` that text is
 * the denylist itself — every module name and config key the no-cloud gate exists
 * to find. This suite scans this repo with its own scanner, and the scanner does
 * not consult `.gitignore`, so the record was evidence against the repo that wrote
 * it.
 *
 * MEASURED on a pristine tree with NO mutation applied: `tests/conformance.test.ts`
 * plus `tests/cli.test.ts` went from 96 pass / 0 fail to 92 pass / 4 fail on the
 * record's presence alone. The baseline is taken BEFORE the record exists, so every
 * mutation then ran against a +4 false-failure floor the baseline never saw, and a
 * mutation nothing genuinely catches still reported `caught` on those four alone.
 *
 * THE FIX IS LOCATION, NOT AN IGNORE LIST. An ignore list has to be repeated in
 * every scanner — repo conformance, the no-cloud gate, the artifact scan, the
 * hostname guard, and whatever is added next — and the scanner that forgets is
 * always the next one. A path no scanner can reach is one decision instead of a
 * standing obligation. This assertion is what keeps that true against an
 * `XDG_STATE_HOME` pointed into the repo or an edit that moves the record back
 * "so you can see it".
 */
export function assertOutsideScannedTree(resolvedRepoRoot: string, candidate: string): void {
  if (!isWithin(resolvedRepoRoot, candidate)) return;
  throw new MutationRecordRefusal(
    `Refusing to run: the in-flight record would be written inside the scanned tree (${candidate}).\n` +
      "It carries the pristine text of the file being mutated, which this suite's own scanners read as findings.",
  );
}

/**
 * A record may only ever restore a file in the tree this run owns.
 *
 * `recover` reads a JSON file off disk and hands `record.path` and `record.original`
 * to `writeFileSync`. Whatever protects the directory, the file's CONTENTS are
 * still the least trusted input this script has — a stale record from a moved
 * worktree names a path that is no longer ours, and a planted one names anything at
 * all. Bounding the write to the repo root turns "restore what the record says"
 * into "restore a file this script could have mutated in the first place", which is
 * the only restore that was ever intended.
 */
export function assertRecordTargetsScannedTree(resolvedRepoRoot: string, sentinel: string, target: string): void {
  if (isWithin(resolvedRepoRoot, target)) return;
  throw new MutationRecordRefusal(
    `Refusing to run: the in-flight record at ${sentinel} names ${target}, which is outside this repository ` +
      `(${resolvedRepoRoot}). This script only ever mutates files in its own tree, so nothing was restored.`,
  );
}

/**
 * The directory must be ours and private, checked rather than assumed.
 *
 * `mkdirSync(dir, {recursive: true, mode})` applies `mode` only to directories it
 * CREATES: against one that already exists it neither throws nor tightens, so
 * asking for 0700 says nothing about what is on disk. Measured, not assumed — a
 * pre-existing 0777 directory survives the call untouched. So the mode is read back
 * and a directory that anyone else can write to, or that belongs to another user,
 * stops the run: a writable record directory is a writable record, and a writable
 * record is an arbitrary file write.
 *
 * `lstat` rather than `stat`, on an already-resolved path, so the answer describes
 * the directory the record is actually in and not a symlink's target.
 */
export function assertPrivateDirectory(resolvedDirectory: string): void {
  const info = lstatSync(resolvedDirectory);
  if (!info.isDirectory()) {
    throw new MutationRecordRefusal(`Refusing to run: ${resolvedDirectory} is not a directory.`);
  }
  const uid = process.getuid?.();
  if (uid !== undefined && info.uid !== uid) {
    throw new MutationRecordRefusal(
      `Refusing to run: the in-flight record directory ${resolvedDirectory} is owned by uid ${info.uid}, not ${uid}. ` +
        "Its contents are handed to writeFileSync, so a directory somebody else controls is an arbitrary file write.",
    );
  }
  if ((info.mode & 0o022) !== 0) {
    throw new MutationRecordRefusal(
      `Refusing to run: the in-flight record directory ${resolvedDirectory} is writable by group or other ` +
        `(mode ${(info.mode & 0o777).toString(8).padStart(3, "0")}). Its contents are handed to writeFileSync, ` +
        "so anyone who can write there can make this script overwrite any file you can write. Expected 0700.",
    );
  }
}

/**
 * Create the record directory, then prove it is private before trusting it.
 *
 * The outside-the-tree check runs BEFORE `mkdirSync`, not after: a run pointed at
 * `XDG_STATE_HOME=$PWD/.state` should refuse without first littering the tree it is
 * about to scan with a directory that then shows up as an untracked change. The
 * check runs a second time on the resolved path, because a symlink could still land
 * the real directory inside the repo.
 */
export function prepareRecordDirectory(
  resolvedRepoRoot: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const directory = recordDirectoryPath(env);
  assertOutsideScannedTree(resolvedRepoRoot, directory);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const resolved = realpathSync(directory);
  assertPrivateDirectory(resolved);
  assertOutsideScannedTree(resolvedRepoRoot, resolved);
  return resolved;
}

/** `kill -0`: does this pid exist and are we allowed to signal it? */
export function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means it exists and belongs to somebody else, which still counts.
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Crash-surviving record of the file currently holding a mutation.
 *
 * WHY THIS EXISTS. The audit edits tracked source in place and restores it on the
 * next line. Anything that stops the process between those two lines leaves the
 * mutation on disk looking exactly like someone's edit — that is how
 * `if (false) roots.push(...)` reached a commit in this repo.
 *
 * SIGNAL HANDLERS DO NOT CLOSE IT, and the reason is specific to that script rather
 * than general: it spends essentially all of its life inside a blocking
 * `Bun.spawnSync`, which does not yield to the event loop, so a queued handler gets
 * no turn until the suite returns. Measured — SIGTERM to the audit process was
 * delivered and the process kept going through two more mutations with the handler
 * never running. SIGKILL cannot be caught at all.
 *
 * So the original text is ALSO written to disk before the mutation, and the next
 * run repairs from it. That path is the one that works, and it was verified the
 * only honest way: SIGKILL the audit mid-mutation, confirm the mutation is left on
 * disk, then confirm the next run prints RECOVERED and restores the file. The
 * handlers in the audit are a cheap best effort for the idle case, not the
 * guarantee.
 */
export function openInFlightRecordStore(
  repoRoot: string,
  env: NodeJS.ProcessEnv = process.env,
): InFlightRecordStore {
  const resolvedRepoRoot = realpathSync(repoRoot);
  const directory = prepareRecordDirectory(resolvedRepoRoot, env);
  const sentinel = sentinelPathFor(resolvedRepoRoot, directory);
  assertOutsideScannedTree(resolvedRepoRoot, sentinel);

  /**
   * The pre-relocation path, recovered from once and then deleted.
   *
   * A run killed by the older script left its record here, and the new path would
   * never look — leaving a mutated tracked file on disk looking exactly like
   * somebody's edit, which is the one failure this record exists to prevent. The
   * shim therefore outlives the move. Recovery runs before the baseline, so a
   * leftover legacy record cannot contaminate a reading either.
   */
  const legacySentinel = join(resolvedRepoRoot, ".mutation-audit-inflight.json");

  let inFlight: { path: string; original: string } | null = null;

  return {
    sentinel,
    legacySentinel,

    begin(path: string, original: string): void {
      inFlight = { path, original };
      // Staged and renamed, because recovery PARSES this file before it can
      // restore anything: a crash mid-write would otherwise leave truncated JSON,
      // and the mutation it was holding would be unrecoverable.
      //
      // 0600 on creation as well as 0700 on the directory: the payload is the full
      // text of a source file, and one of the two protections being enough is not a
      // reason to skip the other.
      const staging = `${sentinel}.${process.pid}.tmp`;
      writeFileSync(staging, JSON.stringify({ pid: process.pid, path, original } satisfies InFlightRecord), {
        mode: 0o600,
      });
      renameSync(staging, sentinel);
    },

    end(): void {
      if (inFlight) {
        const { path, original } = inFlight;
        inFlight = null;
        writeFileSync(path, original);
      }
      if (existsSync(sentinel)) rmSync(sentinel, { force: true });
    },

    /**
     * Repair a previous run that was killed before it could restore.
     *
     * REFUSES TO RUN CONCURRENTLY, and that guard is not hygiene — without it this
     * function is a corruption source. Two audits in the same worktree share one
     * tree: the second one's recovery restores the file the first one is actively
     * mutating, so the first then measures an unmutated tree and reports SURVIVED
     * for rules that are fine. Reproduced by starting a second run by accident.
     *
     * The record carries the owning pid, so "abandoned" can be told from "someone
     * else is working". A stale pid that has been recycled onto an unrelated
     * process is possible and would make this refuse instead of recover — the safe
     * direction, and the message says what to do.
     */
    recover(): string[] {
      const restored: string[] = [];
      for (const candidate of [sentinel, legacySentinel]) {
        if (!existsSync(candidate)) continue;
        const record = JSON.parse(readFileSync(candidate, "utf8")) as InFlightRecord;
        if (record.pid !== undefined && record.pid !== process.pid && processIsAlive(record.pid)) {
          throw new MutationRecordRefusal(
            `Refusing to run: pid ${record.pid} holds a mutation in ${record.path}. ` +
              `Wait for it, or kill that pid and re-run to recover. Record: ${candidate}`,
          );
        }
        assertRecordTargetsScannedTree(resolvedRepoRoot, candidate, record.path);
        if (readFileSync(record.path, "utf8") !== record.original) {
          writeFileSync(record.path, record.original);
          restored.push(`RECOVERED: a previous run left ${record.path} mutated. Restored it.`);
        }
        rmSync(candidate, { force: true });
      }
      return restored;
    },
  };
}
