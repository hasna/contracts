// The mutation audit's in-flight record, under test.
//
// WHY THIS FILE EXISTS. The record is the only thing in this repo that writes the
// pristine text of a tracked source file to disk and then, on a later run, writes
// that text back — so it is simultaneously the audit's safety net and its largest
// blast radius. It shipped with no test at all: nothing in `tests/`, `.github/`, or
// `package.json` ran `scripts/mutation-audit.ts`, so deleting every guard below
// left the suite and CI green. A rule with no test is exactly what the audit exists
// to find, and it had one at home.
//
// The unit cases import `scripts/mutation-audit-record.ts` directly and run in
// milliseconds. The end-to-end cases spawn the real script with `--anchors`, which
// applies every guard and exits in ~0.2 s without running a suite, so the rc=2 a
// runbook depends on is asserted against the actual entry point rather than a
// stand-in.

import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MutationRecordRefusal,
  assertOutsideScannedTree,
  assertPrivateDirectory,
  assertRecordTargetsScannedTree,
  openInFlightRecordStore,
  prepareRecordDirectory,
  recordDirectoryPath,
  sentinelPathFor,
} from "../scripts/mutation-audit-record";

const root = realpathSync(join(import.meta.dir, ".."));

/** A scratch dir that is torn down whether the body throws or not. */
function withScratch<T>(prefix: string, body: (scratch: string) => T): T {
  const scratch = mkdtempSync(join(tmpdir(), prefix));
  try {
    return body(scratch);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/**
 * A fake repo root plus a private state home, which is the whole world a store
 * needs. Nothing here touches the real `$XDG_STATE_HOME`, so a test run never
 * disturbs a real audit's record.
 */
function withStoreFixture<T>(
  body: (fixture: { repoRoot: string; env: NodeJS.ProcessEnv; stateHome: string }) => T,
): T {
  return withScratch("mutation-audit-record-", (scratch) => {
    const repoRoot = join(scratch, "repo");
    const stateHome = join(scratch, "state");
    mkdirSync(join(repoRoot, "src"), { recursive: true });
    mkdirSync(stateHome, { recursive: true, mode: 0o700 });
    return body({ repoRoot, stateHome, env: { HOME: scratch, XDG_STATE_HOME: stateHome } });
  });
}

/** Run the real script, which applies every guard before `--anchors` is read. */
function runAudit(env: Record<string, string>): { exitCode: number | null; output: string } {
  const result = Bun.spawnSync(["bun", "scripts/mutation-audit.ts", "--anchors"], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, ...env },
  });
  const decoder = new TextDecoder();
  return { exitCode: result.exitCode, output: decoder.decode(result.stdout) + decoder.decode(result.stderr) };
}

describe("mutation audit in-flight record: where it goes", () => {
  test("uses an absolute XDG_STATE_HOME and otherwise falls back to ~/.local/state", () => {
    expect(recordDirectoryPath({ XDG_STATE_HOME: "/somewhere/state", HOME: "/home/example" })).toBe(
      join("/somewhere/state", "hasna-mutation-audit"),
    );
    // Relative values are ignored, per the XDG spec — and a relative one resolved
    // against the audit's cwd would land inside the repo it is scanning.
    expect(recordDirectoryPath({ XDG_STATE_HOME: "relative/state", HOME: "/home/example" })).toBe(
      join("/home/example", ".local", "state", "hasna-mutation-audit"),
    );
    expect(recordDirectoryPath({ HOME: "/home/example" })).toBe(
      join("/home/example", ".local", "state", "hasna-mutation-audit"),
    );
  });

  test("gives two repo roots two different record files", () => {
    const directory = "/state/hasna-mutation-audit";
    const first = sentinelPathFor("/checkouts/alpha/contracts", directory);
    const second = sentinelPathFor("/checkouts/beta/contracts", directory);
    // Same basename on purpose: two worktrees of one repo are the case that
    // matters, and a name keyed on the basename alone would collide, so one run's
    // recovery would restore the other's file mid-mutation.
    expect(first).not.toBe(second);
    expect(sentinelPathFor("/checkouts/alpha/contracts", directory)).toBe(first);
    expect(first.startsWith(join(directory, "contracts-"))).toBe(true);
  });

  test("refuses a record that would land inside the scanned tree", () => {
    expect(() => assertOutsideScannedTree(root, join(root, ".mutation-audit-inflight.json"))).toThrow(
      MutationRecordRefusal,
    );
    expect(() => assertOutsideScannedTree(root, join(root, "nested", "deep", "record.json"))).toThrow(
      /inside the scanned tree/,
    );
    expect(() => assertOutsideScannedTree(root, root)).toThrow(MutationRecordRefusal);
    // A traversal that leaves the tree is outside it, however it is spelled.
    expect(() => assertOutsideScannedTree(root, join(root, "..", "elsewhere.json"))).not.toThrow();
    expect(() => assertOutsideScannedTree(root, "/var/lib/elsewhere.json")).not.toThrow();
  });

  test("refuses a record directory anyone else can write to", () => {
    withScratch("mutation-audit-perm-", (scratch) => {
      const directory = join(scratch, "records");
      mkdirSync(directory, { mode: 0o700 });
      expect(() => assertPrivateDirectory(directory)).not.toThrow();

      // `mkdirSync(dir, {recursive: true, mode})` does not tighten a directory that
      // already exists, so asking for 0700 proves nothing — the mode has to be read
      // back. Group-writable is not a lesser case: on a shared box umask 0002 makes
      // it the DEFAULT, so every agent profile could plant a record.
      chmodSync(directory, 0o770);
      expect(() => assertPrivateDirectory(directory)).toThrow(/writable by group or other/);
      chmodSync(directory, 0o707);
      expect(() => assertPrivateDirectory(directory)).toThrow(MutationRecordRefusal);
      chmodSync(directory, 0o777);
      expect(() => assertPrivateDirectory(directory)).toThrow(MutationRecordRefusal);

      chmodSync(directory, 0o700);
      const file = join(scratch, "not-a-directory");
      writeFileSync(file, "");
      expect(() => assertPrivateDirectory(file)).toThrow(/not a directory/);
    });
  });

  test("creates the record directory private, and creates nothing when it refuses", () => {
    withScratch("mutation-audit-prepare-", (scratch) => {
      const repoRoot = join(scratch, "repo");
      const stateHome = join(scratch, "state");
      mkdirSync(repoRoot, { recursive: true });

      const directory = prepareRecordDirectory(realpathSync(repoRoot), { XDG_STATE_HOME: stateHome });
      expect(lstatSync(directory).mode & 0o777).toBe(0o700);

      // A pre-existing loose directory is refused rather than silently reused.
      chmodSync(directory, 0o777);
      expect(() => prepareRecordDirectory(realpathSync(repoRoot), { XDG_STATE_HOME: stateHome })).toThrow(
        MutationRecordRefusal,
      );
      chmodSync(directory, 0o700);

      // Refusing must come BEFORE the mkdir, or a run pointed into the repo
      // litters the tree it is about to scan with an untracked directory.
      const insideTree = join(repoRoot, ".state");
      expect(() => prepareRecordDirectory(realpathSync(repoRoot), { XDG_STATE_HOME: insideTree })).toThrow(
        /inside the scanned tree/,
      );
      expect(existsSync(insideTree)).toBe(false);
    });
  });
});

describe("mutation audit in-flight record: writing and restoring", () => {
  test("writes the record 0600, staged and renamed rather than in place", () => {
    withStoreFixture(({ repoRoot, env }) => {
      const source = join(repoRoot, "src", "guarded.ts");
      writeFileSync(source, "export const guarded = true;\n");
      const store = openInFlightRecordStore(repoRoot, env);

      // Pre-seed the destination so the inode can be compared. `writeFileSync`
      // truncates in place and KEEPS the inode; `renameSync` replaces the
      // directory entry and changes it. That difference is the whole point: a
      // crash mid-write to the live path leaves truncated JSON, and recovery
      // parses this file before it can restore anything.
      writeFileSync(store.sentinel, "{}");
      const before = statSync(store.sentinel).ino;

      store.begin(source, readFileSync(source, "utf8"));
      expect(statSync(store.sentinel).ino).not.toBe(before);
      expect(lstatSync(store.sentinel).mode & 0o777).toBe(0o600);
      expect(JSON.parse(readFileSync(store.sentinel, "utf8"))).toMatchObject({
        pid: process.pid,
        path: source,
        original: "export const guarded = true;\n",
      });
      // No staging file is left behind to be found by the next run.
      expect(readdirSync(join(store.sentinel, "..")).filter((name) => name.endsWith(".tmp"))).toEqual([]);

      writeFileSync(source, "export const guarded = false;\n");
      store.end();
      expect(readFileSync(source, "utf8")).toBe("export const guarded = true;\n");
      expect(existsSync(store.sentinel)).toBe(false);
    });
  });

  test("recovers a legacy repo-root record once, then deletes it", () => {
    withStoreFixture(({ repoRoot, env }) => {
      const source = join(repoRoot, "src", "guarded.ts");
      const pristine = "export const guarded = true;\n";
      writeFileSync(source, "export const guarded = false;\n");
      const store = openInFlightRecordStore(repoRoot, env);
      writeFileSync(store.legacySentinel, JSON.stringify({ path: source, original: pristine }));

      expect(store.recover()).toEqual([`RECOVERED: a previous run left ${source} mutated. Restored it.`]);
      expect(readFileSync(source, "utf8")).toBe(pristine);
      expect(existsSync(store.legacySentinel)).toBe(false);

      // Once, not every run: a second pass has nothing to say and nothing to undo.
      writeFileSync(source, "export const guarded = false;\n");
      expect(store.recover()).toEqual([]);
      expect(readFileSync(source, "utf8")).toBe("export const guarded = false;\n");
    });
  });

  test("refuses to restore a record that names a path outside the repo", () => {
    withStoreFixture(({ repoRoot, env, stateHome }) => {
      const victim = join(stateHome, "victim.txt");
      writeFileSync(victim, "untouched\n");
      const store = openInFlightRecordStore(repoRoot, env);
      // The record's CONTENTS are the least trusted input this script has:
      // whatever protects the directory, a stale record from a moved worktree
      // names a path that is no longer ours and a planted one names anything.
      writeFileSync(store.sentinel, JSON.stringify({ path: victim, original: "OVERWRITTEN\n" }));

      expect(() => store.recover()).toThrow(/outside this repository/);
      expect(readFileSync(victim, "utf8")).toBe("untouched\n");
    });
  });

  test("refuses while another live process holds the record", () => {
    withStoreFixture(({ repoRoot, env }) => {
      const source = join(repoRoot, "src", "guarded.ts");
      writeFileSync(source, "export const guarded = false;\n");
      const store = openInFlightRecordStore(repoRoot, env);
      // pid 1 is always alive and never us, so "someone else is working" is
      // deterministic here rather than a race.
      writeFileSync(store.sentinel, JSON.stringify({ pid: 1, path: source, original: "pristine\n" }));

      expect(() => store.recover()).toThrow(/pid 1 holds a mutation/);
      expect(readFileSync(source, "utf8")).toBe("export const guarded = false;\n");
    });
  });
});

describe("mutation audit script: the guards are wired to rc=2", () => {
  test("refuses a planted record naming a file outside the repo, and writes nothing", () => {
    withScratch("mutation-audit-e2e-", (scratch) => {
      const stateHome = join(scratch, "state");
      const directory = join(stateHome, "hasna-mutation-audit");
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const victim = join(scratch, "victim.txt");
      writeFileSync(victim, "untouched\n");
      writeFileSync(
        sentinelPathFor(root, realpathSync(directory)),
        JSON.stringify({ path: victim, original: "OVERWRITTEN\n" }),
      );

      const result = runAudit({ XDG_STATE_HOME: stateHome });
      expect(result.exitCode).toBe(2);
      expect(result.output).toContain("outside this repository");
      expect(readFileSync(victim, "utf8")).toBe("untouched\n");
    });
  });

  test("refuses a record directory anyone can write to", () => {
    withScratch("mutation-audit-e2e-perm-", (scratch) => {
      const stateHome = join(scratch, "state");
      mkdirSync(join(stateHome, "hasna-mutation-audit"), { recursive: true });
      chmodSync(join(stateHome, "hasna-mutation-audit"), 0o777);

      const result = runAudit({ XDG_STATE_HOME: stateHome });
      expect(result.exitCode).toBe(2);
      expect(result.output).toContain("writable by group or other");
    });
  });

  test("refuses a state home inside the repo without creating it", () => {
    const insideTree = join(root, ".mutation-audit-state-under-test");
    try {
      const result = runAudit({ XDG_STATE_HOME: insideTree });
      expect(result.exitCode).toBe(2);
      expect(result.output).toContain("inside the scanned tree");
      expect(existsSync(insideTree)).toBe(false);
    } finally {
      rmSync(insideTree, { recursive: true, force: true });
    }
  });

  test("runs its cheap check clean when the record directory is private", () => {
    withScratch("mutation-audit-e2e-ok-", (scratch) => {
      const result = runAudit({ XDG_STATE_HOME: join(scratch, "state") });
      expect(result.exitCode, result.output).toBe(0);
      expect(result.output).toContain("anchors present");
    });
  });
});
