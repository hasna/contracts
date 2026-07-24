import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applySecureLocalStorePlan,
  DEFAULT_SECURE_LOCAL_STORE_POLICY,
  modeToString,
  planSecureLocalStoreLifecycle,
  secureLocalStorePolicy,
  sqliteSidecarPaths,
  validateContract,
  SCHEMA_IDS
} from "../src";

function tempHome(): string {
  return mkdtempSync(join(tmpdir(), "contracts-secure-store-"));
}

function makeTodosStore(home: string) {
  const todosDir = join(home, ".hasna", "todos");
  const backupsDir = join(todosDir, "backups");
  mkdirSync(backupsDir, { recursive: true });
  const db = join(todosDir, "todos.db");
  const wal = `${db}-wal`;
  const shm = `${db}-shm`;
  const backup = join(backupsDir, "old.jsonl");
  writeFileSync(db, "not a real database fixture\n");
  writeFileSync(wal, "wal sidecar fixture\n");
  writeFileSync(shm, "shm sidecar fixture\n");
  writeFileSync(backup, "redacted backup fixture\n");
  chmodSync(join(home, ".hasna"), 0o755);
  chmodSync(todosDir, 0o755);
  chmodSync(backupsDir, 0o755);
  chmodSync(db, 0o644);
  chmodSync(wal, 0o644);
  chmodSync(shm, 0o644);
  chmodSync(backup, 0o644);
  const old = new Date(Date.now() - 45 * 24 * 60 * 60 * 1000);
  utimesSync(backup, old, old);
  return { todosDir, backupsDir, db, wal, shm, backup };
}

describe("secure local store contract", () => {
  test("default policy validates and inventories required stores", () => {
    const result = validateContract(SCHEMA_IDS.secureLocalStorePolicy, DEFAULT_SECURE_LOCAL_STORE_POLICY);
    expect(result.success).toBe(true);
    const storeIds = new Set(DEFAULT_SECURE_LOCAL_STORE_POLICY.stores.map((store) => store.storeId));
    for (const id of ["codewith", "todos", "conversations", "mementos", "knowledge", "projects", "browser", "terminal", "logs", "loops"]) {
      expect(storeIds.has(id)).toBe(true);
    }
    expect(DEFAULT_SECURE_LOCAL_STORE_POLICY.defaults.dryRunDefault).toBe(true);
    expect(DEFAULT_SECURE_LOCAL_STORE_POLICY.lifecycle.requireArtifactAllowlist).toBe(true);
  });

  test("filters policy by store id and derives sqlite sidecars", () => {
    expect(secureLocalStorePolicy(["todos"]).stores.map((store) => store.storeId)).toEqual(["todos"]);
    expect(sqliteSidecarPaths("/tmp/example.db")).toEqual(["/tmp/example.db-wal", "/tmp/example.db-shm"]);
  });

  test("dry-run plans owner-only mode repairs without mutating files", () => {
    const home = tempHome();
    try {
      const store = makeTodosStore(home);
      const plan = planSecureLocalStoreLifecycle({ home, stores: ["todos"] });
      expect(plan.mode).toBe("dry-run");
      expect(plan.summary.planned).toBeGreaterThanOrEqual(4);
      expect(plan.actions.some((action) => action.kind === "chmod_dir" && action.path === store.todosDir)).toBe(true);
      expect(plan.actions.some((action) => action.kind === "chmod_file" && action.path === store.db && action.expectedMode === "0600")).toBe(true);
      expect(modeToString(statSync(store.db).mode)).toBe("0644");
      expect(modeToString(statSync(store.todosDir).mode)).toBe("0755");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test("apply mode repairs permissions but does not delete retention artifacts unless explicitly allowed", async () => {
    const home = tempHome();
    try {
      const store = makeTodosStore(home);
      const plan = planSecureLocalStoreLifecycle({
        home,
        stores: ["todos"],
        apply: true,
        includeRetention: true,
        activeRecordProofs: ["todos-exports-backups"]
      });
      const applied = await applySecureLocalStorePlan(plan);
      expect(applied.summary.applied).toBeGreaterThanOrEqual(4);
      expect(applied.actions.some((action) => action.kind === "retention_delete" && action.status === "skipped")).toBe(true);
      expect(existsSync(store.backup)).toBe(true);
      expect(modeToString(statSync(store.db).mode)).toBe("0600");
      expect(modeToString(statSync(store.todosDir).mode)).toBe("0700");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test("retention candidates require adapter proof and skip active paths", () => {
    const home = tempHome();
    try {
      const store = makeTodosStore(home);
      const blocked = planSecureLocalStoreLifecycle({ home, stores: ["todos"], includeRetention: true });
      expect(blocked.actions.some((action) => action.kind === "blocked" && action.adapterId === "todos-exports-backups")).toBe(true);

      const active = planSecureLocalStoreLifecycle({
        home,
        stores: ["todos"],
        includeRetention: true,
        activePaths: [store.backup]
      });
      expect(active.actions.some((action) => action.kind === "retention_delete" && action.status === "skipped" && action.path === store.backup)).toBe(true);

      const planned = planSecureLocalStoreLifecycle({
        home,
        stores: ["todos"],
        includeRetention: true,
        activeRecordProofs: ["todos-exports-backups"]
      });
      expect(planned.actions.some((action) => action.kind === "retention_delete" && action.status === "planned" && action.path === store.backup)).toBe(true);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test("lifecycle artifact classes are owner-only even without explicit sensitive globs", () => {
    const home = tempHome();
    try {
      const logsDir = join(home, ".hasna", "logs");
      mkdirSync(logsDir, { recursive: true });
      const logFile = join(logsDir, "foo.log");
      writeFileSync(logFile, "log fixture\n");
      chmodSync(logFile, 0o644);
      const plan = planSecureLocalStoreLifecycle({ home, stores: ["logs"] });
      expect(plan.actions.some((action) => action.kind === "chmod_file" && action.path === logFile && action.expectedMode === "0600")).toBe(true);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test("sqlite maintenance requires explicit exclusive access", () => {
    const home = tempHome();
    try {
      const store = makeTodosStore(home);
      const blocked = planSecureLocalStoreLifecycle({ home, stores: ["todos"], includeSqliteMaintenance: true });
      expect(blocked.actions.some((action) => action.kind === "blocked" && action.path === store.db && action.reason.includes("exclusive"))).toBe(true);

      const planned = planSecureLocalStoreLifecycle({
        home,
        stores: ["todos"],
        includeSqliteMaintenance: true,
        assumeExclusiveSqlite: true
      });
      expect(planned.actions.some((action) => action.kind === "sqlite_maintenance" && action.path === store.db)).toBe(true);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test("symlinks inside stores are blocked and never chmod their targets", async () => {
    const home = tempHome();
    try {
      const todosDir = join(home, ".hasna", "todos");
      const outsideDir = join(home, "outside");
      mkdirSync(todosDir, { recursive: true });
      mkdirSync(outsideDir, { recursive: true });
      const target = join(outsideDir, "target.db");
      const link = join(todosDir, "todos.db");
      writeFileSync(target, "outside target fixture\n");
      chmodSync(target, 0o644);
      symlinkSync(target, link);

      const plan = planSecureLocalStoreLifecycle({ home, stores: ["todos"], apply: true });
      expect(plan.actions.some((action) => action.kind === "blocked" && action.path === link && action.reason.includes("symlink"))).toBe(true);
      const applied = await applySecureLocalStorePlan(plan);
      expect(applied.actions.some((action) => action.kind === "blocked" && action.path === link)).toBe(true);
      expect(modeToString(statSync(target).mode)).toBe("0644");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
