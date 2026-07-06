import {
  chmodSync,
  existsSync,
  lstatSync,
  readdirSync,
  rmSync,
  type Stats
} from "node:fs";
import { homedir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";
import {
  SCHEMA_IDS,
  SecureLocalStorePolicySchema,
  type SecureLocalStoreArtifactClass,
  type SecureLocalStoreDefinition,
  type SecureLocalStorePolicy,
  type SecureLocalStoreRetentionAdapter,
  type SecureLocalStoreSqliteMaintenance
} from "./schemas";

export const SECURE_LOCAL_STORE_POLICY_VERSION = "2026-07-06";
export const OWNER_ONLY_DIR_MODE = 0o700;
export const OWNER_ONLY_FILE_MODE = 0o600;

export type SecureLocalStorePlanMode = "dry-run" | "apply";
export type SecureLocalStoreActionKind =
  | "chmod_dir"
  | "chmod_file"
  | "retention_delete"
  | "sqlite_maintenance"
  | "blocked";
export type SecureLocalStoreActionStatus = "planned" | "applied" | "skipped" | "blocked" | "failed";

export interface SecureLocalStoreAction {
  kind: SecureLocalStoreActionKind;
  status: SecureLocalStoreActionStatus;
  storeId: string;
  packageName: string;
  path: string;
  artifactClass: SecureLocalStoreArtifactClass | "sqlite_maintenance";
  reason: string;
  expectedMode?: string;
  currentMode?: string;
  adapterId?: string;
  ageDays?: number;
  operations?: string[];
  error?: string;
}

export interface SecureLocalStorePlan {
  ok: boolean;
  mode: SecureLocalStorePlanMode;
  home: string;
  policy: SecureLocalStorePolicy;
  actions: SecureLocalStoreAction[];
  summary: {
    stores: number;
    scannedEntries: number;
    planned: number;
    blocked: number;
    skipped: number;
    applied: number;
    failed: number;
  };
  warnings: string[];
}

export interface PlanSecureLocalStoreOptions {
  home?: string;
  policy?: SecureLocalStorePolicy;
  stores?: string[];
  apply?: boolean;
  includeRetention?: boolean;
  includeSqliteMaintenance?: boolean;
  activePaths?: string[];
  activeRecordProofs?: string[];
  assumeExclusiveSqlite?: boolean;
  now?: Date;
  maxEntries?: number;
}

export interface ApplySecureLocalStoreOptions {
  applyRetention?: boolean;
  applySqliteMaintenance?: boolean;
}

interface ScannedEntry {
  path: string;
  relFromStore: string;
  stats: Stats;
  artifactClass: SecureLocalStoreArtifactClass;
}

type ActiveRecordExclusionInput = Omit<SecureLocalStoreRetentionAdapter["activeRecordExclusions"][number], "required"> & {
  required?: boolean;
};

function retentionAdapter(
  id: string,
  description: string,
  ttlDays: number,
  artifactClasses: SecureLocalStoreArtifactClass[],
  allowlistGlobs: string[],
  activeRecordExclusions: ActiveRecordExclusionInput[] = [],
  sqliteMaintenance?: SecureLocalStoreSqliteMaintenance
): SecureLocalStoreRetentionAdapter {
  return {
    id,
    description,
    ttlDays,
    artifactClasses,
    allowlistGlobs,
    activeRecordExclusions: activeRecordExclusions.map((exclusion) => ({ ...exclusion, required: exclusion.required ?? true })),
    sqliteMaintenance
  };
}

export const DEFAULT_SECURE_LOCAL_STORE_POLICY: SecureLocalStorePolicy = SecureLocalStorePolicySchema.parse({
  schema: SCHEMA_IDS.secureLocalStorePolicy,
  id: "hasna-secure-local-store-defaults",
  createdAt: "2026-07-06T00:00:00.000Z",
  version: SECURE_LOCAL_STORE_POLICY_VERSION,
  scope: [".hasna", ".codewith"],
  defaults: {
    directoryMode: "0700",
    fileMode: "0600",
    dryRunDefault: true,
    requireExplicitApply: true,
    includeSqliteSidecars: true,
    redactedEvidenceOnly: true
  },
  lifecycle: {
    retentionDryRunDefault: true,
    requireActiveRecordExclusionProof: true,
    requireArtifactAllowlist: true,
    sqliteMaintenanceRequiresExclusiveAccess: true
  },
  stores: [
    {
      storeId: "codewith",
      packageName: "codewith",
      displayName: "Codewith native state",
      root: ".codewith",
      relativePath: ".",
      sqliteDatabaseGlobs: ["logs_*.sqlite", "state_*.sqlite", "goals_*.sqlite"],
      sensitiveFileGlobs: ["sessions/**/*.jsonl", "shell_snapshots/**/*", "logs*.sqlite", "state*.sqlite", "goals*.sqlite"],
      backupGlobs: ["backups/**/*"],
      exportGlobs: ["exports/**/*"],
      retentionAdapters: [
        retentionAdapter(
          "codewith-session-snapshots",
          "Codewith sessions, shell snapshots, logs, monitor output, mailbox payloads, and scheduler state need package-owned redaction before retention applies.",
          30,
          ["session", "snapshot", "log"],
          ["sessions/**/*.jsonl", "shell_snapshots/**/*", "logs/**/*"],
          [
            {
              id: "codewith-active-session",
              source: "package_adapter",
              description: "Exclude currently active sessions, leased schedules, monitors, pending interactions, and active goal rows."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ],
      notes: ["Includes native .codewith DBs and transcript-like artifacts; redaction-before-persistence remains package-owned."]
    },
    {
      storeId: "todos",
      packageName: "@hasna/todos",
      displayName: "Todos",
      root: ".hasna",
      relativePath: "todos",
      sqliteDatabaseGlobs: ["todos.db"],
      sensitiveFileGlobs: ["todos.db", "todos.db-wal", "todos.db-shm", "exports/**/*", "backups/**/*"],
      backupGlobs: ["backups/**/*", "*.bak", "*.backup"],
      exportGlobs: ["exports/**/*", "*.jsonl", "*.csv"],
      retentionAdapters: [
        retentionAdapter(
          "todos-exports-backups",
          "Todos backups and exports are deleted only after package redaction and active task/evidence references are excluded.",
          14,
          ["backup", "export"],
          ["backups/**/*", "exports/**/*"],
          [
            {
              id: "todos-active-evidence",
              source: "sqlite",
              table: "task_files",
              column: "path",
              description: "Exclude files still referenced by active tasks, verification evidence, task comments, or handoff records."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ]
    },
    {
      storeId: "conversations",
      packageName: "@hasna/conversations",
      displayName: "Conversations",
      root: ".hasna",
      relativePath: "conversations",
      sqliteDatabaseGlobs: ["messages.db"],
      sensitiveFileGlobs: ["messages.db", "messages.db-wal", "messages.db-shm", "exports/**/*", "attachments/**/*"],
      backupGlobs: ["backups/**/*", "*.bak"],
      exportGlobs: ["exports/**/*", "*.json", "*.csv"],
      retentionAdapters: [
        retentionAdapter(
          "conversations-exports-attachments",
          "Conversation exports and attachments require message-id redaction and active attachment reference checks before deletion.",
          14,
          ["export", "backup"],
          ["exports/**/*", "backups/**/*", "attachments/**/*"],
          [
            {
              id: "conversations-active-attachments",
              source: "sqlite",
              table: "messages",
              column: "attachments",
              description: "Exclude attachments still referenced by retained messages or audited redaction records."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ]
    },
    {
      storeId: "mementos",
      packageName: "@hasna/mementos",
      displayName: "Mementos",
      root: ".hasna",
      relativePath: "mementos",
      sqliteDatabaseGlobs: ["mementos.db"],
      sensitiveFileGlobs: ["mementos.db", "mementos.db-wal", "mementos.db-shm", "exports/**/*", "backups/**/*"],
      backupGlobs: ["backups/**/*", "*.bak"],
      exportGlobs: ["exports/**/*"],
      retentionAdapters: [
        retentionAdapter(
          "mementos-audit-search-history",
          "Mementos retention must preserve active memory versions while compacting audit/search surfaces through package-owned adapters.",
          30,
          ["backup", "export", "log"],
          ["backups/**/*", "exports/**/*", "audit/**/*"],
          [
            {
              id: "mementos-active-memory-versions",
              source: "sqlite",
              table: "memory_versions",
              column: "memory_id",
              description: "Exclude current memory versions and audit entries required for provenance."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ]
    },
    {
      storeId: "knowledge",
      packageName: "@hasna/knowledge",
      displayName: "Knowledge",
      root: ".hasna",
      relativePath: "knowledge",
      sqliteDatabaseGlobs: ["knowledge.db"],
      sensitiveFileGlobs: ["knowledge.db", "knowledge.db-wal", "knowledge.db-shm", "db.json", "migration-exports/**/*", "*.bak"],
      backupGlobs: ["*.bak", "backups/**/*", "*.pre-cloud-*"],
      exportGlobs: ["migration-exports/**/*", "exports/**/*", "*.jsonl"],
      retentionAdapters: [
        retentionAdapter(
          "knowledge-migrations-exports",
          "Knowledge migration exports and pre-cloud backups require replacement, encryption, or redaction before retention deletion.",
          14,
          ["backup", "export"],
          ["migration-exports/**/*", "exports/**/*", "*.bak", "*.pre-cloud-*"],
          [
            {
              id: "knowledge-current-catalog",
              source: "manifest",
              description: "Exclude files referenced by the active catalog or migration ledger."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ]
    },
    {
      storeId: "projects",
      packageName: "@hasna/projects",
      displayName: "Projects",
      root: ".hasna",
      relativePath: "projects",
      sqliteDatabaseGlobs: ["projects.db", "data/*/project.db"],
      sensitiveFileGlobs: ["projects.db", "projects.db-wal", "projects.db-shm", "data/*/project.db", "data/*/project.db-wal", "data/*/project.db-shm", "reports/**/*"],
      backupGlobs: ["backups/**/*", "data/*/backups/**/*"],
      exportGlobs: ["reports/**/*", "exports/**/*"],
      retentionAdapters: [
        retentionAdapter(
          "projects-reports-workspaces",
          "Project reports, dashboards, workspaces, and per-project DBs need active workspace/location references before cleanup.",
          30,
          ["backup", "export", "report", "tmp"],
          ["backups/**/*", "reports/**/*", "workspaces/**/*", "data/*/backups/**/*"],
          [
            {
              id: "projects-active-workspaces",
              source: "sqlite",
              table: "workspaces",
              column: "primary_path",
              description: "Exclude active workspace paths, locations, linked reports, and project store artifacts."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ]
    },
    {
      storeId: "browser",
      packageName: "@hasna/browser",
      displayName: "Browser",
      root: ".hasna",
      relativePath: "browser",
      sqliteDatabaseGlobs: ["browser.db"],
      sensitiveFileGlobs: ["browser.db", "browser.db-wal", "browser.db-shm", "profiles/**/cookies.json", "states/**/*.json", "auth/**/*"],
      backupGlobs: ["backups/**/*"],
      exportGlobs: ["exports/**/*", "traces/**/*", "har/**/*"],
      retentionAdapters: [
        retentionAdapter(
          "browser-auth-traces",
          "Browser state, trace, HAR, and auth artifacts require session invalidation or redaction before deletion.",
          7,
          ["backup", "export", "session", "snapshot"],
          ["profiles/**/*", "states/**/*", "traces/**/*", "har/**/*", "exports/**/*"],
          [
            {
              id: "browser-active-profiles",
              source: "sqlite",
              table: "sessions",
              column: "profile_path",
              description: "Exclude profiles, cookies, and storage state used by active browser sessions."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ]
    },
    {
      storeId: "terminal",
      packageName: "@hasna/terminal",
      displayName: "Terminal",
      root: ".hasna",
      relativePath: "terminal",
      sqliteDatabaseGlobs: ["sessions.db"],
      sensitiveFileGlobs: ["sessions.db", "sessions.db-wal", "sessions.db-shm", "exports/**/*"],
      backupGlobs: ["backups/**/*"],
      exportGlobs: ["exports/**/*"],
      retentionAdapters: [
        retentionAdapter(
          "terminal-sessions",
          "Terminal sessions and interactions need active session exclusion plus command-output redaction before retention.",
          30,
          ["backup", "export", "session", "log"],
          ["backups/**/*", "exports/**/*", "sessions/**/*"],
          [
            {
              id: "terminal-active-sessions",
              source: "sqlite",
              table: "sessions",
              column: "id",
              description: "Exclude active terminal session records and any linked interaction artifacts."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ]
    },
    {
      storeId: "logs",
      packageName: "@hasna/logs",
      displayName: "Logs",
      root: ".hasna",
      relativePath: "logs",
      sqliteDatabaseGlobs: ["logs.db"],
      sensitiveFileGlobs: ["logs.db", "logs.db-wal", "logs.db-shm", "exports/**/*"],
      backupGlobs: ["backups/**/*"],
      exportGlobs: ["exports/**/*"],
      retentionAdapters: [
        retentionAdapter(
          "logs-retention",
          "Logs require redaction before compaction and must preserve active incident/evidence references.",
          14,
          ["backup", "export", "log"],
          ["backups/**/*", "exports/**/*", "*.log", "logs/**/*"],
          [
            {
              id: "logs-active-evidence",
              source: "sqlite",
              table: "logs",
              column: "id",
              description: "Exclude log rows or files linked to active incidents, tasks, or proof bundles."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ]
    },
    {
      storeId: "loops",
      packageName: "@hasna/loops",
      displayName: "OpenLoops",
      root: ".hasna",
      relativePath: "loops",
      sqliteDatabaseGlobs: ["loops.db", "state.db", "*.sqlite"],
      sensitiveFileGlobs: ["*.db", "*.sqlite", "*.db-wal", "*.db-shm", "reports/**/*", "tmp/**/*", "runs/**/*"],
      backupGlobs: ["backups/**/*", "tmp/**/*"],
      exportGlobs: ["reports/**/*", "runs/**/*", "exports/**/*"],
      retentionAdapters: [
        retentionAdapter(
          "loops-reports-tmp",
          "Loop reports, tmp files, workflow artifacts, and command output need run-state checks and redaction before retention deletion.",
          14,
          ["backup", "export", "report", "tmp", "log"],
          ["reports/**/*", "tmp/**/*", "runs/**/*", "exports/**/*"],
          [
            {
              id: "loops-active-runs",
              source: "sqlite",
              table: "loop_runs",
              column: "id",
              description: "Exclude active, leased, recently failed, or evidence-linked loop and workflow run artifacts."
            }
          ],
          { safeWhen: "exclusive_access", operations: ["wal_checkpoint_truncate", "optimize"] }
        )
      ]
    }
  ],
  warnings: [
    "This contract only handles owner-only storage and lifecycle planning; redaction-before-persistence remains package-owned.",
    "Retention deletion defaults to dry-run and must use package adapters to prove active-record exclusions.",
    "SQLite maintenance requires explicit exclusive access and must not run against active stores."
  ]
});

export function secureLocalStorePolicy(stores?: string[]): SecureLocalStorePolicy {
  if (!stores || stores.length === 0) {
    return DEFAULT_SECURE_LOCAL_STORE_POLICY;
  }
  const selected = new Set(stores);
  const known = new Set(DEFAULT_SECURE_LOCAL_STORE_POLICY.stores.map((store) => store.storeId));
  const unknown = stores.filter((store) => !known.has(store));
  if (unknown.length > 0) {
    throw new Error(`Unknown secure local store id: ${unknown.join(", ")}`);
  }
  return SecureLocalStorePolicySchema.parse({
    ...DEFAULT_SECURE_LOCAL_STORE_POLICY,
    stores: DEFAULT_SECURE_LOCAL_STORE_POLICY.stores.filter((store) => selected.has(store.storeId))
  });
}

export function sqliteSidecarPaths(databasePath: string): string[] {
  return [`${databasePath}-wal`, `${databasePath}-shm`];
}

export function modeToString(mode: number): string {
  return `0${(mode & 0o777).toString(8)}`;
}

function expectedModeForClass(artifactClass: SecureLocalStoreArtifactClass): number {
  return artifactClass === "directory" ? OWNER_ONLY_DIR_MODE : OWNER_ONLY_FILE_MODE;
}

function normalizeRelativePath(value: string): string {
  return value.split(sep).join("/");
}

function globToRegExp(glob: string): RegExp {
  const normalized = normalizeRelativePath(glob);
  let pattern = "";
  for (let index = 0; index < normalized.length; index += 1) {
    const char = normalized[index];
    const next = normalized[index + 1];
    if (char === "*" && next === "*") {
      pattern += ".*";
      index += 1;
    } else if (char === "*") {
      pattern += "[^/]*";
    } else if ("\\^$+?.()|{}[]".includes(char ?? "")) {
      pattern += `\\${char}`;
    } else {
      pattern += char;
    }
  }
  return new RegExp(`^${pattern}$`);
}

function matchesGlob(relPath: string, glob: string): boolean {
  const normalized = normalizeRelativePath(relPath);
  const normalizedGlob = normalizeRelativePath(glob);
  if (normalizedGlob.endsWith("/**/*")) {
    const prefix = normalizedGlob.slice(0, -"/**/*".length);
    return normalized.startsWith(`${prefix}/`) && normalized.length > prefix.length + 1;
  }
  if (normalizedGlob.endsWith("/**")) {
    const prefix = normalizedGlob.slice(0, -"/**".length);
    return normalized === prefix || normalized.startsWith(`${prefix}/`);
  }
  return globToRegExp(normalizedGlob).test(normalized);
}

function matchesAnyGlob(relPath: string, globs: readonly string[]): boolean {
  return globs.some((glob) => matchesGlob(relPath, glob));
}

function storeBase(home: string, store: SecureLocalStoreDefinition): string {
  return resolve(join(home, store.root, store.relativePath === "." ? "" : store.relativePath));
}

function classifyEntry(store: SecureLocalStoreDefinition, relPath: string, stats: Stats): SecureLocalStoreArtifactClass {
  const normalized = normalizeRelativePath(relPath);
  const name = basename(normalized);
  if (stats.isDirectory()) return "directory";
  if (matchesAnyGlob(normalized, store.backupGlobs)) return "backup";
  if (matchesAnyGlob(normalized, store.exportGlobs)) return "export";
  if (normalized.includes("/reports/") || normalized.startsWith("reports/")) return "report";
  if (normalized.includes("/tmp/") || normalized.startsWith("tmp/")) return "tmp";
  if (name.endsWith("-wal")) return "sqlite_wal";
  if (name.endsWith("-shm")) return "sqlite_shm";
  if (matchesAnyGlob(normalized, store.sqliteDatabaseGlobs) || name.endsWith(".db") || name.endsWith(".sqlite")) return "sqlite_db";
  if (normalized.includes("session") || normalized.includes("sessions/")) return "session";
  if (normalized.includes("snapshot") || normalized.includes("shell_snapshots/")) return "snapshot";
  if (name.endsWith(".log") || normalized.includes("/logs/") || normalized.startsWith("logs/")) return "log";
  return "file";
}

function isSensitiveStoreFile(store: SecureLocalStoreDefinition, entry: ScannedEntry): boolean {
  if (entry.stats.isDirectory()) return true;
  if (["sqlite_db", "sqlite_wal", "sqlite_shm", "backup", "export", "report", "tmp", "log", "session", "snapshot"].includes(entry.artifactClass)) return true;
  return matchesAnyGlob(entry.relFromStore, store.sensitiveFileGlobs);
}

function hasActiveRecordProof(storeId: string, adapterId: string, proofs: Set<string>): boolean {
  return proofs.has("all") || proofs.has(adapterId) || proofs.has(`${storeId}:${adapterId}`);
}

function scanStore(base: string, store: SecureLocalStoreDefinition, maxEntries: number): { entries: ScannedEntry[]; warnings: string[] } {
  const entries: ScannedEntry[] = [];
  const warnings: string[] = [];
  if (!existsSync(base)) {
    return { entries, warnings: [`store_missing:${store.storeId}`] };
  }

  const visit = (path: string) => {
    if (entries.length >= maxEntries) {
      warnings.push(`max_entries_reached:${store.storeId}:${maxEntries}`);
      return;
    }
    let stats: Stats;
    try {
      stats = lstatSync(path);
    } catch (error) {
      warnings.push(`stat_failed:${store.storeId}:${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    const relFromStore = normalizeRelativePath(relative(base, path)) || ".";
    entries.push({ path, relFromStore, stats, artifactClass: classifyEntry(store, relFromStore, stats) });
    if (stats.isSymbolicLink()) return;
    if (!stats.isDirectory()) return;
    let children: string[];
    try {
      children = readdirSync(path).sort();
    } catch (error) {
      warnings.push(`read_dir_failed:${store.storeId}:${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    for (const child of children) {
      visit(join(path, child));
      if (entries.length >= maxEntries) return;
    }
  };

  visit(base);
  return { entries, warnings };
}

function activePathMatches(path: string, activePaths: Set<string>): boolean {
  const resolved = resolve(path);
  return activePaths.has(resolved);
}

function isRetentionCandidate(entry: ScannedEntry, adapter: SecureLocalStoreRetentionAdapter, now: Date): boolean {
  if (entry.stats.isDirectory()) return false;
  if (!adapter.artifactClasses.includes(entry.artifactClass)) return false;
  if (!matchesAnyGlob(entry.relFromStore, adapter.allowlistGlobs)) return false;
  if (adapter.ttlDays === undefined) return true;
  const ageMs = now.getTime() - entry.stats.mtimeMs;
  return ageMs >= adapter.ttlDays * 24 * 60 * 60 * 1000;
}

function summarize(plan: Omit<SecureLocalStorePlan, "summary" | "ok">, scannedEntries: number): SecureLocalStorePlan["summary"] {
  return {
    stores: plan.policy.stores.length,
    scannedEntries,
    planned: plan.actions.filter((action) => action.status === "planned").length,
    blocked: plan.actions.filter((action) => action.status === "blocked").length,
    skipped: plan.actions.filter((action) => action.status === "skipped").length,
    applied: plan.actions.filter((action) => action.status === "applied").length,
    failed: plan.actions.filter((action) => action.status === "failed").length
  };
}

export function planSecureLocalStoreLifecycle(options: PlanSecureLocalStoreOptions = {}): SecureLocalStorePlan {
  const home = resolve(options.home ?? homedir());
  const sourcePolicy = options.policy ?? DEFAULT_SECURE_LOCAL_STORE_POLICY;
  const policy = options.stores && options.stores.length > 0
    ? SecureLocalStorePolicySchema.parse({
        ...sourcePolicy,
        stores: sourcePolicy.stores.filter((store) => options.stores?.includes(store.storeId))
      })
    : sourcePolicy;
  const now = options.now ?? new Date();
  const mode: SecureLocalStorePlanMode = options.apply ? "apply" : "dry-run";
  const activePaths = new Set((options.activePaths ?? []).map((path) => resolve(path)));
  const activeRecordProofs = new Set(options.activeRecordProofs ?? []);
  const actions: SecureLocalStoreAction[] = [];
  const warnings = [...policy.warnings];
  let scannedEntries = 0;
  const maxEntries = options.maxEntries ?? 25_000;

  for (const root of policy.scope) {
    const rootPath = join(home, root);
    if (!existsSync(rootPath)) continue;
    try {
      const stats = lstatSync(rootPath);
      if (stats.isSymbolicLink()) {
        actions.push({
          kind: "blocked",
          status: "blocked",
          storeId: `${root.slice(1)}-root`,
          packageName: "@hasna/contracts",
          path: rootPath,
          artifactClass: "directory",
          reason: "local store root is a symlink; refusing to follow or chmod target"
        });
        continue;
      }
      if (stats.isDirectory() && (stats.mode & 0o777) !== OWNER_ONLY_DIR_MODE) {
        actions.push({
          kind: "chmod_dir",
          status: "planned",
          storeId: `${root.slice(1)}-root`,
          packageName: "@hasna/contracts",
          path: rootPath,
          artifactClass: "directory",
          reason: "owner-only local store root mode",
          expectedMode: "0700",
          currentMode: modeToString(stats.mode)
        });
      }
    } catch (error) {
      warnings.push(`stat_failed:${root}:${error instanceof Error ? error.message : String(error)}`);
    }
  }

  for (const store of policy.stores) {
    const base = storeBase(home, store);
    const scan = scanStore(base, store, maxEntries);
    warnings.push(...scan.warnings);
    scannedEntries += scan.entries.length;

    for (const entry of scan.entries) {
      if (entry.stats.isSymbolicLink()) {
        actions.push({
          kind: "blocked",
          status: "blocked",
          storeId: store.storeId,
          packageName: store.packageName,
          path: entry.path,
          artifactClass: entry.artifactClass,
          reason: "local store symlink requires package-owned migration; refusing to follow or chmod target"
        });
        continue;
      }
      if (!isSensitiveStoreFile(store, entry)) continue;
      const expectedMode = expectedModeForClass(entry.artifactClass);
      const currentMode = entry.stats.mode & 0o777;
      if (currentMode !== expectedMode) {
        actions.push({
          kind: entry.stats.isDirectory() ? "chmod_dir" : "chmod_file",
          status: "planned",
          storeId: store.storeId,
          packageName: store.packageName,
          path: entry.path,
          artifactClass: entry.artifactClass,
          reason: "owner-only local store mode",
          expectedMode: modeToString(expectedMode),
          currentMode: modeToString(currentMode)
        });
      }
    }

    if (options.includeRetention) {
      for (const adapter of store.retentionAdapters) {
        for (const entry of scan.entries) {
          if (!isRetentionCandidate(entry, adapter, now)) continue;
          const ageDays = Math.max(0, Math.floor((now.getTime() - entry.stats.mtimeMs) / (24 * 60 * 60 * 1000)));
          if (activePathMatches(entry.path, activePaths)) {
            actions.push({
              kind: "retention_delete",
              status: "skipped",
              storeId: store.storeId,
              packageName: store.packageName,
              path: entry.path,
              artifactClass: entry.artifactClass,
              reason: "active-record exclusion matched active path",
              adapterId: adapter.id,
              ageDays
            });
            continue;
          }
          if (adapter.activeRecordExclusions.some((exclusion) => exclusion.required) && !hasActiveRecordProof(store.storeId, adapter.id, activeRecordProofs)) {
            actions.push({
              kind: "blocked",
              status: "blocked",
              storeId: store.storeId,
              packageName: store.packageName,
              path: entry.path,
              artifactClass: entry.artifactClass,
              reason: "retention requires package-owned active-record exclusion proof",
              adapterId: adapter.id,
              ageDays
            });
            continue;
          }
          actions.push({
            kind: "retention_delete",
            status: "planned",
            storeId: store.storeId,
            packageName: store.packageName,
            path: entry.path,
            artifactClass: entry.artifactClass,
            reason: "allowlisted artifact exceeded retention TTL",
            adapterId: adapter.id,
            ageDays
          });
        }
      }
    }

    if (options.includeSqliteMaintenance) {
      for (const entry of scan.entries.filter((candidate) => candidate.artifactClass === "sqlite_db")) {
        for (const adapter of store.retentionAdapters) {
          const maintenance = adapter.sqliteMaintenance;
          if (!maintenance || maintenance.safeWhen === "never" || maintenance.operations.length === 0) continue;
          const safe = maintenance.safeWhen === "exclusive_access" && options.assumeExclusiveSqlite;
          actions.push({
            kind: safe ? "sqlite_maintenance" : "blocked",
            status: safe ? "planned" : "blocked",
            storeId: store.storeId,
            packageName: store.packageName,
            path: entry.path,
            artifactClass: "sqlite_maintenance",
            reason: safe ? "SQLite maintenance allowed by explicit exclusive-access assertion" : "SQLite maintenance requires exclusive access",
            adapterId: adapter.id,
            operations: maintenance.operations
          });
        }
      }
    }
  }

  const partial = { mode, home, policy, actions, warnings };
  const summary = summarize(partial, scannedEntries);
  return { ...partial, ok: summary.blocked === 0 && summary.failed === 0, summary };
}

async function runSqliteMaintenance(path: string, operations: readonly string[]): Promise<void> {
  const { Database } = await import("bun:sqlite");
  const db = new Database(path);
  try {
    for (const operation of operations) {
      if (operation === "wal_checkpoint_truncate") db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
      if (operation === "incremental_vacuum") db.exec("PRAGMA incremental_vacuum");
      if (operation === "optimize") db.exec("PRAGMA optimize");
      if (operation === "vacuum") db.exec("VACUUM");
    }
  } finally {
    db.close();
  }
}

export async function applySecureLocalStorePlan(
  plan: SecureLocalStorePlan,
  options: ApplySecureLocalStoreOptions = {}
): Promise<SecureLocalStorePlan> {
  if (plan.mode !== "apply") {
    return plan;
  }

  const actions: SecureLocalStoreAction[] = [];
  for (const action of plan.actions) {
    if (action.status !== "planned") {
      actions.push(action);
      continue;
    }
    try {
      if (action.kind === "chmod_dir" || action.kind === "chmod_file") {
        const expected = action.expectedMode === "0700" ? OWNER_ONLY_DIR_MODE : OWNER_ONLY_FILE_MODE;
        chmodSync(action.path, expected);
        actions.push({ ...action, status: "applied" });
        continue;
      }
      if (action.kind === "retention_delete") {
        if (!options.applyRetention) {
          actions.push({ ...action, status: "skipped", reason: "retention deletion needs applyRetention=true" });
          continue;
        }
        rmSync(action.path, { force: true });
        actions.push({ ...action, status: "applied" });
        continue;
      }
      if (action.kind === "sqlite_maintenance") {
        if (!options.applySqliteMaintenance) {
          actions.push({ ...action, status: "skipped", reason: "SQLite maintenance needs applySqliteMaintenance=true" });
          continue;
        }
        await runSqliteMaintenance(action.path, action.operations ?? []);
        actions.push({ ...action, status: "applied" });
        continue;
      }
      actions.push(action);
    } catch (error) {
      actions.push({
        ...action,
        status: "failed",
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  const next = { ...plan, actions };
  const summary = summarize(next, plan.summary.scannedEntries);
  return { ...next, ok: summary.blocked === 0 && summary.failed === 0, summary };
}
