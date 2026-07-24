import {
  SCHEMA_IDS,
  SecureLocalStorePolicySchema,
  type SecureLocalStoreArtifactClass,
  type SecureLocalStorePolicy,
  type SecureLocalStoreRetentionAdapter,
  type SecureLocalStoreSqliteMaintenance
} from "./schemas";

export const SECURE_LOCAL_STORE_POLICY_VERSION = "2026-07-06";

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
    "This package publishes declarations only; each owning package implements and verifies its own local-store lifecycle.",
    "Retention and redaction evidence remain package-owned and must preserve active-record exclusions.",
    "SQLite maintenance is descriptive policy metadata only and is never executed by @hasna/contracts."
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
