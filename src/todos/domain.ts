import * as z from "zod/v4";
import {
  TodosContentRefSchema,
  TodosCursorSchema,
  TodosDateSchema,
  TodosEntityIdSchema,
  TodosOwnerIdSchema,
  TodosOwnerQualifiedRefSchema,
  TodosRelativePathSchema,
  TodosSha256DigestSchema,
  TodosSlugSchema,
  TodosTimestampSchema,
} from "./common";
import { TodosIdentityRoleSchema } from "./identity";

export const TODOS_DOMAIN_SCHEMA_IDS = {
  ownerQualifiedRef: "hasna.todos.owner_qualified_ref.v1",
  externalOwnerRef: "hasna.todos.external_owner_ref.v1",
  task: "hasna.todos.task.v1",
  project: "hasna.todos.project.v1",
  taskList: "hasna.todos.task_list.v1",
  plan: "hasna.todos.plan.v1",
  agent: "hasna.todos.agent.v1",
  comment: "hasna.todos.comment.v1",
  dependency: "hasna.todos.dependency.v1",
  activity: "hasna.todos.activity.v1",
  savedView: "hasna.todos.saved_view.v1",
  searchRequest: "hasna.todos.search_request.v1",
  verificationEvidence: "hasna.todos.verification_evidence.v1",
  taskFile: "hasna.todos.task_file.v1",
  run: "hasna.todos.run.v1",
  runEvent: "hasna.todos.run_event.v1",
  runCommand: "hasna.todos.run_command.v1",
  runFile: "hasna.todos.run_file.v1",
  runArtifact: "hasna.todos.run_artifact.v1",
  gitObjectId: "hasna.todos.git_object_id.v1",
  gitCommit: "hasna.todos.git_commit.v1",
  gitRef: "hasna.todos.git_ref.v1",
  traceability: "hasna.todos.traceability.v1",
  taskTemplate: "hasna.todos.task_template.v1",
  approval: "hasna.todos.approval.v1",
  deletionRecord: "hasna.todos.deletion_record.v1",
  taskContext: "hasna.todos.task_context.v1",
  stats: "hasna.todos.stats.v1",
} as const;

const EntityBaseShape = {
  id: TodosEntityIdSchema,
  owner: TodosOwnerIdSchema,
  version: z.number().int().positive(),
  createdAt: TodosTimestampSchema,
  updatedAt: TodosTimestampSchema,
} as const;

export const TodosExternalOwnerRefSchema = z.strictObject({
  owner: TodosOwnerIdSchema,
  id: TodosEntityIdSchema,
  digest: TodosSha256DigestSchema,
});
export type TodosExternalOwnerRef = z.infer<typeof TodosExternalOwnerRefSchema>;

export const TodosTaskStatusSchema = z.enum([
  "pending",
  "ready",
  "in_progress",
  "blocked",
  "completed",
  "failed",
  "cancelled",
]);
export type TodosTaskStatus = z.infer<typeof TodosTaskStatusSchema>;

export const TODOS_TERMINAL_TASK_STATUSES = Object.freeze([
  "completed",
  "failed",
  "cancelled",
] as const satisfies readonly TodosTaskStatus[]);

export const TODOS_TASK_STATUS_TRANSITIONS: Readonly<
  Record<TodosTaskStatus, readonly TodosTaskStatus[]>
> = Object.freeze({
  pending: ["ready", "in_progress", "blocked", "cancelled"],
  ready: ["in_progress", "blocked", "cancelled"],
  in_progress: ["blocked", "completed", "failed", "cancelled"],
  blocked: ["pending", "ready", "in_progress", "failed", "cancelled"],
  completed: [],
  failed: [],
  cancelled: [],
} as const satisfies Record<TodosTaskStatus, readonly TodosTaskStatus[]>);

export type TodosTaskStatusTransitionValidation =
  | {
    success: true;
    replayed: boolean;
    terminal: boolean;
  }
  | {
    success: false;
    reason: "invalid_status" | "terminal_status" | "transition_not_allowed";
    allowedTargets: readonly TodosTaskStatus[];
  };

export function isTodosTerminalTaskStatus(status: TodosTaskStatus): boolean {
  return TODOS_TERMINAL_TASK_STATUSES.includes(
    status as (typeof TODOS_TERMINAL_TASK_STATUSES)[number],
  );
}

/**
 * Portable task lifecycle validation only. It intentionally does not encode
 * worker assignment, queue selection, leases, retries, or other platform policy.
 */
// @todos-runtime-validator domain.task_status_transition
export function validateTodosTaskStatusTransition(
  currentInput: unknown,
  targetInput: unknown,
): TodosTaskStatusTransitionValidation {
  const current = TodosTaskStatusSchema.safeParse(currentInput);
  const target = TodosTaskStatusSchema.safeParse(targetInput);
  if (!current.success || !target.success) {
    return {
      success: false,
      reason: "invalid_status",
      allowedTargets: [],
    };
  }
  if (current.data === target.data) {
    return {
      success: true,
      replayed: true,
      terminal: isTodosTerminalTaskStatus(current.data),
    };
  }
  const allowedTargets = TODOS_TASK_STATUS_TRANSITIONS[current.data];
  if (isTodosTerminalTaskStatus(current.data)) {
    return {
      success: false,
      reason: "terminal_status",
      allowedTargets,
    };
  }
  if (!allowedTargets.includes(target.data)) {
    return {
      success: false,
      reason: "transition_not_allowed",
      allowedTargets,
    };
  }
  return {
    success: true,
    replayed: false,
    terminal: isTodosTerminalTaskStatus(target.data),
  };
}

export const TodosTaskPrioritySchema = z.enum(["low", "medium", "high", "critical"]);

// @todos-runtime-validator domain.task_record_semantics
export const TodosTaskSchema = z.strictObject({
  ...EntityBaseShape,
  shortId: z.string().min(1).max(40).nullable(),
  title: z.string().min(1).max(512),
  description: z.string().max(100_000).nullable(),
  status: TodosTaskStatusSchema,
  priority: TodosTaskPrioritySchema,
  projectId: TodosEntityIdSchema.nullable(),
  taskListId: TodosEntityIdSchema.nullable(),
  planId: TodosEntityIdSchema.nullable(),
  parentTaskId: TodosEntityIdSchema.nullable(),
  assignedAgentId: TodosEntityIdSchema.nullable(),
  fingerprint: z.string().min(1).max(256).nullable(),
  tags: z.array(z.string().min(1).max(96)).max(128),
  acceptanceCriteria: z.array(z.string().min(1).max(4096)).max(256),
  dueAt: TodosTimestampSchema.nullable(),
  completedAt: TodosTimestampSchema.nullable(),
  externalOwnerRefs: z.array(TodosExternalOwnerRefSchema).max(64),
}).superRefine((value, ctx) => {
  if (new Set(value.tags).size !== value.tags.length) {
    ctx.addIssue({ code: "custom", message: "Task tags must be unique", path: ["tags"] });
  }
  if (value.status === "completed" && value.completedAt === null) {
    ctx.addIssue({
      code: "custom",
      message: "Completed tasks require completedAt",
      path: ["completedAt"],
    });
  }
});
export type TodosTask = z.infer<typeof TodosTaskSchema>;

export const TodosProjectSchema = z.strictObject({
  ...EntityBaseShape,
  slug: TodosSlugSchema,
  name: z.string().min(1).max(256),
  description: z.string().max(20_000).nullable(),
  repositoryRef: TodosExternalOwnerRefSchema.nullable(),
  archivedAt: TodosTimestampSchema.nullable(),
});
export type TodosProject = z.infer<typeof TodosProjectSchema>;

export const TodosTaskListSchema = z.strictObject({
  ...EntityBaseShape,
  projectId: TodosEntityIdSchema.nullable(),
  slug: TodosSlugSchema,
  name: z.string().min(1).max(256),
  description: z.string().max(20_000).nullable(),
  archivedAt: TodosTimestampSchema.nullable(),
});
export type TodosTaskList = z.infer<typeof TodosTaskListSchema>;

export const TodosPlanStatusSchema = z.enum(["draft", "active", "completed", "archived"]);
export const TodosPlanSchema = z.strictObject({
  ...EntityBaseShape,
  slug: TodosSlugSchema,
  projectId: TodosEntityIdSchema.nullable(),
  taskListId: TodosEntityIdSchema.nullable(),
  name: z.string().min(1).max(256),
  description: z.string().max(40_000).nullable(),
  status: TodosPlanStatusSchema,
  objective: z.string().min(1).max(20_000),
  taskIds: z.array(TodosEntityIdSchema).max(10_000),
  completedAt: TodosTimestampSchema.nullable(),
});
export type TodosPlan = z.infer<typeof TodosPlanSchema>;

export const TodosAgentStatusSchema = z.enum(["active", "inactive", "released"]);
// @todos-runtime-validator domain.agent_role_uniqueness
export const TodosAgentSchema = z.strictObject({
  ...EntityBaseShape,
  displayName: z.string().min(1).max(256),
  status: TodosAgentStatusSchema,
  roles: z.array(TodosIdentityRoleSchema).min(1).max(32),
  activeProjectId: TodosEntityIdSchema.nullable(),
  activeTaskListId: TodosEntityIdSchema.nullable(),
  lastHeartbeatAt: TodosTimestampSchema.nullable(),
  releasedAt: TodosTimestampSchema.nullable(),
}).superRefine((value, ctx) => {
  if (new Set(value.roles).size !== value.roles.length) {
    ctx.addIssue({ code: "custom", message: "Agent roles must be unique", path: ["roles"] });
  }
});
export type TodosAgent = z.infer<typeof TodosAgentSchema>;

export const TodosCommentKindSchema = z.enum(["comment", "progress", "note"]);
export const TodosCommentSchema = z.strictObject({
  ...EntityBaseShape,
  taskId: TodosEntityIdSchema,
  authorRef: TodosExternalOwnerRefSchema,
  kind: TodosCommentKindSchema,
  content: z.string().min(1).max(100_000),
  progressPercent: z.number().min(0).max(100).nullable(),
});
export type TodosComment = z.infer<typeof TodosCommentSchema>;

export const TodosDependencyKindSchema = z.enum(["requires", "blocks"]);
// @todos-runtime-validator domain.dependency_self_reference
export const TodosDependencySchema = z.strictObject({
  ...EntityBaseShape,
  sourceTaskId: TodosEntityIdSchema,
  targetTaskId: TodosEntityIdSchema,
  kind: TodosDependencyKindSchema,
}).superRefine((value, ctx) => {
  if (value.sourceTaskId === value.targetTaskId) {
    ctx.addIssue({
      code: "custom",
      message: "A task cannot depend on itself",
      path: ["targetTaskId"],
    });
  }
});
export type TodosDependency = z.infer<typeof TodosDependencySchema>;

export const TodosActivitySchema = z.strictObject({
  ...EntityBaseShape,
  actorRef: TodosExternalOwnerRefSchema,
  resourceRef: TodosOwnerQualifiedRefSchema,
  action: z.string().min(1).max(160).regex(/^[a-z][a-z0-9_.:-]*$/),
  summary: z.string().min(1).max(4096),
  occurredAt: TodosTimestampSchema,
});
export type TodosActivity = z.infer<typeof TodosActivitySchema>;

export const TodosSearchFilterSchema = z.strictObject({
  projectIds: z.array(TodosEntityIdSchema).max(256),
  taskListIds: z.array(TodosEntityIdSchema).max(256),
  planIds: z.array(TodosEntityIdSchema).max(256),
  agentIds: z.array(TodosEntityIdSchema).max(256),
  statuses: z.array(TodosTaskStatusSchema).max(16),
  priorities: z.array(TodosTaskPrioritySchema).max(8),
  tags: z.array(z.string().min(1).max(96)).max(128),
  changedAfter: TodosTimestampSchema.nullable(),
  dueBefore: TodosTimestampSchema.nullable(),
});
export type TodosSearchFilter = z.infer<typeof TodosSearchFilterSchema>;

export const TodosSearchRequestSchema = z.strictObject({
  query: z.string().min(1).max(4096),
  filters: TodosSearchFilterSchema,
  cursor: TodosCursorSchema.nullable(),
  limit: z.number().int().positive().max(500),
});
export type TodosSearchRequest = z.infer<typeof TodosSearchRequestSchema>;

export const TodosSavedViewSchema = z.strictObject({
  ...EntityBaseShape,
  name: z.string().min(1).max(256),
  description: z.string().max(4096).nullable(),
  query: TodosSearchRequestSchema,
  audience: z.enum(["private", "organization"]),
});
export type TodosSavedView = z.infer<typeof TodosSavedViewSchema>;

export const TodosVerificationCommandSchema = z.strictObject({
  command: z.string().min(1).max(16_000),
  exitCode: z.number().int(),
  durationMs: z.number().int().nonnegative(),
});

export const TodosVerificationCheckSchema = z.strictObject({
  name: z.string().min(1).max(512),
  status: z.enum(["passed", "failed", "skipped"]),
  summary: z.string().max(4096).nullable(),
  durationMs: z.number().int().nonnegative().nullable(),
});

export const TodosVerificationEvidenceSchema = z.strictObject({
  ...EntityBaseShape,
  taskId: TodosEntityIdSchema.nullable(),
  runId: TodosEntityIdSchema.nullable(),
  verifierRef: TodosExternalOwnerRefSchema,
  status: z.enum(["passed", "failed", "inconclusive"]),
  summary: z.string().min(1).max(20_000),
  confidence: z.number().min(0).max(1).nullable(),
  commands: z.array(TodosVerificationCommandSchema).max(256),
  checks: z.array(TodosVerificationCheckSchema).max(10_000),
  contentRefs: z.array(TodosContentRefSchema).max(10_000),
  startedAt: TodosTimestampSchema,
  completedAt: TodosTimestampSchema.nullable(),
});
export type TodosVerificationEvidence = z.infer<typeof TodosVerificationEvidenceSchema>;

export const TodosTaskFileSchema = z.strictObject({
  ...EntityBaseShape,
  taskId: TodosEntityIdSchema,
  logicalName: z.string().min(1).max(512),
  relativePath: TodosRelativePathSchema.nullable(),
  contentRef: TodosContentRefSchema,
  purpose: z.enum(["attachment", "evidence", "deliverable"]),
});
export type TodosTaskFile = z.infer<typeof TodosTaskFileSchema>;

export const TodosRunStatusSchema = z.enum(["queued", "running", "succeeded", "failed", "cancelled"]);
export const TodosRunSchema = z.strictObject({
  ...EntityBaseShape,
  objective: z.string().min(1).max(20_000),
  status: TodosRunStatusSchema,
  taskIds: z.array(TodosEntityIdSchema).max(10_000),
  planId: TodosEntityIdSchema.nullable(),
  agentId: TodosEntityIdSchema.nullable(),
  startedAt: TodosTimestampSchema.nullable(),
  completedAt: TodosTimestampSchema.nullable(),
  ledgerDigest: TodosSha256DigestSchema,
});
export type TodosRun = z.infer<typeof TodosRunSchema>;

export const TodosRunEventSchema = z.strictObject({
  ...EntityBaseShape,
  runId: TodosEntityIdSchema,
  sequence: z.number().int().nonnegative(),
  type: z.string().min(1).max(160).regex(/^[a-z][a-z0-9_.:-]*$/),
  summary: z.string().min(1).max(20_000),
  occurredAt: TodosTimestampSchema,
  evidenceIds: z.array(TodosEntityIdSchema).max(10_000),
});
export type TodosRunEvent = z.infer<typeof TodosRunEventSchema>;

export const TodosRunCommandSchema = z.strictObject({
  ...EntityBaseShape,
  runId: TodosEntityIdSchema,
  sequence: z.number().int().nonnegative(),
  command: z.string().min(1).max(16_000),
  exitCode: z.number().int().nullable(),
  durationMs: z.number().int().nonnegative().nullable(),
  outputRefs: z.array(TodosContentRefSchema).max(1024),
  completedAt: TodosTimestampSchema.nullable(),
});
export type TodosRunCommand = z.infer<typeof TodosRunCommandSchema>;

export const TodosRunFileSchema = z.strictObject({
  ...EntityBaseShape,
  runId: TodosEntityIdSchema,
  logicalName: z.string().min(1).max(512),
  relativePath: TodosRelativePathSchema.nullable(),
  contentRef: TodosContentRefSchema,
  role: z.enum(["input", "output", "evidence"]),
});
export type TodosRunFile = z.infer<typeof TodosRunFileSchema>;

export const TodosRunArtifactSchema = z.strictObject({
  ...EntityBaseShape,
  runId: TodosEntityIdSchema,
  name: z.string().min(1).max(512),
  kind: z.string().min(1).max(160).regex(/^[a-z][a-z0-9_.:-]*$/),
  contentRef: TodosContentRefSchema,
  verified: z.boolean(),
  verificationEvidenceId: TodosEntityIdSchema.nullable(),
});
export type TodosRunArtifact = z.infer<typeof TodosRunArtifactSchema>;

// @todos-runtime-validator domain.git_object_id
export const TodosGitObjectIdSchema = z.strictObject({
  algorithm: z.enum(["sha1", "sha256"]),
  value: z.string().regex(/^[a-f0-9]+$/),
}).superRefine((value, ctx) => {
  const expectedLength = value.algorithm === "sha1" ? 40 : 64;
  if (value.value.length !== expectedLength) {
    ctx.addIssue({
      code: "custom",
      message: `Git object id must contain ${expectedLength} hexadecimal characters`,
      path: ["value"],
    });
  }
});
export type TodosGitObjectId = z.infer<typeof TodosGitObjectIdSchema>;

export const TodosGitCommitSchema = z.strictObject({
  ...EntityBaseShape,
  repositoryRef: TodosExternalOwnerRefSchema,
  objectId: TodosGitObjectIdSchema,
  message: z.string().min(1).max(20_000),
  authorRef: TodosExternalOwnerRefSchema,
  committedAt: TodosTimestampSchema,
  changedFiles: z.array(TodosRelativePathSchema).max(50_000),
});
export type TodosGitCommit = z.infer<typeof TodosGitCommitSchema>;

export const TodosGitRefSchema = z.strictObject({
  ...EntityBaseShape,
  repositoryRef: TodosExternalOwnerRefSchema,
  type: z.enum(["branch", "tag", "pull_request"]),
  name: z.string().min(1).max(512),
  target: TodosGitObjectIdSchema,
  published: z.boolean(),
  providerObservedAt: TodosTimestampSchema.nullable(),
});
export type TodosGitRef = z.infer<typeof TodosGitRefSchema>;

export const TodosTraceabilitySchema = z.strictObject({
  ...EntityBaseShape,
  taskId: TodosEntityIdSchema,
  commitIds: z.array(TodosEntityIdSchema).max(10_000),
  gitRefIds: z.array(TodosEntityIdSchema).max(10_000),
  verificationEvidenceIds: z.array(TodosEntityIdSchema).max(10_000),
  projectionIds: z.array(TodosEntityIdSchema).max(10_000),
});
export type TodosTraceability = z.infer<typeof TodosTraceabilitySchema>;

export const TodosTaskTemplateSchema = z.strictObject({
  ...EntityBaseShape,
  name: z.string().min(1).max(256),
  description: z.string().max(4096).nullable(),
  titlePattern: z.string().min(1).max(512),
  descriptionPattern: z.string().max(20_000).nullable(),
  priority: TodosTaskPrioritySchema,
  tags: z.array(z.string().min(1).max(96)).max(128),
  acceptanceCriteria: z.array(z.string().min(1).max(4096)).max(256),
});
export type TodosTaskTemplate = z.infer<typeof TodosTaskTemplateSchema>;

export const TodosApprovalSchema = z.strictObject({
  ...EntityBaseShape,
  resourceRef: TodosOwnerQualifiedRefSchema,
  status: z.enum(["pending", "approved", "rejected", "expired"]),
  reason: z.string().min(1).max(4096),
  requestedBy: TodosExternalOwnerRefSchema,
  decidedBy: TodosExternalOwnerRefSchema.nullable(),
  requestedAt: TodosTimestampSchema,
  decidedAt: TodosTimestampSchema.nullable(),
  expiresAt: TodosTimestampSchema.nullable(),
});
export type TodosApproval = z.infer<typeof TodosApprovalSchema>;

export const TodosDeletionRecordSchema = z.strictObject({
  id: TodosEntityIdSchema,
  owner: TodosOwnerIdSchema,
  entityKind: z.string().min(1).max(64).regex(/^[a-z][a-z0-9_]*$/),
  entityIdDigest: TodosSha256DigestSchema,
  priorRecordDigest: TodosSha256DigestSchema,
  tombstoneVersion: z.number().int().positive(),
  redaction: z.literal("full"),
  reasonCode: z.string().min(1).max(128).regex(/^[a-z][a-z0-9_]*$/),
  deletedAt: TodosTimestampSchema,
});
export type TodosDeletionRecord = z.infer<typeof TodosDeletionRecordSchema>;

export const TodosTaskContextSchema = z.strictObject({
  task: TodosTaskSchema,
  project: TodosProjectSchema.nullable(),
  taskList: TodosTaskListSchema.nullable(),
  plan: TodosPlanSchema.nullable(),
  comments: z.array(TodosCommentSchema),
  dependencies: z.array(TodosDependencySchema),
  verificationEvidence: z.array(TodosVerificationEvidenceSchema),
  files: z.array(TodosTaskFileSchema),
  traceability: TodosTraceabilitySchema.nullable(),
});
export type TodosTaskContext = z.infer<typeof TodosTaskContextSchema>;

export const TodosStatsSchema = z.strictObject({
  asOfDate: TodosDateSchema,
  tasks: z.strictObject({
    total: z.number().int().nonnegative(),
    pending: z.number().int().nonnegative(),
    ready: z.number().int().nonnegative(),
    inProgress: z.number().int().nonnegative(),
    blocked: z.number().int().nonnegative(),
    completed: z.number().int().nonnegative(),
    failed: z.number().int().nonnegative(),
    cancelled: z.number().int().nonnegative(),
  }),
  projects: z.number().int().nonnegative(),
  plans: z.number().int().nonnegative(),
  activeAgents: z.number().int().nonnegative(),
  activeRuns: z.number().int().nonnegative(),
});
export type TodosStats = z.infer<typeof TodosStatsSchema>;

export const TODOS_DOMAIN_SCHEMAS = Object.freeze({
  [TODOS_DOMAIN_SCHEMA_IDS.ownerQualifiedRef]: TodosOwnerQualifiedRefSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.externalOwnerRef]: TodosExternalOwnerRefSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.task]: TodosTaskSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.project]: TodosProjectSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.taskList]: TodosTaskListSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.plan]: TodosPlanSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.agent]: TodosAgentSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.comment]: TodosCommentSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.dependency]: TodosDependencySchema,
  [TODOS_DOMAIN_SCHEMA_IDS.activity]: TodosActivitySchema,
  [TODOS_DOMAIN_SCHEMA_IDS.savedView]: TodosSavedViewSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.searchRequest]: TodosSearchRequestSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.verificationEvidence]: TodosVerificationEvidenceSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.taskFile]: TodosTaskFileSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.run]: TodosRunSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.runEvent]: TodosRunEventSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.runCommand]: TodosRunCommandSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.runFile]: TodosRunFileSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.runArtifact]: TodosRunArtifactSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.gitObjectId]: TodosGitObjectIdSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.gitCommit]: TodosGitCommitSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.gitRef]: TodosGitRefSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.traceability]: TodosTraceabilitySchema,
  [TODOS_DOMAIN_SCHEMA_IDS.taskTemplate]: TodosTaskTemplateSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.approval]: TodosApprovalSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.deletionRecord]: TodosDeletionRecordSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.taskContext]: TodosTaskContextSchema,
  [TODOS_DOMAIN_SCHEMA_IDS.stats]: TodosStatsSchema,
});

export type TodosTransferFieldClass = "portable" | "reference_only" | "excluded";

function classifyFields(
  portable: readonly string[],
  referenceOnly: readonly string[] = [],
  excluded: readonly string[] = [],
): Record<string, TodosTransferFieldClass> {
  return Object.freeze({
    ...Object.fromEntries(portable.map((field) => [field, "portable"] as const)),
    ...Object.fromEntries(referenceOnly.map((field) => [field, "reference_only"] as const)),
    ...Object.fromEntries(excluded.map((field) => [field, "excluded"] as const)),
  });
}

const BASE_FIELDS = ["id", "owner", "version", "createdAt", "updatedAt"] as const;

export const TODOS_DOMAIN_FIELD_CLASSIFICATION = Object.freeze({
  [TODOS_DOMAIN_SCHEMA_IDS.ownerQualifiedRef]: classifyFields(["owner", "kind", "id", "digest"]),
  [TODOS_DOMAIN_SCHEMA_IDS.externalOwnerRef]: classifyFields([], ["owner", "id", "digest"]),
  [TODOS_DOMAIN_SCHEMA_IDS.task]: classifyFields(
    [
      ...BASE_FIELDS,
      "shortId",
      "title",
      "description",
      "status",
      "priority",
      "projectId",
      "taskListId",
      "planId",
      "parentTaskId",
      "fingerprint",
      "tags",
      "acceptanceCriteria",
      "dueAt",
      "completedAt",
    ],
    ["assignedAgentId", "externalOwnerRefs"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.project]: classifyFields(
    [...BASE_FIELDS, "slug", "name", "description", "archivedAt"],
    ["repositoryRef"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.taskList]: classifyFields([
    ...BASE_FIELDS,
    "projectId",
    "slug",
    "name",
    "description",
    "archivedAt",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.plan]: classifyFields([
    ...BASE_FIELDS,
    "slug",
    "projectId",
    "taskListId",
    "name",
    "description",
    "status",
    "objective",
    "taskIds",
    "completedAt",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.agent]: classifyFields(
    [],
    ["id", "owner"],
    ["version", "createdAt", "updatedAt", "displayName", "status", "roles", "activeProjectId", "activeTaskListId", "lastHeartbeatAt", "releasedAt"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.comment]: classifyFields(
    [...BASE_FIELDS, "taskId", "kind", "content", "progressPercent"],
    ["authorRef"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.dependency]: classifyFields([
    ...BASE_FIELDS,
    "sourceTaskId",
    "targetTaskId",
    "kind",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.activity]: classifyFields(
    [...BASE_FIELDS, "resourceRef", "action", "summary", "occurredAt"],
    ["actorRef"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.savedView]: classifyFields([
    ...BASE_FIELDS,
    "name",
    "description",
    "query",
    "audience",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.searchRequest]: classifyFields(["query", "filters", "cursor", "limit"]),
  [TODOS_DOMAIN_SCHEMA_IDS.verificationEvidence]: classifyFields(
    [
      ...BASE_FIELDS,
      "taskId",
      "runId",
      "status",
      "summary",
      "confidence",
      "checks",
      "contentRefs",
      "startedAt",
      "completedAt",
    ],
    ["verifierRef"],
    ["commands"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.taskFile]: classifyFields([
    ...BASE_FIELDS,
    "taskId",
    "logicalName",
    "contentRef",
    "purpose",
  ], [], ["relativePath"]),
  [TODOS_DOMAIN_SCHEMA_IDS.run]: classifyFields(
    [...BASE_FIELDS, "objective", "status", "taskIds", "planId", "startedAt", "completedAt", "ledgerDigest"],
    ["agentId"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.runEvent]: classifyFields([
    ...BASE_FIELDS,
    "runId",
    "sequence",
    "type",
    "summary",
    "occurredAt",
    "evidenceIds",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.runCommand]: classifyFields([
    ...BASE_FIELDS,
    "runId",
    "sequence",
    "exitCode",
    "durationMs",
    "outputRefs",
    "completedAt",
  ], [], ["command"]),
  [TODOS_DOMAIN_SCHEMA_IDS.runFile]: classifyFields([
    ...BASE_FIELDS,
    "runId",
    "logicalName",
    "contentRef",
    "role",
  ], [], ["relativePath"]),
  [TODOS_DOMAIN_SCHEMA_IDS.runArtifact]: classifyFields([
    ...BASE_FIELDS,
    "runId",
    "name",
    "kind",
    "contentRef",
    "verified",
    "verificationEvidenceId",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.gitObjectId]: classifyFields(["algorithm", "value"]),
  [TODOS_DOMAIN_SCHEMA_IDS.gitCommit]: classifyFields(
    [...BASE_FIELDS, "objectId", "message", "committedAt"],
    ["repositoryRef", "authorRef"],
    ["changedFiles"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.gitRef]: classifyFields(
    [...BASE_FIELDS, "type", "name", "target", "published", "providerObservedAt"],
    ["repositoryRef"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.traceability]: classifyFields([
    ...BASE_FIELDS,
    "taskId",
    "commitIds",
    "gitRefIds",
    "verificationEvidenceIds",
    "projectionIds",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.taskTemplate]: classifyFields([
    ...BASE_FIELDS,
    "name",
    "description",
    "titlePattern",
    "descriptionPattern",
    "priority",
    "tags",
    "acceptanceCriteria",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.approval]: classifyFields(
    [
      ...BASE_FIELDS,
      "resourceRef",
      "status",
      "reason",
      "requestedAt",
      "decidedAt",
      "expiresAt",
    ],
    ["requestedBy", "decidedBy"],
  ),
  [TODOS_DOMAIN_SCHEMA_IDS.deletionRecord]: classifyFields([
    "id",
    "owner",
    "entityKind",
    "entityIdDigest",
    "priorRecordDigest",
    "tombstoneVersion",
    "redaction",
    "reasonCode",
    "deletedAt",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.taskContext]: classifyFields([
    "task",
    "project",
    "taskList",
    "plan",
    "comments",
    "dependencies",
    "verificationEvidence",
    "files",
    "traceability",
  ]),
  [TODOS_DOMAIN_SCHEMA_IDS.stats]: classifyFields(["asOfDate", "tasks", "projects", "plans", "activeAgents", "activeRuns"]),
});
