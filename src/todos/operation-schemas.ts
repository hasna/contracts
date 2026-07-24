import * as z from "zod/v4";
import {
  TODOS_CONTRACT_VERSION,
  TodosContentRefSchema,
  TodosCursorSchema,
  TodosEntityIdSchema,
  TodosOwnerIdSchema,
  TodosOwnerQualifiedRefSchema,
  TodosRelativePathSchema,
  TodosSha256DigestSchema,
  TodosSlugSchema,
  TodosTimestampSchema,
} from "./common";
import {
  TodosAuthorityHandshakeSchema,
  TodosServiceStatusSchema,
} from "./authority";
import {
  TodosCapabilitySchema,
} from "./capability-schema";
import {
  TodosActivitySchema,
  TodosAgentSchema,
  TodosApprovalSchema,
  TodosCommentSchema,
  TodosDeletionRecordSchema,
  TodosDependencySchema,
  TodosExternalOwnerRefSchema,
  TodosGitCommitSchema,
  TodosGitObjectIdSchema,
  TodosGitRefSchema,
  TodosPlanSchema,
  TodosPlanStatusSchema,
  TodosProjectSchema,
  TodosRunArtifactSchema,
  TodosRunCommandSchema,
  TodosRunEventSchema,
  TodosRunFileSchema,
  TodosRunSchema,
  TodosRunStatusSchema,
  TodosSavedViewSchema,
  TodosSearchFilterSchema,
  TodosSearchRequestSchema,
  TodosStatsSchema,
  TodosTaskContextSchema,
  TodosTaskFileSchema,
  TodosTaskListSchema,
  TodosTaskPrioritySchema,
  TodosTaskSchema,
  TodosTaskStatusSchema,
  TodosTaskTemplateSchema,
  TodosTraceabilitySchema,
  TodosVerificationCheckSchema,
  TodosVerificationCommandSchema,
  TodosVerificationEvidenceSchema,
} from "./domain";
import {
  TodosErrorSchema,
  TodosMutationReceiptSchema,
  createTodosPageSchema,
  createTodosResultSchema,
} from "./errors";
import {
  TaskToPrProjectionSchema,
} from "./projection";
import {
  TODOS_TRANSFER_SECTION_NAMES,
  TodosMigrationReceiptSchema,
  TodosTransferBundleSchema,
  TodosTransferCheckpointSchema,
  TodosTransferImportPreviewSchema,
  TodosTransferValidationSchema,
  computeTodosImportPlanId,
} from "./transfer-schema";

export const TODOS_COMMON_SCHEMA_IDS = {
  error: "hasna.todos.error.v1",
  mutationReceipt: "hasna.todos.mutation_receipt.v1",
} as const;

export const TODOS_REQUEST_SCHEMA_IDS = {
  empty: "hasna.todos.request.empty.v1",
  ref: "hasna.todos.request.ref.v1",
  versionedRef: "hasna.todos.request.versioned_ref.v1",
  list: "hasna.todos.request.list.v1",
  refList: "hasna.todos.request.ref_list.v1",
  existsMany: "hasna.todos.request.exists_many.v1",
  taskCreate: "hasna.todos.request.task_create.v1",
  taskUpsert: "hasna.todos.request.task_upsert.v1",
  taskUpdate: "hasna.todos.request.task_update.v1",
  taskBatch: "hasna.todos.request.task_batch.v1",
  taskStart: "hasna.todos.request.task_start.v1",
  taskComplete: "hasna.todos.request.task_complete.v1",
  taskFail: "hasna.todos.request.task_fail.v1",
  taskClaim: "hasna.todos.request.task_claim.v1",
  taskChanged: "hasna.todos.request.task_changed.v1",
  taskLock: "hasna.todos.request.task_lock.v1",
  commentCreate: "hasna.todos.request.comment_create.v1",
  dependencyCreate: "hasna.todos.request.dependency_create.v1",
  dependencyDelete: "hasna.todos.request.dependency_delete.v1",
  projectCreate: "hasna.todos.request.project_create.v1",
  projectUpdate: "hasna.todos.request.project_update.v1",
  projectRename: "hasna.todos.request.project_rename.v1",
  taskListCreate: "hasna.todos.request.task_list_create.v1",
  taskListUpdate: "hasna.todos.request.task_list_update.v1",
  planCreate: "hasna.todos.request.plan_create.v1",
  planUpdate: "hasna.todos.request.plan_update.v1",
  agentRegister: "hasna.todos.request.agent_register.v1",
  agentHeartbeat: "hasna.todos.request.agent_heartbeat.v1",
  agentRelease: "hasna.todos.request.agent_release.v1",
  search: "hasna.todos.request.search.v1",
  savedViewCreate: "hasna.todos.request.saved_view_create.v1",
  savedViewUpdate: "hasna.todos.request.saved_view_update.v1",
  savedViewExecute: "hasna.todos.request.saved_view_execute.v1",
  verificationCreate: "hasna.todos.request.verification_create.v1",
  verificationExport: "hasna.todos.request.verification_export.v1",
  taskFileRecord: "hasna.todos.request.task_file_record.v1",
  runStart: "hasna.todos.request.run_start.v1",
  runFinish: "hasna.todos.request.run_finish.v1",
  runEventCreate: "hasna.todos.request.run_event_create.v1",
  runCommandCreate: "hasna.todos.request.run_command_create.v1",
  runFileCreate: "hasna.todos.request.run_file_create.v1",
  runArtifactCreate: "hasna.todos.request.run_artifact_create.v1",
  runArtifactVerify: "hasna.todos.request.run_artifact_verify.v1",
  gitCommitLink: "hasna.todos.request.git_commit_link.v1",
  gitCommitUnlink: "hasna.todos.request.git_commit_unlink.v1",
  gitCommitFind: "hasna.todos.request.git_commit_find.v1",
  gitRefLink: "hasna.todos.request.git_ref_link.v1",
  gitRefFind: "hasna.todos.request.git_ref_find.v1",
  transferExport: "hasna.todos.request.transfer_export.v1",
  transferValidate: "hasna.todos.request.transfer_validate.v1",
  transferImportPreview: "hasna.todos.request.transfer_import_preview.v1",
  transferImportExecute: "hasna.todos.request.transfer_import_execute.v1",
  approvalRequest: "hasna.todos.request.approval_request.v1",
  approvalDecision: "hasna.todos.request.approval_decision.v1",
  approvalExpire: "hasna.todos.request.approval_expire.v1",
  taskTemplateCreate: "hasna.todos.request.task_template_create.v1",
  taskTemplateUpdate: "hasna.todos.request.task_template_update.v1",
  taskTemplateInstantiate: "hasna.todos.request.task_template_instantiate.v1",
  reportGenerate: "hasna.todos.request.report_generate.v1",
  workspaceBootstrap: "hasna.todos.request.workspace_bootstrap.v1",
  serverStart: "hasna.todos.request.server_start.v1",
  databaseBackup: "hasna.todos.request.database_backup.v1",
  databaseRestore: "hasna.todos.request.database_restore.v1",
  databaseCheck: "hasna.todos.request.database_check.v1",
  databaseCompact: "hasna.todos.request.database_compact.v1",
  upgradeValidate: "hasna.todos.request.upgrade_validate.v1",
  upgradeExecute: "hasna.todos.request.upgrade_execute.v1",
  projectionRebuild: "hasna.todos.request.projection_rebuild.v1",
} as const;

export const TODOS_RESPONSE_SCHEMA_IDS = {
  serviceStatus: "hasna.todos.response.service_status.v1",
  authority: "hasna.todos.response.authority.v1",
  artifactDocument: "hasna.todos.response.artifact_document.v1",
  capabilityPage: "hasna.todos.response.capability_page.v1",
  capability: "hasna.todos.response.capability.v1",
  taskPage: "hasna.todos.response.task_page.v1",
  task: "hasna.todos.response.task.v1",
  count: "hasna.todos.response.count.v1",
  existsMany: "hasna.todos.response.exists_many.v1",
  mutation: "hasna.todos.response.mutation.v1",
  batch: "hasna.todos.response.batch.v1",
  taskContext: "hasna.todos.response.task_context.v1",
  activityPage: "hasna.todos.response.activity_page.v1",
  commentPage: "hasna.todos.response.comment_page.v1",
  comment: "hasna.todos.response.comment.v1",
  dependencyPage: "hasna.todos.response.dependency_page.v1",
  dependency: "hasna.todos.response.dependency.v1",
  projectPage: "hasna.todos.response.project_page.v1",
  project: "hasna.todos.response.project.v1",
  taskListPage: "hasna.todos.response.task_list_page.v1",
  taskList: "hasna.todos.response.task_list.v1",
  planPage: "hasna.todos.response.plan_page.v1",
  plan: "hasna.todos.response.plan.v1",
  agentPage: "hasna.todos.response.agent_page.v1",
  agent: "hasna.todos.response.agent.v1",
  stats: "hasna.todos.response.stats.v1",
  savedViewPage: "hasna.todos.response.saved_view_page.v1",
  savedView: "hasna.todos.response.saved_view.v1",
  verificationPage: "hasna.todos.response.verification_page.v1",
  verification: "hasna.todos.response.verification.v1",
  verificationExport: "hasna.todos.response.verification_export.v1",
  taskFilePage: "hasna.todos.response.task_file_page.v1",
  taskFile: "hasna.todos.response.task_file.v1",
  runPage: "hasna.todos.response.run_page.v1",
  run: "hasna.todos.response.run.v1",
  runLedger: "hasna.todos.response.run_ledger.v1",
  runEventPage: "hasna.todos.response.run_event_page.v1",
  runEvent: "hasna.todos.response.run_event.v1",
  runCommandPage: "hasna.todos.response.run_command_page.v1",
  runCommand: "hasna.todos.response.run_command.v1",
  runFilePage: "hasna.todos.response.run_file_page.v1",
  runFile: "hasna.todos.response.run_file.v1",
  runArtifactPage: "hasna.todos.response.run_artifact_page.v1",
  runArtifact: "hasna.todos.response.run_artifact.v1",
  gitCommitPage: "hasna.todos.response.git_commit_page.v1",
  gitCommit: "hasna.todos.response.git_commit.v1",
  gitRefPage: "hasna.todos.response.git_ref_page.v1",
  gitRef: "hasna.todos.response.git_ref.v1",
  traceability: "hasna.todos.response.traceability.v1",
  projectionPage: "hasna.todos.response.projection_page.v1",
  projection: "hasna.todos.response.projection.v1",
  transferBundle: "hasna.todos.response.transfer_bundle.v1",
  transferValidation: "hasna.todos.response.transfer_validation.v1",
  transferImportPreview: "hasna.todos.response.transfer_import_preview.v1",
  migrationReceiptPage: "hasna.todos.response.migration_receipt_page.v1",
  migrationReceipt: "hasna.todos.response.migration_receipt.v1",
  deletionRecordPage: "hasna.todos.response.deletion_record_page.v1",
  deletionRecord: "hasna.todos.response.deletion_record.v1",
  approvalPage: "hasna.todos.response.approval_page.v1",
  approval: "hasna.todos.response.approval.v1",
  taskTemplatePage: "hasna.todos.response.task_template_page.v1",
  taskTemplate: "hasna.todos.response.task_template.v1",
  report: "hasna.todos.response.report.v1",
  serverStart: "hasna.todos.response.server_start.v1",
} as const;

const EmptyRequestSchema = z.strictObject({});
const RefRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
});
const VersionedRefRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
});
const ListRequestSchema = z.strictObject({
  cursor: TodosCursorSchema.nullable(),
  limit: z.number().int().positive().max(500),
  projectId: TodosEntityIdSchema.nullable(),
  taskListId: TodosEntityIdSchema.nullable(),
  planId: TodosEntityIdSchema.nullable(),
  agentId: TodosEntityIdSchema.nullable(),
  status: z.string().min(1).max(64).nullable(),
  changedAfter: TodosTimestampSchema.nullable(),
});
const RefListRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  cursor: TodosCursorSchema.nullable(),
  limit: z.number().int().positive().max(500),
});
const ExistsManyRequestSchema = z.strictObject({
  refs: z.array(TodosEntityIdSchema).min(1).max(10_000),
});

const TaskCreateInputSchema = z.strictObject({
  title: z.string().min(1).max(512),
  description: z.string().max(100_000).nullable(),
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
  externalOwnerRefs: z.array(TodosExternalOwnerRefSchema).max(64),
});

const TaskUpdateFieldsSchema = z.strictObject({
  title: z.string().min(1).max(512).optional(),
  description: z.string().max(100_000).nullable().optional(),
  priority: TodosTaskPrioritySchema.optional(),
  projectId: TodosEntityIdSchema.nullable().optional(),
  taskListId: TodosEntityIdSchema.nullable().optional(),
  planId: TodosEntityIdSchema.nullable().optional(),
  parentTaskId: TodosEntityIdSchema.nullable().optional(),
  assignedAgentId: TodosEntityIdSchema.nullable().optional(),
  tags: z.array(z.string().min(1).max(96)).max(128).optional(),
  acceptanceCriteria: z.array(z.string().min(1).max(4096)).max(256).optional(),
  dueAt: TodosTimestampSchema.nullable().optional(),
});

// @todos-runtime-validator operation.task_update_nonempty
const TaskUpdateRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  changes: TaskUpdateFieldsSchema,
}).superRefine((value, ctx) => {
  if (Object.keys(value.changes).length === 0) {
    ctx.addIssue({ code: "custom", message: "Task update requires at least one change", path: ["changes"] });
  }
});

const TaskUpsertRequestSchema = z.strictObject({
  fingerprint: z.string().min(1).max(256),
  create: TaskCreateInputSchema,
  update: TaskUpdateFieldsSchema,
  expectedVersion: z.number().int().positive().nullable(),
});

const TaskBatchItemSchema = z.discriminatedUnion("action", [
  z.strictObject({
    action: z.literal("create"),
    input: TaskCreateInputSchema,
  }),
  z.strictObject({
    action: z.literal("update"),
    ref: TodosEntityIdSchema,
    expectedVersion: z.number().int().positive(),
    changes: TaskUpdateFieldsSchema,
  }),
  z.strictObject({
    action: z.literal("delete"),
    ref: TodosEntityIdSchema,
    expectedVersion: z.number().int().positive(),
  }),
]);
const TaskBatchRequestSchema = z.strictObject({
  operations: z.array(TaskBatchItemSchema).min(1).max(500),
});

const TaskTransitionShape = {
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  summary: z.string().max(4096).nullable(),
} as const;
const TaskStartRequestSchema = z.strictObject({
  ...TaskTransitionShape,
  targetStatus: z.literal("in_progress"),
});
const TaskCompleteRequestSchema = z.strictObject({
  ...TaskTransitionShape,
  targetStatus: z.literal("completed"),
});
const TaskFailRequestSchema = z.strictObject({
  ...TaskTransitionShape,
  targetStatus: z.literal("failed"),
});
const TaskClaimRequestSchema = z.strictObject({
  agentId: TodosEntityIdSchema,
  projectId: TodosEntityIdSchema.nullable(),
  taskListId: TodosEntityIdSchema.nullable(),
  planId: TodosEntityIdSchema.nullable(),
  tags: z.array(z.string().min(1).max(96)).max(128),
});
const TaskChangedRequestSchema = z.strictObject({
  changedAfter: TodosTimestampSchema,
  cursor: TodosCursorSchema.nullable(),
  limit: z.number().int().positive().max(500),
});
const TaskLockRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  ownerRef: TodosExternalOwnerRefSchema,
  expectedVersion: z.number().int().positive(),
  expiresAt: TodosTimestampSchema.nullable(),
});
const CommentCreateRequestSchema = z.strictObject({
  taskRef: TodosEntityIdSchema,
  authorRef: TodosExternalOwnerRefSchema,
  kind: z.enum(["comment", "progress", "note"]),
  content: z.string().min(1).max(100_000),
  progressPercent: z.number().min(0).max(100).nullable(),
});
const DependencyCreateRequestSchema = z.strictObject({
  sourceTaskRef: TodosEntityIdSchema,
  targetTaskRef: TodosEntityIdSchema,
  kind: z.enum(["requires", "blocks"]),
});
const DependencyDeleteRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
});

const ProjectCreateRequestSchema = z.strictObject({
  slug: TodosSlugSchema,
  name: z.string().min(1).max(256),
  description: z.string().max(20_000).nullable(),
  repositoryRef: TodosExternalOwnerRefSchema.nullable(),
});
const ProjectUpdateRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  name: z.string().min(1).max(256).optional(),
  description: z.string().max(20_000).nullable().optional(),
  repositoryRef: TodosExternalOwnerRefSchema.nullable().optional(),
});
const ProjectRenameRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  slug: TodosSlugSchema,
  name: z.string().min(1).max(256).nullable(),
});
const TaskListCreateRequestSchema = z.strictObject({
  projectId: TodosEntityIdSchema.nullable(),
  slug: TodosSlugSchema,
  name: z.string().min(1).max(256),
  description: z.string().max(20_000).nullable(),
});
const TaskListUpdateRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  slug: TodosSlugSchema.optional(),
  name: z.string().min(1).max(256).optional(),
  description: z.string().max(20_000).nullable().optional(),
});
const PlanCreateRequestSchema = z.strictObject({
  slug: TodosSlugSchema,
  projectId: TodosEntityIdSchema.nullable(),
  taskListId: TodosEntityIdSchema.nullable(),
  name: z.string().min(1).max(256),
  description: z.string().max(40_000).nullable(),
  objective: z.string().min(1).max(20_000),
  taskIds: z.array(TodosEntityIdSchema).max(10_000),
});
const PlanUpdateRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  name: z.string().min(1).max(256).optional(),
  description: z.string().max(40_000).nullable().optional(),
  status: TodosPlanStatusSchema.optional(),
  objective: z.string().min(1).max(20_000).optional(),
  taskIds: z.array(TodosEntityIdSchema).max(10_000).optional(),
});
const AgentRegisterRequestSchema = z.strictObject({
  id: TodosEntityIdSchema,
  displayName: z.string().min(1).max(256),
  roles: z.array(z.enum(["customer_member", "customer_manager", "tenant_admin"])).min(1).max(32),
  activeProjectId: TodosEntityIdSchema.nullable(),
  activeTaskListId: TodosEntityIdSchema.nullable(),
});
const AgentHeartbeatRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  observedAt: TodosTimestampSchema,
  activeProjectId: TodosEntityIdSchema.nullable(),
  activeTaskListId: TodosEntityIdSchema.nullable(),
});
const AgentReleaseRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  releasedAt: TodosTimestampSchema,
});

const SavedViewCreateRequestSchema = z.strictObject({
  name: z.string().min(1).max(256),
  description: z.string().max(4096).nullable(),
  query: TodosSearchRequestSchema,
  audience: z.enum(["private", "organization"]),
});
const SavedViewUpdateRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  name: z.string().min(1).max(256).optional(),
  description: z.string().max(4096).nullable().optional(),
  query: TodosSearchRequestSchema.optional(),
  audience: z.enum(["private", "organization"]).optional(),
});
const SavedViewExecuteRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  cursor: TodosCursorSchema.nullable(),
  limit: z.number().int().positive().max(500),
});
const VerificationCreateRequestSchema = z.strictObject({
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
const VerificationExportRequestSchema = z.strictObject({
  taskId: TodosEntityIdSchema.nullable(),
  runId: TodosEntityIdSchema.nullable(),
  contentType: z.literal("application/json"),
});
const TaskFileRecordRequestSchema = z.strictObject({
  taskId: TodosEntityIdSchema,
  logicalName: z.string().min(1).max(512),
  relativePath: TodosRelativePathSchema.nullable(),
  contentRef: TodosContentRefSchema,
  purpose: z.enum(["attachment", "evidence", "deliverable"]),
});
const RunStartRequestSchema = z.strictObject({
  objective: z.string().min(1).max(20_000),
  taskIds: z.array(TodosEntityIdSchema).max(10_000),
  planId: TodosEntityIdSchema.nullable(),
  agentId: TodosEntityIdSchema.nullable(),
});
const RunFinishRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  status: z.enum(["succeeded", "failed", "cancelled"]),
  completedAt: TodosTimestampSchema,
  ledgerDigest: TodosSha256DigestSchema,
});
const RunEventCreateRequestSchema = z.strictObject({
  runId: TodosEntityIdSchema,
  sequence: z.number().int().nonnegative(),
  type: z.string().min(1).max(160).regex(/^[a-z][a-z0-9_.:-]*$/),
  summary: z.string().min(1).max(20_000),
  occurredAt: TodosTimestampSchema,
  evidenceIds: z.array(TodosEntityIdSchema).max(10_000),
});
const RunCommandCreateRequestSchema = z.strictObject({
  runId: TodosEntityIdSchema,
  sequence: z.number().int().nonnegative(),
  command: z.string().min(1).max(16_000),
  exitCode: z.number().int().nullable(),
  durationMs: z.number().int().nonnegative().nullable(),
  outputRefs: z.array(TodosContentRefSchema).max(1024),
  completedAt: TodosTimestampSchema.nullable(),
});
const RunFileCreateRequestSchema = z.strictObject({
  runId: TodosEntityIdSchema,
  logicalName: z.string().min(1).max(512),
  relativePath: TodosRelativePathSchema.nullable(),
  contentRef: TodosContentRefSchema,
  role: z.enum(["input", "output", "evidence"]),
});
const RunArtifactCreateRequestSchema = z.strictObject({
  runId: TodosEntityIdSchema,
  name: z.string().min(1).max(512),
  kind: z.string().min(1).max(160).regex(/^[a-z][a-z0-9_.:-]*$/),
  contentRef: TodosContentRefSchema,
});
const RunArtifactVerifyRequestSchema = z.strictObject({
  runId: TodosEntityIdSchema,
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  verificationEvidenceId: TodosEntityIdSchema,
});

const GitCommitLinkRequestSchema = z.strictObject({
  taskId: TodosEntityIdSchema,
  repositoryRef: TodosExternalOwnerRefSchema,
  objectId: TodosGitObjectIdSchema,
  message: z.string().min(1).max(20_000),
  authorRef: TodosExternalOwnerRefSchema,
  committedAt: TodosTimestampSchema,
  changedFiles: z.array(TodosRelativePathSchema).max(50_000),
});
const GitCommitUnlinkRequestSchema = z.strictObject({
  taskId: TodosEntityIdSchema,
  commitRef: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
});
const GitCommitFindRequestSchema = z.strictObject({
  repositoryRef: TodosExternalOwnerRefSchema,
  objectId: TodosGitObjectIdSchema,
});
const GitRefLinkRequestSchema = z.strictObject({
  taskId: TodosEntityIdSchema,
  repositoryRef: TodosExternalOwnerRefSchema,
  type: z.enum(["branch", "tag", "pull_request"]),
  name: z.string().min(1).max(512),
  target: TodosGitObjectIdSchema,
  published: z.boolean(),
  providerObservedAt: TodosTimestampSchema.nullable(),
});
const GitRefFindRequestSchema = z.strictObject({
  repositoryRef: TodosExternalOwnerRefSchema,
  type: z.enum(["branch", "tag", "pull_request"]),
  name: z.string().min(1).max(512),
});

const TransferExportRequestSchema = z.strictObject({
  bundleId: TodosEntityIdSchema,
  createdAt: TodosTimestampSchema,
  projectIds: z.array(TodosEntityIdSchema).max(10_000),
  sectionNames: z.array(z.enum(TODOS_TRANSFER_SECTION_NAMES)).min(1),
});
const TransferValidateRequestSchema = z.strictObject({
  bundle: TodosTransferBundleSchema,
  dryRun: z.literal(true),
});
const TransferImportPreviewRequestSchema = z.strictObject({
  bundle: TodosTransferBundleSchema,
  targetAuthorityId: TodosOwnerIdSchema,
  dryRun: z.literal(true),
});
// @todos-runtime-validator operation.transfer_checkpoint_binding
const TransferImportExecuteRequestSchema = z.strictObject({
  bundle: TodosTransferBundleSchema,
  targetAuthorityId: TodosOwnerIdSchema,
  importPlanId: TodosEntityIdSchema,
  importPlanDigest: TodosSha256DigestSchema,
  checkpoint: TodosTransferCheckpointSchema.nullable(),
}).superRefine((value, ctx) => {
  if (value.importPlanId !== computeTodosImportPlanId({
    sourceAuthorityId: value.bundle.source.authorityId,
    targetAuthorityId: value.targetAuthorityId,
    bundleId: value.bundle.bundleId,
    bundleChecksum: value.bundle.bundleChecksum,
    contractDigest: value.bundle.contractDigest,
    manifestDigest: value.bundle.manifestDigest,
  })) {
    ctx.addIssue({
      code: "custom",
      message: "Transfer execution import plan id does not bind this bundle and target",
      path: ["importPlanId"],
    });
  }
  if (!value.checkpoint) return;
  if (
    value.checkpoint.bundleId !== value.bundle.bundleId
    || value.checkpoint.sourceAuthorityId !== value.bundle.source.authorityId
    || value.checkpoint.bundleChecksum !== value.bundle.bundleChecksum
    || value.checkpoint.contractDigest !== value.bundle.contractDigest
    || value.checkpoint.manifestDigest !== value.bundle.manifestDigest
    || value.checkpoint.importPlanId !== value.importPlanId
    || value.checkpoint.importPlanDigest !== value.importPlanDigest
    || value.checkpoint.targetAuthorityId !== value.targetAuthorityId
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Transfer execution checkpoint does not bind this bundle and import plan",
      path: ["checkpoint"],
    });
  }
});
const ApprovalRequestSchema = z.strictObject({
  resourceRef: TodosOwnerQualifiedRefSchema,
  reason: z.string().min(1).max(4096),
  requestedBy: TodosExternalOwnerRefSchema,
  expiresAt: TodosTimestampSchema.nullable(),
});
const ApprovalDecisionRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  decidedBy: TodosExternalOwnerRefSchema,
  reason: z.string().min(1).max(4096),
});
const ApprovalExpireRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  expiredAt: TodosTimestampSchema,
});
const TaskTemplateCreateRequestSchema = z.strictObject({
  name: z.string().min(1).max(256),
  description: z.string().max(4096).nullable(),
  titlePattern: z.string().min(1).max(512),
  descriptionPattern: z.string().max(20_000).nullable(),
  priority: TodosTaskPrioritySchema,
  tags: z.array(z.string().min(1).max(96)).max(128),
  acceptanceCriteria: z.array(z.string().min(1).max(4096)).max(256),
});
const TaskTemplateUpdateRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  expectedVersion: z.number().int().positive(),
  name: z.string().min(1).max(256).optional(),
  description: z.string().max(4096).nullable().optional(),
  titlePattern: z.string().min(1).max(512).optional(),
  descriptionPattern: z.string().max(20_000).nullable().optional(),
  priority: TodosTaskPrioritySchema.optional(),
  tags: z.array(z.string().min(1).max(96)).max(128).optional(),
  acceptanceCriteria: z.array(z.string().min(1).max(4096)).max(256).optional(),
});
const TaskTemplateInstantiateRequestSchema = z.strictObject({
  ref: TodosEntityIdSchema,
  projectId: TodosEntityIdSchema.nullable(),
  taskListId: TodosEntityIdSchema.nullable(),
  planId: TodosEntityIdSchema.nullable(),
  variables: z.record(z.string(), z.string().max(4096)),
});
const ReportGenerateRequestSchema = z.strictObject({
  kind: z.enum(["task_summary", "plan_progress", "run_evidence", "traceability"]),
  projectId: TodosEntityIdSchema.nullable(),
  taskListId: TodosEntityIdSchema.nullable(),
  planId: TodosEntityIdSchema.nullable(),
  taskId: TodosEntityIdSchema.nullable(),
  asOf: TodosTimestampSchema,
});
const WorkspaceBootstrapRequestSchema = z.strictObject({
  projectSlug: TodosSlugSchema,
  projectName: z.string().min(1).max(256),
  repositoryRef: TodosExternalOwnerRefSchema,
  createDefaultTaskList: z.boolean(),
});
const ServerStartRequestSchema = z.strictObject({
  interface: z.enum(["loopback", "workspace"]),
  port: z.number().int().min(1024).max(65_535),
  expectedState: z.literal("stopped"),
});
const DatabaseBackupRequestSchema = z.strictObject({
  label: z.string().min(1).max(256),
  createdAt: TodosTimestampSchema,
});
const DatabaseRestoreRequestSchema = z.strictObject({
  backupContentRef: TodosContentRefSchema,
  expectedCurrentDigest: TodosSha256DigestSchema,
});
const DatabaseCheckRequestSchema = z.strictObject({
  expectedSchemaVersion: z.string().min(1).max(64),
});
const DatabaseCompactRequestSchema = z.strictObject({
  expectedCurrentDigest: TodosSha256DigestSchema,
});
const UpgradeValidateRequestSchema = z.strictObject({
  targetVersion: z.string().min(1).max(64),
  packageContentRef: TodosContentRefSchema,
  expectedContractVersion: z.literal(TODOS_CONTRACT_VERSION),
});
const UpgradeExecuteRequestSchema = z.strictObject({
  targetVersion: z.string().min(1).max(64),
  packageContentRef: TodosContentRefSchema,
  validationDigest: TodosSha256DigestSchema,
});
const ProjectionRebuildRequestSchema = z.strictObject({
  taskRefs: z.array(TodosEntityIdSchema).max(10_000),
  expectedManifestDigest: TodosSha256DigestSchema,
});

const CountDataSchema = z.strictObject({ count: z.number().int().nonnegative() });
const ExistsManyDataSchema = z.strictObject({
  results: z.array(z.strictObject({
    ref: TodosEntityIdSchema,
    exists: z.boolean(),
  })).min(1),
});
const BatchDataSchema = z.strictObject({
  receipts: z.array(TodosMutationReceiptSchema).min(1),
});
const ArtifactDocumentDataSchema = z.strictObject({
  mediaType: z.literal("application/json"),
  digest: TodosSha256DigestSchema,
  document: z.record(z.string(), z.unknown()),
});
const VerificationExportDataSchema = z.strictObject({
  records: z.array(TodosVerificationEvidenceSchema),
  digest: TodosSha256DigestSchema,
});
const RunLedgerDataSchema = z.strictObject({
  run: TodosRunSchema,
  events: z.array(TodosRunEventSchema),
  commands: z.array(TodosRunCommandSchema),
  files: z.array(TodosRunFileSchema),
  artifacts: z.array(TodosRunArtifactSchema),
  digest: TodosSha256DigestSchema,
});
const ReportDataSchema = z.strictObject({
  reportId: TodosEntityIdSchema,
  kind: z.enum(["task_summary", "plan_progress", "run_evidence", "traceability"]),
  contentRef: TodosContentRefSchema,
  generatedAt: TodosTimestampSchema,
});
const ServerStartDataSchema = z.strictObject({
  authorityId: TodosOwnerIdSchema,
  interface: z.enum(["loopback", "workspace"]),
  port: z.number().int().min(1024).max(65_535),
  state: z.literal("started"),
  startedAt: TodosTimestampSchema,
});

export const TODOS_REQUEST_SCHEMAS = Object.freeze({
  [TODOS_REQUEST_SCHEMA_IDS.empty]: EmptyRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.ref]: RefRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.versionedRef]: VersionedRefRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.list]: ListRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.refList]: RefListRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.existsMany]: ExistsManyRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskCreate]: TaskCreateInputSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskUpsert]: TaskUpsertRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskUpdate]: TaskUpdateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskBatch]: TaskBatchRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskStart]: TaskStartRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskComplete]: TaskCompleteRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskFail]: TaskFailRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskClaim]: TaskClaimRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskChanged]: TaskChangedRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskLock]: TaskLockRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.commentCreate]: CommentCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.dependencyCreate]: DependencyCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.dependencyDelete]: DependencyDeleteRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.projectCreate]: ProjectCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.projectUpdate]: ProjectUpdateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.projectRename]: ProjectRenameRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskListCreate]: TaskListCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskListUpdate]: TaskListUpdateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.planCreate]: PlanCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.planUpdate]: PlanUpdateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.agentRegister]: AgentRegisterRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.agentHeartbeat]: AgentHeartbeatRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.agentRelease]: AgentReleaseRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.search]: TodosSearchRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.savedViewCreate]: SavedViewCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.savedViewUpdate]: SavedViewUpdateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.savedViewExecute]: SavedViewExecuteRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.verificationCreate]: VerificationCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.verificationExport]: VerificationExportRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskFileRecord]: TaskFileRecordRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.runStart]: RunStartRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.runFinish]: RunFinishRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.runEventCreate]: RunEventCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.runCommandCreate]: RunCommandCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.runFileCreate]: RunFileCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.runArtifactCreate]: RunArtifactCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.runArtifactVerify]: RunArtifactVerifyRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.gitCommitLink]: GitCommitLinkRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.gitCommitUnlink]: GitCommitUnlinkRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.gitCommitFind]: GitCommitFindRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.gitRefLink]: GitRefLinkRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.gitRefFind]: GitRefFindRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.transferExport]: TransferExportRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.transferValidate]: TransferValidateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.transferImportPreview]: TransferImportPreviewRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.transferImportExecute]: TransferImportExecuteRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.approvalRequest]: ApprovalRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.approvalDecision]: ApprovalDecisionRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.approvalExpire]: ApprovalExpireRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskTemplateCreate]: TaskTemplateCreateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskTemplateUpdate]: TaskTemplateUpdateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.taskTemplateInstantiate]: TaskTemplateInstantiateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.reportGenerate]: ReportGenerateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.workspaceBootstrap]: WorkspaceBootstrapRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.serverStart]: ServerStartRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.databaseBackup]: DatabaseBackupRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.databaseRestore]: DatabaseRestoreRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.databaseCheck]: DatabaseCheckRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.databaseCompact]: DatabaseCompactRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.upgradeValidate]: UpgradeValidateRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.upgradeExecute]: UpgradeExecuteRequestSchema,
  [TODOS_REQUEST_SCHEMA_IDS.projectionRebuild]: ProjectionRebuildRequestSchema,
});

export const TODOS_RESPONSE_SCHEMAS = Object.freeze({
  [TODOS_RESPONSE_SCHEMA_IDS.serviceStatus]: createTodosResultSchema(TodosServiceStatusSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.authority]: createTodosResultSchema(TodosAuthorityHandshakeSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.artifactDocument]: createTodosResultSchema(ArtifactDocumentDataSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.capabilityPage]: createTodosResultSchema(createTodosPageSchema(TodosCapabilitySchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.capability]: createTodosResultSchema(TodosCapabilitySchema),
  [TODOS_RESPONSE_SCHEMA_IDS.taskPage]: createTodosResultSchema(createTodosPageSchema(TodosTaskSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.task]: createTodosResultSchema(TodosTaskSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.count]: createTodosResultSchema(CountDataSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.existsMany]: createTodosResultSchema(ExistsManyDataSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.mutation]: createTodosResultSchema(TodosMutationReceiptSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.batch]: createTodosResultSchema(BatchDataSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.taskContext]: createTodosResultSchema(TodosTaskContextSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.activityPage]: createTodosResultSchema(createTodosPageSchema(TodosActivitySchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.commentPage]: createTodosResultSchema(createTodosPageSchema(TodosCommentSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.comment]: createTodosResultSchema(TodosCommentSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.dependencyPage]: createTodosResultSchema(createTodosPageSchema(TodosDependencySchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.dependency]: createTodosResultSchema(TodosDependencySchema),
  [TODOS_RESPONSE_SCHEMA_IDS.projectPage]: createTodosResultSchema(createTodosPageSchema(TodosProjectSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.project]: createTodosResultSchema(TodosProjectSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.taskListPage]: createTodosResultSchema(createTodosPageSchema(TodosTaskListSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.taskList]: createTodosResultSchema(TodosTaskListSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.planPage]: createTodosResultSchema(createTodosPageSchema(TodosPlanSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.plan]: createTodosResultSchema(TodosPlanSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.agentPage]: createTodosResultSchema(createTodosPageSchema(TodosAgentSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.agent]: createTodosResultSchema(TodosAgentSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.stats]: createTodosResultSchema(TodosStatsSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.savedViewPage]: createTodosResultSchema(createTodosPageSchema(TodosSavedViewSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.savedView]: createTodosResultSchema(TodosSavedViewSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.verificationPage]: createTodosResultSchema(createTodosPageSchema(TodosVerificationEvidenceSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.verification]: createTodosResultSchema(TodosVerificationEvidenceSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.verificationExport]: createTodosResultSchema(VerificationExportDataSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.taskFilePage]: createTodosResultSchema(createTodosPageSchema(TodosTaskFileSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.taskFile]: createTodosResultSchema(TodosTaskFileSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.runPage]: createTodosResultSchema(createTodosPageSchema(TodosRunSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.run]: createTodosResultSchema(TodosRunSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.runLedger]: createTodosResultSchema(RunLedgerDataSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.runEventPage]: createTodosResultSchema(createTodosPageSchema(TodosRunEventSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.runEvent]: createTodosResultSchema(TodosRunEventSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.runCommandPage]: createTodosResultSchema(createTodosPageSchema(TodosRunCommandSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.runCommand]: createTodosResultSchema(TodosRunCommandSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.runFilePage]: createTodosResultSchema(createTodosPageSchema(TodosRunFileSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.runFile]: createTodosResultSchema(TodosRunFileSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.runArtifactPage]: createTodosResultSchema(createTodosPageSchema(TodosRunArtifactSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.runArtifact]: createTodosResultSchema(TodosRunArtifactSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.gitCommitPage]: createTodosResultSchema(createTodosPageSchema(TodosGitCommitSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.gitCommit]: createTodosResultSchema(TodosGitCommitSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.gitRefPage]: createTodosResultSchema(createTodosPageSchema(TodosGitRefSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.gitRef]: createTodosResultSchema(TodosGitRefSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.traceability]: createTodosResultSchema(TodosTraceabilitySchema),
  [TODOS_RESPONSE_SCHEMA_IDS.projectionPage]: createTodosResultSchema(createTodosPageSchema(TaskToPrProjectionSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.projection]: createTodosResultSchema(TaskToPrProjectionSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.transferBundle]: createTodosResultSchema(TodosTransferBundleSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.transferValidation]: createTodosResultSchema(TodosTransferValidationSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.transferImportPreview]: createTodosResultSchema(TodosTransferImportPreviewSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.migrationReceiptPage]: createTodosResultSchema(createTodosPageSchema(TodosMigrationReceiptSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.migrationReceipt]: createTodosResultSchema(TodosMigrationReceiptSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.deletionRecordPage]: createTodosResultSchema(createTodosPageSchema(TodosDeletionRecordSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.deletionRecord]: createTodosResultSchema(TodosDeletionRecordSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.approvalPage]: createTodosResultSchema(createTodosPageSchema(TodosApprovalSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.approval]: createTodosResultSchema(TodosApprovalSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.taskTemplatePage]: createTodosResultSchema(createTodosPageSchema(TodosTaskTemplateSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.taskTemplate]: createTodosResultSchema(TodosTaskTemplateSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.report]: createTodosResultSchema(ReportDataSchema),
  [TODOS_RESPONSE_SCHEMA_IDS.serverStart]: createTodosResultSchema(ServerStartDataSchema),
});

export const TODOS_COMMON_SCHEMAS = Object.freeze({
  [TODOS_COMMON_SCHEMA_IDS.error]: TodosErrorSchema,
  [TODOS_COMMON_SCHEMA_IDS.mutationReceipt]: TodosMutationReceiptSchema,
});
