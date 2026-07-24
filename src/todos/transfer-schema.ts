import * as z from "zod/v4";
import {
  TODOS_CONTRACT_VERSION,
  TODOS_MANIFEST_VERSION,
  TODOS_TRANSFER_VERSION,
  TodosContentRefSchema,
  TodosEntityIdSchema,
  TodosIdempotencyKeySchema,
  TodosModeSchema,
  TodosOwnerIdSchema,
  TodosOwnerQualifiedRefSchema,
  type TodosOwnerQualifiedRef,
  TodosSha256DigestSchema,
  TodosTimestampSchema,
  sha256TodosValue,
  sortTodosRecords,
  stableTodosJson,
  uniqueSortedTodosStrings,
} from "./common";
import {
  TODOS_DOMAIN_FIELD_CLASSIFICATION,
  TODOS_DOMAIN_SCHEMA_IDS,
  TodosActivitySchema,
  TodosApprovalSchema,
  TodosCommentSchema,
  TodosDeletionRecordSchema,
  TodosDependencySchema,
  TodosExternalOwnerRefSchema,
  TodosGitObjectIdSchema,
  TodosGitRefSchema,
  TodosPlanSchema,
  TodosProjectSchema,
  TodosRunEventSchema,
  TodosRunSchema,
  TodosSavedViewSchema,
  TodosTaskListSchema,
  TodosTaskSchema,
  TodosTaskTemplateSchema,
  TodosTraceabilitySchema,
  TodosVerificationEvidenceSchema,
  type TodosActivity,
  type TodosApproval,
  type TodosComment,
  type TodosDeletionRecord,
  type TodosDependency,
  type TodosExternalOwnerRef,
  type TodosGitRef,
  type TodosPlan,
  type TodosProject,
  type TodosRun,
  type TodosRunEvent,
  type TodosSavedView,
  type TodosTask,
  type TodosTaskList,
  type TodosTaskTemplate,
  type TodosTraceability,
} from "./domain";
import {
  TaskToPrProjectionSchema,
  validateTaskToPrProjectionHistory,
  type TaskToPrProjection,
} from "./projection";
import {
  createTodosError,
  type TodosError,
} from "./errors";

export const TODOS_TRANSFER_SCHEMA_IDS = {
  bundle: "hasna.todos.transfer_bundle.v1",
  validation: "hasna.todos.transfer_validation.v1",
  importPreview: "hasna.todos.transfer_import_preview.v1",
  importExecution: "hasna.todos.transfer_import_execution.v1",
  executionContext: "hasna.todos.transfer_execution_context.v1",
  checkpoint: "hasna.todos.transfer_checkpoint.v1",
  migrationReceipt: "hasna.todos.migration_receipt.v1",
} as const;

export const TODOS_TRANSFER_SECTION_NAMES = [
  "projects",
  "task_lists",
  "plans",
  "tasks",
  "comments",
  "dependencies",
  "activities",
  "verification_evidence",
  "task_files",
  "runs",
  "run_events",
  "run_commands",
  "run_files",
  "run_artifacts",
  "git_commits",
  "git_refs",
  "traceability",
  "task_to_pr_projections",
  "saved_views",
  "task_templates",
  "approvals",
  "deletion_records",
] as const;

export const TodosTransferSectionNameSchema = z.enum(TODOS_TRANSFER_SECTION_NAMES);
export type TodosTransferSectionName = z.infer<typeof TodosTransferSectionNameSchema>;

const TodosPortableLogicalNameSchema = z.string()
  .min(1)
  .max(512)
  .refine((value) => !value.includes("/") && !value.includes("\\"), {
    message: "Portable logical names cannot contain path separators",
  });

export const TodosPortableCommandReceiptSchema = z.strictObject({
  commandDigest: TodosSha256DigestSchema,
  argumentsDigest: TodosSha256DigestSchema.nullable(),
  exitCode: z.number().int().nullable(),
  durationMs: z.number().int().nonnegative().nullable(),
  outputRefs: z.array(TodosContentRefSchema).max(1024),
});
export type TodosPortableCommandReceipt = z.infer<typeof TodosPortableCommandReceiptSchema>;

export const TodosPortableVerificationEvidenceSchema = TodosVerificationEvidenceSchema
  .omit({ commands: true })
  .extend({
    commandReceipts: z.array(TodosPortableCommandReceiptSchema).max(256),
  });
export type TodosPortableVerificationEvidence =
  z.infer<typeof TodosPortableVerificationEvidenceSchema>;

export const TodosPortableTaskFileSchema = z.strictObject({
  id: TodosEntityIdSchema,
  owner: TodosOwnerIdSchema,
  version: z.number().int().positive(),
  createdAt: TodosTimestampSchema,
  updatedAt: TodosTimestampSchema,
  taskId: TodosEntityIdSchema,
  logicalName: TodosPortableLogicalNameSchema,
  contentRef: TodosContentRefSchema,
  purpose: z.enum(["attachment", "evidence", "deliverable"]),
});
export type TodosPortableTaskFile = z.infer<typeof TodosPortableTaskFileSchema>;

export const TodosPortableRunCommandSchema = z.strictObject({
  id: TodosEntityIdSchema,
  owner: TodosOwnerIdSchema,
  version: z.number().int().positive(),
  createdAt: TodosTimestampSchema,
  updatedAt: TodosTimestampSchema,
  runId: TodosEntityIdSchema,
  sequence: z.number().int().nonnegative(),
  commandDigest: TodosSha256DigestSchema,
  argumentsDigest: TodosSha256DigestSchema.nullable(),
  exitCode: z.number().int().nullable(),
  durationMs: z.number().int().nonnegative().nullable(),
  outputRefs: z.array(TodosContentRefSchema).max(1024),
  completedAt: TodosTimestampSchema.nullable(),
});
export type TodosPortableRunCommand = z.infer<typeof TodosPortableRunCommandSchema>;

export const TodosPortableRunFileSchema = z.strictObject({
  id: TodosEntityIdSchema,
  owner: TodosOwnerIdSchema,
  version: z.number().int().positive(),
  createdAt: TodosTimestampSchema,
  updatedAt: TodosTimestampSchema,
  runId: TodosEntityIdSchema,
  logicalName: TodosPortableLogicalNameSchema,
  contentRef: TodosContentRefSchema,
  role: z.enum(["input", "output", "evidence"]),
});
export type TodosPortableRunFile = z.infer<typeof TodosPortableRunFileSchema>;

export const TodosPortableRunArtifactSchema = z.strictObject({
  id: TodosEntityIdSchema,
  owner: TodosOwnerIdSchema,
  version: z.number().int().positive(),
  createdAt: TodosTimestampSchema,
  updatedAt: TodosTimestampSchema,
  runId: TodosEntityIdSchema,
  logicalName: TodosPortableLogicalNameSchema,
  kind: z.string().min(1).max(160).regex(/^[a-z][a-z0-9_.:-]*$/),
  contentRef: TodosContentRefSchema,
  verified: z.boolean(),
  verificationEvidenceId: TodosEntityIdSchema.nullable(),
});
export type TodosPortableRunArtifact = z.infer<typeof TodosPortableRunArtifactSchema>;

export const TodosPortableGitCommitSchema = z.strictObject({
  id: TodosEntityIdSchema,
  owner: TodosOwnerIdSchema,
  version: z.number().int().positive(),
  createdAt: TodosTimestampSchema,
  updatedAt: TodosTimestampSchema,
  repositoryRef: TodosExternalOwnerRefSchema,
  objectId: TodosGitObjectIdSchema,
  message: z.string().min(1).max(20_000),
  authorRef: TodosExternalOwnerRefSchema,
  committedAt: TodosTimestampSchema,
  changedFileDigests: z.array(TodosSha256DigestSchema).max(50_000),
});
export type TodosPortableGitCommit = z.infer<typeof TodosPortableGitCommitSchema>;

function createTransferSectionSchema<const T extends z.ZodType>(recordSchema: T) {
  return z.strictObject({
    owner: TodosOwnerIdSchema,
    count: z.number().int().nonnegative(),
    digest: TodosSha256DigestSchema,
    records: z.array(recordSchema),
  });
}

export const TodosTransferSectionsSchema = z.strictObject({
  projects: createTransferSectionSchema(TodosProjectSchema),
  task_lists: createTransferSectionSchema(TodosTaskListSchema),
  plans: createTransferSectionSchema(TodosPlanSchema),
  tasks: createTransferSectionSchema(TodosTaskSchema),
  comments: createTransferSectionSchema(TodosCommentSchema),
  dependencies: createTransferSectionSchema(TodosDependencySchema),
  activities: createTransferSectionSchema(TodosActivitySchema),
  verification_evidence: createTransferSectionSchema(TodosPortableVerificationEvidenceSchema),
  task_files: createTransferSectionSchema(TodosPortableTaskFileSchema),
  runs: createTransferSectionSchema(TodosRunSchema),
  run_events: createTransferSectionSchema(TodosRunEventSchema),
  run_commands: createTransferSectionSchema(TodosPortableRunCommandSchema),
  run_files: createTransferSectionSchema(TodosPortableRunFileSchema),
  run_artifacts: createTransferSectionSchema(TodosPortableRunArtifactSchema),
  git_commits: createTransferSectionSchema(TodosPortableGitCommitSchema),
  git_refs: createTransferSectionSchema(TodosGitRefSchema),
  traceability: createTransferSectionSchema(TodosTraceabilitySchema),
  task_to_pr_projections: createTransferSectionSchema(TaskToPrProjectionSchema),
  saved_views: createTransferSectionSchema(TodosSavedViewSchema),
  task_templates: createTransferSectionSchema(TodosTaskTemplateSchema),
  approvals: createTransferSectionSchema(TodosApprovalSchema),
  deletion_records: createTransferSectionSchema(TodosDeletionRecordSchema),
});
export type TodosTransferSections = z.infer<typeof TodosTransferSectionsSchema>;

export const TodosDependencyClosureEntrySchema = z.strictObject({
  owner: TodosOwnerIdSchema,
  taskId: TodosEntityIdSchema,
  dependencyTaskIds: z.array(TodosEntityIdSchema),
});
export type TodosDependencyClosureEntry = z.infer<typeof TodosDependencyClosureEntrySchema>;

export const TodosAttachmentContentReferenceSchema = z.strictObject({
  owner: TodosOwnerIdSchema,
  source: z.strictObject({
    section: z.enum([
      "verification_evidence",
      "task_files",
      "run_commands",
      "run_files",
      "run_artifacts",
    ]),
    id: TodosEntityIdSchema,
  }),
  index: z.number().int().nonnegative(),
  contentRef: TodosContentRefSchema,
});
export type TodosAttachmentContentReference = z.infer<typeof TodosAttachmentContentReferenceSchema>;

export const TodosTransferRecordRefSchema = z.strictObject({
  owner: TodosOwnerIdSchema,
  section: TodosTransferSectionNameSchema,
  id: TodosEntityIdSchema,
  kind: z.literal("task_to_pr_projection").optional(),
  version: z.number().int().positive().optional(),
  digest: TodosSha256DigestSchema.optional(),
});
export type TodosTransferRecordRef = z.infer<typeof TodosTransferRecordRefSchema>;

export const TodosTransferReferenceClosureEntrySchema = z.strictObject({
  source: TodosTransferRecordRefSchema,
  references: z.array(TodosTransferRecordRefSchema),
});
export type TodosTransferReferenceClosureEntry =
  z.infer<typeof TodosTransferReferenceClosureEntrySchema>;

export const TodosTransferReferenceOnlySchema = z.strictObject({
  owner: TodosOwnerIdSchema,
  agentIds: z.array(TodosEntityIdSchema),
  externalOwnerRefs: z.array(TodosExternalOwnerRefSchema),
  ownerQualifiedRefs: z.array(TodosOwnerQualifiedRefSchema),
});
export type TodosTransferReferenceOnly = z.infer<typeof TodosTransferReferenceOnlySchema>;

// @todos-runtime-validator transfer.bundle_owner_binding
export const TodosTransferBundleSchema = z.strictObject({
  schema: z.literal(TODOS_TRANSFER_SCHEMA_IDS.bundle),
  version: z.literal(TODOS_TRANSFER_VERSION),
  bundleId: TodosEntityIdSchema,
  createdAt: TodosTimestampSchema,
  source: z.strictObject({
    authorityId: TodosOwnerIdSchema,
    mode: TodosModeSchema,
  }),
  contractVersion: z.literal(TODOS_CONTRACT_VERSION),
  contractDigest: TodosSha256DigestSchema,
  manifestVersion: z.literal(TODOS_MANIFEST_VERSION),
  manifestDigest: TodosSha256DigestSchema,
  sections: TodosTransferSectionsSchema,
  dependencyClosure: z.array(TodosDependencyClosureEntrySchema),
  referenceClosure: z.array(TodosTransferReferenceClosureEntrySchema),
  attachmentContentReferences: z.array(TodosAttachmentContentReferenceSchema),
  referenceOnly: TodosTransferReferenceOnlySchema,
  bundleChecksum: TodosSha256DigestSchema,
}).superRefine((value, ctx) => {
  const expectedOwner = value.source.authorityId;
  const visit = (input: unknown, path: Array<string | number>): void => {
    if (Array.isArray(input)) {
      input.forEach((entry, index) => visit(entry, [...path, index]));
      return;
    }
    if (!input || typeof input !== "object") return;
    for (const [key, entry] of Object.entries(input)) {
      const entryPath = [...path, key];
      if (key === "owner" && entry !== expectedOwner) {
        ctx.addIssue({
          code: "custom",
          message: "Every portable owner must equal the bundle source authority",
          path: entryPath,
        });
      }
      visit(entry, entryPath);
    }
  };
  visit(value.sections, ["sections"]);
  visit(value.dependencyClosure, ["dependencyClosure"]);
  visit(value.referenceClosure, ["referenceClosure"]);
  visit(value.attachmentContentReferences, ["attachmentContentReferences"]);
  visit(value.referenceOnly, ["referenceOnly"]);
});
export type TodosTransferBundle = z.infer<typeof TodosTransferBundleSchema>;

export interface TodosTransferBundleWithDigestsInput {
  bundleId: string;
  createdAt: string;
  source: {
    authorityId: string;
    mode: "local" | "cloud";
  };
  contractDigest: string;
  manifestDigest: string;
  records: {
    projects: TodosProject[];
    task_lists: TodosTaskList[];
    plans: TodosPlan[];
    tasks: TodosTask[];
    comments: TodosComment[];
    dependencies: TodosDependency[];
    activities: TodosActivity[];
    verification_evidence: TodosPortableVerificationEvidence[];
    task_files: TodosPortableTaskFile[];
    runs: TodosRun[];
    run_events: TodosRunEvent[];
    run_commands: TodosPortableRunCommand[];
    run_files: TodosPortableRunFile[];
    run_artifacts: TodosPortableRunArtifact[];
    git_commits: TodosPortableGitCommit[];
    git_refs: TodosGitRef[];
    traceability: TodosTraceability[];
    task_to_pr_projections: TaskToPrProjection[];
    saved_views: TodosSavedView[];
    task_templates: TodosTaskTemplate[];
    approvals: TodosApproval[];
    deletion_records: TodosDeletionRecord[];
  };
}

export interface TodosTransferBundleUnsigned extends Omit<TodosTransferBundle, "bundleChecksum"> {}

function createSection<T>(owner: string, records: readonly T[]) {
  const sortedRecords = sortTodosRecords(records);
  return {
    owner,
    count: sortedRecords.length,
    digest: sha256TodosValue(sortedRecords),
    records: sortedRecords,
  };
}

function dependencyEdges(dependencies: readonly TodosDependency[]): Map<string, Set<string>> {
  const edges = new Map<string, Set<string>>();
  for (const dependency of dependencies) {
    const source = dependency.kind === "requires"
      ? dependency.sourceTaskId
      : dependency.targetTaskId;
    const target = dependency.kind === "requires"
      ? dependency.targetTaskId
      : dependency.sourceTaskId;
    const targets = edges.get(source) ?? new Set<string>();
    targets.add(target);
    edges.set(source, targets);
  }
  return edges;
}

export function computeTodosDependencyClosure(
  tasks: readonly TodosTask[],
  dependencies: readonly TodosDependency[],
): TodosDependencyClosureEntry[] {
  const edges = dependencyEdges(dependencies);
  const visit = (taskId: string, visited: Set<string>): Set<string> => {
    const direct = edges.get(taskId) ?? new Set<string>();
    for (const dependencyId of direct) {
      if (visited.has(dependencyId)) {
        continue;
      }
      visited.add(dependencyId);
      visit(dependencyId, visited);
    }
    return visited;
  };

  return [...tasks]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((task) => ({
      owner: task.owner,
      taskId: task.id,
      dependencyTaskIds: [...visit(task.id, new Set<string>())].sort((left, right) => left.localeCompare(right)),
    }));
}

const OWNER_REF_KIND_TO_SECTION: Readonly<Record<string, TodosTransferSectionName>> =
  Object.freeze({
    project: "projects",
    task_list: "task_lists",
    plan: "plans",
    task: "tasks",
    comment: "comments",
    dependency: "dependencies",
    activity: "activities",
    verification_evidence: "verification_evidence",
    task_file: "task_files",
    run: "runs",
    run_event: "run_events",
    run_command: "run_commands",
    run_file: "run_files",
    run_artifact: "run_artifacts",
    git_commit: "git_commits",
    git_ref: "git_refs",
    traceability: "traceability",
    task_to_pr_projection: "task_to_pr_projections",
    saved_view: "saved_views",
    task_template: "task_templates",
    approval: "approvals",
    deletion_record: "deletion_records",
  });

function transferRecordKey(ref: TodosTransferRecordRef): string {
  return stableTodosJson(ref);
}

function parseTransferRecordKey(key: string): TodosTransferRecordRef {
  return TodosTransferRecordRefSchema.parse(JSON.parse(key));
}

function transferRecordRef(
  owner: string,
  section: TodosTransferSectionName,
  id: string,
): TodosTransferRecordRef {
  return { owner, section, id };
}

function projectionTransferRecordRef(
  owner: string,
  projection: Pick<TaskToPrProjection, "id" | "version" | "digest">,
): TodosTransferRecordRef {
  return {
    owner,
    section: "task_to_pr_projections",
    id: projection.id,
    kind: "task_to_pr_projection",
    version: projection.version,
    digest: projection.digest,
  };
}

function ownerRefTarget(ref: TodosOwnerQualifiedRef): TodosTransferRecordRef | null {
  const section = OWNER_REF_KIND_TO_SECTION[ref.kind];
  return section ? { owner: ref.owner, section, id: ref.id } : null;
}

export function computeTodosTransferReferenceClosure(
  sections: TodosTransferSections,
): TodosTransferReferenceClosureEntry[] {
  const direct = new Map<string, Set<string>>();
  const projectionsById = new Map<string, TodosTransferRecordRef[]>();
  for (const sectionName of TODOS_TRANSFER_SECTION_NAMES) {
    const section = sections[sectionName];
    for (const record of section.records as readonly { id: string }[]) {
      const ref = sectionName === "task_to_pr_projections"
        ? projectionTransferRecordRef(
          section.owner,
          record as TaskToPrProjection,
        )
        : transferRecordRef(section.owner, sectionName, record.id);
      direct.set(transferRecordKey(ref), new Set());
      if (sectionName === "task_to_pr_projections") {
        const idKey = stableTodosJson({
          owner: section.owner,
          section: sectionName,
          id: record.id,
        });
        projectionsById.set(idKey, [
          ...(projectionsById.get(idKey) ?? []),
          ref,
        ]);
      }
    }
  }
  const addReference = (
    source: TodosTransferRecordRef,
    target: TodosTransferRecordRef,
  ): void => {
    const sourceKey = transferRecordKey(source);
    const targets = direct.get(sourceKey) ?? new Set<string>();
    targets.add(transferRecordKey(target));
    direct.set(sourceKey, targets);
  };
  const add = (
    sourceSection: TodosTransferSectionName,
    sourceId: string,
    targetSection: TodosTransferSectionName,
    targetId: string | null,
    targetOwner = sections[targetSection].owner,
  ) => {
    if (!targetId) return;
    const source = transferRecordRef(
      sections[sourceSection].owner,
      sourceSection,
      sourceId,
    );
    const target = transferRecordRef(targetOwner, targetSection, targetId);
    if (targetSection === "task_to_pr_projections") {
      const projections = projectionsById.get(stableTodosJson(target));
      if (projections && projections.length > 0) {
        projections.forEach((projection) => addReference(source, projection));
        return;
      }
    }
    addReference(source, target);
  };
  const addOwnerRef = (
    sourceSection: TodosTransferSectionName,
    sourceId: string,
    ref: TodosOwnerQualifiedRef | null,
  ) => {
    if (!ref) return;
    const target = ownerRefTarget(ref);
    if (target) add(sourceSection, sourceId, target.section, target.id, target.owner);
  };

  for (const record of sections.task_lists.records) {
    add("task_lists", record.id, "projects", record.projectId);
  }
  for (const record of sections.plans.records) {
    add("plans", record.id, "projects", record.projectId);
    add("plans", record.id, "task_lists", record.taskListId);
    for (const taskId of record.taskIds) add("plans", record.id, "tasks", taskId);
  }
  for (const record of sections.tasks.records) {
    add("tasks", record.id, "projects", record.projectId);
    add("tasks", record.id, "task_lists", record.taskListId);
    add("tasks", record.id, "plans", record.planId);
    add("tasks", record.id, "tasks", record.parentTaskId);
  }
  for (const record of sections.comments.records) {
    add("comments", record.id, "tasks", record.taskId);
  }
  for (const record of sections.dependencies.records) {
    add("dependencies", record.id, "tasks", record.sourceTaskId);
    add("dependencies", record.id, "tasks", record.targetTaskId);
  }
  for (const record of sections.activities.records) {
    addOwnerRef("activities", record.id, record.resourceRef);
  }
  for (const record of sections.verification_evidence.records) {
    add("verification_evidence", record.id, "tasks", record.taskId);
    add("verification_evidence", record.id, "runs", record.runId);
  }
  for (const record of sections.task_files.records) {
    add("task_files", record.id, "tasks", record.taskId);
  }
  for (const record of sections.runs.records) {
    add("runs", record.id, "plans", record.planId);
    for (const taskId of record.taskIds) add("runs", record.id, "tasks", taskId);
  }
  for (const record of sections.run_events.records) {
    add("run_events", record.id, "runs", record.runId);
    for (const evidenceId of record.evidenceIds) {
      add("run_events", record.id, "verification_evidence", evidenceId);
    }
  }
  for (const record of sections.run_commands.records) {
    add("run_commands", record.id, "runs", record.runId);
  }
  for (const record of sections.run_files.records) {
    add("run_files", record.id, "runs", record.runId);
  }
  for (const record of sections.run_artifacts.records) {
    add("run_artifacts", record.id, "runs", record.runId);
    add(
      "run_artifacts",
      record.id,
      "verification_evidence",
      record.verificationEvidenceId,
    );
  }
  for (const record of sections.traceability.records) {
    add("traceability", record.id, "tasks", record.taskId);
    for (const id of record.commitIds) add("traceability", record.id, "git_commits", id);
    for (const id of record.gitRefIds) add("traceability", record.id, "git_refs", id);
    for (const id of record.verificationEvidenceIds) {
      add("traceability", record.id, "verification_evidence", id);
    }
    for (const id of record.projectionIds) {
      add("traceability", record.id, "task_to_pr_projections", id);
    }
  }
  for (const record of sections.task_to_pr_projections.records) {
    const source = projectionTransferRecordRef(
      sections.task_to_pr_projections.owner,
      record,
    );
    const taskTarget = ownerRefTarget(record.identity.taskRef);
    if (taskTarget) {
      addReference(source, transferRecordRef(
        taskTarget.owner,
        taskTarget.section,
        taskTarget.id,
      ));
    }
    if (record.predecessor) {
      addReference(source, {
        owner: record.predecessor.owner,
        section: "task_to_pr_projections",
        id: record.predecessor.projectionId,
        kind: record.predecessor.kind,
        version: record.predecessor.version,
        digest: record.predecessor.digest,
      });
    }
  }
  for (const record of sections.saved_views.records) {
    for (const id of record.query.filters.projectIds) add("saved_views", record.id, "projects", id);
    for (const id of record.query.filters.taskListIds) add("saved_views", record.id, "task_lists", id);
    for (const id of record.query.filters.planIds) add("saved_views", record.id, "plans", id);
  }
  for (const record of sections.approvals.records) {
    addOwnerRef("approvals", record.id, record.resourceRef);
  }

  const visit = (sourceKey: string): Set<string> => {
    const visited = new Set<string>([sourceKey]);
    const pending = [...(direct.get(sourceKey) ?? [])];
    while (pending.length > 0) {
      const target = pending.shift()!;
      if (visited.has(target)) continue;
      visited.add(target);
      pending.push(...(direct.get(target) ?? []));
    }
    visited.delete(sourceKey);
    return visited;
  };

  return [...direct.keys()]
    .sort((left, right) => left.localeCompare(right))
    .map((sourceKey) => ({
      source: parseTransferRecordKey(sourceKey),
      references: [...visit(sourceKey)]
        .sort((left, right) => left.localeCompare(right))
        .map(parseTransferRecordKey),
    }));
}

function externalOwnerRefKey(ref: TodosExternalOwnerRef): string {
  return `${ref.owner}\u0000${ref.id}\u0000${ref.digest}`;
}

function ownerQualifiedRefKey(ref: TodosOwnerQualifiedRef): string {
  return `${ref.owner}\u0000${ref.kind}\u0000${ref.id}\u0000${ref.digest}`;
}

function deriveReferenceOnly(
  owner: string,
  input: TodosTransferBundleWithDigestsInput["records"],
): TodosTransferReferenceOnly {
  const agentIds = uniqueSortedTodosStrings([
    ...input.tasks.flatMap((task) => task.assignedAgentId ? [task.assignedAgentId] : []),
    ...input.runs.flatMap((run) => run.agentId ? [run.agentId] : []),
    ...input.saved_views.flatMap((view) => view.query.filters.agentIds),
  ]);
  const refs = [
    ...input.tasks.flatMap((task) => task.externalOwnerRefs),
    ...input.projects.flatMap((project) => project.repositoryRef ? [project.repositoryRef] : []),
    ...input.comments.map((comment) => comment.authorRef),
    ...input.activities.map((activity) => activity.actorRef),
    ...input.verification_evidence.map((evidence) => evidence.verifierRef),
    ...input.git_commits.flatMap((commit) => [commit.repositoryRef, commit.authorRef]),
    ...input.git_refs.map((ref) => ref.repositoryRef),
    ...input.approvals.flatMap((approval) => [
      approval.requestedBy,
      ...(approval.decidedBy ? [approval.decidedBy] : []),
    ]),
  ];
  const byKey = new Map(refs.map((ref) => [externalOwnerRefKey(ref), ref]));
  const ownerQualifiedRefs = [
    ...input.activities.map((activity) => activity.resourceRef),
    ...input.approvals.map((approval) => approval.resourceRef),
    ...input.task_to_pr_projections.flatMap((projection) => [
      projection.identity.taskRef,
      projection.identity.repositoryRef,
      projection.identity.worktreeRef,
      projection.identity.branchRef,
      ...(projection.pullRequestRef ? [projection.pullRequestRef] : []),
      ...(projection.head.equalityProof ? [projection.head.equalityProof.ref] : []),
      ...projection.proofs.map((proof) => proof.ref),
    ]),
  ].filter((ref) => ownerRefTarget(ref) === null);
  const ownerQualifiedByKey = new Map(
    ownerQualifiedRefs.map((ref) => [ownerQualifiedRefKey(ref), ref]),
  );
  return {
    owner,
    agentIds,
    externalOwnerRefs: [...byKey.values()].sort((left, right) => externalOwnerRefKey(left).localeCompare(externalOwnerRefKey(right))),
    ownerQualifiedRefs: [...ownerQualifiedByKey.values()].sort(
      (left, right) => ownerQualifiedRefKey(left).localeCompare(ownerQualifiedRefKey(right)),
    ),
  };
}

function deriveAttachmentContentReferences(
  owner: string,
  input: TodosTransferBundleWithDigestsInput["records"],
): TodosAttachmentContentReference[] {
  return [
    ...input.verification_evidence.flatMap((evidence) => [
      ...evidence.contentRefs.map((contentRef, index) => ({
        owner,
        source: { section: "verification_evidence" as const, id: evidence.id },
        index,
        contentRef,
      })),
      ...evidence.commandReceipts.flatMap((receipt, receiptIndex) => (
        receipt.outputRefs.map((contentRef, outputIndex) => ({
          owner,
          source: { section: "verification_evidence" as const, id: evidence.id },
          index: evidence.contentRefs.length + receiptIndex * 1024 + outputIndex,
          contentRef,
        }))
      )),
    ]),
    ...input.task_files.map((file) => ({
      owner,
      source: { section: "task_files" as const, id: file.id },
      index: 0,
      contentRef: file.contentRef,
    })),
    ...input.run_commands.flatMap((command) => command.outputRefs.map((contentRef, index) => ({
      owner,
      source: { section: "run_commands" as const, id: command.id },
      index,
      contentRef,
    }))),
    ...input.run_files.map((file) => ({
      owner,
      source: { section: "run_files" as const, id: file.id },
      index: 0,
      contentRef: file.contentRef,
    })),
    ...input.run_artifacts.map((artifact) => ({
      owner,
      source: { section: "run_artifacts" as const, id: artifact.id },
      index: 0,
      contentRef: artifact.contentRef,
    })),
  ].sort((left, right) => stableTodosJson(left).localeCompare(stableTodosJson(right)));
}

function unsignedTransferBundle(value: TodosTransferBundle): TodosTransferBundleUnsigned {
  const { bundleChecksum: _bundleChecksum, ...unsigned } = value;
  return unsigned;
}

export function computeTodosTransferBundleChecksum(value: TodosTransferBundleUnsigned): string {
  return sha256TodosValue(value);
}

export function createTodosTransferBundleWithDigests(
  input: TodosTransferBundleWithDigestsInput,
): TodosTransferBundle {
  const owner = input.source.authorityId;
  const sections: TodosTransferSections = {
    projects: createSection(owner, input.records.projects),
    task_lists: createSection(owner, input.records.task_lists),
    plans: createSection(owner, input.records.plans),
    tasks: createSection(owner, input.records.tasks),
    comments: createSection(owner, input.records.comments),
    dependencies: createSection(owner, input.records.dependencies),
    activities: createSection(owner, input.records.activities),
    verification_evidence: createSection(owner, input.records.verification_evidence),
    task_files: createSection(owner, input.records.task_files),
    runs: createSection(owner, input.records.runs),
    run_events: createSection(owner, input.records.run_events),
    run_commands: createSection(owner, input.records.run_commands),
    run_files: createSection(owner, input.records.run_files),
    run_artifacts: createSection(owner, input.records.run_artifacts),
    git_commits: createSection(owner, input.records.git_commits),
    git_refs: createSection(owner, input.records.git_refs),
    traceability: createSection(owner, input.records.traceability),
    task_to_pr_projections: createSection(owner, input.records.task_to_pr_projections),
    saved_views: createSection(owner, input.records.saved_views),
    task_templates: createSection(owner, input.records.task_templates),
    approvals: createSection(owner, input.records.approvals),
    deletion_records: createSection(owner, input.records.deletion_records),
  };
  const unsigned: TodosTransferBundleUnsigned = {
    schema: TODOS_TRANSFER_SCHEMA_IDS.bundle,
    version: TODOS_TRANSFER_VERSION,
    bundleId: input.bundleId,
    createdAt: input.createdAt,
    source: input.source,
    contractVersion: TODOS_CONTRACT_VERSION,
    contractDigest: input.contractDigest,
    manifestVersion: TODOS_MANIFEST_VERSION,
    manifestDigest: input.manifestDigest,
    sections,
    dependencyClosure: computeTodosDependencyClosure(input.records.tasks, input.records.dependencies),
    referenceClosure: computeTodosTransferReferenceClosure(sections),
    attachmentContentReferences: deriveAttachmentContentReferences(owner, input.records),
    referenceOnly: deriveReferenceOnly(owner, input.records),
  };
  return TodosTransferBundleSchema.parse({
    ...unsigned,
    bundleChecksum: computeTodosTransferBundleChecksum(unsigned),
  });
}

export const TodosTransferIssueSchema = z.strictObject({
  code: z.enum([
    "invalid_bundle",
    "canonical_digest_mismatch",
    "count_mismatch",
    "section_digest_mismatch",
    "bundle_checksum_mismatch",
    "duplicate_record",
    "classification_mismatch",
    "missing_reference",
    "projection_history_mismatch",
    "dependency_cycle",
    "closure_mismatch",
    "reference_closure_mismatch",
    "attachment_reference_mismatch",
    "deletion_redaction_failure",
  ]),
  path: z.string().min(1).max(512),
  message: z.string().min(1).max(2048),
  repairable: z.boolean(),
});
export type TodosTransferIssue = z.infer<typeof TodosTransferIssueSchema>;

export const TodosTransferConflictSchema = z.strictObject({
  resourceKind: z.string().min(1).max(64),
  resourceId: TodosEntityIdSchema,
  reason: z.string().min(1).max(2048),
});
export type TodosTransferConflict = z.infer<typeof TodosTransferConflictSchema>;

export const TodosTransferRepairIssueSchema = z.strictObject({
  section: TodosTransferSectionNameSchema,
  resourceId: TodosEntityIdSchema.nullable(),
  action: z.enum([
    "supply_reference",
    "remove_cycle",
    "regenerate_digest",
    "regenerate_closure",
    "regenerate_reference_closure",
    "regenerate_classification",
  ]),
  reason: z.string().min(1).max(2048),
});
export type TodosTransferRepairIssue = z.infer<typeof TodosTransferRepairIssueSchema>;

export const TodosTransferValidationSchema = z.strictObject({
  schema: z.literal(TODOS_TRANSFER_SCHEMA_IDS.validation),
  dryRun: z.literal(true),
  valid: z.boolean(),
  issues: z.array(TodosTransferIssueSchema),
  conflicts: z.array(TodosTransferConflictSchema),
  repairIssues: z.array(TodosTransferRepairIssueSchema),
  verifiedCounts: z.record(z.string(), z.number().int().nonnegative()),
  verifiedDigests: z.record(z.string(), TodosSha256DigestSchema),
});
export type TodosTransferValidation = z.infer<typeof TodosTransferValidationSchema>;

function addTransferIssue(
  issues: TodosTransferIssue[],
  code: TodosTransferIssue["code"],
  path: string,
  message: string,
  repairable: boolean,
): void {
  issues.push({ code, path, message, repairable });
}

function sectionRecords(bundle: TodosTransferBundle, section: TodosTransferSectionName): readonly unknown[] {
  return bundle.sections[section].records;
}

const TRANSFER_SECTION_SCHEMA_IDS: Partial<
  Record<TodosTransferSectionName, keyof typeof TODOS_DOMAIN_FIELD_CLASSIFICATION>
> = Object.freeze({
  projects: TODOS_DOMAIN_SCHEMA_IDS.project,
  task_lists: TODOS_DOMAIN_SCHEMA_IDS.taskList,
  plans: TODOS_DOMAIN_SCHEMA_IDS.plan,
  tasks: TODOS_DOMAIN_SCHEMA_IDS.task,
  comments: TODOS_DOMAIN_SCHEMA_IDS.comment,
  dependencies: TODOS_DOMAIN_SCHEMA_IDS.dependency,
  activities: TODOS_DOMAIN_SCHEMA_IDS.activity,
  verification_evidence: TODOS_DOMAIN_SCHEMA_IDS.verificationEvidence,
  task_files: TODOS_DOMAIN_SCHEMA_IDS.taskFile,
  runs: TODOS_DOMAIN_SCHEMA_IDS.run,
  run_events: TODOS_DOMAIN_SCHEMA_IDS.runEvent,
  run_commands: TODOS_DOMAIN_SCHEMA_IDS.runCommand,
  run_files: TODOS_DOMAIN_SCHEMA_IDS.runFile,
  run_artifacts: TODOS_DOMAIN_SCHEMA_IDS.runArtifact,
  git_commits: TODOS_DOMAIN_SCHEMA_IDS.gitCommit,
  git_refs: TODOS_DOMAIN_SCHEMA_IDS.gitRef,
  traceability: TODOS_DOMAIN_SCHEMA_IDS.traceability,
  saved_views: TODOS_DOMAIN_SCHEMA_IDS.savedView,
  task_templates: TODOS_DOMAIN_SCHEMA_IDS.taskTemplate,
  approvals: TODOS_DOMAIN_SCHEMA_IDS.approval,
  deletion_records: TODOS_DOMAIN_SCHEMA_IDS.deletionRecord,
});

function recordsFromBundle(
  bundle: TodosTransferBundle,
): TodosTransferBundleWithDigestsInput["records"] {
  return Object.fromEntries(
    TODOS_TRANSFER_SECTION_NAMES.map((name) => [name, sectionRecords(bundle, name)]),
  ) as unknown as TodosTransferBundleWithDigestsInput["records"];
}

const TRANSFER_FIELD_CLASSIFICATION_OVERRIDES: Partial<
  Record<TodosTransferSectionName, Readonly<Record<string, "portable" | "reference_only" | "excluded">>>
> = Object.freeze({
  verification_evidence: Object.freeze({
    id: "portable",
    owner: "portable",
    version: "portable",
    createdAt: "portable",
    updatedAt: "portable",
    taskId: "portable",
    runId: "portable",
    verifierRef: "reference_only",
    status: "portable",
    summary: "portable",
    confidence: "portable",
    commandReceipts: "portable",
    checks: "portable",
    contentRefs: "portable",
    startedAt: "portable",
    completedAt: "portable",
  }),
  task_files: Object.freeze({
    id: "portable",
    owner: "portable",
    version: "portable",
    createdAt: "portable",
    updatedAt: "portable",
    taskId: "portable",
    logicalName: "portable",
    contentRef: "portable",
    purpose: "portable",
  }),
  run_commands: Object.freeze({
    id: "portable",
    owner: "portable",
    version: "portable",
    createdAt: "portable",
    updatedAt: "portable",
    runId: "portable",
    sequence: "portable",
    commandDigest: "portable",
    argumentsDigest: "portable",
    exitCode: "portable",
    durationMs: "portable",
    outputRefs: "portable",
    completedAt: "portable",
  }),
  run_files: Object.freeze({
    id: "portable",
    owner: "portable",
    version: "portable",
    createdAt: "portable",
    updatedAt: "portable",
    runId: "portable",
    logicalName: "portable",
    contentRef: "portable",
    role: "portable",
  }),
  run_artifacts: Object.freeze({
    id: "portable",
    owner: "portable",
    version: "portable",
    createdAt: "portable",
    updatedAt: "portable",
    runId: "portable",
    logicalName: "portable",
    kind: "portable",
    contentRef: "portable",
    verified: "portable",
    verificationEvidenceId: "portable",
  }),
  git_commits: Object.freeze({
    id: "portable",
    owner: "portable",
    version: "portable",
    createdAt: "portable",
    updatedAt: "portable",
    repositoryRef: "reference_only",
    objectId: "portable",
    message: "portable",
    authorRef: "reference_only",
    committedAt: "portable",
    changedFileDigests: "portable",
  }),
  task_to_pr_projections: Object.freeze({
    schema: "portable",
    id: "portable",
    owner: "portable",
    version: "portable",
    sequence: "portable",
    predecessor: "portable",
    identity: "portable",
    pullRequestRef: "portable",
    head: "portable",
    proofs: "portable",
    derivedAt: "portable",
    digest: "portable",
  }),
});

function validateTransferClassification(
  bundle: TodosTransferBundle,
  issues: TodosTransferIssue[],
  repairIssues: TodosTransferRepairIssue[],
): void {
  for (const sectionName of TODOS_TRANSFER_SECTION_NAMES) {
    const records = bundle.sections[sectionName].records as readonly Record<string, unknown>[];
    const seenIds = new Set<string>();
    for (const [index, record] of records.entries()) {
      const recordId = typeof record.id === "string" ? record.id : null;
      const recordIdentity = (
        sectionName === "task_to_pr_projections"
        && typeof record.version === "number"
      )
        ? `${recordId}\u0000${record.version}`
        : recordId;
      if (recordIdentity && seenIds.has(recordIdentity)) {
        addTransferIssue(
          issues,
          "duplicate_record",
          `sections.${sectionName}.records.${index}.id`,
          sectionName === "task_to_pr_projections"
            ? `Section contains duplicate projection id and version: ${recordId}@${record.version}`
            : `Section contains duplicate record id: ${recordId}`,
          false,
        );
      }
      if (recordIdentity) seenIds.add(recordIdentity);

      const schemaId = TRANSFER_SECTION_SCHEMA_IDS[sectionName];
      const classification = TRANSFER_FIELD_CLASSIFICATION_OVERRIDES[sectionName]
        ?? (schemaId ? TODOS_DOMAIN_FIELD_CLASSIFICATION[schemaId] : undefined);
      if (!classification) continue;
      for (const field of Object.keys(record)) {
        const fieldClass = classification[field];
        if (!fieldClass || fieldClass === "excluded") {
          addTransferIssue(
            issues,
            "classification_mismatch",
            `sections.${sectionName}.records.${index}.${field}`,
            fieldClass === "excluded"
              ? "Excluded fields cannot enter a transfer bundle"
              : "Record field is absent from the transfer classification registry",
            false,
          );
        }
      }
    }
  }

  const expectedReferenceOnly = deriveReferenceOnly(
    bundle.source.authorityId,
    recordsFromBundle(bundle),
  );
  if (stableTodosJson(bundle.referenceOnly) !== stableTodosJson(expectedReferenceOnly)) {
    addTransferIssue(
      issues,
      "classification_mismatch",
      "referenceOnly",
      "Reference-only identities do not exactly match the classified record fields",
      true,
    );
    repairIssues.push({
      section: "tasks",
      resourceId: null,
      action: "regenerate_classification",
      reason: "Recompute the reference-only identity inventory from classified fields",
    });
  }
}

function validateReferences(bundle: TodosTransferBundle, issues: TodosTransferIssue[]): void {
  const existing = new Set<string>();
  for (const sectionName of TODOS_TRANSFER_SECTION_NAMES) {
    for (const record of bundle.sections[sectionName].records as readonly {
      id: string;
      version?: number;
      digest?: string;
    }[]) {
      const owner = bundle.sections[sectionName].owner;
      existing.add(transferRecordKey(transferRecordRef(owner, sectionName, record.id)));
      if (
        sectionName === "task_to_pr_projections"
        && record.version !== undefined
        && record.digest !== undefined
      ) {
        existing.add(transferRecordKey({
          owner,
          section: sectionName,
          id: record.id,
          kind: "task_to_pr_projection",
          version: record.version,
          digest: record.digest,
        }));
      }
    }
  }
  const expectedClosure = computeTodosTransferReferenceClosure(bundle.sections);
  for (const entry of expectedClosure) {
    for (const reference of entry.references) {
      if (!existing.has(transferRecordKey(reference))) {
        addTransferIssue(
          issues,
          "missing_reference",
          `referenceClosure.${entry.source.section}.${entry.source.id}`,
          `Referenced ${reference.section} record is missing: ${reference.id}`,
          true,
        );
      }
    }
  }
}

function validateTransferredProjectionHistories(
  bundle: TodosTransferBundle,
  issues: TodosTransferIssue[],
): void {
  const histories = new Map<string, TaskToPrProjection[]>();
  for (const projection of bundle.sections.task_to_pr_projections.records) {
    const key = stableTodosJson({
      owner: projection.owner,
      id: projection.id,
    });
    histories.set(key, [
      ...(histories.get(key) ?? []),
      projection,
    ]);
  }
  for (const history of histories.values()) {
    const ordered = [...history].sort((left, right) => left.version - right.version);
    const result = validateTaskToPrProjectionHistory(ordered, {
      expectedOwner: bundle.source.authorityId,
    });
    if (result.success) continue;
    for (const issue of result.issues) {
      addTransferIssue(
        issues,
        "projection_history_mismatch",
        `sections.task_to_pr_projections.${ordered[0]?.id ?? "unknown"}.${issue.path}`,
        issue.reason,
        false,
      );
    }
  }
}

function closureContainsCycle(closure: readonly TodosDependencyClosureEntry[]): boolean {
  return closure.some((entry) => entry.dependencyTaskIds.includes(entry.taskId));
}

// @todos-runtime-validator transfer.integrity
export function validateTodosTransferBundleIntegrity(input: unknown): TodosTransferValidation {
  const parsed = TodosTransferBundleSchema.safeParse(input);
  if (!parsed.success) {
    return TodosTransferValidationSchema.parse({
      schema: TODOS_TRANSFER_SCHEMA_IDS.validation,
      dryRun: true,
      valid: false,
      issues: parsed.error.issues.map((issue) => ({
        code: "invalid_bundle",
        path: issue.path.join(".") || "bundle",
        message: issue.message,
        repairable: false,
      })),
      conflicts: [],
      repairIssues: [],
      verifiedCounts: {},
      verifiedDigests: {},
    });
  }

  const bundle = parsed.data;
  const issues: TodosTransferIssue[] = [];
  const repairIssues: TodosTransferRepairIssue[] = [];
  const verifiedCounts: Record<string, number> = {};
  const verifiedDigests: Record<string, string> = {};

  for (const sectionName of TODOS_TRANSFER_SECTION_NAMES) {
    const section = bundle.sections[sectionName];
    verifiedCounts[sectionName] = section.records.length;
    const digest = sha256TodosValue(section.records);
    verifiedDigests[sectionName] = digest;
    if (section.count !== section.records.length) {
      addTransferIssue(
        issues,
        "count_mismatch",
        `sections.${sectionName}.count`,
        "Section count does not match its records",
        true,
      );
    }
    if (section.digest !== digest) {
      addTransferIssue(
        issues,
        "section_digest_mismatch",
        `sections.${sectionName}.digest`,
        "Section digest does not match its canonical records",
        true,
      );
      repairIssues.push({
        section: sectionName,
        resourceId: null,
        action: "regenerate_digest",
        reason: "Recompute the section digest from canonical records",
      });
    }
  }

  const expectedBundleChecksum = computeTodosTransferBundleChecksum(unsignedTransferBundle(bundle));
  if (bundle.bundleChecksum !== expectedBundleChecksum) {
    addTransferIssue(
      issues,
      "bundle_checksum_mismatch",
      "bundleChecksum",
      "Bundle checksum does not match canonical bundle content",
      true,
    );
  }

  validateTransferClassification(bundle, issues, repairIssues);
  validateReferences(bundle, issues);
  validateTransferredProjectionHistories(bundle, issues);
  const expectedClosure = computeTodosDependencyClosure(
    bundle.sections.tasks.records,
    bundle.sections.dependencies.records,
  );
  if (closureContainsCycle(expectedClosure)) {
    addTransferIssue(
      issues,
      "dependency_cycle",
      "dependencyClosure",
      "Dependency graph contains a cycle",
      true,
    );
    repairIssues.push({
      section: "dependencies",
      resourceId: null,
      action: "remove_cycle",
      reason: "Remove at least one dependency edge from every cycle",
    });
  }
  if (stableTodosJson(bundle.dependencyClosure) !== stableTodosJson(expectedClosure)) {
    addTransferIssue(
      issues,
      "closure_mismatch",
      "dependencyClosure",
      "Dependency closure does not match dependency records",
      true,
    );
    repairIssues.push({
      section: "dependencies",
      resourceId: null,
      action: "regenerate_closure",
      reason: "Recompute transitive dependency closure",
    });
  }

  const expectedReferenceClosure = computeTodosTransferReferenceClosure(bundle.sections);
  if (stableTodosJson(bundle.referenceClosure) !== stableTodosJson(expectedReferenceClosure)) {
    addTransferIssue(
      issues,
      "reference_closure_mismatch",
      "referenceClosure",
      "Transitive reference closure does not match all portable foreign keys",
      true,
    );
    repairIssues.push({
      section: "tasks",
      resourceId: null,
      action: "regenerate_reference_closure",
      reason: "Recompute the complete portable-record reference closure",
    });
  }

  const expectedAttachments = deriveAttachmentContentReferences(
    bundle.source.authorityId,
    recordsFromBundle(bundle),
  );
  if (stableTodosJson(bundle.attachmentContentReferences) !== stableTodosJson(expectedAttachments)) {
    addTransferIssue(
      issues,
      "attachment_reference_mismatch",
      "attachmentContentReferences",
      "Attachment content references do not match file and artifact sections",
      true,
    );
  }
  const attachmentSources = bundle.attachmentContentReferences.map(
    (reference) => (
      `${reference.owner}\u0000${reference.source.section}\u0000`
      + `${reference.source.id}\u0000${reference.index}`
    ),
  );
  if (new Set(attachmentSources).size !== attachmentSources.length) {
    addTransferIssue(
      issues,
      "attachment_reference_mismatch",
      "attachmentContentReferences",
      "Attachment sources must each have exactly one content-addressed reference",
      false,
    );
  }
  for (const [index, record] of bundle.sections.deletion_records.records.entries()) {
    if (record.redaction !== "full") {
      addTransferIssue(
        issues,
        "deletion_redaction_failure",
        `sections.deletion_records.records.${index}.redaction`,
        "Deletion records must remain fully redacted",
        false,
      );
    }
  }

  return TodosTransferValidationSchema.parse({
    schema: TODOS_TRANSFER_SCHEMA_IDS.validation,
    dryRun: true,
    valid: issues.length === 0,
    issues,
    conflicts: [],
    repairIssues,
    verifiedCounts,
    verifiedDigests,
  });
}

// @todos-runtime-validator transfer.import_plan_digest
export const TodosTransferImportPreviewSchema = z.strictObject({
  schema: z.literal(TODOS_TRANSFER_SCHEMA_IDS.importPreview),
  dryRun: z.literal(true),
  sourceAuthorityId: TodosOwnerIdSchema,
  bundleId: TodosEntityIdSchema,
  bundleChecksum: TodosSha256DigestSchema,
  contractDigest: TodosSha256DigestSchema,
  manifestDigest: TodosSha256DigestSchema,
  targetAuthorityId: TodosOwnerIdSchema,
  importPlanId: TodosEntityIdSchema,
  valid: z.boolean(),
  conflicts: z.array(TodosTransferConflictSchema),
  repairIssues: z.array(TodosTransferRepairIssueSchema),
  sectionCounts: z.record(z.string(), z.number().int().nonnegative()),
  importPlanDigest: TodosSha256DigestSchema,
}).superRefine((value, ctx) => {
  const expectedPlanId = computeTodosImportPlanId(value);
  if (value.importPlanId !== expectedPlanId) {
    ctx.addIssue({
      code: "custom",
      message: "Import plan id does not match its source, target, bundle, and canonical digests",
      path: ["importPlanId"],
    });
  }
  const {
    importPlanDigest: _importPlanDigest,
    ...unsigned
  } = value;
  if (value.importPlanDigest !== sha256TodosValue(unsigned)) {
    ctx.addIssue({
      code: "custom",
      message: "Import plan digest does not match canonical preview content",
      path: ["importPlanDigest"],
    });
  }
});
export type TodosTransferImportPreview = z.infer<typeof TodosTransferImportPreviewSchema>;

export interface TodosImportPlanIdentityInput {
  sourceAuthorityId: string;
  targetAuthorityId: string;
  bundleId: string;
  bundleChecksum: string;
  contractDigest: string;
  manifestDigest: string;
}

export function computeTodosImportPlanId(
  input: TodosImportPlanIdentityInput,
): string {
  return `import-plan:${sha256TodosValue({
    sourceAuthorityId: input.sourceAuthorityId,
    targetAuthorityId: input.targetAuthorityId,
    bundleId: input.bundleId,
    bundleChecksum: input.bundleChecksum,
    contractDigest: input.contractDigest,
    manifestDigest: input.manifestDigest,
  })}`;
}

export function createTodosTransferImportPreviewIntegrity(
  bundle: TodosTransferBundle,
  targetAuthorityId: string,
  conflicts: TodosTransferConflict[] = [],
  validation = validateTodosTransferBundleIntegrity(bundle),
): TodosTransferImportPreview {
  const unsigned = {
    schema: TODOS_TRANSFER_SCHEMA_IDS.importPreview,
    dryRun: true,
    sourceAuthorityId: bundle.source.authorityId,
    bundleId: bundle.bundleId,
    bundleChecksum: bundle.bundleChecksum,
    contractDigest: bundle.contractDigest,
    manifestDigest: bundle.manifestDigest,
    targetAuthorityId,
    importPlanId: computeTodosImportPlanId({
      sourceAuthorityId: bundle.source.authorityId,
      targetAuthorityId,
      bundleId: bundle.bundleId,
      bundleChecksum: bundle.bundleChecksum,
      contractDigest: bundle.contractDigest,
      manifestDigest: bundle.manifestDigest,
    }),
    valid: validation.valid && conflicts.length === 0,
    conflicts,
    repairIssues: validation.repairIssues,
    sectionCounts: validation.verifiedCounts,
  } as const;
  return TodosTransferImportPreviewSchema.parse({
    ...unsigned,
    importPlanDigest: sha256TodosValue(unsigned),
  });
}

// @todos-runtime-validator transfer.checkpoint_record
export const TodosTransferCheckpointSchema = z.strictObject({
  schema: z.literal(TODOS_TRANSFER_SCHEMA_IDS.checkpoint),
  sourceAuthorityId: TodosOwnerIdSchema,
  bundleId: TodosEntityIdSchema,
  bundleChecksum: TodosSha256DigestSchema,
  importPlanId: TodosEntityIdSchema,
  importPlanDigest: TodosSha256DigestSchema,
  contractDigest: TodosSha256DigestSchema,
  manifestDigest: TodosSha256DigestSchema,
  targetAuthorityId: TodosOwnerIdSchema,
  idempotencyKey: TodosIdempotencyKeySchema,
  sequence: z.number().int().nonnegative(),
  completedSections: z.array(TodosTransferSectionNameSchema),
  nextSection: TodosTransferSectionNameSchema.nullable(),
  state: z.enum(["pending", "interrupted", "committed"]),
  digest: TodosSha256DigestSchema,
}).superRefine((value, ctx) => {
  if (value.importPlanId !== computeTodosImportPlanId(value)) {
    ctx.addIssue({
      code: "custom",
      message: "Checkpoint import plan id does not match its source, target, bundle, and digests",
      path: ["importPlanId"],
    });
  }
  if (new Set(value.completedSections).size !== value.completedSections.length) {
    ctx.addIssue({
      code: "custom",
      message: "Checkpoint completed sections must be unique",
      path: ["completedSections"],
    });
  }
  const expectedCompleted = TODOS_TRANSFER_SECTION_NAMES.slice(
    0,
    value.completedSections.length,
  );
  if (stableTodosJson(value.completedSections) !== stableTodosJson(expectedCompleted)) {
    ctx.addIssue({
      code: "custom",
      message: "Checkpoint completed sections must be the canonical section-order prefix",
      path: ["completedSections"],
    });
  }
  if (value.sequence !== value.completedSections.length) {
    ctx.addIssue({
      code: "custom",
      message: "Checkpoint sequence must equal the number of completed sections",
      path: ["sequence"],
    });
  }
  const expectedNext = TODOS_TRANSFER_SECTION_NAMES[value.completedSections.length] ?? null;
  if (value.state === "committed") {
    if (
      value.completedSections.length !== TODOS_TRANSFER_SECTION_NAMES.length
      || value.nextSection !== null
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Committed checkpoints must contain every section and no next section",
        path: ["state"],
      });
    }
  } else if (value.nextSection !== expectedNext) {
    ctx.addIssue({
      code: "custom",
      message: "Non-terminal checkpoints must identify the next canonical section",
      path: ["nextSection"],
    });
  }
  if (
    value.state === "pending"
    && (value.sequence !== 0 || value.completedSections.length !== 0)
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Pending is the initial checkpoint state only",
      path: ["state"],
    });
  }
  if (value.state === "interrupted" && value.sequence === 0) {
    ctx.addIssue({
      code: "custom",
      message: "Interrupted checkpoints must contain completed progress",
      path: ["state"],
    });
  }
  const expected = sha256TodosValue({
    schema: value.schema,
    sourceAuthorityId: value.sourceAuthorityId,
    bundleId: value.bundleId,
    bundleChecksum: value.bundleChecksum,
    importPlanId: value.importPlanId,
    importPlanDigest: value.importPlanDigest,
    contractDigest: value.contractDigest,
    manifestDigest: value.manifestDigest,
    targetAuthorityId: value.targetAuthorityId,
    idempotencyKey: value.idempotencyKey,
    sequence: value.sequence,
    completedSections: value.completedSections,
    nextSection: value.nextSection,
    state: value.state,
  });
  if (value.digest !== expected) {
    ctx.addIssue({
      code: "custom",
      message: "Checkpoint digest does not match canonical checkpoint content",
      path: ["digest"],
    });
  }
});
export type TodosTransferCheckpoint = z.infer<typeof TodosTransferCheckpointSchema>;

export interface TodosTransferCheckpointInput {
  sourceAuthorityId: string;
  bundleId: string;
  bundleChecksum: string;
  importPlanId: string;
  importPlanDigest: string;
  contractDigest: string;
  manifestDigest: string;
  targetAuthorityId: string;
  idempotencyKey: string;
  sequence: number;
  completedSections: TodosTransferSectionName[];
  nextSection: TodosTransferSectionName | null;
  state: "pending" | "interrupted" | "committed";
}

export function createTodosTransferCheckpoint(input: TodosTransferCheckpointInput): TodosTransferCheckpoint {
  const unsigned = {
    schema: TODOS_TRANSFER_SCHEMA_IDS.checkpoint,
    ...input,
    completedSections: [...input.completedSections],
  } as const;
  return TodosTransferCheckpointSchema.parse({
    ...unsigned,
    digest: sha256TodosValue(unsigned),
  });
}

// @todos-runtime-validator transfer.checkpoint_transition
export function validateTodosTransferCheckpointTransition(
  previousInput: unknown,
  currentInput: unknown,
): boolean {
  const previousParsed = TodosTransferCheckpointSchema.safeParse(previousInput);
  const currentParsed = TodosTransferCheckpointSchema.safeParse(currentInput);
  if (!previousParsed.success || !currentParsed.success) {
    return false;
  }
  const previous = previousParsed.data;
  const current = currentParsed.data;
  if (
    previous.bundleId !== current.bundleId
    || previous.sourceAuthorityId !== current.sourceAuthorityId
    || previous.bundleChecksum !== current.bundleChecksum
    || previous.importPlanId !== current.importPlanId
    || previous.importPlanDigest !== current.importPlanDigest
    || previous.contractDigest !== current.contractDigest
    || previous.manifestDigest !== current.manifestDigest
    || previous.targetAuthorityId !== current.targetAuthorityId
    || previous.idempotencyKey !== current.idempotencyKey
    || current.sequence !== previous.sequence + 1
    || previous.state === "committed"
  ) {
    return false;
  }
  return current.completedSections.length === previous.completedSections.length + 1
    && previous.completedSections.every(
      (section, index) => current.completedSections[index] === section,
    )
    && current.completedSections[current.completedSections.length - 1]
      === previous.nextSection;
}

// @todos-runtime-validator transfer.execution_request
export const TodosTransferImportExecutionSchema = z.strictObject({
  schema: z.literal(TODOS_TRANSFER_SCHEMA_IDS.importExecution),
  sourceAuthorityId: TodosOwnerIdSchema,
  bundleId: TodosEntityIdSchema,
  bundleChecksum: TodosSha256DigestSchema,
  importPlanId: TodosEntityIdSchema,
  importPlanDigest: TodosSha256DigestSchema,
  contractDigest: TodosSha256DigestSchema,
  manifestDigest: TodosSha256DigestSchema,
  targetAuthorityId: TodosOwnerIdSchema,
  idempotencyKey: TodosIdempotencyKeySchema,
  checkpoint: TodosTransferCheckpointSchema.nullable(),
}).superRefine((value, ctx) => {
  if (value.importPlanId !== computeTodosImportPlanId(value)) {
    ctx.addIssue({
      code: "custom",
      message: "Execution import plan id does not match its source, target, bundle, and digests",
      path: ["importPlanId"],
    });
  }
  if (!value.checkpoint) return;
  for (const [field, checkpointValue] of [
    ["sourceAuthorityId", value.checkpoint.sourceAuthorityId],
    ["bundleId", value.checkpoint.bundleId],
    ["bundleChecksum", value.checkpoint.bundleChecksum],
    ["importPlanId", value.checkpoint.importPlanId],
    ["importPlanDigest", value.checkpoint.importPlanDigest],
    ["contractDigest", value.checkpoint.contractDigest],
    ["manifestDigest", value.checkpoint.manifestDigest],
    ["targetAuthorityId", value.checkpoint.targetAuthorityId],
    ["idempotencyKey", value.checkpoint.idempotencyKey],
  ] as const) {
    if (value[field] !== checkpointValue) {
      ctx.addIssue({
        code: "custom",
        message: `Execution ${field} must match its checkpoint`,
        path: ["checkpoint", field],
      });
    }
  }
});
export type TodosTransferImportExecution = z.infer<typeof TodosTransferImportExecutionSchema>;

// @todos-runtime-validator transfer.receipt_record
export const TodosMigrationReceiptSchema = z.strictObject({
  schema: z.literal(TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt),
  id: TodosEntityIdSchema,
  receiptSequence: z.number().int().positive(),
  previousReceiptDigest: TodosSha256DigestSchema.nullable(),
  sourceAuthorityId: TodosOwnerIdSchema,
  targetAuthorityId: TodosOwnerIdSchema,
  bundleId: TodosEntityIdSchema,
  bundleChecksum: TodosSha256DigestSchema,
  importPlanId: TodosEntityIdSchema,
  importPlanDigest: TodosSha256DigestSchema,
  contractDigest: TodosSha256DigestSchema,
  manifestDigest: TodosSha256DigestSchema,
  idempotencyKey: TodosIdempotencyKeySchema,
  status: z.literal("committed"),
  importedCounts: z.record(z.string(), z.number().int().nonnegative()),
  checkpoint: TodosTransferCheckpointSchema,
  committedAt: TodosTimestampSchema,
  receiptDigest: TodosSha256DigestSchema,
}).superRefine((value, ctx) => {
  if (
    (value.receiptSequence === 1 && value.previousReceiptDigest !== null)
    || (value.receiptSequence > 1 && value.previousReceiptDigest === null)
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Receipt sequence and previous receipt digest must form a chain",
      path: ["previousReceiptDigest"],
    });
  }
  if (
    value.checkpoint.state !== "committed"
    || value.checkpoint.sourceAuthorityId !== value.sourceAuthorityId
    || value.checkpoint.bundleId !== value.bundleId
    || value.checkpoint.bundleChecksum !== value.bundleChecksum
    || value.checkpoint.importPlanId !== value.importPlanId
    || value.checkpoint.importPlanDigest !== value.importPlanDigest
    || value.checkpoint.contractDigest !== value.contractDigest
    || value.checkpoint.manifestDigest !== value.manifestDigest
    || value.checkpoint.targetAuthorityId !== value.targetAuthorityId
    || value.checkpoint.idempotencyKey !== value.idempotencyKey
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Receipt must bind one committed terminal checkpoint",
      path: ["checkpoint"],
    });
  }
  const importedSections = Object.keys(value.importedCounts).sort(
    (left, right) => left.localeCompare(right),
  );
  const expectedSections = [...TODOS_TRANSFER_SECTION_NAMES].sort(
    (left, right) => left.localeCompare(right),
  );
  if (stableTodosJson(importedSections) !== stableTodosJson(expectedSections)) {
    ctx.addIssue({
      code: "custom",
      message: "Receipt imported counts must cover every portable section exactly",
      path: ["importedCounts"],
    });
  }
  const expected = sha256TodosValue({
    schema: value.schema,
    id: value.id,
    receiptSequence: value.receiptSequence,
    previousReceiptDigest: value.previousReceiptDigest,
    sourceAuthorityId: value.sourceAuthorityId,
    targetAuthorityId: value.targetAuthorityId,
    bundleId: value.bundleId,
    bundleChecksum: value.bundleChecksum,
    importPlanId: value.importPlanId,
    importPlanDigest: value.importPlanDigest,
    contractDigest: value.contractDigest,
    manifestDigest: value.manifestDigest,
    idempotencyKey: value.idempotencyKey,
    status: value.status,
    importedCounts: value.importedCounts,
    checkpoint: value.checkpoint,
    committedAt: value.committedAt,
  });
  if (value.receiptDigest !== expected) {
    ctx.addIssue({
      code: "custom",
      message: "Receipt digest does not match canonical receipt content",
      path: ["receiptDigest"],
    });
  }
});
export type TodosMigrationReceipt = z.infer<typeof TodosMigrationReceiptSchema>;

export interface TodosMigrationReceiptInput {
  id: string;
  receiptSequence: number;
  previousReceiptDigest: string | null;
  sourceAuthorityId: string;
  targetAuthorityId: string;
  bundleId: string;
  bundleChecksum: string;
  importPlanId: string;
  importPlanDigest: string;
  contractDigest: string;
  manifestDigest: string;
  idempotencyKey: string;
  importedCounts: Record<string, number>;
  checkpoint: TodosTransferCheckpoint;
  committedAt: string;
}

export function createTodosMigrationReceipt(input: TodosMigrationReceiptInput): TodosMigrationReceipt {
  const unsigned = {
    schema: TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt,
    ...input,
    status: "committed" as const,
  };
  return TodosMigrationReceiptSchema.parse({
    ...unsigned,
    receiptDigest: sha256TodosValue(unsigned),
  });
}

export type TodosMigrationReceiptChainValidation =
  | {
    success: true;
    action: "valid";
    canonicalReceiptCount: number;
  }
  | {
    success: true;
    action: "replay";
    canonicalReceiptCount: number;
    receipt: TodosMigrationReceipt;
  }
  | {
    success: false;
    action: "conflict";
    issues: string[];
  };

function migrationReceiptIdempotencyTuple(
  receipt: TodosMigrationReceipt,
): unknown {
  return {
    sourceAuthorityId: receipt.sourceAuthorityId,
    targetAuthorityId: receipt.targetAuthorityId,
    bundleId: receipt.bundleId,
    bundleChecksum: receipt.bundleChecksum,
    importPlanId: receipt.importPlanId,
    importPlanDigest: receipt.importPlanDigest,
    contractDigest: receipt.contractDigest,
    manifestDigest: receipt.manifestDigest,
    terminalResult: {
      status: receipt.status,
      importedCounts: receipt.importedCounts,
      checkpointDigest: receipt.checkpoint.digest,
    },
  };
}

// @todos-runtime-validator transfer.receipt_chain
export function validateTodosMigrationReceiptChain(
  input: unknown,
): TodosMigrationReceiptChainValidation {
  if (!Array.isArray(input)) {
    return {
      success: false,
      action: "conflict",
      issues: ["Receipt chain must be an array"],
    };
  }
  const receipts: TodosMigrationReceipt[] = [];
  const issues: string[] = [];
  for (const [index, value] of input.entries()) {
    const parsed = TodosMigrationReceiptSchema.safeParse(value);
    if (!parsed.success) {
      issues.push(
        ...parsed.error.issues.map(
          (issue) => `receipts.${index}.${issue.path.join(".")}: ${issue.message}`,
        ),
      );
    } else {
      receipts.push(parsed.data);
    }
  }
  if (issues.length > 0) {
    return { success: false, action: "conflict", issues };
  }
  const ids = new Set<string>();
  const digests = new Set<string>();
  const receiptsByIdempotencyKey = new Map<string, TodosMigrationReceipt>();
  const canonicalReceipts: TodosMigrationReceipt[] = [];
  let replayReceipt: TodosMigrationReceipt | null = null;
  for (const [index, receipt] of receipts.entries()) {
    const existingForKey = receiptsByIdempotencyKey.get(receipt.idempotencyKey);
    if (existingForKey) {
      if (stableTodosJson(existingForKey) === stableTodosJson(receipt)) {
        if (index !== receipts.length - 1) {
          issues.push(
            `receipts.${index}: an exact receipt replay cannot precede another chain entry`,
          );
        } else {
          replayReceipt = existingForKey;
        }
      } else if (
        stableTodosJson(migrationReceiptIdempotencyTuple(existingForKey))
        === stableTodosJson(migrationReceiptIdempotencyTuple(receipt))
      ) {
        issues.push(
          `receipts.${index}.idempotencyKey: duplicate committed receipt for one canonical import tuple`,
        );
      } else {
        issues.push(
          `receipts.${index}.idempotencyKey: key is already bound to a different canonical import tuple`,
        );
      }
      continue;
    }
    if (ids.has(receipt.id)) {
      issues.push(`receipts.${index}.id: duplicate receipt id`);
    }
    if (digests.has(receipt.receiptDigest)) {
      issues.push(`receipts.${index}.receiptDigest: duplicate receipt digest`);
    }
    const previous = canonicalReceipts[canonicalReceipts.length - 1];
    if (canonicalReceipts.length === 0) {
      if (receipt.receiptSequence !== 1 || receipt.previousReceiptDigest !== null) {
        issues.push("receipts.0: chain must start at sequence one without a predecessor");
      }
    } else if (
      !previous
      || receipt.receiptSequence !== previous.receiptSequence + 1
      || receipt.previousReceiptDigest !== previous.receiptDigest
      || receipt.sourceAuthorityId !== previous.sourceAuthorityId
      || receipt.targetAuthorityId !== previous.targetAuthorityId
      || receipt.contractDigest !== previous.contractDigest
      || receipt.manifestDigest !== previous.manifestDigest
    ) {
      issues.push(`receipts.${index}: receipt predecessor linkage is invalid`);
    }
    ids.add(receipt.id);
    digests.add(receipt.receiptDigest);
    receiptsByIdempotencyKey.set(receipt.idempotencyKey, receipt);
    canonicalReceipts.push(receipt);
  }
  if (issues.length > 0) {
    return { success: false, action: "conflict", issues };
  }
  if (replayReceipt) {
    return {
      success: true,
      action: "replay",
      canonicalReceiptCount: canonicalReceipts.length,
      receipt: replayReceipt,
    };
  }
  return {
    success: true,
    action: "valid",
    canonicalReceiptCount: canonicalReceipts.length,
  };
}

export type TodosImportExecutionDecision =
  | { action: "commit" }
  | { action: "replay"; receipt: TodosMigrationReceipt }
  | { action: "reject"; error: TodosError };

// @todos-runtime-validator transfer.execution_context
export const TodosTransferExecutionContextSchema = z.discriminatedUnion("state", [
  z.strictObject({
    state: z.literal("uncommitted"),
  }),
  z.strictObject({
    state: z.literal("committed"),
    receipt: TodosMigrationReceiptSchema,
  }),
]);
export type TodosTransferExecutionContext =
  z.infer<typeof TodosTransferExecutionContextSchema>;

// @todos-runtime-validator transfer.execution_replay
export function evaluateTodosImportExecutionIntegrity(
  requestInput: unknown,
  contextInput: unknown,
): TodosImportExecutionDecision {
  const request = TodosTransferImportExecutionSchema.safeParse(requestInput);
  if (!request.success) {
    return {
      action: "reject",
      error: createTodosError("TODOS_TRANSFER_INVALID", "Import execution request is invalid"),
    };
  }
  const context = TodosTransferExecutionContextSchema.safeParse(contextInput);
  if (!context.success) {
    return {
      action: "reject",
      error: createTodosError("TODOS_TRANSFER_INVALID", "Import execution context is invalid"),
    };
  }
  if (context.data.state === "uncommitted") {
    return { action: "commit" };
  }
  const existingReceipt = context.data.receipt;
  if (existingReceipt.idempotencyKey !== request.data.idempotencyKey) {
    return { action: "commit" };
  }
  if (
    existingReceipt.sourceAuthorityId === request.data.sourceAuthorityId
    && existingReceipt.bundleId === request.data.bundleId
    && existingReceipt.bundleChecksum === request.data.bundleChecksum
    && existingReceipt.importPlanId === request.data.importPlanId
    && existingReceipt.importPlanDigest === request.data.importPlanDigest
    && existingReceipt.contractDigest === request.data.contractDigest
    && existingReceipt.manifestDigest === request.data.manifestDigest
    && existingReceipt.targetAuthorityId === request.data.targetAuthorityId
  ) {
    return { action: "replay", receipt: existingReceipt };
  }
  return {
    action: "reject",
    error: createTodosError(
      "TODOS_IDEMPOTENCY_CONFLICT",
      "The idempotency key is already committed for different import content",
    ),
  };
}

export const TODOS_TRANSFER_CLASSIFICATION = Object.freeze({
  version: TODOS_TRANSFER_VERSION,
  portableSections: TODOS_TRANSFER_SECTION_NAMES,
  referenceOnly: Object.freeze([
    "agent_ids",
    "external_owner_ids",
    "owner_qualified_refs",
  ] as const),
  excludedCategories: Object.freeze([
    "credentials",
    "authentication_tokens",
    "session_state",
    "billing_records",
    "worker_state",
    "lease_state",
    "machine_topology",
    "process_configuration",
    "command_text",
    "command_arguments",
    "filesystem_paths",
    "storage_internals",
    "provider_internals",
  ] as const),
  fieldClassification: Object.freeze({
    ...TODOS_DOMAIN_FIELD_CLASSIFICATION,
    transferSections: Object.freeze({
      ...TRANSFER_FIELD_CLASSIFICATION_OVERRIDES,
    }),
  }),
});

export const TODOS_TRANSFER_SCHEMAS = Object.freeze({
  [TODOS_TRANSFER_SCHEMA_IDS.bundle]: TodosTransferBundleSchema,
  [TODOS_TRANSFER_SCHEMA_IDS.validation]: TodosTransferValidationSchema,
  [TODOS_TRANSFER_SCHEMA_IDS.importPreview]: TodosTransferImportPreviewSchema,
  [TODOS_TRANSFER_SCHEMA_IDS.importExecution]: TodosTransferImportExecutionSchema,
  [TODOS_TRANSFER_SCHEMA_IDS.executionContext]: TodosTransferExecutionContextSchema,
  [TODOS_TRANSFER_SCHEMA_IDS.checkpoint]: TodosTransferCheckpointSchema,
  [TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt]: TodosMigrationReceiptSchema,
});
