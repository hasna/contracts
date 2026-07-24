import { describe, expect, test } from "bun:test";
import {
  TODOS_TRANSFER_SECTION_NAMES,
  computeTodosTransferBundleChecksum,
  computeTodosTransferReferenceClosure,
  createTaskToPrProjection,
  createTodosTransferBundle,
  sha256TodosText,
  sha256TodosValue,
  validateTodosTransferBundle,
  type TaskToPrProjection,
  type TaskToPrOwnerRef,
  type TodosTransferBundle,
  type TodosTransferBundleUnsigned,
  type TodosTransferBundleInput,
} from "../../src/todos";

const owner = "tenant-a";
const timestamp = "2026-07-24T01:00:00.000Z";

function externalRef(id: string) {
  return {
    owner,
    id,
    digest: sha256TodosText(`${owner}:${id}`),
  };
}

function ownerRef<const T extends string>(
  kind: T,
  id: string,
): TaskToPrOwnerRef & { kind: T } {
  return {
    owner,
    kind,
    id,
    digest: sha256TodosText(`${owner}:${kind}:${id}`),
  };
}

function contentRef(id: string) {
  return {
    algorithm: "sha256" as const,
    digest: sha256TodosText(`content:${id}`),
    mediaType: "application/octet-stream",
    byteLength: id.length,
  };
}

function entity(id: string) {
  return {
    id,
    owner,
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function completeRecords(): TodosTransferBundleInput["records"] {
  const head = { algorithm: "sha1" as const, value: "a".repeat(40) };
  const projection = createTaskToPrProjection({
    schema: "hasna.todos.task_to_pr_projection.v1",
    id: "projection-1",
    owner,
    version: 1,
    sequence: 1,
    predecessor: null,
    identity: {
      taskRef: ownerRef("task", "task-1"),
      repositoryRef: ownerRef("repository", "repository-1"),
      worktreeRef: ownerRef("worktree", "worktree-1"),
      branchRef: ownerRef("branch", "branch-1"),
      baseHead: { algorithm: "sha1", value: "b".repeat(40) },
    },
    pullRequestRef: ownerRef("pull_request", "pull-request-1"),
    head: {
      branchHead: head,
      publishedHead: head,
      providerObservedHead: head,
      equalityProof: {
        ref: ownerRef("proof_bundle", "head-proof-1"),
        kind: "head_equality",
        head,
        observedAt: timestamp,
      },
    },
    proofs: [{
      ref: ownerRef("proof_bundle", "review-proof-1"),
      kind: "review",
      head,
      observedAt: timestamp,
    }],
    derivedAt: timestamp,
  });
  const taskBase = {
    owner,
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    shortId: null,
    description: null,
    status: "pending" as const,
    priority: "medium" as const,
    projectId: "project-1",
    taskListId: "task-list-1",
    planId: "plan-1",
    parentTaskId: null,
    assignedAgentId: "agent-1",
    fingerprint: null,
    tags: [],
    acceptanceCriteria: [],
    dueAt: null,
    completedAt: null,
    externalOwnerRefs: [externalRef("external-task-1")],
  };
  return {
    projects: [{
      ...entity("project-1"),
      slug: "project-one",
      name: "Project one",
      description: null,
      repositoryRef: externalRef("repository-1"),
      archivedAt: null,
    }],
    task_lists: [{
      ...entity("task-list-1"),
      projectId: "project-1",
      slug: "list-one",
      name: "List one",
      description: null,
      archivedAt: null,
    }],
    plans: [{
      ...entity("plan-1"),
      slug: "plan-one",
      projectId: "project-1",
      taskListId: "task-list-1",
      name: "Plan one",
      description: null,
      status: "active",
      objective: "Prove complete closure",
      taskIds: ["task-1", "task-2"],
      completedAt: null,
    }],
    tasks: [
      { ...taskBase, id: "task-1", title: "Task one" },
      { ...taskBase, id: "task-2", title: "Task two", assignedAgentId: null },
    ],
    comments: [{
      ...entity("comment-1"),
      taskId: "task-1",
      authorRef: externalRef("author-1"),
      kind: "comment",
      content: "Complete graph",
      progressPercent: null,
    }],
    dependencies: [{
      ...entity("dependency-1"),
      sourceTaskId: "task-2",
      targetTaskId: "task-1",
      kind: "requires",
    }],
    activities: [{
      ...entity("activity-1"),
      actorRef: externalRef("actor-1"),
      resourceRef: ownerRef("task", "task-1"),
      action: "task.updated",
      summary: "Task changed",
      occurredAt: timestamp,
    }],
    verification_evidence: [{
      ...entity("evidence-1"),
      taskId: "task-1",
      runId: "run-1",
      verifierRef: externalRef("verifier-1"),
      status: "passed",
      summary: "Verified",
      confidence: 1,
      commandReceipts: [{
        commandDigest: sha256TodosText("command"),
        argumentsDigest: sha256TodosText("arguments"),
        exitCode: 0,
        durationMs: 10,
        outputRefs: [contentRef("evidence-command-output")],
      }],
      checks: [{
        name: "complete",
        status: "passed",
        summary: null,
        durationMs: 10,
      }],
      contentRefs: [contentRef("evidence-content")],
      startedAt: timestamp,
      completedAt: timestamp,
    }],
    task_files: [{
      ...entity("task-file-1"),
      taskId: "task-1",
      logicalName: "deliverable.bin",
      contentRef: contentRef("task-file"),
      purpose: "deliverable",
    }],
    runs: [{
      ...entity("run-1"),
      objective: "Exercise all sections",
      status: "succeeded",
      taskIds: ["task-1"],
      planId: "plan-1",
      agentId: "agent-1",
      startedAt: timestamp,
      completedAt: timestamp,
      ledgerDigest: sha256TodosText("run-ledger"),
    }],
    run_events: [{
      ...entity("run-event-1"),
      runId: "run-1",
      sequence: 0,
      type: "run.completed",
      summary: "Run completed",
      occurredAt: timestamp,
      evidenceIds: ["evidence-1"],
    }],
    run_commands: [{
      ...entity("run-command-1"),
      runId: "run-1",
      sequence: 0,
      commandDigest: sha256TodosText("run-command"),
      argumentsDigest: null,
      exitCode: 0,
      durationMs: 10,
      outputRefs: [contentRef("run-command-output")],
      completedAt: timestamp,
    }],
    run_files: [{
      ...entity("run-file-1"),
      runId: "run-1",
      logicalName: "output.bin",
      contentRef: contentRef("run-file"),
      role: "output",
    }],
    run_artifacts: [{
      ...entity("run-artifact-1"),
      runId: "run-1",
      logicalName: "artifact",
      kind: "verification_bundle",
      contentRef: contentRef("run-artifact"),
      verified: true,
      verificationEvidenceId: "evidence-1",
    }],
    git_commits: [{
      ...entity("git-commit-1"),
      repositoryRef: externalRef("repository-1"),
      objectId: { algorithm: "sha1", value: "c".repeat(40) },
      message: "Portable commit",
      authorRef: externalRef("author-1"),
      committedAt: timestamp,
      changedFileDigests: [sha256TodosText("changed-file")],
    }],
    git_refs: [{
      ...entity("git-ref-1"),
      repositoryRef: externalRef("repository-1"),
      type: "branch",
      name: "task-branch",
      target: { algorithm: "sha1", value: "c".repeat(40) },
      published: true,
      providerObservedAt: timestamp,
    }],
    traceability: [{
      ...entity("traceability-1"),
      taskId: "task-1",
      commitIds: ["git-commit-1"],
      gitRefIds: ["git-ref-1"],
      verificationEvidenceIds: ["evidence-1"],
      projectionIds: ["projection-1"],
    }],
    task_to_pr_projections: [projection],
    saved_views: [{
      ...entity("saved-view-1"),
      name: "All linked work",
      description: null,
      query: {
        query: "linked",
        filters: {
          projectIds: ["project-1"],
          taskListIds: ["task-list-1"],
          planIds: ["plan-1"],
          agentIds: ["agent-1"],
          statuses: ["pending"],
          priorities: ["medium"],
          tags: [],
          changedAfter: null,
          dueBefore: null,
        },
        cursor: null,
        limit: 100,
      },
      audience: "organization",
    }],
    task_templates: [{
      ...entity("task-template-1"),
      name: "Template",
      description: null,
      titlePattern: "Task",
      descriptionPattern: null,
      priority: "medium",
      tags: [],
      acceptanceCriteria: [],
    }],
    approvals: [{
      ...entity("approval-1"),
      resourceRef: ownerRef("task", "task-1"),
      status: "approved",
      reason: "Approved",
      requestedBy: externalRef("requester-1"),
      decidedBy: externalRef("decider-1"),
      requestedAt: timestamp,
      decidedAt: timestamp,
      expiresAt: null,
    }],
    deletion_records: [{
      id: "deletion-1",
      owner,
      entityKind: "task",
      entityIdDigest: sha256TodosText("deleted-task"),
      priorRecordDigest: sha256TodosText("deleted-record"),
      tombstoneVersion: 1,
      redaction: "full",
      reasonCode: "customer_request",
      deletedAt: timestamp,
    }],
  };
}

function completeBundle(): TodosTransferBundle {
  return createTodosTransferBundle({
    bundleId: "complete-bundle",
    createdAt: timestamp,
    source: { authorityId: owner, mode: "local" },
    records: completeRecords(),
  });
}

function successorProjection(
  previous: TaskToPrProjection,
  predecessorOverrides: Partial<NonNullable<TaskToPrProjection["predecessor"]>> = {},
): TaskToPrProjection {
  const {
    digest: _digest,
    predecessor: _predecessor,
    version: _version,
    sequence: _sequence,
    ...stable
  } = previous;
  return createTaskToPrProjection({
    ...stable,
    version: previous.version + 1,
    sequence: previous.sequence + 1,
    predecessor: {
      kind: "task_to_pr_projection",
      projectionId: previous.id,
      owner: previous.owner,
      version: previous.version,
      digest: previous.digest,
      ...predecessorOverrides,
    },
  });
}

function rehash(bundle: TodosTransferBundle): TodosTransferBundle {
  const { bundleChecksum: _checksum, ...unsigned } = bundle;
  return {
    ...bundle,
    bundleChecksum: computeTodosTransferBundleChecksum(
      unsigned as TodosTransferBundleUnsigned,
    ),
  };
}

describe("Todos complete portable closure", () => {
  test("covers every record and resolves transitive references across every section", () => {
    const bundle = completeBundle();
    const validation = validateTodosTransferBundle(bundle);
    expect(validation.valid).toBe(true);
    expect(new Set(bundle.referenceClosure.map((entry) => entry.source.section)))
      .toEqual(new Set(TODOS_TRANSFER_SECTION_NAMES));
    const recordCount = Object.values(bundle.sections)
      .reduce((count, section) => count + section.records.length, 0);
    expect(bundle.referenceClosure).toHaveLength(recordCount);
    expect(bundle.attachmentContentReferences).toHaveLength(6);
    expect(bundle.referenceOnly.agentIds).toEqual(["agent-1"]);
    expect(bundle.referenceOnly.externalOwnerRefs.length).toBeGreaterThan(5);
    expect(bundle.referenceOnly.ownerQualifiedRefs.map((ref) => ref.kind).sort())
      .toEqual([
        "branch",
        "proof_bundle",
        "proof_bundle",
        "pull_request",
        "repository",
        "worktree",
      ]);

    const traceability = bundle.referenceClosure.find(
      (entry) => entry.source.section === "traceability",
    );
    const transferredProjection =
      bundle.sections.task_to_pr_projections.records[0]!;
    expect(traceability?.references).toContainEqual({
      owner,
      section: "projects",
      id: "project-1",
    });
    expect(traceability?.references).toContainEqual({
      owner,
      section: "task_to_pr_projections",
      id: "projection-1",
      kind: "task_to_pr_projection",
      version: transferredProjection.version,
      digest: transferredProjection.digest,
    });
  });

  test("rejects dangling targets and independently corrupted reference-only inventories", () => {
    const dangling = structuredClone(completeBundle());
    dangling.sections.projects.records = [];
    dangling.sections.projects.count = 0;
    dangling.sections.projects.digest = sha256TodosValue([]);
    dangling.referenceClosure = computeTodosTransferReferenceClosure(dangling.sections);
    const danglingValidation = validateTodosTransferBundle(rehash(dangling));
    expect(danglingValidation.valid).toBe(false);
    expect(danglingValidation.issues.some((issue) => issue.code === "missing_reference"))
      .toBe(true);

    const inventory = structuredClone(completeBundle());
    inventory.referenceOnly.externalOwnerRefs = [];
    const inventoryValidation = validateTodosTransferBundle(rehash(inventory));
    expect(inventoryValidation.valid).toBe(false);
    expect(inventoryValidation.issues.some(
      (issue) => issue.code === "classification_mismatch",
    )).toBe(true);
  });

  test("requires the exact projection predecessor record at every transferred version", () => {
    const missingFirstRecords = completeRecords();
    const first = missingFirstRecords.task_to_pr_projections[0]!;
    const second = successorProjection(first);
    missingFirstRecords.task_to_pr_projections = [second];
    const missingFirst = createTodosTransferBundle({
      bundleId: "projection-v2-without-v1",
      createdAt: timestamp,
      source: { authorityId: owner, mode: "local" },
      records: missingFirstRecords,
    });
    expect(
      validateTodosTransferBundle(missingFirst).issues.some(
        (issue) => issue.code === "missing_reference",
      ),
    ).toBe(true);

    const missingMiddleRecords = completeRecords();
    const middle = successorProjection(first);
    const third = successorProjection(middle);
    missingMiddleRecords.task_to_pr_projections = [first, third];
    const missingMiddle = createTodosTransferBundle({
      bundleId: "projection-v3-without-v2",
      createdAt: timestamp,
      source: { authorityId: owner, mode: "local" },
      records: missingMiddleRecords,
    });
    expect(
      validateTodosTransferBundle(missingMiddle).issues.some(
        (issue) => issue.code === "missing_reference",
      ),
    ).toBe(true);

    const mismatchedRecords = completeRecords();
    const mismatched = successorProjection(first, {
      digest: sha256TodosText("mismatched-predecessor"),
    });
    mismatchedRecords.task_to_pr_projections = [first, mismatched];
    const mismatchedBundle = createTodosTransferBundle({
      bundleId: "projection-predecessor-mismatch",
      createdAt: timestamp,
      source: { authorityId: owner, mode: "local" },
      records: mismatchedRecords,
    });
    expect(
      validateTodosTransferBundle(mismatchedBundle).issues.some(
        (issue) => issue.code === "missing_reference",
      ),
    ).toBe(true);

    const identityMismatchRecords = completeRecords();
    const {
      digest: _secondDigest,
      identity: secondIdentity,
      ...secondUnsigned
    } = second;
    const identityMismatch = createTaskToPrProjection({
      ...secondUnsigned,
      identity: {
        ...secondIdentity,
        branchRef: ownerRef("branch", "branch-substituted"),
      },
    });
    identityMismatchRecords.task_to_pr_projections = [first, identityMismatch];
    const identityMismatchBundle = createTodosTransferBundle({
      bundleId: "projection-predecessor-identity-mismatch",
      createdAt: timestamp,
      source: { authorityId: owner, mode: "local" },
      records: identityMismatchRecords,
    });
    expect(validateTodosTransferBundle(identityMismatchBundle).valid).toBe(false);

    const completeHistoryRecords = completeRecords();
    completeHistoryRecords.task_to_pr_projections = [first, middle, third];
    const completeHistory = createTodosTransferBundle({
      bundleId: "projection-complete-history",
      createdAt: timestamp,
      source: { authorityId: owner, mode: "local" },
      records: completeHistoryRecords,
    });
    expect(validateTodosTransferBundle(completeHistory).valid).toBe(true);
    expect(
      completeHistory.referenceClosure.find(
        (entry) => (
          entry.source.section === "task_to_pr_projections"
          && entry.source.id === third.id
          && entry.source.version === third.version
        ),
      )?.references,
    ).toContainEqual({
      owner,
      section: "task_to_pr_projections",
      id: middle.id,
      kind: "task_to_pr_projection",
      version: middle.version,
      digest: middle.digest,
    });
  });
});
