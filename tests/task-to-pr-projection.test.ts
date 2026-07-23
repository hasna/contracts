import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  SCHEMA_IDS,
  TASK_TO_PR_ROLE_AUTHORITIES,
  type TaskToPrProjection,
  type TaskToPrRef,
  TaskToPrAdapterExtensionSchema,
  TaskToPrHandoffSchema,
  TaskToPrProjectionSchema,
  TaskToPrRecoverySchema,
  TaskToPrRefSchema,
  WorkRunSchema,
  deriveTaskToPrEvidenceId,
  deriveTaskToPrIdentityDigest,
  deriveTaskToPrRefId,
  parseContract,
  parseEmbeddedContract,
  validateContract,
  validateTaskToPrAdapterCoreEquivalence,
  validateTaskToPrProjectionTransition
} from "../src";

type TaskToPrRole = keyof typeof TASK_TO_PR_ROLE_AUTHORITIES;
type TaskToPrAuthority = (typeof TASK_TO_PR_ROLE_AUTHORITIES)[TaskToPrRole][number];
type Redaction = "none" | "partial" | "full";

const createdAt = "2026-07-23T15:10:00.000Z";

function sha(seed: string): string {
  return seed.repeat(64);
}

function opaque32(seed: string): string {
  return createHash("sha256").update(seed, "utf8").digest("hex").slice(0, 32);
}

function projectionId(seed: string): string {
  return `task_to_pr_projection:opaque-${opaque32(seed)}`;
}

function attemptNonce(seed: string): string {
  return `attempt_nonce:opaque-${opaque32(seed)}`;
}

function ref(role: TaskToPrRole, authority: TaskToPrAuthority, seed: string, redaction: Redaction = "none") {
  const digest = createHash("sha256").update(`${role}:${authority}:${seed}`, "utf8").digest("hex");
  return {
    role,
    authority,
    id: deriveTaskToPrRefId(role, authority, digest),
    digest,
    redaction
  };
}

function evidence(id: string, seed: string, redaction: "partial" | "full" = "full") {
  const digest = sha(seed);
  return { id: deriveTaskToPrEvidenceId(digest), digest, redaction };
}

function head(seed: string) {
  return { algorithm: "sha1" as const, value: seed.repeat(40) };
}

function withActiveProvenance<T extends Record<string, any>>(
  projection: T
): Omit<T, "provenanceLedger"> & { provenanceLedger: TaskToPrProjection["provenanceLedger"] } {
  const terminalStates = new Set([
    "merged",
    "closed_unmerged",
    "failed",
    "blocked",
    "cancelled",
    "cleanup_complete",
    "rolled_back"
  ]);
  const normalized = {
    ...projection,
    terminalDispositionRef: terminalStates.has(projection.state)
      ? projection.terminalDispositionRef
      : undefined,
    merge:
      projection.merge && projection.state === "merge_ready"
        ? {
            ...projection.merge,
            guard: { ...projection.merge.guard, decision: "eligible" }
          }
        : projection.merge
  };
  const active = [
    { category: "projection_id", projectionId: normalized.id },
    { category: "work_run", ref: normalized.workRunRef },
    { category: "attempt", ref: normalized.attempt.ref },
    { category: "admission", ref: normalized.attempt.admissionRef },
    { category: "worker_actor", ref: normalized.attempt.workerActorRef },
    { category: "worker_assignment", ref: normalized.attempt.workerRef },
    { category: "attempt_nonce", nonce: normalized.attempt.nonce },
    { category: "runtime", ref: normalized.attempt.runtimeRef },
    { category: "writer_generation", ref: normalized.attempt.writerGenerationRef },
    { category: "writer_lease", ref: normalized.attempt.writerLeaseRef },
    { category: "writer_fence", ref: normalized.attempt.writerFenceRef },
    { category: "provider_profile", ref: normalized.attempt.providerProfileRef },
    { category: "provider_route", ref: normalized.attempt.providerRouteRef },
    { category: "replay_cursor", ref: normalized.events.replayCursorRef },
    {
      category: "replay_prefix",
      sequence: normalized.events.sequence,
      prefixDigest: normalized.events.prefixDigest
    },
    { category: "repair_state", ref: normalized.repair.ref },
    ...(normalized.repair.latestRepairRef
      ? [{ category: "latest_repair", ref: normalized.repair.latestRepairRef }]
      : []),
    ...(normalized.handoff ? [{ category: "handoff", ref: normalized.handoff.ref }] : []),
    ...(normalized.recovery ? [{ category: "recovery", ref: normalized.recovery.ref }] : []),
    ...(normalized.exactHead
      ? [
          {
            category: "equality_proof",
            ref: normalized.exactHead.equalityProofRef,
            base: normalized.exactHead.expectedBase,
            head: normalized.exactHead.localHead
          },
          ...normalized.exactHead.ciProofBundleRefs.map((proofRef: TaskToPrRef) => ({
            category: "ci_proof",
            ref: proofRef,
            base: normalized.exactHead.expectedBase,
            head: normalized.exactHead.localHead
          }))
        ]
      : []),
    ...((normalized.reviews ?? []) as Array<{
      ref: TaskToPrRef;
      reviewRunRef: TaskToPrRef;
      proofBundleRef: TaskToPrRef;
      base: ReturnType<typeof head>;
      head: ReturnType<typeof head>;
    }>).flatMap((review) => [
      { category: "review_proof", ref: review.proofBundleRef, base: review.base, head: review.head },
      { category: "review_record", ref: review.ref, base: review.base, head: review.head },
      { category: "review_run", ref: review.reviewRunRef, base: review.base, head: review.head }
    ]),
    ...(normalized.merge
      ? [
          { category: "merge_guard", ref: normalized.merge.guard.ref },
          {
            category: "provider_guard_receipt",
            ref: normalized.merge.guard.providerGuardReceiptRef,
            base: normalized.merge.guard.expectedBase,
            head: normalized.merge.guard.expectedHead
          }
        ]
      : []),
    ...(normalized.cleanup
      ? [{ category: "cleanup_eligibility", ref: normalized.cleanup.eligibility.ref }]
      : []),
    ...(normalized.rollback
      ? [{ category: "rollback_plan", ref: normalized.rollback.plan.ref }]
      : []),
    ...(normalized.terminalDispositionRef
      ? [{ category: "terminal_disposition", ref: normalized.terminalDispositionRef }]
      : [])
  ];
  const provenanceLedger = [...(normalized.provenanceLedger ?? [])];
  for (const entry of active) {
    if (!provenanceLedger.some((existing: unknown) => JSON.stringify(existing) === JSON.stringify(entry))) {
      provenanceLedger.push(entry);
    }
  }
  return { ...normalized, provenanceLedger } as Omit<T, "provenanceLedger"> & {
    provenanceLedger: TaskToPrProjection["provenanceLedger"];
  };
}

function parseProjection<T extends Record<string, any>>(projection: T): TaskToPrProjection {
  return TaskToPrProjectionSchema.parse(withActiveProvenance(projection));
}

function validProjection() {
  const reviewedHead = head("a");
  const pullRequestRef = ref("pull_request", "todos", "b");
  const currentGeneration = ref("writer_generation", "todos", "c");
  const currentAttempt = ref("attempt", "todos", "d");
  const reviewRef = ref("review", "review", "e");
  const proofBundleRef = ref("proof_bundle", "review", "f");
  const headEqualityProofRef = ref("proof_bundle", "review", "0");
  const ciProofBundleRef = ref("proof_bundle", "review", "1");
  const rootRequestRef = ref("root_request", "todos", "4");
  const prGroupRef = ref("pr_group", "todos", "5");
  const leafTaskRef = ref("leaf_task", "todos", "6");
  const repoRef = ref("repo", "repos", "b");
  const worktreeRef = ref("worktree", "repos", "c", "partial");
  const branchRef = ref("branch", "repos", "d");
  const baseHead = head("e");
  const frozenScopeDigest = sha("2");
  const identityDigest = deriveTaskToPrIdentityDigest({
    canonicalizationVersion: 2,
    rootRequestRef,
    prGroupRef,
    leafTaskRef,
    repoRef,
    worktreeRef,
    branchRef,
    baseHead,
    frozenScopeDigest
  });

  return withActiveProvenance({
    schema: SCHEMA_IDS.taskToPrProjection,
    id: projectionId("valid-projection"),
    createdAt,
    canonicalizationVersion: 2,
    identityDigest,
    frozenScopeDigest,
    state: "cleanup_complete",
    workRunRef: ref("work_run", "codewith", "3"),
    rootRequestRef,
    prGroupRef,
    leafTaskRef,
    attempt: {
      ref: currentAttempt,
      nonce: attemptNonce("valid-attempt"),
      admissionRef: ref("admission", "codewith", "1", "partial"),
      workerActorRef: ref("worker_actor", "codewith", "stable-worker", "partial"),
      workerRef: ref("worker", "codewith", "2", "partial"),
      runtimeRef: ref("runtime", "codewith", "3", "partial"),
      writerGenerationRef: currentGeneration,
      writerLeaseRef: ref("writer_lease", "repos", "7", "partial"),
      writerFenceRef: ref("writer_fence", "repos", "8", "full"),
      providerProfileRef: ref("provider_profile", "codewith", "9", "full"),
      providerRouteRef: ref("provider_route", "codewith", "a", "partial")
    },
    repository: {
      repoRef,
      worktreeRef,
      branchRef,
      baseHead,
      branchHead: reviewedHead
    },
    events: {
      streamRef: ref("event_stream", "todos", "e"),
      replayCursorRef: ref("replay_cursor", "todos", "f"),
      sequence: 42,
      prefixDigest: sha("0")
    },
    openLoopsInvocationRef: ref("openloops_invocation", "openloops", "1", "partial"),
    pullRequestRef,
    handoff: {
      ref: ref("handoff", "todos", "2"),
      previousAttemptRef: ref("attempt", "todos", "1"),
      nextAttemptRef: currentAttempt,
      previousWriterGenerationRef: ref("writer_generation", "todos", "3"),
      nextWriterGenerationRef: currentGeneration,
      stoppedWorkRunRef: ref("work_run", "codewith", "4"),
      stopEvidenceRef: evidence("ev_prior_worker_stopped", "5"),
      leaseRevocationEvidenceRef: evidence("ev_prior_lease_revoked", "6")
    },
    exactHead: {
      pullRequestRef,
      remoteBranchRef: ref("branch", "repos", "d"),
      expectedBase: baseHead,
      providerPullRequestBase: baseHead,
      localHead: reviewedHead,
      remoteHead: reviewedHead,
      providerPullRequestHead: reviewedHead,
      equalityProofRef: headEqualityProofRef,
      ciProofBundleRefs: [ciProofBundleRef],
      verifiedAt: createdAt
    },
    reviews: [
      {
        ref: reviewRef,
        pullRequestRef,
        base: baseHead,
        head: reviewedHead,
        reviewerRef: ref("reviewer", "review", "7"),
        reviewRunRef: ref("review_run", "review", "8"),
        proofBundleRef,
        verdict: "approved",
        reviewedAt: createdAt
      }
    ],
    repair: {
      ref: ref("repair_cycle", "todos", "9"),
      cycle: 1,
      cap: 2,
      exhausted: false,
      latestRepairRef: ref("repair_cycle", "todos", "a")
    },
    merge: {
      guard: {
        ref: ref("merge_guard", "todos", "b"),
        pullRequestRef,
        expectedBase: baseHead,
        expectedHead: reviewedHead,
        reviewRefs: [reviewRef],
        proofBundleRefs: [proofBundleRef, headEqualityProofRef, ciProofBundleRef],
        operatorRef: ref("merge_operator", "merge_provider", "c", "partial"),
        operatorRunRef: ref("merge_operator_run", "merge_provider", "d", "partial"),
        providerGuardReceiptRef: ref("merge_guard_receipt", "merge_provider", "c", "full"),
        mechanism: "compare_and_swap",
        decision: "consumed",
        evaluatedAt: createdAt
      },
      outcome: {
        ref: ref("merge_outcome", "merge_provider", "d", "partial"),
        guardRef: ref("merge_guard", "todos", "b"),
        pullRequestRef,
        expectedBase: baseHead,
        observedBase: baseHead,
        expectedHead: reviewedHead,
        observedHead: reviewedHead,
        status: "merged",
        mergeCommitRef: ref("commit", "repos", "e"),
        finishedAt: createdAt,
        evidenceRefs: [evidence("ev_merge_cas", "f")]
      }
    },
    terminalDispositionRef: ref("terminal_disposition", "todos", "terminal"),
    cleanup: {
      eligibility: {
        ref: ref("cleanup_eligibility", "repos", "6"),
        status: "eligible",
        targetWorktreeRef: ref("worktree", "repos", "c", "partial"),
        eventCursorRef: ref("replay_cursor", "todos", "f"),
        terminalDispositionRef: ref("terminal_disposition", "todos", "terminal"),
        writerLeaseRef: ref("writer_lease", "repos", "7", "partial"),
        leaseRevocationEvidenceRef: evidence("ev_cleanup_lease_revoked", "1"),
        consumedEventEvidenceRef: evidence("ev_cleanup_event_consumed", "2"),
        evaluatedAt: createdAt,
        evidenceRefs: [evidence("ev_cleanup_gate", "7")]
      },
      outcome: {
        ref: ref("cleanup_outcome", "repos", "8"),
        eligibilityRef: ref("cleanup_eligibility", "repos", "6"),
        targetWorktreeRef: ref("worktree", "repos", "c", "partial"),
        status: "deleted",
        finishedAt: createdAt,
        evidenceRefs: [evidence("ev_cleanup_deleted", "9")]
      }
    },
    provenanceLedger: [],
    adapterExtensions: [
      {
        mode: "local",
        schema: "hasna.task_to_pr_adapter_extension.v1",
        ref: ref("adapter_extension", "adapter", "a", "partial"),
        digest: sha("b")
      },
      {
        mode: "cloud",
        schema: "hasna.task_to_pr_adapter_extension.v1",
        ref: ref("adapter_extension", "adapter", "c", "full"),
        digest: sha("d")
      }
    ],
    evidenceRefs: [evidence("ev_projection", "e")]
  });
}

function validRecoveryProjection() {
  const projection = validProjection();
  return {
    ...projection,
    handoff: undefined,
    recovery: {
      ref: ref("recovery", "todos", "7"),
      priorAttemptRef: ref("attempt", "todos", "1"),
      priorWriterGenerationRef: ref("writer_generation", "todos", "2"),
      priorWorkRunRef: ref("work_run", "codewith", "4"),
      successorAttemptNonce: projection.attempt.nonce,
      successorWriterGenerationRef: projection.attempt.writerGenerationRef,
      preservedStateRefs: [
        ref("work_run", "codewith", "4"),
        projection.rootRequestRef,
        projection.prGroupRef,
        projection.leafTaskRef,
        projection.repository.repoRef,
        projection.repository.worktreeRef,
        projection.repository.branchRef,
        projection.events.streamRef,
        projection.pullRequestRef
      ],
      stopEvidenceRef: evidence("ev_recovery_stop", "4"),
      leaseRevocationEvidenceRef: evidence("ev_recovery_revoke", "5")
    },
    provenanceLedger: [
      ...projection.provenanceLedger,
      { category: "recovery" as const, ref: ref("recovery", "todos", "7") }
    ]
  };
}

describe("task-to-PR projection v1", () => {
  test("parses and round-trips the strict provider-neutral projection", () => {
    const input = validProjection();
    const parsed = TaskToPrProjectionSchema.parse(input);
    const roundTrip = parseEmbeddedContract(JSON.parse(JSON.stringify(parsed)));

    expect(roundTrip).toEqual(parsed);
    expect(parseContract(SCHEMA_IDS.taskToPrProjection, input)).toEqual(parsed);
    expect(parsed.workRunRef.role).toBe("work_run");
    expect(parsed.events.sequence).toBe(42);
  });

  test("derives and verifies the non-circular canonical root/PR-group/leaf/repo/base/scope binding", () => {
    const projection = validProjection();
    expect(
      deriveTaskToPrIdentityDigest({
        canonicalizationVersion: 2,
        rootRequestRef: projection.rootRequestRef,
        prGroupRef: projection.prGroupRef,
        leafTaskRef: projection.leafTaskRef,
        repoRef: projection.repository.repoRef,
        worktreeRef: projection.repository.worktreeRef,
        branchRef: projection.repository.branchRef,
        baseHead: projection.repository.baseHead,
        frozenScopeDigest: projection.frozenScopeDigest
      })
    ).toBe(projection.identityDigest);
    expect(projection.prGroupRef.digest).not.toBe(projection.identityDigest);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        identityDigest: sha("0")
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        leafTaskRef: { ...projection.leafTaskRef, id: "leaf_task_changed" }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        prGroupRef: { ...projection.prGroupRef, id: "pr_group:opaque-changed" }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        prGroupRef: { ...projection.prGroupRef, digest: sha("0") }
      }).success
    ).toBe(false);
  });

  test("enforces the exhaustive role-to-authority matrix", () => {
    const expectedRoles = [
      "work_run",
      "root_request",
      "pr_group",
      "leaf_task",
      "attempt",
      "writer_generation",
      "writer_lease",
      "writer_fence",
      "provider_profile",
      "provider_route",
      "admission",
      "worker_actor",
      "worker",
      "runtime",
      "repo",
      "worktree",
      "branch",
      "event_stream",
      "replay_cursor",
      "handoff",
      "pull_request",
      "commit",
      "review",
      "reviewer",
      "review_run",
      "proof_bundle",
      "repair_cycle",
      "merge_guard",
      "merge_operator",
      "merge_operator_run",
      "merge_guard_receipt",
      "merge_outcome",
      "recovery",
      "cancellation",
      "cleanup_eligibility",
      "cleanup_outcome",
      "rollback_plan",
      "rollback_outcome",
      "terminal_disposition",
      "openloops_invocation",
      "adapter_extension"
    ];
    expect(Object.keys(TASK_TO_PR_ROLE_AUTHORITIES)).toEqual(expectedRoles);

    const redactedRoles = new Set<TaskToPrRole>([
      "writer_lease",
      "writer_fence",
      "provider_profile",
      "provider_route",
      "admission",
      "worker_actor",
      "worker",
      "runtime",
      "worktree",
      "merge_operator",
      "merge_operator_run",
      "merge_guard_receipt",
      "merge_outcome",
      "openloops_invocation",
      "adapter_extension"
    ]);
    for (const [role, authorities] of Object.entries(TASK_TO_PR_ROLE_AUTHORITIES)) {
      for (const authority of authorities) {
        expect(
          TaskToPrRefSchema.safeParse(ref(role as TaskToPrRole, authority, "a", redactedRoles.has(role as TaskToPrRole) ? "full" : "none"))
            .success
        ).toBe(true);
      }
      const invalidAuthority = (authorities as readonly string[]).includes("todos") ? "codewith" : "todos";
      expect(
        TaskToPrRefSchema.safeParse({
          ...ref(role as TaskToPrRole, authorities[0], "b", redactedRoles.has(role as TaskToPrRole) ? "full" : "none"),
          authority: invalidAuthority
        }).success
      ).toBe(false);
    }
  });

  test("exposes an immutable role-to-authority matrix without changing validation", () => {
    const validRootRef = ref("root_request", "todos", "a");
    expect(TaskToPrRefSchema.safeParse(validRootRef).success).toBe(true);
    expect(Object.isFrozen(TASK_TO_PR_ROLE_AUTHORITIES)).toBe(true);
    expect(Object.isFrozen(TASK_TO_PR_ROLE_AUTHORITIES.root_request)).toBe(true);
    expect(Reflect.set(TASK_TO_PR_ROLE_AUTHORITIES, "root_request", Object.freeze(["codewith"]))).toBe(false);
    expect(Reflect.set(TASK_TO_PR_ROLE_AUTHORITIES.root_request, 0, "codewith")).toBe(false);
    expect(TASK_TO_PR_ROLE_AUTHORITIES.root_request).toEqual(["todos"]);
    expect(TaskToPrRefSchema.safeParse(validRootRef).success).toBe(true);
  });

  test("keeps singular canonical identities required and rejects embedded mutable payloads", () => {
    const missingRoot = validProjection() as Record<string, unknown>;
    delete missingRoot.rootRequestRef;
    expect(TaskToPrProjectionSchema.safeParse(missingRoot).success).toBe(false);

    const embeddedTask = validProjection();
    const invalid = {
      ...embeddedTask,
      leafTaskRef: {
        ...embeddedTask.leafTaskRef,
        title: "mutable task payload",
        status: "in_progress"
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(invalid).success).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...validProjection(),
        rootRequestRefs: [validProjection().rootRequestRef]
      }).success
    ).toBe(false);
  });

  test("rejects raw account, credential, token, fence, and adapter payload fields", () => {
    const projection = validProjection();
    const rawProfile = {
      ...projection,
      attempt: {
        ...projection.attempt,
        providerProfileRef: {
          ...projection.attempt.providerProfileRef,
          accountId: "provider-account-123"
        }
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(rawProfile).success).toBe(false);

    const rawFenceInvalidFixture = {
      ...projection,
      attempt: {
        ...projection.attempt,
        fenceToken: "raw-fence-value"
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(rawFenceInvalidFixture).success).toBe(false);

    const rawExtension = {
      ...projection,
      adapterExtensions: [
        {
          ...projection.adapterExtensions[0],
          provider: "github",
          credentials: { token: "raw-token" },
          payload: { mutable: true }
        }
      ]
    };
    expect(TaskToPrProjectionSchema.safeParse(rawExtension).success).toBe(false);

    const secretBearingIds = [
      ["provider_profile", "codewith", "provider_profile:opaque-alice@example.com"],
      ["provider_route", "codewith", "provider_route:opaque-provider.route?token=value"],
      ["writer_fence", "repos", "writer_fence:opaque-github_pat_example"],
      ["writer_fence", "repos", "writer_fence:opaque-f.ence447"],
      ["writer_lease", "repos", "writer_lease:opaque-raw-fence-value"],
      ["runtime", "codewith", "runtime:opaque------BEGIN-PRIVATE-KEY"],
      ["merge_operator", "merge_provider", "merge_operator:opaque-Bearer-token"],
      ["root_request", "todos", "root_request:opaque-acc.ount013"],
      ["branch", "repos", "branch:opaque-raw-fence-447"]
    ] as const;
    for (const [role, authority, id] of secretBearingIds) {
      expect(
        TaskToPrRefSchema.safeParse({
          ...ref(role, authority, "a", "full"),
          id
        }).success
      ).toBe(false);
    }
    const delimiterNormalizedGithubPatRef: TaskToPrRef = {
      role: "writer_fence",
      authority: "repos",
      id: "writer_fence:opaque-github-pat-example",
      digest: sha("a"),
      redaction: "full"
    };
    expect(TaskToPrRefSchema.safeParse(delimiterNormalizedGithubPatRef).success).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        evidenceRefs: [
          {
            ...evidence("ev_secret", "a"),
            uri: "https://user:password@example.com/artifact"
          }
        ]
      }).success
    ).toBe(false);

    for (const invalidId of [
      "task_to_pr_projection:account013",
      "task_to_pr_projection:raw-fence-447",
      "task_to_pr_projection:https-provider",
      "task_to_pr_projection:opaque-"
    ]) {
      expect(TaskToPrProjectionSchema.safeParse({ ...projection, id: invalidId }).success).toBe(false);
    }
    for (const invalidNonce of [
      "attempt_nonce:account013",
      "attempt_nonce:raw-fence-447",
      "attempt_nonce:opaque-to.ken447",
      "raw-untyped-nonce",
      "attempt_nonce:opaque-"
    ]) {
      expect(
        TaskToPrProjectionSchema.safeParse({
          ...projection,
          attempt: { ...projection.attempt, nonce: invalidNonce }
        }).success
      ).toBe(false);
    }
    expect(
      TaskToPrRefSchema.safeParse({
        ...ref("root_request", "todos", "a"),
        id: "root_request:opaque-"
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        adapterExtensions: [
          {
            ...projection.adapterExtensions[0],
            schema: "hasna.task_to_pr_adapter_acc_ount.v1"
          }
        ]
      }).success
    ).toBe(false);
    for (const rawEvidenceId of ["evidence:opaque-account013", "evidence:opaque-raw-fence-447", "evidence:untyped"]) {
      expect(
        TaskToPrProjectionSchema.safeParse({
          ...projection,
          evidenceRefs: [{ ...evidence("ev_safe", "a"), id: rawEvidenceId }]
        }).success
      ).toBe(false);
    }

    expect(
      TaskToPrProjectionSchema.safeParse(
        withActiveProvenance({
          ...projection,
          id: projectionId("valid-projection"),
          attempt: {
            ...projection.attempt,
            nonce: attemptNonce("owner-record")
          },
          provenanceLedger: projection.provenanceLedger.filter(
            (entry) => entry.category !== "attempt_nonce"
          )
        })
      ).success
    ).toBe(true);
  });

  test("requires redaction for opaque profile, route, lease, fence, worktree, and provider refs", () => {
    const sensitiveRoles: TaskToPrRole[] = [
      "writer_lease",
      "writer_fence",
      "provider_profile",
      "provider_route",
      "admission",
      "worker",
      "runtime",
      "worktree",
      "merge_operator",
      "merge_operator_run",
      "merge_guard_receipt",
      "merge_outcome",
      "openloops_invocation",
      "adapter_extension"
    ];
    for (const role of sensitiveRoles) {
      const authority = TASK_TO_PR_ROLE_AUTHORITIES[role][0];
      expect(TaskToPrRefSchema.safeParse(ref(role, authority, "a", "none")).success).toBe(false);
      expect(TaskToPrRefSchema.safeParse(ref(role, authority, "a", "partial")).success).toBe(true);
    }
  });

  test("binds replay cursors to a non-negative sequence and prefix digest", () => {
    const projection = validProjection();
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        events: { ...projection.events, sequence: -1 }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        events: { ...projection.events, prefixDigest: "not-a-digest" }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        events: {
          ...projection.events,
          replayCursorRef: ref("event_stream", "todos", "a")
        }
      }).success
    ).toBe(false);
  });

  test("prevents review and merge-CAS from floating away from the exact PR head", () => {
    const projection = validProjection();
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        exactHead: {
          ...projection.exactHead,
          remoteBranchRef: ref("branch", "repos", "f")
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        exactHead: {
          ...projection.exactHead,
          remoteHead: head("b")
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        exactHead: {
          ...projection.exactHead,
          ciProofBundleRefs: []
        }
      }).success
    ).toBe(false);
    const driftedGuard = {
      ...projection,
      merge: {
        ...projection.merge,
        guard: {
          ...projection.merge.guard,
          expectedHead: head("b")
        }
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(driftedGuard).success).toBe(false);

    const driftedMerge = {
      ...projection,
      merge: {
        ...projection.merge,
        outcome: {
          ...projection.merge.outcome,
          observedHead: head("b")
        }
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(driftedMerge).success).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "closed_unmerged",
        cleanup: undefined,
        merge: {
          ...projection.merge,
          outcome: {
            ...projection.merge.outcome,
            status: "refused",
            observedHead: head("b"),
            mergeCommitRef: undefined
          }
        }
      }).success
    ).toBe(false);

    const refusedDrift = {
      ...projection,
      state: "closed_unmerged",
      cleanup: undefined,
      merge: {
        ...projection.merge,
        outcome: {
          ...projection.merge.outcome,
          status: "head_drift",
          observedHead: head("b"),
          mergeCommitRef: undefined
        }
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(refusedDrift).success).toBe(true);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        exactHead: {
          ...projection.exactHead,
          ciProofBundleRefs: [
            projection.exactHead.ciProofBundleRefs[0],
            {
              ...projection.exactHead.ciProofBundleRefs[0],
              digest: sha("9")
            }
          ]
        }
      }).success
    ).toBe(false);

    const duplicateCiDigest = {
      ...projection.exactHead.ciProofBundleRefs[0],
      id: "proof_bundle:opaque-ci-duplicate-digest"
    };
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        exactHead: {
          ...projection.exactHead,
          ciProofBundleRefs: [...projection.exactHead.ciProofBundleRefs, duplicateCiDigest]
        },
        merge: {
          ...projection.merge,
          guard: {
            ...projection.merge.guard,
            proofBundleRefs: [...projection.merge.guard.proofBundleRefs, duplicateCiDigest]
          }
        }
      }).success
    ).toBe(false);

    const ciWithEqualityDigest = {
      ...projection.exactHead.ciProofBundleRefs[0],
      digest: projection.exactHead.equalityProofRef.digest
    };
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        exactHead: {
          ...projection.exactHead,
          ciProofBundleRefs: [ciWithEqualityDigest]
        },
        merge: {
          ...projection.merge,
          guard: {
            ...projection.merge.guard,
            proofBundleRefs: projection.merge.guard.proofBundleRefs.map((proofRef) =>
              proofRef.id === projection.exactHead.ciProofBundleRefs[0]!.id ? ciWithEqualityDigest : proofRef
            )
          }
        }
      }).success
    ).toBe(false);
  });

  test("keeps equality, CI, and review proof obligations globally distinct by identity and digest", () => {
    const projection = validProjection();
    const reviewOnly = parseProjection({
      ...projection,
      state: "reviewing",
      merge: undefined,
      cleanup: undefined
    });
    const equalityProof = reviewOnly.exactHead!.equalityProofRef;
    const sameIdentityAlias: TaskToPrProjection = {
      ...reviewOnly,
      reviews: [
        {
          ...reviewOnly.reviews[0]!,
          proofBundleRef: {
            ...reviewOnly.reviews[0]!.proofBundleRef,
            id: equalityProof.id
          }
        }
      ]
    };
    expect(TaskToPrProjectionSchema.safeParse(sameIdentityAlias).success).toBe(false);

    const sameDigestAlias: TaskToPrProjection = {
      ...reviewOnly,
      reviews: [
        {
          ...reviewOnly.reviews[0]!,
          proofBundleRef: {
            ...reviewOnly.reviews[0]!.proofBundleRef,
            digest: equalityProof.digest
          }
        }
      ]
    };
    expect(TaskToPrProjectionSchema.safeParse(sameDigestAlias).success).toBe(false);

    const eligible = parseProjection({
      ...projection,
      state: "merge_ready",
      merge: {
        guard: projection.merge.guard
      },
      cleanup: undefined
    });
    const ciProof = eligible.exactHead!.ciProofBundleRefs[0]!;
    const originalReviewProof = eligible.reviews[0]!.proofBundleRef;
    const sharedCiReviewProof: TaskToPrProjection = {
      ...eligible,
      reviews: [
        {
          ...eligible.reviews[0]!,
          proofBundleRef: ciProof
        }
      ],
      merge: {
        guard: {
          ...eligible.merge!.guard,
          proofBundleRefs: eligible.merge!.guard.proofBundleRefs.filter(
            (proofRef) => proofRef.id !== originalReviewProof.id
          )
        }
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(sharedCiReviewProof).success).toBe(false);

    const reviewProofWithCiDigest = {
      ...originalReviewProof,
      digest: ciProof.digest
    };
    const aliasedEligibleGuard: TaskToPrProjection = {
      ...eligible,
      reviews: [
        {
          ...eligible.reviews[0]!,
          proofBundleRef: reviewProofWithCiDigest
        }
      ],
      merge: {
        guard: {
          ...eligible.merge!.guard,
          proofBundleRefs: eligible.merge!.guard.proofBundleRefs.map((proofRef) =>
            proofRef.id === originalReviewProof.id ? reviewProofWithCiDigest : proofRef
          )
        }
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(aliasedEligibleGuard).success).toBe(false);
  });

  test("supports multiple exact-head reviews and keeps worker, reviewers, and merge operator distinct", () => {
    const projection = validProjection();
    const secondReview = {
      ...projection.reviews[0]!,
      ref: ref("review", "review", "3"),
      reviewerRef: ref("reviewer", "review", "5"),
      reviewRunRef: ref("review_run", "review", "4"),
      proofBundleRef: ref("proof_bundle", "review", "5")
    };
    const reviewed = withActiveProvenance({
      ...projection,
      reviews: [...projection.reviews, secondReview],
      merge: {
        ...projection.merge,
        guard: {
          ...projection.merge.guard,
          reviewRefs: [...projection.merge.guard.reviewRefs, secondReview.ref],
          proofBundleRefs: [...projection.merge.guard.proofBundleRefs, secondReview.proofBundleRef]
        }
      }
    });
    expect(TaskToPrProjectionSchema.safeParse(reviewed).success).toBe(true);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...reviewed,
        merge: {
          ...reviewed.merge,
          guard: {
            ...reviewed.merge.guard,
            reviewRefs: [...reviewed.merge.guard.reviewRefs, ref("review", "review", "9")]
          }
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...reviewed,
        merge: {
          ...reviewed.merge,
          guard: {
            ...reviewed.merge.guard,
            reviewRefs: [reviewed.reviews[0]!.ref]
          }
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...reviewed,
        merge: {
          ...reviewed.merge,
          guard: {
            ...reviewed.merge.guard,
            reviewRefs: [...reviewed.merge.guard.reviewRefs].reverse()
          }
        }
      }).success
    ).toBe(true);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...reviewed,
        reviews: [
          reviewed.reviews[0],
          {
            ...secondReview,
            reviewerRef: reviewed.reviews[0]!.reviewerRef
          }
        ]
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...reviewed,
        reviews: [
          reviewed.reviews[0],
          {
            ...secondReview,
            ref: {
              ...secondReview.ref,
              digest: reviewed.reviews[0]!.ref.digest
            }
          }
        ]
      }).success
    ).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        reviews: [
          {
            ...projection.reviews[0]!,
            reviewerRef: { ...projection.reviews[0]!.reviewerRef, digest: projection.attempt.workerRef.digest }
          }
        ]
      }).success
    ).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        reviews: [
          {
            ...projection.reviews[0]!,
            reviewRunRef: { ...projection.reviews[0]!.reviewRunRef, digest: projection.attempt.runtimeRef.digest }
          }
        ]
      }).success
    ).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        merge: {
          ...projection.merge,
          guard: {
            ...projection.merge.guard,
            operatorRef: { ...projection.merge.guard.operatorRef, digest: projection.reviews[0]!.reviewerRef.digest }
          }
        }
      }).success
    ).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...reviewed,
        reviews: [
          reviewed.reviews[0],
          {
            ...secondReview,
            reviewerRef: { ...secondReview.reviewerRef, id: reviewed.reviews[0]!.reviewerRef.id }
          }
        ]
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...reviewed,
        reviews: [
          reviewed.reviews[0],
          {
            ...secondReview,
            reviewerRef: { ...secondReview.reviewerRef, digest: reviewed.reviews[0]!.reviewerRef.digest }
          }
        ]
      }).success
    ).toBe(false);

    const reviewOnly = {
      ...reviewed,
      state: "reviewing",
      merge: undefined,
      cleanup: undefined
    };
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...reviewOnly,
        reviews: [
          reviewOnly.reviews[0],
          {
            ...reviewOnly.reviews[1],
            proofBundleRef: {
              ...reviewOnly.reviews[1]!.proofBundleRef,
              id: reviewOnly.reviews[0]!.proofBundleRef.id
            }
          }
        ]
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...reviewOnly,
        reviews: [
          reviewOnly.reviews[0],
          {
            ...reviewOnly.reviews[1],
            proofBundleRef: {
              ...reviewOnly.reviews[1]!.proofBundleRef,
              digest: reviewOnly.reviews[0]!.proofBundleRef.digest
            }
          }
        ]
      }).success
    ).toBe(false);

    const duplicateGuardDigest = {
      ...projection.merge.guard.proofBundleRefs[0],
      id: "proof_bundle:opaque-guard-duplicate-digest"
    };
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        merge: {
          ...projection.merge,
          guard: {
            ...projection.merge.guard,
            proofBundleRefs: [...projection.merge.guard.proofBundleRefs, duplicateGuardDigest]
          }
        }
      }).success
    ).toBe(false);
    const duplicateGuardCanonicalId = {
      ...projection.merge.guard.proofBundleRefs[0],
      digest: sha("9")
    };
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        merge: {
          ...projection.merge,
          guard: {
            ...projection.merge.guard,
            proofBundleRefs: [...projection.merge.guard.proofBundleRefs, duplicateGuardCanonicalId]
          }
        }
      }).success
    ).toBe(false);
  });

  test("enforces exact-head, review, guard, outcome, cleanup, and rollback chronology", () => {
    const projection = validProjection();
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        exactHead: {
          ...projection.exactHead,
          verifiedAt: "2026-07-23T15:09:59.000Z"
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        reviews: [
          {
            ...projection.reviews[0]!,
            reviewedAt: "2026-07-23T15:09:59.000Z"
          }
        ]
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        merge: {
          ...projection.merge,
          guard: {
            ...projection.merge.guard,
            evaluatedAt: "2026-07-23T15:09:59.000Z"
          }
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        cleanup: {
          ...projection.cleanup,
          outcome: {
            ...projection.cleanup.outcome,
            finishedAt: "2026-07-23T15:09:59.000Z"
          }
        }
      }).success
    ).toBe(false);
  });

  test("enforces repair cap and immutable cumulative state", () => {
    const projection = validProjection();
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        repair: { ...projection.repair, cycle: 3, exhausted: true }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        repair: { ...projection.repair, cycle: 2, exhausted: false }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        repair: { ...projection.repair, cycle: 0, exhausted: false, latestRepairRef: projection.repair.latestRepairRef }
      }).success
    ).toBe(false);
  });

  test("validates monotonic replay, repair, attempt, and terminal transitions", () => {
    const projection = validProjection();
    const previous = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      createdAt: "2026-07-23T15:09:00.000Z",
      state: "running",
      pullRequestRef: undefined,
      exactHead: undefined,
      reviews: [],
      handoff: undefined,
      merge: undefined,
      recovery: undefined,
      cleanup: undefined,
      repair: {
        ref: ref("repair_cycle", "todos", "0"),
        cycle: 0,
        cap: 2,
        exhausted: false
      },
      evidenceRefs: []
    });
    const current = parseProjection({
      ...previous,
      id: projectionId("valid-projection"),
      createdAt,
      events: {
        ...previous.events,
        replayCursorRef: ref("replay_cursor", "todos", "a"),
        sequence: previous.events.sequence + 1,
        prefixDigest: sha("b")
      }
    });
    expect(validateTaskToPrProjectionTransition(previous, current)).toEqual({ success: true, issues: [] });

    const replayed = {
      ...current,
      id: projectionId("valid-projection"),
      events: { ...current.events, sequence: previous.events.sequence - 1 }
    };
    expect(validateTaskToPrProjectionTransition(previous, replayed).success).toBe(false);

    const staleCursor = {
      ...current,
      id: projectionId("valid-projection"),
      events: {
        ...current.events,
        replayCursorRef: previous.events.replayCursorRef
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, staleCursor).success).toBe(false);

    const reusedCursorDigest: TaskToPrProjection = {
      ...current,
      id: projectionId("valid-projection"),
      events: {
        ...current.events,
        replayCursorRef: {
          ...current.events.replayCursorRef,
          id: "replay_cursor:opaque-fresh-id-stale-digest",
          digest: previous.events.replayCursorRef.digest
        }
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, reusedCursorDigest).success).toBe(false);

    const stalePrefix = {
      ...current,
      id: projectionId("valid-projection"),
      events: {
        ...current.events,
        prefixDigest: previous.events.prefixDigest
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, stalePrefix).success).toBe(false);

    const partialAttemptAdvance = {
      ...current,
      id: projectionId("valid-projection"),
      attempt: {
        ...current.attempt,
        nonce: attemptNonce("fresh")
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, partialAttemptAdvance).success).toBe(false);
    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...current,
        id: projectionId("valid-projection"),
        attempt: {
          ...current.attempt,
          runtimeRef: ref("runtime", "codewith", "c", "partial")
        }
      }).success
    ).toBe(false);
    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...current,
        id: projectionId("valid-projection"),
        repair: {
          ...current.repair,
          ref: ref("repair_cycle", "todos", "c")
        }
      }).success
    ).toBe(false);

    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...current,
        id: projectionId("valid-projection"),
        unknownMutablePayload: true
      }).success
    ).toBe(false);

    const mutatedTerminal = {
      ...projection,
      id: projectionId("valid-projection"),
      merge: {
        ...projection.merge,
        outcome: {
          ...projection.merge.outcome,
          finishedAt: "2026-07-23T15:11:00.000Z"
        }
      },
      cleanup: {
        ...projection.cleanup,
        eligibility: {
          ...projection.cleanup.eligibility,
          evaluatedAt: "2026-07-23T15:11:00.000Z"
        },
        outcome: {
          ...projection.cleanup.outcome,
          finishedAt: "2026-07-23T15:11:00.000Z"
        }
      }
    };
    expect(validateTaskToPrProjectionTransition(TaskToPrProjectionSchema.parse(projection), parseProjection(mutatedTerminal)).success).toBe(
      false
    );
  });

  test("requires immutable or fully rotated merge, cleanup, and rollback owner records", () => {
    const projection = validProjection();
    const mergePrevious = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "merge_ready",
      merge: {
        guard: projection.merge.guard
      },
      cleanup: undefined
    });
    const mergeRotated = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...mergePrevious,
      id: projectionId("valid-projection"),
      events: {
        ...mergePrevious.events,
        replayCursorRef: ref("replay_cursor", "todos", "2"),
        sequence: mergePrevious.events.sequence + 1,
        prefixDigest: sha("3")
      },
      merge: {
        guard: {
          ...mergePrevious.merge!.guard,
          ref: ref("merge_guard", "todos", "a"),
          mechanism: "queue_expected_head"
        }
      }
    }));

    const cleanupPrevious = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "merged",
      cleanup: {
        eligibility: projection.cleanup.eligibility
      }
    });
    const cleanupCursorRef = ref("replay_cursor", "todos", "4");
    const cleanupRotated = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...cleanupPrevious,
      id: projectionId("valid-projection"),
      events: {
        ...cleanupPrevious.events,
        replayCursorRef: cleanupCursorRef,
        sequence: cleanupPrevious.events.sequence + 1,
        prefixDigest: sha("5")
      },
      cleanup: {
        eligibility: {
          ...cleanupPrevious.cleanup!.eligibility,
          ref: ref("cleanup_eligibility", "repos", "a"),
          status: "preserved",
          eventCursorRef: cleanupCursorRef
        }
      }
    }));

    const rollbackPrevious = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...projection,
      id: projectionId("valid-projection"),
      state: "merged",
      cleanup: undefined,
      rollback: {
        plan: {
          ref: ref("rollback_plan", "todos", "a"),
          targetRef: projection.merge.outcome.mergeCommitRef!,
          createdAt
        }
      }
    }));
    const rollbackRotated = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...rollbackPrevious,
      id: projectionId("valid-projection"),
      events: {
        ...rollbackPrevious.events,
        replayCursorRef: ref("replay_cursor", "todos", "6"),
        sequence: rollbackPrevious.events.sequence + 1,
        prefixDigest: sha("7")
      },
      rollback: {
        plan: {
          ...rollbackPrevious.rollback!.plan,
          ref: ref("rollback_plan", "todos", "d"),
          targetRef: rollbackPrevious.repository.branchRef
        }
      }
    }));

    const cases = [
      {
        name: "merge guard mechanism",
        path: "merge.guard",
        previous: mergePrevious,
        rotated: mergeRotated,
        withRef: (candidate: TaskToPrProjection, ownerRef: TaskToPrRef) => ({
          ...candidate,
          merge: {
            guard: {
              ...candidate.merge!.guard,
              ref: ownerRef
            }
          }
        })
      },
      {
        name: "cleanup eligibility decision",
        path: "cleanup.eligibility",
        previous: cleanupPrevious,
        rotated: cleanupRotated,
        withRef: (candidate: TaskToPrProjection, ownerRef: TaskToPrRef) => ({
          ...candidate,
          cleanup: {
            eligibility: {
              ...candidate.cleanup!.eligibility,
              ref: ownerRef
            }
          }
        })
      },
      {
        name: "rollback target",
        path: "rollback.plan",
        previous: rollbackPrevious,
        rotated: rollbackRotated,
        withRef: (candidate: TaskToPrProjection, ownerRef: TaskToPrRef) => ({
          ...candidate,
          rollback: {
            plan: {
              ...candidate.rollback!.plan,
              ref: ownerRef
            }
          }
        })
      }
    ] as const;

    for (const ownerCase of cases) {
      const retained = parseProjection({
        ...ownerCase.previous,
        id: projectionId("valid-projection"),
      });
      expect(
        validateTaskToPrProjectionTransition(ownerCase.previous, retained),
        `${ownerCase.name} permits an exactly retained owner record`
      ).toEqual({ success: true, issues: [] });
      expect(
        validateTaskToPrProjectionTransition(ownerCase.previous, ownerCase.rotated),
        `${ownerCase.name} permits a fully fresh owner-record rotation`
      ).toEqual({ success: true, issues: [] });

      const previousRef =
        ownerCase.path === "merge.guard"
          ? ownerCase.previous.merge!.guard.ref
          : ownerCase.path === "cleanup.eligibility"
            ? ownerCase.previous.cleanup!.eligibility.ref
            : ownerCase.previous.rollback!.plan.ref;
      const rotatedRef =
        ownerCase.path === "merge.guard"
          ? ownerCase.rotated.merge!.guard.ref
          : ownerCase.path === "cleanup.eligibility"
            ? ownerCase.rotated.cleanup!.eligibility.ref
            : ownerCase.rotated.rollback!.plan.ref;
      const invalidRefs = [
        previousRef,
        {
          ...rotatedRef,
          digest: previousRef.digest
        },
        {
          ...rotatedRef,
          id: previousRef.id,
          digest: sha("c")
        }
      ];

      for (const [index, invalidRef] of invalidRefs.entries()) {
        const invalid = ownerCase.withRef(
          ownerCase.rotated,
          invalidRef
        );
        const parsedInvalid = TaskToPrProjectionSchema.safeParse(invalid);
        if (!parsedInvalid.success) {
          expect(parsedInvalid.success, `${ownerCase.name} stale provenance is rejected statically`).toBe(false);
          continue;
        }
        const result = validateTaskToPrProjectionTransition(ownerCase.previous, invalid);
        expect(result.success, `${ownerCase.name} invalid ref rotation ${index}`).toBe(false);
        expect(
          result.issues.some((issue) => issue.path === ownerCase.path),
          `${ownerCase.name} reports its owner-record path`
        ).toBe(true);
      }
    }
  });

  test("binds recovery and handoff transitions to the prior attempt, generation, WorkRun, and fresh attempt-scoped refs", () => {
    const base = validProjection();
    const previous = parseProjection({
      ...base,
      id: projectionId("valid-projection"),
      createdAt: "2026-07-23T15:08:00.000Z",
      state: "running",
      pullRequestRef: undefined,
      exactHead: undefined,
      handoff: undefined,
      reviews: [],
      merge: undefined,
      recovery: undefined,
      cleanup: undefined,
      repair: {
        ref: ref("repair_cycle", "todos", "0"),
        cycle: 0,
        cap: 2,
        exhausted: false
      },
      provenanceLedger: [],
      evidenceRefs: []
    });
    const nextAttempt = {
      ...previous.attempt,
      ref: ref("attempt", "todos", "a"),
      nonce: attemptNonce("next"),
      admissionRef: ref("admission", "codewith", "next", "partial"),
      workerRef: ref("worker", "codewith", "next", "partial"),
      runtimeRef: ref("runtime", "codewith", "b", "partial"),
      writerGenerationRef: ref("writer_generation", "todos", "5"),
      writerLeaseRef: ref("writer_lease", "repos", "d", "partial"),
      writerFenceRef: ref("writer_fence", "repos", "e", "full"),
      providerProfileRef: ref("provider_profile", "codewith", "f", "full"),
      providerRouteRef: ref("provider_route", "codewith", "0", "partial")
    };
    const nextWorkRunRef = ref("work_run", "codewith", "1");
    const recovery = {
      ref: ref("recovery", "todos", "2"),
      priorAttemptRef: previous.attempt.ref,
      priorWriterGenerationRef: previous.attempt.writerGenerationRef,
      priorWorkRunRef: previous.workRunRef,
      successorAttemptNonce: nextAttempt.nonce,
      successorWriterGenerationRef: nextAttempt.writerGenerationRef,
      preservedStateRefs: [
        previous.workRunRef,
        previous.rootRequestRef,
        previous.prGroupRef,
        previous.leafTaskRef,
        previous.repository.repoRef,
        previous.repository.worktreeRef,
        previous.repository.branchRef,
        previous.events.streamRef
      ],
      stopEvidenceRef: evidence("ev_transition_stop", "2"),
      leaseRevocationEvidenceRef: evidence("ev_transition_revoke", "3")
    };
    const recovered = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...previous,
      id: projectionId("valid-projection"),
      createdAt,
      state: "recovering",
      workRunRef: nextWorkRunRef,
      attempt: nextAttempt,
      recovery,
      events: {
        ...previous.events,
        replayCursorRef: ref("replay_cursor", "todos", "4"),
        sequence: previous.events.sequence + 1,
        prefixDigest: sha("5")
      }
    }));
    expect(validateTaskToPrProjectionTransition(previous, recovered)).toEqual({ success: true, issues: [] });

    const reusedAttemptDigest: TaskToPrProjection = {
      ...recovered,
      id: projectionId("valid-projection"),
      attempt: {
        ...recovered.attempt,
        ref: {
          ...recovered.attempt.ref,
          id: "attempt:opaque-fresh-id-stale-digest",
          digest: previous.attempt.ref.digest
        }
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, reusedAttemptDigest).success).toBe(false);

    const reusedGenerationDigest: TaskToPrProjection = {
      ...recovered,
      id: projectionId("valid-projection"),
      attempt: {
        ...recovered.attempt,
        writerGenerationRef: {
          ...recovered.attempt.writerGenerationRef,
          id: "writer_generation:opaque-fresh-id-stale-digest",
          digest: previous.attempt.writerGenerationRef.digest
        }
      },
      recovery: {
        ...recovered.recovery!,
        successorWriterGenerationRef: {
          ...recovered.attempt.writerGenerationRef,
          id: "writer_generation:opaque-fresh-id-stale-digest",
          digest: previous.attempt.writerGenerationRef.digest
        }
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, reusedGenerationDigest).success).toBe(false);

    const reusedWorkRunDigest: TaskToPrProjection = {
      ...recovered,
      id: projectionId("valid-projection"),
      workRunRef: {
        ...recovered.workRunRef,
        id: "work_run:opaque-fresh-id-stale-digest",
        digest: previous.workRunRef.digest
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, reusedWorkRunDigest).success).toBe(false);

    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...recovered,
        id: projectionId("valid-projection"),
        attempt: {
          ...recovered.attempt,
          ref: {
            ...recovered.attempt.ref,
            id: previous.attempt.ref.id,
            digest: sha("6")
          }
        }
      }).success
    ).toBe(false);
    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...recovered,
        id: projectionId("valid-projection"),
        attempt: {
          ...recovered.attempt,
          writerGenerationRef: {
            ...recovered.attempt.writerGenerationRef,
            id: previous.attempt.writerGenerationRef.id,
            digest: sha("7")
          }
        },
        recovery: {
          ...recovered.recovery,
          successorWriterGenerationRef: {
            ...recovered.attempt.writerGenerationRef,
            id: previous.attempt.writerGenerationRef.id,
            digest: sha("7")
          }
        }
      }).success
    ).toBe(false);
    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...recovered,
        id: projectionId("valid-projection"),
        workRunRef: {
          ...recovered.workRunRef,
          id: previous.workRunRef.id,
          digest: sha("8")
        }
      }).success
    ).toBe(false);

    for (const [field, staleRef] of [
      ["runtimeRef", previous.attempt.runtimeRef],
      ["writerLeaseRef", previous.attempt.writerLeaseRef],
      ["writerFenceRef", previous.attempt.writerFenceRef],
      ["providerProfileRef", previous.attempt.providerProfileRef],
      ["providerRouteRef", previous.attempt.providerRouteRef]
    ] as const) {
      expect(
        validateTaskToPrProjectionTransition(previous, {
          ...recovered,
          id: projectionId("valid-projection"),
          attempt: { ...recovered.attempt, [field]: staleRef }
        }).success
      ).toBe(false);
    }
    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...recovered,
        id: projectionId("valid-projection"),
        attempt: {
          ...recovered.attempt,
          runtimeRef: {
            ...recovered.attempt.runtimeRef,
            id: "runtime:opaque-fresh-display",
            digest: previous.attempt.runtimeRef.digest
          }
        }
      }).success
    ).toBe(false);

    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...recovered,
        id: projectionId("valid-projection"),
        recovery: { ...recovered.recovery, priorWorkRunRef: nextWorkRunRef }
      }).success
    ).toBe(false);

    const handedOff = withActiveProvenance({
      ...recovered,
      id: projectionId("valid-projection"),
      state: "handed_off",
      provenanceLedger: previous.provenanceLedger,
      recovery: undefined,
      handoff: {
        ref: ref("handoff", "todos", "6"),
        previousAttemptRef: previous.attempt.ref,
        nextAttemptRef: nextAttempt.ref,
        previousWriterGenerationRef: previous.attempt.writerGenerationRef,
        nextWriterGenerationRef: nextAttempt.writerGenerationRef,
        stoppedWorkRunRef: previous.workRunRef,
        stopEvidenceRef: evidence("ev_handoff_stop", "6"),
        leaseRevocationEvidenceRef: evidence("ev_handoff_revoke", "7")
      }
    });
    expect(validateTaskToPrProjectionTransition(previous, handedOff).success).toBe(true);
    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...handedOff,
        id: projectionId("valid-projection"),
        handoff: {
          ...handedOff.handoff,
          previousAttemptRef: nextAttempt.ref
        }
      }).success
    ).toBe(false);

    const retainedHandoff = withActiveProvenance({
      ...handedOff,
      id: projectionId("valid-projection"),
      events: {
        ...handedOff.events,
        replayCursorRef: ref("replay_cursor", "todos", "8"),
        sequence: handedOff.events.sequence + 1,
        prefixDigest: sha("9")
      }
    });
    expect(validateTaskToPrProjectionTransition(handedOff, retainedHandoff)).toEqual({
      success: true,
      issues: []
    });

    const removedHandoff = withActiveProvenance({
      ...retainedHandoff,
      id: projectionId("valid-projection"),
      state: "running" as const,
      handoff: undefined
    });
    expect(TaskToPrProjectionSchema.safeParse(removedHandoff).success).toBe(true);
    expect(validateTaskToPrProjectionTransition(handedOff, removedHandoff).success).toBe(false);

    const mutatedHandoff = withActiveProvenance({
      ...retainedHandoff,
      id: projectionId("valid-projection"),
      handoff: {
        ...retainedHandoff.handoff,
        stopEvidenceRef: evidence("ev_handoff_stop_mutated", "a")
      }
    });
    expect(TaskToPrProjectionSchema.safeParse(mutatedHandoff).success).toBe(true);
    expect(validateTaskToPrProjectionTransition(handedOff, mutatedHandoff).success).toBe(false);

    const switchedToRecovery = withActiveProvenance({
      ...retainedHandoff,
      id: projectionId("valid-projection"),
      state: "recovering" as const,
      handoff: undefined,
      recovery: {
        ...recovery,
        successorAttemptNonce: handedOff.attempt.nonce,
        successorWriterGenerationRef: handedOff.attempt.writerGenerationRef
      }
    });
    expect(TaskToPrProjectionSchema.safeParse(switchedToRecovery).success).toBe(true);
    expect(validateTaskToPrProjectionTransition(handedOff, switchedToRecovery).success).toBe(false);

    const retainedRecovery = withActiveProvenance({
      ...recovered,
      id: projectionId("valid-projection"),
      events: {
        ...recovered.events,
        replayCursorRef: ref("replay_cursor", "todos", "b"),
        sequence: recovered.events.sequence + 1,
        prefixDigest: sha("c")
      }
    });
    expect(validateTaskToPrProjectionTransition(recovered, retainedRecovery)).toEqual({
      success: true,
      issues: []
    });
    const mutatedRecovery = withActiveProvenance({
      ...retainedRecovery,
      id: projectionId("valid-projection"),
      recovery: {
        ...retainedRecovery.recovery!,
        stopEvidenceRef: evidence("ev_recovery_stop_mutated", "d")
      }
    });
    expect(TaskToPrProjectionSchema.safeParse(mutatedRecovery).success).toBe(true);
    expect(validateTaskToPrProjectionTransition(recovered, mutatedRecovery).success).toBe(false);
  });

  test("requires fresh handoff and recovery owner refs across consecutive attempt and WorkRun rotations", () => {
    const projection = validProjection();
    const initial = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "running",
      pullRequestRef: undefined,
      exactHead: undefined,
      handoff: undefined,
      reviews: [],
      merge: undefined,
      recovery: undefined,
      cleanup: undefined,
      rollback: undefined,
      repair: {
        ref: ref("repair_cycle", "todos", "0"),
        cycle: 0,
        cap: 2,
        exhausted: false
      },
      provenanceLedger: [],
      evidenceRefs: []
    });
    const firstSeeds = {
      attempt: "a",
      runtime: "b",
      generation: "5",
      lease: "d",
      fence: "e",
      profile: "f",
      route: "0",
      workRun: "1",
      cursor: "2",
      prefix: "3",
      owner: "4",
      stop: "5",
      revoke: "6"
    } as const;
    const secondSeeds = {
      attempt: "b",
      runtime: "c",
      generation: "6",
      lease: "e",
      fence: "f",
      profile: "0",
      route: "1",
      workRun: "2",
      cursor: "3",
      prefix: "4",
      owner: "5",
      stop: "6",
      revoke: "7"
    } as const;

    function rotateAttemptOwner(
      previous: TaskToPrProjection,
      owner: "handoff" | "recovery",
      seeds: typeof firstSeeds | typeof secondSeeds,
      label: string
    ): TaskToPrProjection {
      const nextAttempt = {
        ...previous.attempt,
        ref: ref("attempt", "todos", seeds.attempt),
        nonce: attemptNonce(`${label}`),
        admissionRef: ref("admission", "codewith", `${label}-admission`, "partial"),
        workerRef: ref("worker", "codewith", `${label}-worker`, "partial"),
        runtimeRef: ref("runtime", "codewith", seeds.runtime, "partial"),
        writerGenerationRef: ref("writer_generation", "todos", seeds.generation),
        writerLeaseRef: ref("writer_lease", "repos", seeds.lease, "partial"),
        writerFenceRef: ref("writer_fence", "repos", seeds.fence, "full"),
        providerProfileRef: ref("provider_profile", "codewith", seeds.profile, "full"),
        providerRouteRef: ref("provider_route", "codewith", seeds.route, "partial")
      };
      const nextWorkRunRef = ref("work_run", "codewith", seeds.workRun);
      const transitionRef = ref(owner, "todos", seeds.owner);
      const preservedStateRefs = [
        previous.workRunRef,
        previous.rootRequestRef,
        previous.prGroupRef,
        previous.leafTaskRef,
        previous.repository.repoRef,
        previous.repository.worktreeRef,
        previous.repository.branchRef,
        previous.events.streamRef
      ];

      return TaskToPrProjectionSchema.parse(withActiveProvenance({
        ...previous,
        id: projectionId("valid-projection"),
        state: owner === "handoff" ? "handed_off" : "recovering",
        workRunRef: nextWorkRunRef,
        attempt: nextAttempt,
        events: {
          ...previous.events,
          replayCursorRef: ref("replay_cursor", "todos", seeds.cursor),
          sequence: previous.events.sequence + 1,
          prefixDigest: sha(seeds.prefix)
        },
        handoff:
          owner === "handoff"
            ? {
                ref: transitionRef,
                previousAttemptRef: previous.attempt.ref,
                nextAttemptRef: nextAttempt.ref,
                previousWriterGenerationRef: previous.attempt.writerGenerationRef,
                nextWriterGenerationRef: nextAttempt.writerGenerationRef,
                stoppedWorkRunRef: previous.workRunRef,
                stopEvidenceRef: evidence(`ev_${owner}_${label}_stop`, seeds.stop),
                leaseRevocationEvidenceRef: evidence(`ev_${owner}_${label}_revoke`, seeds.revoke)
              }
            : undefined,
        recovery:
          owner === "recovery"
            ? {
                ref: transitionRef,
                priorAttemptRef: previous.attempt.ref,
                priorWriterGenerationRef: previous.attempt.writerGenerationRef,
                priorWorkRunRef: previous.workRunRef,
                successorAttemptNonce: nextAttempt.nonce,
                successorWriterGenerationRef: nextAttempt.writerGenerationRef,
                preservedStateRefs,
                stopEvidenceRef: evidence(`ev_${owner}_${label}_stop`, seeds.stop),
                leaseRevocationEvidenceRef: evidence(`ev_${owner}_${label}_revoke`, seeds.revoke)
              }
            : undefined
      }));
    }

    for (const owner of ["handoff", "recovery"] as const) {
      const first = rotateAttemptOwner(initial, owner, firstSeeds, "first");
      expect(validateTaskToPrProjectionTransition(initial, first), `${owner} establishes the first rotated owner fact`).toEqual({
        success: true,
        issues: []
      });
      const rotated = rotateAttemptOwner(first, owner, secondSeeds, "second");
      expect(
        validateTaskToPrProjectionTransition(first, rotated),
        `${owner} permits a fully fresh owner-record rotation`
      ).toEqual({ success: true, issues: [] });

      const previousRef = owner === "handoff" ? first.handoff!.ref : first.recovery!.ref;
      const rotatedRef = owner === "handoff" ? rotated.handoff!.ref : rotated.recovery!.ref;
      const invalidRefs = [
        previousRef,
        {
          ...rotatedRef,
          digest: previousRef.digest
        },
        {
          ...rotatedRef,
          id: previousRef.id,
          digest: sha("8")
        }
      ];

      for (const [index, invalidRef] of invalidRefs.entries()) {
        const invalid = {
          ...rotated,
          [owner]: {
            ...(owner === "handoff" ? rotated.handoff! : rotated.recovery!),
            ref: invalidRef
          }
        };
        const parsedInvalid = TaskToPrProjectionSchema.safeParse(invalid);
        if (!parsedInvalid.success) {
          expect(parsedInvalid.success, `${owner} stale provenance is rejected statically`).toBe(false);
          continue;
        }
        const result = validateTaskToPrProjectionTransition(first, invalid);
        expect(result.success, `${owner} invalid ref rotation ${index}`).toBe(false);
        expect(result.issues.some((issue) => issue.path === owner), `${owner} reports its owner-record path`).toBe(
          true
        );
      }
    }
  });

  test("rejects A-to-C reuse across every attempt, replay, and repair provenance identity", () => {
    const projection = validProjection();
    const initial = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "running",
      workRunRef: ref("work_run", "codewith", "lineage-a"),
      attempt: {
        ...projection.attempt,
        ref: ref("attempt", "todos", "lineage-a"),
        nonce: attemptNonce("lineage-a"),
        runtimeRef: ref("runtime", "codewith", "lineage-a", "partial"),
        writerGenerationRef: ref("writer_generation", "todos", "lineage-a"),
        writerLeaseRef: ref("writer_lease", "repos", "lineage-a", "partial"),
        writerFenceRef: ref("writer_fence", "repos", "lineage-a", "full"),
        providerProfileRef: ref("provider_profile", "codewith", "lineage-a", "full"),
        providerRouteRef: ref("provider_route", "codewith", "lineage-a", "partial")
      },
      events: {
        ...projection.events,
        replayCursorRef: ref("replay_cursor", "todos", "lineage-a"),
        sequence: 0,
        prefixDigest: sha("0")
      },
      pullRequestRef: undefined,
      exactHead: undefined,
      handoff: undefined,
      reviews: [],
      repair: {
        ref: ref("repair_cycle", "todos", "lineage-a"),
        cycle: 0,
        cap: 2,
        exhausted: false
      },
      merge: undefined,
      recovery: undefined,
      cancellation: undefined,
      cleanup: undefined,
      rollback: undefined,
      provenanceLedger: [],
      evidenceRefs: []
    });

    function rotateAttempt(
      previous: TaskToPrProjection,
      label: "b" | "c",
      prefixDigest: string
    ): TaskToPrProjection {
      const nextAttempt = {
        ...previous.attempt,
        ref: ref("attempt", "todos", `lineage-${label}`),
        nonce: attemptNonce(`lineage-${label}`),
        admissionRef: ref("admission", "codewith", `lineage-${label}`, "partial"),
        workerRef: ref("worker", "codewith", `lineage-${label}`, "partial"),
        runtimeRef: ref("runtime", "codewith", `lineage-${label}`, "partial"),
        writerGenerationRef: ref("writer_generation", "todos", `lineage-${label}`),
        writerLeaseRef: ref("writer_lease", "repos", `lineage-${label}`, "partial"),
        writerFenceRef: ref("writer_fence", "repos", `lineage-${label}`, "full"),
        providerProfileRef: ref("provider_profile", "codewith", `lineage-${label}`, "full"),
        providerRouteRef: ref("provider_route", "codewith", `lineage-${label}`, "partial")
      };
      return parseProjection({
        ...previous,
        id: projectionId("valid-projection"),
        state: "handed_off",
        workRunRef: ref("work_run", "codewith", `lineage-${label}`),
        attempt: nextAttempt,
        events: {
          ...previous.events,
          replayCursorRef: ref("replay_cursor", "todos", `lineage-${label}`),
          sequence: previous.events.sequence + 1,
          prefixDigest
        },
        handoff: {
          ref: ref("handoff", "todos", `lineage-${label}`),
          previousAttemptRef: previous.attempt.ref,
          nextAttemptRef: nextAttempt.ref,
          previousWriterGenerationRef: previous.attempt.writerGenerationRef,
          nextWriterGenerationRef: nextAttempt.writerGenerationRef,
          stoppedWorkRunRef: previous.workRunRef,
          stopEvidenceRef: evidence(`lineage_${label}_stop`, label === "b" ? "1" : "2"),
          leaseRevocationEvidenceRef: evidence(
            `lineage_${label}_revoke`,
            label === "b" ? "3" : "4"
          )
        },
        recovery: undefined,
        provenanceLedger: previous.provenanceLedger
      });
    }

    const middle = rotateAttempt(initial, "b", sha("1"));
    const current = rotateAttempt(middle, "c", sha("2"));
    expect(validateTaskToPrProjectionTransition(initial, middle)).toEqual({
      success: true,
      issues: []
    });
    expect(validateTaskToPrProjectionTransition(middle, current)).toEqual({
      success: true,
      issues: []
    });

    expect(initial.id).toBe(middle.id);
    expect(middle.id).toBe(current.id);

    type RefReuseCase = {
      category:
        | "work_run"
        | "attempt"
        | "runtime"
        | "writer_generation"
        | "writer_lease"
        | "writer_fence"
        | "provider_profile"
        | "provider_route"
        | "replay_cursor";
      prior: TaskToPrRef;
      read: (value: TaskToPrProjection) => TaskToPrRef;
      write: (value: TaskToPrProjection, next: TaskToPrRef) => void;
    };
    const refReuseCases: readonly RefReuseCase[] = [
      {
        category: "work_run",
        prior: initial.workRunRef,
        read: (value) => value.workRunRef,
        write: (value, next) => {
          value.workRunRef = next;
        }
      },
      {
        category: "attempt",
        prior: initial.attempt.ref,
        read: (value) => value.attempt.ref,
        write: (value, next) => {
          value.attempt.ref = next;
          value.handoff!.nextAttemptRef = next;
        }
      },
      {
        category: "runtime",
        prior: initial.attempt.runtimeRef,
        read: (value) => value.attempt.runtimeRef,
        write: (value, next) => {
          value.attempt.runtimeRef = next;
        }
      },
      {
        category: "writer_generation",
        prior: initial.attempt.writerGenerationRef,
        read: (value) => value.attempt.writerGenerationRef,
        write: (value, next) => {
          value.attempt.writerGenerationRef = next;
          value.handoff!.nextWriterGenerationRef = next;
        }
      },
      {
        category: "writer_lease",
        prior: initial.attempt.writerLeaseRef,
        read: (value) => value.attempt.writerLeaseRef,
        write: (value, next) => {
          value.attempt.writerLeaseRef = next;
        }
      },
      {
        category: "writer_fence",
        prior: initial.attempt.writerFenceRef,
        read: (value) => value.attempt.writerFenceRef,
        write: (value, next) => {
          value.attempt.writerFenceRef = next;
        }
      },
      {
        category: "provider_profile",
        prior: initial.attempt.providerProfileRef,
        read: (value) => value.attempt.providerProfileRef,
        write: (value, next) => {
          value.attempt.providerProfileRef = next;
        }
      },
      {
        category: "provider_route",
        prior: initial.attempt.providerRouteRef,
        read: (value) => value.attempt.providerRouteRef,
        write: (value, next) => {
          value.attempt.providerRouteRef = next;
        }
      },
      {
        category: "replay_cursor",
        prior: initial.events.replayCursorRef,
        read: (value) => value.events.replayCursorRef,
        write: (value, next) => {
          value.events.replayCursorRef = next;
        }
      }
    ];

    function latestCategoryIndex(
      value: TaskToPrProjection,
      category: TaskToPrProjection["provenanceLedger"][number]["category"]
    ): number {
      for (let index = value.provenanceLedger.length - 1; index >= 0; index -= 1) {
        if (value.provenanceLedger[index]!.category === category) {
          return index;
        }
      }
      throw new Error(`missing ${category} provenance entry`);
    }

    for (const reuseCase of refReuseCases) {
      const identityReuse = structuredClone(current);
      reuseCase.write(identityReuse, reuseCase.prior);
      identityReuse.provenanceLedger.splice(
        latestCategoryIndex(identityReuse, reuseCase.category),
        1
      );
      expect(TaskToPrProjectionSchema.safeParse(identityReuse).success, `${reuseCase.category} id fixture`).toBe(
        true
      );
      expect(
        validateTaskToPrProjectionTransition(middle, identityReuse).success,
        `${reuseCase.category} A identity cannot reactivate in C`
      ).toBe(false);

      const digestReuse = structuredClone(current);
      const currentRef = reuseCase.read(digestReuse);
      const reusedDigestRef = { ...currentRef, digest: reuseCase.prior.digest };
      reuseCase.write(digestReuse, reusedDigestRef);
      digestReuse.provenanceLedger[latestCategoryIndex(digestReuse, reuseCase.category)] = {
        category: reuseCase.category,
        ref: reusedDigestRef
      };
      expect(
        TaskToPrProjectionSchema.safeParse(digestReuse).success,
        `${reuseCase.category} A digest cannot be reused in C`
      ).toBe(false);
    }

    const nonceReuse = structuredClone(current);
    nonceReuse.attempt.nonce = initial.attempt.nonce;
    nonceReuse.provenanceLedger.splice(latestCategoryIndex(nonceReuse, "attempt_nonce"), 1);
    expect(TaskToPrProjectionSchema.safeParse(nonceReuse).success).toBe(true);
    expect(validateTaskToPrProjectionTransition(middle, nonceReuse).success).toBe(false);

    const duplicateNonceTombstone = structuredClone(current);
    duplicateNonceTombstone.attempt.nonce = initial.attempt.nonce;
    duplicateNonceTombstone.provenanceLedger[
      latestCategoryIndex(duplicateNonceTombstone, "attempt_nonce")
    ] = {
      category: "attempt_nonce",
      nonce: initial.attempt.nonce
    };
    expect(TaskToPrProjectionSchema.safeParse(duplicateNonceTombstone).success).toBe(false);

    const prefixReuse = structuredClone(current);
    prefixReuse.events.prefixDigest = initial.events.prefixDigest;
    prefixReuse.provenanceLedger[latestCategoryIndex(prefixReuse, "replay_prefix")] = {
      category: "replay_prefix",
      sequence: prefixReuse.events.sequence,
      prefixDigest: initial.events.prefixDigest
    };
    expect(TaskToPrProjectionSchema.safeParse(prefixReuse).success).toBe(false);

    const repairMiddle = parseProjection({
      ...initial,
      id: projectionId("valid-projection"),
      state: "repairing",
      events: {
        ...initial.events,
        replayCursorRef: ref("replay_cursor", "todos", "repair-b"),
        sequence: initial.events.sequence + 1,
        prefixDigest: sha("3")
      },
      repair: {
        ref: ref("repair_cycle", "todos", "repair-b-state"),
        cycle: 1,
        cap: 2,
        exhausted: false,
        latestRepairRef: ref("repair_cycle", "todos", "repair-b-latest")
      },
      provenanceLedger: initial.provenanceLedger
    });
    const repairCurrent = parseProjection({
      ...repairMiddle,
      id: projectionId("valid-projection"),
      events: {
        ...repairMiddle.events,
        replayCursorRef: ref("replay_cursor", "todos", "repair-c"),
        sequence: repairMiddle.events.sequence + 1,
        prefixDigest: sha("4")
      },
      repair: {
        ref: ref("repair_cycle", "todos", "repair-c-state"),
        cycle: 2,
        cap: 2,
        exhausted: true,
        latestRepairRef: ref("repair_cycle", "todos", "repair-c-latest")
      },
      provenanceLedger: repairMiddle.provenanceLedger
    });
    expect(validateTaskToPrProjectionTransition(initial, repairMiddle)).toEqual({
      success: true,
      issues: []
    });
    expect(validateTaskToPrProjectionTransition(repairMiddle, repairCurrent)).toEqual({
      success: true,
      issues: []
    });

    const repairStateIdentityReuse = structuredClone(repairCurrent);
    repairStateIdentityReuse.repair.ref = initial.repair.ref;
    repairStateIdentityReuse.provenanceLedger.splice(
      latestCategoryIndex(repairStateIdentityReuse, "repair_state"),
      1
    );
    expect(TaskToPrProjectionSchema.safeParse(repairStateIdentityReuse).success).toBe(true);
    expect(
      validateTaskToPrProjectionTransition(repairMiddle, repairStateIdentityReuse).success
    ).toBe(false);

    for (const category of ["repair_state", "latest_repair"] as const) {
      const repairDigestReuse = structuredClone(repairCurrent);
      const reused = {
        ...(category === "repair_state"
          ? repairDigestReuse.repair.ref
          : repairDigestReuse.repair.latestRepairRef!),
        digest: initial.repair.ref.digest
      };
      if (category === "repair_state") {
        repairDigestReuse.repair.ref = reused;
      } else {
        repairDigestReuse.repair.latestRepairRef = reused;
      }
      repairDigestReuse.provenanceLedger[latestCategoryIndex(repairDigestReuse, category)] = {
        category,
        ref: reused
      };
      expect(
        TaskToPrProjectionSchema.safeParse(repairDigestReuse).success,
        `${category} cannot reuse the A repair digest in cycle 2`
      ).toBe(false);
    }

    const latestRepairIdentityReuse = structuredClone(repairCurrent);
    latestRepairIdentityReuse.repair.latestRepairRef = initial.repair.ref;
    latestRepairIdentityReuse.provenanceLedger[
      latestCategoryIndex(latestRepairIdentityReuse, "latest_repair")
    ] = {
      category: "latest_repair",
      ref: initial.repair.ref
    };
    expect(TaskToPrProjectionSchema.safeParse(latestRepairIdentityReuse).success).toBe(false);
  });

  test("requires fresh repair refs and enforces the legal state graph without active re-entry", () => {
    const base = validProjection();
    const previous = parseProjection({
      ...base,
      id: projectionId("valid-projection"),
      createdAt: "2026-07-23T15:09:00.000Z",
      state: "reviewing",
      cleanup: undefined,
      merge: undefined,
      repair: {
        ref: ref("repair_cycle", "todos", "0"),
        cycle: 1,
        cap: 2,
        exhausted: false,
        latestRepairRef: ref("repair_cycle", "todos", "5")
      }
    });
    const repairing = parseProjection({
      ...previous,
      id: projectionId("valid-projection"),
      createdAt,
      state: "repairing",
      repair: {
        ref: ref("repair_cycle", "todos", "1"),
        cycle: 2,
        cap: 2,
        exhausted: true,
        latestRepairRef: ref("repair_cycle", "todos", "2")
      },
      events: {
        ...previous.events,
        replayCursorRef: ref("replay_cursor", "todos", "3"),
        sequence: previous.events.sequence + 1,
        prefixDigest: sha("4")
      }
    });
    expect(validateTaskToPrProjectionTransition(previous, repairing).success).toBe(true);

    const reusedRepairStateDigest: TaskToPrProjection = {
      ...repairing,
      id: projectionId("valid-projection"),
      repair: {
        ...repairing.repair,
        ref: {
          ...repairing.repair.ref,
          id: "repair_cycle:opaque-fresh-state-id-stale-digest",
          digest: previous.repair.ref.digest
        }
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, reusedRepairStateDigest).success).toBe(false);

    const reusedLatestRepairDigest: TaskToPrProjection = {
      ...repairing,
      id: projectionId("valid-projection"),
      repair: {
        ...repairing.repair,
        latestRepairRef: {
          ...repairing.repair.latestRepairRef!,
          id: "repair_cycle:opaque-fresh-latest-id-stale-digest",
          digest: previous.repair.latestRepairRef!.digest
        }
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, reusedLatestRepairDigest).success).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...repairing,
        repair: {
          ...repairing.repair,
          latestRepairRef: {
            ...repairing.repair.latestRepairRef!,
            digest: repairing.repair.ref.digest
          }
        }
      }).success
    ).toBe(false);

    const repairStateReusingPriorLatest: TaskToPrProjection = {
      ...repairing,
      id: projectionId("valid-projection"),
      repair: {
        ...repairing.repair,
        ref: {
          ...repairing.repair.ref,
          digest: previous.repair.latestRepairRef!.digest
        }
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, repairStateReusingPriorLatest).success).toBe(false);

    const latestRepairReusingPriorState: TaskToPrProjection = {
      ...repairing,
      id: projectionId("valid-projection"),
      repair: {
        ...repairing.repair,
        latestRepairRef: {
          ...repairing.repair.latestRepairRef!,
          digest: previous.repair.ref.digest
        }
      }
    };
    expect(validateTaskToPrProjectionTransition(previous, latestRepairReusingPriorState).success).toBe(false);

    expect(
      validateTaskToPrProjectionTransition(previous, {
        ...repairing,
        id: projectionId("valid-projection"),
        repair: {
          ...repairing.repair,
          ref: previous.repair.ref
        }
      }).success
    ).toBe(false);

    expect(
      validateTaskToPrProjectionTransition(
        parseProjection({
          ...previous,
          id: projectionId("valid-projection"),
          state: "running",
          reviews: [],
          exactHead: undefined,
          pullRequestRef: undefined
        }),
        {
          ...previous,
          id: projectionId("valid-projection"),
          state: "admitted",
          reviews: [],
          exactHead: undefined,
          pullRequestRef: undefined
        }
      ).success
    ).toBe(false);
    expect(
      validateTaskToPrProjectionTransition(base, {
        ...base,
        id: projectionId("valid-projection"),
        state: "running",
        merge: undefined,
        exactHead: undefined,
        reviews: [],
        pullRequestRef: undefined,
        cleanup: undefined
      }).success
    ).toBe(false);
  });

  test("enforces bidirectional lifecycle phase requirements", () => {
    const projection = validProjection();
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "handed_off",
        handoff: undefined,
        merge: undefined,
        cleanup: undefined
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "reviewing",
        reviews: [],
        merge: undefined,
        cleanup: undefined
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        cleanup: {
          ...projection.cleanup,
          outcome: { ...projection.cleanup.outcome, status: "failed" }
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "running"
      }).success
    ).toBe(false);

    const reviewOnly = parseProjection({
      ...projection,
      state: "reviewing",
      merge: undefined,
      cleanup: undefined
    });
    for (const state of ["admitted", "running", "handed_off"] as const) {
      expect(
        TaskToPrProjectionSchema.safeParse({
          ...reviewOnly,
          state,
          handoff: state === "handed_off" ? projection.handoff : undefined,
          recovery: undefined
        }).success
      ).toBe(false);
    }

    const earlyEligibleGuard = {
      ...projection,
      state: "reviewing" as const,
      merge: {
        guard: projection.merge.guard
      },
      cleanup: undefined
    };
    expect(TaskToPrProjectionSchema.safeParse(earlyEligibleGuard).success).toBe(false);

    const runningPrevious = parseProjection({
      ...reviewOnly,
      id: projectionId("valid-projection"),
      state: "running",
      reviews: []
    });
    const runningWithApprovedReview: TaskToPrProjection = {
      ...runningPrevious,
      id: projectionId("valid-projection"),
      reviews: reviewOnly.reviews
    };
    expect(TaskToPrProjectionSchema.safeParse(runningWithApprovedReview).success).toBe(false);
    expect(validateTaskToPrProjectionTransition(runningPrevious, runningWithApprovedReview).success).toBe(false);
  });

  test("requires replay advancement for semantic lifecycle drift and preserves canonical pull-request identity", () => {
    const projection = validProjection();
    const runningWithPullRequest = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "running",
      exactHead: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined
    });

    const phaseDrift = withActiveProvenance({
      ...runningWithPullRequest,
      id: projectionId("valid-projection"),
      state: "blocked",
      terminalDispositionRef: ref("terminal_disposition", "todos", "blocked-stale-cursor"),
      evidenceRefs: [evidence("blocked_stale_cursor", "1")]
    });
    const phaseDriftResult = validateTaskToPrProjectionTransition(runningWithPullRequest, phaseDrift);
    expect(phaseDriftResult.success).toBe(false);
    expect(phaseDriftResult.issues.some((issue) => issue.path === "events.sequence")).toBe(true);

    const recoveryProjection = parseProjection({
      ...validRecoveryProjection(),
      id: projectionId("valid-projection"),
      state: "recovering",
      pullRequestRef: undefined,
      exactHead: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      recovery: {
        ...validRecoveryProjection().recovery,
        preservedStateRefs: validRecoveryProjection().recovery.preservedStateRefs.filter(
          (preservedRef) => preservedRef.role !== "pull_request"
        )
      }
    });
    const recoveryIdentityDrift = withActiveProvenance({
      ...recoveryProjection,
      id: projectionId("valid-projection"),
      recovery: {
        ...recoveryProjection.recovery!,
        ref: ref("recovery", "todos", "a")
      }
    });
    const recoveryDriftResult = validateTaskToPrProjectionTransition(recoveryProjection, recoveryIdentityDrift);
    expect(recoveryDriftResult.success).toBe(false);
    expect(recoveryDriftResult.issues.some((issue) => issue.path === "events.sequence")).toBe(true);

    const advancedEvents = {
      ...runningWithPullRequest.events,
      replayCursorRef: ref("replay_cursor", "todos", "a"),
      sequence: runningWithPullRequest.events.sequence + 1,
      prefixDigest: sha("b")
    };
    for (const pullRequestRef of [undefined, ref("pull_request", "todos", "c")]) {
      const pullRequestDriftResult = validateTaskToPrProjectionTransition(
        runningWithPullRequest,
        withActiveProvenance({
          ...runningWithPullRequest,
          id: projectionId("valid-projection"),
          events: advancedEvents,
          pullRequestRef
        })
      );
      expect(pullRequestDriftResult.success).toBe(false);
      expect(pullRequestDriftResult.issues.some((issue) => issue.path === "pullRequestRef")).toBe(true);
    }
  });

  test("preserves immutable same-head review history and permits append-only review evidence", () => {
    const projection = validProjection();
    const adverseReview = {
      ...projection.reviews[0],
      verdict: "changes_requested" as const
    };
    const previous = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...projection,
      id: projectionId("valid-projection"),
      state: "reviewing",
      reviews: [adverseReview],
      merge: undefined,
      cleanup: undefined
    }));
    const approvedReview = {
      ref: ref("review", "review", "3"),
      pullRequestRef: projection.pullRequestRef,
      base: projection.repository.baseHead,
      head: projection.repository.branchHead,
      reviewerRef: ref("reviewer", "review", "3"),
      reviewRunRef: ref("review_run", "review", "4"),
      proofBundleRef: ref("proof_bundle", "review", "5"),
      verdict: "approved" as const,
      reviewedAt: createdAt
    };
    const advancedEvents = {
      ...previous.events,
      replayCursorRef: ref("replay_cursor", "todos", "6"),
      sequence: previous.events.sequence + 1,
      prefixDigest: sha("7")
    };

    const appendOnly = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...previous,
      id: projectionId("valid-projection"),
      events: advancedEvents,
      reviews: [adverseReview, approvedReview]
    }));
    expect(validateTaskToPrProjectionTransition(previous, appendOnly)).toEqual({ success: true, issues: [] });

    const reorderedHistory = parseProjection({
      ...appendOnly,
      id: projectionId("valid-projection"),
      events: {
        ...appendOnly.events,
        replayCursorRef: ref("replay_cursor", "todos", "8"),
        sequence: appendOnly.events.sequence + 1,
        prefixDigest: sha("9")
      },
      reviews: [approvedReview, adverseReview]
    });
    expect(validateTaskToPrProjectionTransition(appendOnly, reorderedHistory).success).toBe(false);

    const prependedHistory = parseProjection({
      ...appendOnly,
      id: projectionId("valid-projection"),
      reviews: [approvedReview, adverseReview]
    });
    expect(validateTaskToPrProjectionTransition(previous, prependedHistory).success).toBe(false);

    const rewrittenAdverseReview = validateTaskToPrProjectionTransition(
      previous,
      withActiveProvenance({
        ...previous,
        id: projectionId("valid-projection"),
        events: advancedEvents,
        reviews: [{ ...adverseReview, verdict: "approved" }]
      })
    );
    expect(rewrittenAdverseReview.success).toBe(false);
    expect(rewrittenAdverseReview.issues.some((issue) => issue.path === "reviews")).toBe(true);

    const replacedForEligibility = withActiveProvenance({
      ...appendOnly,
      id: projectionId("valid-projection"),
      state: "merge_ready" as const,
      reviews: [approvedReview],
      merge: {
        guard: {
          ...projection.merge.guard,
          reviewRefs: [approvedReview.ref],
          proofBundleRefs: [
            approvedReview.proofBundleRef,
            projection.exactHead.equalityProofRef,
            ...projection.exactHead.ciProofBundleRefs
          ]
        }
      }
    });
    const replacedHistoryResult = validateTaskToPrProjectionTransition(previous, replacedForEligibility);
    expect(replacedHistoryResult.success).toBe(false);
    expect(replacedHistoryResult.issues.some((issue) => issue.path === "reviews")).toBe(true);
  });

  test("preserves the complete exact-head fact for an unchanged branch head", () => {
    const projection = validProjection();
    const secondCiProof = ref("proof_bundle", "review", "3");
    const previous = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...projection,
      id: projectionId("valid-projection"),
      createdAt: "2026-07-23T15:09:00.000Z",
      state: "running",
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      exactHead: {
        ...projection.exactHead,
        ciProofBundleRefs: [...projection.exactHead.ciProofBundleRefs, secondCiProof]
      }
    }));
    const advancedEvents = {
      ...previous.events,
      replayCursorRef: ref("replay_cursor", "todos", "3"),
      sequence: previous.events.sequence + 1,
      prefixDigest: sha("4")
    };
    const retained = parseProjection({
      ...previous,
      id: projectionId("valid-projection"),
      createdAt,
      events: advancedEvents
    });
    expect(validateTaskToPrProjectionTransition(previous, retained)).toEqual({ success: true, issues: [] });

    const removed = parseProjection({
      ...retained,
      id: projectionId("valid-projection"),
      exactHead: undefined
    });
    expect(validateTaskToPrProjectionTransition(previous, removed).success).toBe(false);

    const replacedEqualityProof = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...retained,
      id: projectionId("valid-projection"),
      exactHead: {
        ...retained.exactHead!,
        equalityProofRef: ref("proof_bundle", "review", "5")
      }
    }));
    expect(validateTaskToPrProjectionTransition(previous, replacedEqualityProof).success).toBe(false);

    const reorderedCiProofs = parseProjection({
      ...retained,
      id: projectionId("valid-projection"),
      exactHead: {
        ...retained.exactHead!,
        ciProofBundleRefs: [...retained.exactHead!.ciProofBundleRefs].reverse()
      }
    });
    expect(validateTaskToPrProjectionTransition(previous, reorderedCiProofs).success).toBe(false);
  });

  test("requires fresh exact-head proof and review identities after branch-head changes", () => {
    const projection = validProjection();
    const previous = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      createdAt: "2026-07-23T15:09:00.000Z",
      state: "reviewing",
      merge: undefined,
      cleanup: undefined
    });
    const nextHead = head("b");
    const freshCrossHead = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...previous,
      id: projectionId("valid-projection"),
      createdAt: "2026-07-23T15:12:00.000Z",
      repository: {
        ...previous.repository,
        branchHead: nextHead
      },
      events: {
        ...previous.events,
        replayCursorRef: ref("replay_cursor", "todos", "a"),
        sequence: previous.events.sequence + 1,
        prefixDigest: sha("b")
      },
      exactHead: {
        ...previous.exactHead!,
        localHead: nextHead,
        remoteHead: nextHead,
        providerPullRequestHead: nextHead,
        equalityProofRef: ref("proof_bundle", "review", "3"),
        ciProofBundleRefs: [ref("proof_bundle", "review", "4")],
        verifiedAt: "2026-07-23T15:12:00.000Z"
      },
      reviews: previous.reviews.map((review) => ({
        ...review,
        ref: ref("review", "review", "7"),
        head: nextHead,
        reviewRunRef: ref("review_run", "review", "9"),
        proofBundleRef: ref("proof_bundle", "review", "5"),
        reviewedAt: "2026-07-23T15:12:00.000Z"
      }))
    }));

    expect(validateTaskToPrProjectionTransition(previous, freshCrossHead)).toEqual({ success: true, issues: [] });
    expect(freshCrossHead.reviews[0]!.reviewerRef).toEqual(previous.reviews[0]!.reviewerRef);

    const reusedEverything: TaskToPrProjection = {
      ...freshCrossHead,
      id: projectionId("valid-projection"),
      exactHead: {
        ...freshCrossHead.exactHead!,
        equalityProofRef: previous.exactHead!.equalityProofRef,
        ciProofBundleRefs: previous.exactHead!.ciProofBundleRefs
      },
      reviews: previous.reviews.map((review) => ({
        ...review,
        head: nextHead,
        reviewedAt: "2026-07-23T15:12:00.000Z"
      }))
    };
    expect(TaskToPrProjectionSchema.safeParse(reusedEverything).success).toBe(false);
    expect(validateTaskToPrProjectionTransition(previous, reusedEverything).success).toBe(false);

    const staleIdentityCases: Array<{
      label: string;
      mutate: (candidate: TaskToPrProjection) => void;
    }> = [
      {
        label: "equality proof canonical id",
        mutate: (candidate) => {
          candidate.exactHead!.equalityProofRef.id = previous.exactHead!.equalityProofRef.id;
        }
      },
      {
        label: "equality proof digest",
        mutate: (candidate) => {
          candidate.exactHead!.equalityProofRef.digest = previous.exactHead!.equalityProofRef.digest;
        }
      },
      {
        label: "CI proof canonical id",
        mutate: (candidate) => {
          candidate.exactHead!.ciProofBundleRefs[0]!.id = previous.exactHead!.ciProofBundleRefs[0]!.id;
        }
      },
      {
        label: "CI proof digest",
        mutate: (candidate) => {
          candidate.exactHead!.ciProofBundleRefs[0]!.digest = previous.exactHead!.ciProofBundleRefs[0]!.digest;
        }
      },
      {
        label: "review canonical id",
        mutate: (candidate) => {
          candidate.reviews[0]!.ref.id = previous.reviews[0]!.ref.id;
        }
      },
      {
        label: "review digest",
        mutate: (candidate) => {
          candidate.reviews[0]!.ref.digest = previous.reviews[0]!.ref.digest;
        }
      },
      {
        label: "review-run canonical id",
        mutate: (candidate) => {
          candidate.reviews[0]!.reviewRunRef.id = previous.reviews[0]!.reviewRunRef.id;
        }
      },
      {
        label: "review-run digest",
        mutate: (candidate) => {
          candidate.reviews[0]!.reviewRunRef.digest = previous.reviews[0]!.reviewRunRef.digest;
        }
      },
      {
        label: "review proof canonical id",
        mutate: (candidate) => {
          candidate.reviews[0]!.proofBundleRef.id = previous.reviews[0]!.proofBundleRef.id;
        }
      },
      {
        label: "review proof digest",
        mutate: (candidate) => {
          candidate.reviews[0]!.proofBundleRef.digest = previous.reviews[0]!.proofBundleRef.digest;
        }
      }
    ];
    for (const { label, mutate } of staleIdentityCases) {
      const candidate = structuredClone(freshCrossHead);
      candidate.id = previous.id;
      mutate(candidate);
      expect(validateTaskToPrProjectionTransition(previous, candidate).success, label).toBe(false);
    }

    const reorderedAndExpanded: TaskToPrProjection = {
      ...freshCrossHead,
      id: projectionId("valid-projection"),
      exactHead: {
        ...freshCrossHead.exactHead!,
        ciProofBundleRefs: [
          ref("proof_bundle", "review", "8"),
          previous.exactHead!.equalityProofRef
        ]
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(reorderedAndExpanded).success).toBe(false);
    expect(validateTaskToPrProjectionTransition(previous, reorderedAndExpanded).success).toBe(false);

    type HeadBoundEvidenceCategory = {
      name: string;
      path: string;
      read: (value: TaskToPrProjection) => TaskToPrRef;
    };
    const headBoundEvidenceCategories: readonly HeadBoundEvidenceCategory[] = [
      {
        name: "equality-proof",
        path: "exactHead.equalityProofRef",
        read: (value) => value.exactHead!.equalityProofRef
      },
      {
        name: "ci-proof",
        path: "exactHead.ciProofBundleRefs.0",
        read: (value) => value.exactHead!.ciProofBundleRefs[0]!
      },
      {
        name: "review-proof",
        path: "reviews.0.proofBundleRef",
        read: (value) => value.reviews[0]!.proofBundleRef
      },
      {
        name: "review-record",
        path: "reviews.0.ref",
        read: (value) => value.reviews[0]!.ref
      },
      {
        name: "review-run",
        path: "reviews.0.reviewRunRef",
        read: (value) => value.reviews[0]!.reviewRunRef
      }
    ];
    const crossHeadCategoryPairs = headBoundEvidenceCategories.flatMap((priorCategory) =>
      headBoundEvidenceCategories.map((currentCategory) => ({ priorCategory, currentCategory }))
    );
    expect(crossHeadCategoryPairs).toHaveLength(25);

    for (const { priorCategory, currentCategory } of crossHeadCategoryPairs) {
      const caseLabel = `${priorCategory.name} to ${currentCategory.name}`;

      const reusedIdentity = structuredClone(freshCrossHead);
      currentCategory.read(reusedIdentity).id = priorCategory.read(previous).id;
      const identitySchemaResult = TaskToPrProjectionSchema.safeParse(reusedIdentity);
      const identityTransitionResult = validateTaskToPrProjectionTransition(previous, reusedIdentity);
      expect(identityTransitionResult.success, `${caseLabel} canonical identity`).toBe(false);
      if (identitySchemaResult.success) {
        expect(identityTransitionResult, `${caseLabel} canonical identity`).toMatchObject({
          success: false,
          issues: [
            {
              path: currentCategory.path,
              message:
                "A changed branch head requires every head-bound evidence ref to use a fresh canonical identity"
            }
          ]
        });
      }

      const reusedDigest = structuredClone(freshCrossHead);
      currentCategory.read(reusedDigest).digest = priorCategory.read(previous).digest;
      expect(validateTaskToPrProjectionTransition(previous, reusedDigest).success, `${caseLabel} digest`).toBe(false);
    }
  });

  test("keeps owner tombstones monotonic across omission and rejects multi-snapshot ABA reactivation", () => {
    const projection = validProjection();
    const present = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "merged",
      cleanup: {
        eligibility: projection.cleanup.eligibility
      }
    });
    const absentCursor = ref("replay_cursor", "todos", "3");
    const absent = parseProjection({
      ...present,
      id: projectionId("valid-projection"),
      cleanup: undefined,
      events: {
        ...present.events,
        replayCursorRef: absentCursor,
        sequence: present.events.sequence + 1,
        prefixDigest: sha("4")
      }
    });
    expect(validateTaskToPrProjectionTransition(present, absent)).toEqual({ success: true, issues: [] });
    expect(absent.provenanceLedger.slice(0, present.provenanceLedger.length)).toEqual(
      present.provenanceLedger
    );
    expect(absent.provenanceLedger.slice(present.provenanceLedger.length).map((entry) => entry.category)).toEqual([
      "replay_cursor",
      "replay_prefix"
    ]);

    const reactivatedCursor = ref("replay_cursor", "todos", "5");
    const reactivated = parseProjection({
      ...absent,
      id: projectionId("valid-projection"),
      cleanup: {
        eligibility: {
          ...present.cleanup!.eligibility,
          eventCursorRef: reactivatedCursor
        }
      },
      events: {
        ...absent.events,
        replayCursorRef: reactivatedCursor,
        sequence: absent.events.sequence + 1,
        prefixDigest: sha("7")
      }
    });
    expect(validateTaskToPrProjectionTransition(absent, reactivated).success).toBe(false);

    const freshCursor = ref("replay_cursor", "todos", "9");
    const freshRotation = TaskToPrProjectionSchema.parse(
      withActiveProvenance({
        ...absent,
        id: projectionId("valid-projection"),
        cleanup: {
          eligibility: {
            ...present.cleanup!.eligibility,
            ref: ref("cleanup_eligibility", "repos", "a"),
            status: "preserved",
            eventCursorRef: freshCursor
          }
        },
        events: {
          ...absent.events,
          replayCursorRef: freshCursor,
          sequence: absent.events.sequence + 1,
          prefixDigest: sha("d")
        }
      })
    );
    expect(validateTaskToPrProjectionTransition(absent, freshRotation)).toEqual({
      success: true,
      issues: []
    });
  });

  test("treats ref redaction as exact provenance in ledger prefixes and active bindings", () => {
    const previous = parseProjection({
      ...validProjection(),
      state: "reviewing",
      handoff: undefined,
      merge: undefined,
      cleanup: undefined
    });
    const prefixRedactionMutation = structuredClone(previous);
    prefixRedactionMutation.id = previous.id;
    const handoffIndex = prefixRedactionMutation.provenanceLedger.findIndex(
      (entry) => entry.category === "handoff"
    );
    const handoffEntry = prefixRedactionMutation.provenanceLedger[handoffIndex]!;
    if (!("ref" in handoffEntry)) {
      throw new Error("expected a handoff ref provenance entry");
    }
    handoffEntry.ref.redaction = "partial";
    prefixRedactionMutation.events = {
      ...prefixRedactionMutation.events,
      replayCursorRef: ref("replay_cursor", "todos", "b"),
      sequence: previous.events.sequence + 1,
      prefixDigest: sha("4")
    };
    const prefixCandidate = withActiveProvenance(prefixRedactionMutation);
    expect(TaskToPrProjectionSchema.safeParse(prefixCandidate).success).toBe(true);
    const prefixCandidateWithStableId = {
      ...prefixCandidate,
      id: previous.id,
      provenanceLedger: prefixCandidate.provenanceLedger.filter(
        (entry) => entry.category !== "projection_id" || entry.projectionId === previous.id
      )
    };
    expect(validateTaskToPrProjectionTransition(previous, prefixCandidateWithStableId)).toMatchObject({
      success: false,
      issues: [
        {
          path: "provenanceLedger",
          message:
            "The provenance ledger is append-only and must retain the previous ledger as an exact immutable prefix"
        }
      ]
    });

    const activeRedactionMismatch = structuredClone(validProjection());
    activeRedactionMismatch.provenanceLedger = activeRedactionMismatch.provenanceLedger.map((entry) =>
      entry.category === "handoff"
        ? { ...entry, ref: { ...entry.ref, redaction: "partial" as const } }
        : entry
    );
    expect(TaskToPrProjectionSchema.safeParse(activeRedactionMismatch).success).toBe(false);
  });

  test("retains head-evidence tombstones through five evidence-free lifecycle steps and rejects stale reuse", () => {
    const projection = validProjection();
    const reviewed = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "reviewing",
      merge: undefined,
      cleanup: undefined
    });
    const repairing = parseProjection({
      ...reviewed,
      id: projectionId("valid-projection"),
      state: "repairing",
      repair: {
        ref: ref("repair_cycle", "todos", "five-step-state"),
        cycle: reviewed.repair.cycle + 1,
        cap: 2,
        exhausted: true,
        latestRepairRef: ref("repair_cycle", "todos", "five-step-latest")
      },
      events: {
        ...reviewed.events,
        replayCursorRef: ref("replay_cursor", "todos", "3"),
        sequence: reviewed.events.sequence + 1,
        prefixDigest: sha("4")
      }
    });
    expect(validateTaskToPrProjectionTransition(reviewed, repairing)).toEqual({
      success: true,
      issues: []
    });

    const nextHead = head("b");
    const evidenceFree = parseProjection({
      ...repairing,
      id: projectionId("valid-projection"),
      state: "running",
      repository: {
        ...repairing.repository,
        branchHead: nextHead
      },
      exactHead: undefined,
      reviews: [],
      events: {
        ...repairing.events,
        replayCursorRef: ref("replay_cursor", "todos", "5"),
        sequence: repairing.events.sequence + 1,
        prefixDigest: sha("7")
      }
    });
    expect(validateTaskToPrProjectionTransition(repairing, evidenceFree)).toEqual({
      success: true,
      issues: []
    });

    const stillEvidenceFree = parseProjection({
      ...evidenceFree,
      id: projectionId("valid-projection"),
      state: "running",
      events: {
        ...evidenceFree.events,
        replayCursorRef: ref("replay_cursor", "todos", "9"),
        sequence: evidenceFree.events.sequence + 1,
        prefixDigest: sha("a")
      }
    });
    expect(validateTaskToPrProjectionTransition(evidenceFree, stillEvidenceFree)).toEqual({
      success: true,
      issues: []
    });

    const staleReview = {
      ...reviewed.reviews[0]!,
      head: nextHead,
      reviewedAt: "2026-07-23T15:12:00.000Z"
    };
    const staleFifthSnapshot = {
      ...stillEvidenceFree,
      id: projectionId("valid-projection"),
      state: "reviewing" as const,
      exactHead: {
        ...reviewed.exactHead!,
        localHead: nextHead,
        remoteHead: nextHead,
        providerPullRequestHead: nextHead,
        verifiedAt: "2026-07-23T15:12:00.000Z"
      },
      reviews: [staleReview],
      events: {
        ...stillEvidenceFree.events,
        replayCursorRef: ref("replay_cursor", "todos", "d"),
        sequence: stillEvidenceFree.events.sequence + 1,
        prefixDigest: sha("3")
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(staleFifthSnapshot).success).toBe(false);
    expect(
      validateTaskToPrProjectionTransition(stillEvidenceFree, staleFifthSnapshot).success
    ).toBe(false);
  });

  test("allows same-head review provenance to survive recovery but rejects recovery-time invention", () => {
    const projection = validProjection();
    const reviewed = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "reviewing",
      merge: undefined,
      cleanup: undefined
    });

    function recoverySnapshot(
      previous: TaskToPrProjection,
      exactHead: TaskToPrProjection["exactHead"],
      reviews: TaskToPrProjection["reviews"],
      provenanceLedger: TaskToPrProjection["provenanceLedger"],
      id: string
    ): TaskToPrProjection {
      const nextAttempt = {
        ...previous.attempt,
        ref: ref("attempt", "todos", "a"),
        nonce: attemptNonce("review-recovery"),
        admissionRef: ref("admission", "codewith", "review-recovery", "partial"),
        workerRef: ref("worker", "codewith", "review-recovery", "partial"),
        runtimeRef: ref("runtime", "codewith", "b", "partial"),
        writerGenerationRef: ref("writer_generation", "todos", "5"),
        writerLeaseRef: ref("writer_lease", "repos", "d", "partial"),
        writerFenceRef: ref("writer_fence", "repos", "e", "full"),
        providerProfileRef: ref("provider_profile", "codewith", "f", "full"),
        providerRouteRef: ref("provider_route", "codewith", "0", "partial")
      };
      const recovery = {
        ref: ref("recovery", "todos", "7"),
        priorAttemptRef: previous.attempt.ref,
        priorWriterGenerationRef: previous.attempt.writerGenerationRef,
        priorWorkRunRef: previous.workRunRef,
        successorAttemptNonce: nextAttempt.nonce,
        successorWriterGenerationRef: nextAttempt.writerGenerationRef,
        preservedStateRefs: [
          previous.workRunRef,
          previous.rootRequestRef,
          previous.prGroupRef,
          previous.leafTaskRef,
          previous.repository.repoRef,
          previous.repository.worktreeRef,
          previous.repository.branchRef,
          previous.events.streamRef,
          previous.pullRequestRef!
        ],
        stopEvidenceRef: evidence("ev_review_recovery_stop", "2"),
        leaseRevocationEvidenceRef: evidence("ev_review_recovery_revoke", "3")
      };
      return TaskToPrProjectionSchema.parse(
        withActiveProvenance({
          ...previous,
          id,
          state: "recovering",
          workRunRef: ref("work_run", "codewith", "1"),
          attempt: nextAttempt,
          handoff: undefined,
          recovery,
          exactHead,
          reviews,
          provenanceLedger,
          events: {
            ...previous.events,
            replayCursorRef: ref("replay_cursor", "todos", "4"),
            sequence: previous.events.sequence + 1,
            prefixDigest: sha("5")
          }
        })
      );
    }

    const retained = recoverySnapshot(
      reviewed,
      reviewed.exactHead,
      reviewed.reviews,
      reviewed.provenanceLedger,
      reviewed.id
    );
    expect(validateTaskToPrProjectionTransition(reviewed, retained)).toEqual({
      success: true,
      issues: []
    });

    const preReview = parseProjection({
      ...reviewed,
      id: projectionId("valid-projection"),
      state: "running",
      handoff: undefined,
      exactHead: undefined,
      reviews: [],
      provenanceLedger: []
    });
    const invented = recoverySnapshot(
      preReview,
      reviewed.exactHead,
      reviewed.reviews,
      preReview.provenanceLedger,
      preReview.id
    );
    expect(TaskToPrProjectionSchema.safeParse(invented).success).toBe(true);
    expect(validateTaskToPrProjectionTransition(preReview, invented).success).toBe(false);
  });

  test("requires a fresh provider guard receipt whenever the guarded expected head changes", () => {
    const projection = validProjection();
    const previous = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "merge_ready",
      merge: {
        guard: projection.merge.guard
      },
      cleanup: undefined
    });
    const nextHead = head("b");
    const nextReview = {
      ...previous.reviews[0]!,
      ref: ref("review", "review", "7"),
      head: nextHead,
      reviewRunRef: ref("review_run", "review", "9"),
      proofBundleRef: ref("proof_bundle", "review", "5"),
      reviewedAt: "2026-07-23T15:12:00.000Z"
    };
    const changedHead = TaskToPrProjectionSchema.parse(
      withActiveProvenance({
        ...previous,
        id: projectionId("valid-projection"),
        createdAt: "2026-07-23T15:12:00.000Z",
        repository: {
          ...previous.repository,
          branchHead: nextHead
        },
        events: {
          ...previous.events,
          replayCursorRef: ref("replay_cursor", "todos", "a"),
          sequence: previous.events.sequence + 1,
          prefixDigest: sha("d")
        },
        exactHead: {
          ...previous.exactHead!,
          localHead: nextHead,
          remoteHead: nextHead,
          providerPullRequestHead: nextHead,
          equalityProofRef: ref("proof_bundle", "review", "3"),
          ciProofBundleRefs: [ref("proof_bundle", "review", "4")],
          verifiedAt: "2026-07-23T15:12:00.000Z"
        },
        reviews: [nextReview],
        merge: {
          guard: {
            ...previous.merge!.guard,
            ref: ref("merge_guard", "todos", "a"),
            expectedHead: nextHead,
            reviewRefs: [nextReview.ref],
            proofBundleRefs: [
              nextReview.proofBundleRef,
              ref("proof_bundle", "review", "3"),
              ref("proof_bundle", "review", "4")
            ],
            providerGuardReceiptRef: ref(
              "merge_guard_receipt",
              "merge_provider",
              "d",
              "full"
            ),
            evaluatedAt: "2026-07-23T15:12:00.000Z"
          }
        }
      })
    );
    expect(validateTaskToPrProjectionTransition(previous, changedHead)).toEqual({
      success: true,
      issues: []
    });

    for (const staleReceipt of [
      previous.merge!.guard.providerGuardReceiptRef,
      {
        ...changedHead.merge!.guard.providerGuardReceiptRef,
        digest: previous.merge!.guard.providerGuardReceiptRef.digest
      }
    ]) {
      const stale = {
        ...changedHead,
        id: projectionId("valid-projection"),
        merge: {
          guard: {
            ...changedHead.merge!.guard,
            providerGuardReceiptRef: staleReceipt
          }
        }
      };
      expect(validateTaskToPrProjectionTransition(previous, stale).success).toBe(false);
    }
  });

  test("binds every merge outcome to its exact immutable merge guard", () => {
    const projection = validProjection();
    const guardBoundProjection = projection;
    expect(TaskToPrProjectionSchema.safeParse(guardBoundProjection).success).toBe(true);
    const { guardRef: _guardRef, ...outcomeWithoutGuardRef } = guardBoundProjection.merge.outcome;
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...guardBoundProjection,
        merge: {
          ...guardBoundProjection.merge,
          outcome: outcomeWithoutGuardRef
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...guardBoundProjection,
        merge: {
          ...guardBoundProjection.merge,
          outcome: {
            ...guardBoundProjection.merge.outcome,
            guardRef: ref("merge_guard", "todos", "f")
          }
        }
      }).success
    ).toBe(false);
  });

  test("rejects hidden review bindings in denied early-phase merge guards", () => {
    const projection = validProjection();
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "running",
        reviews: [],
        merge: {
          guard: {
            ...projection.merge.guard,
            decision: "denied"
          }
        },
        cleanup: undefined
      }).success
    ).toBe(false);
  });

  test("preserves handoff, recovery, and cancellation identity without embedded history", () => {
    const projection = validProjection();
    const recoveryProjection = validRecoveryProjection();
    expect(TaskToPrProjectionSchema.safeParse(recoveryProjection).success).toBe(true);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        recovery: recoveryProjection.recovery
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        handoff: {
          ...projection.handoff,
          nextWriterGenerationRef: ref("writer_generation", "todos", "f")
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...recoveryProjection,
        recovery: {
          ...recoveryProjection.recovery,
          successorAttemptNonce: attemptNonce("different")
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...recoveryProjection,
        recovery: {
          ...recoveryProjection.recovery,
          preservedStateRefs: recoveryProjection.recovery.preservedStateRefs.filter(
            (preservedRef) => preservedRef.id !== recoveryProjection.rootRequestRef.id
          )
        }
      }).success
    ).toBe(false);

    const cancelled = {
      ...projection,
      state: "cancelled",
      recovery: undefined,
      exactHead: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      cancellation: {
        ref: ref("cancellation", "todos", "a"),
        cancelledAttemptRef: projection.attempt.ref,
        preservedStateRefs: [
          projection.workRunRef,
          projection.rootRequestRef,
          projection.prGroupRef,
          projection.leafTaskRef,
          projection.attempt.ref,
          projection.repository.repoRef,
          projection.repository.worktreeRef,
          projection.repository.branchRef,
          projection.events.streamRef,
          projection.pullRequestRef
        ],
        evidenceRefs: [evidence("ev_cancelled_state", "b")]
      }
    };
    expect(TaskToPrProjectionSchema.safeParse(cancelled).success).toBe(true);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...cancelled,
        cancellation: { ...cancelled.cancellation, preservedStateRefs: [] }
      }).success
    ).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        recovery: undefined,
        cancellation: {
          ref: ref("cancellation", "todos", "d"),
          cancelledAttemptRef: projection.attempt.ref,
          preservedStateRefs: [
            projection.workRunRef,
            projection.rootRequestRef,
            projection.prGroupRef,
            projection.leafTaskRef,
            projection.attempt.ref,
            projection.repository.repoRef,
            projection.repository.worktreeRef,
            projection.repository.branchRef,
            projection.events.streamRef,
            projection.pullRequestRef
          ],
          evidenceRefs: [evidence("ev_cancelled_after_merge", "d")]
        }
      }).success
    ).toBe(false);
  });

  test("statically requires fresh canonical ids and digests across handoff and recovery refs", () => {
    const projection = validProjection();
    const handoff = projection.handoff;
    const recoveryProjection = validRecoveryProjection();
    const recovery = recoveryProjection.recovery;

    expect(TaskToPrHandoffSchema.safeParse(handoff).success).toBe(true);
    expect(TaskToPrRecoverySchema.safeParse(recovery).success).toBe(true);

    for (const nextAttemptRef of [
      { ...handoff.nextAttemptRef, id: handoff.previousAttemptRef.id },
      { ...handoff.nextAttemptRef, digest: handoff.previousAttemptRef.digest }
    ]) {
      expect(TaskToPrHandoffSchema.safeParse({ ...handoff, nextAttemptRef }).success).toBe(false);
    }
    for (const nextWriterGenerationRef of [
      { ...handoff.nextWriterGenerationRef, id: handoff.previousWriterGenerationRef.id },
      { ...handoff.nextWriterGenerationRef, digest: handoff.previousWriterGenerationRef.digest }
    ]) {
      expect(TaskToPrHandoffSchema.safeParse({ ...handoff, nextWriterGenerationRef }).success).toBe(false);
    }
    for (const successorWriterGenerationRef of [
      { ...recovery.successorWriterGenerationRef, id: recovery.priorWriterGenerationRef.id },
      { ...recovery.successorWriterGenerationRef, digest: recovery.priorWriterGenerationRef.digest }
    ]) {
      expect(TaskToPrRecoverySchema.safeParse({ ...recovery, successorWriterGenerationRef }).success).toBe(false);
    }

    const handoffOnly = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "handed_off",
      pullRequestRef: undefined,
      exactHead: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      evidenceRefs: []
    });
    const recoveryOnly = parseProjection({
      ...recoveryProjection,
      id: projectionId("valid-projection"),
      state: "recovering",
      pullRequestRef: undefined,
      exactHead: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      recovery: {
        ...recovery,
        preservedStateRefs: recovery.preservedStateRefs.filter((preservedRef) => preservedRef.role !== "pull_request")
      },
      evidenceRefs: []
    });

    for (const stoppedWorkRunRef of [
      { ...handoffOnly.handoff!.stoppedWorkRunRef, id: handoffOnly.workRunRef.id },
      { ...handoffOnly.handoff!.stoppedWorkRunRef, digest: handoffOnly.workRunRef.digest }
    ]) {
      expect(
        TaskToPrProjectionSchema.safeParse({
          ...handoffOnly,
          handoff: { ...handoffOnly.handoff!, stoppedWorkRunRef }
        }).success
      ).toBe(false);
    }
    for (const priorAttemptRef of [
      { ...recoveryOnly.recovery!.priorAttemptRef, id: recoveryOnly.attempt.ref.id },
      { ...recoveryOnly.recovery!.priorAttemptRef, digest: recoveryOnly.attempt.ref.digest }
    ]) {
      expect(
        TaskToPrProjectionSchema.safeParse({
          ...recoveryOnly,
          recovery: { ...recoveryOnly.recovery!, priorAttemptRef }
        }).success
      ).toBe(false);
    }
    for (const priorWorkRunRef of [
      { ...recoveryOnly.recovery!.priorWorkRunRef, id: recoveryOnly.workRunRef.id },
      { ...recoveryOnly.recovery!.priorWorkRunRef, digest: recoveryOnly.workRunRef.digest }
    ]) {
      expect(
        TaskToPrProjectionSchema.safeParse({
          ...recoveryOnly,
          recovery: {
            ...recoveryOnly.recovery!,
            priorWorkRunRef,
            preservedStateRefs: recoveryOnly.recovery!.preservedStateRefs.map((preservedRef) =>
              preservedRef.role === "work_run" ? priorWorkRunRef : preservedRef
            )
          }
        }).success
      ).toBe(false);
    }
  });

  test("freezes complete merge, cleanup, and rollback terminal facts across projections", () => {
    const projection = TaskToPrProjectionSchema.parse(validProjection());
    expect(
      validateTaskToPrProjectionTransition(projection, {
        ...projection,
        id: projectionId("valid-projection"),
        merge: {
          ...projection.merge,
          guard: {
            ...projection.merge!.guard,
            mechanism: "queue_expected_head"
          }
        }
      }).success
    ).toBe(false);
    expect(
      validateTaskToPrProjectionTransition(projection, {
        ...projection,
        id: projectionId("valid-projection"),
        cleanup: {
          ...projection.cleanup,
          eligibility: {
            ...projection.cleanup!.eligibility,
            evidenceRefs: [evidence("ev_rewritten_cleanup_gate", "c")]
          }
        }
      }).success
    ).toBe(false);

    const rolledBack = TaskToPrProjectionSchema.parse(withActiveProvenance({
      ...projection,
      id: projectionId("valid-projection"),
      state: "rolled_back",
      cleanup: undefined,
      rollback: {
        plan: {
          ref: ref("rollback_plan", "todos", "a"),
          targetRef: ref("commit", "repos", "c"),
          createdAt: "2026-07-23T15:11:00.000Z"
        },
        outcome: {
          ref: ref("rollback_outcome", "repos", "d"),
          planRef: ref("rollback_plan", "todos", "a"),
          targetRef: ref("commit", "repos", "c"),
          status: "succeeded",
          finishedAt: "2026-07-23T15:12:00.000Z",
          evidenceRefs: [evidence("ev_rollback_terminal", "e")]
        }
      }
    }));
    expect(
      validateTaskToPrProjectionTransition(rolledBack, {
        ...rolledBack,
        id: projectionId("valid-projection"),
        rollback: {
          ...rolledBack.rollback,
          plan: {
            ...rolledBack.rollback!.plan,
            createdAt: "2026-07-23T15:11:30.000Z"
          }
        }
      }).success
    ).toBe(false);
  });

  test("gates cleanup outcomes on eligibility and preserves non-deletion outcomes", () => {
    const projection = validProjection();
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        cleanup: {
          eligibility: { ...projection.cleanup.eligibility, status: "blocked" },
          outcome: projection.cleanup.outcome
        }
      }).success
    ).toBe(false);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "blocked",
        merge: undefined,
        exactHead: undefined,
        reviews: [],
        cleanup: {
          eligibility: { ...projection.cleanup.eligibility, status: "preserved" },
          outcome: { ...projection.cleanup.outcome, status: "preserved" }
        }
      }).success
    ).toBe(true);

    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        cleanup: {
          ...projection.cleanup,
          eligibility: {
            ...projection.cleanup.eligibility,
            targetWorktreeRef: ref("worktree", "repos", "f", "partial")
          }
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        cleanup: {
          ...projection.cleanup,
          outcome: {
            ...projection.cleanup.outcome,
            eligibilityRef: ref("cleanup_eligibility", "repos", "f")
          }
        }
      }).success
    ).toBe(false);
  });

  test("binds a single rollback plan and immutable outcome by refs", () => {
    const projection = validProjection();
    const rolledBack = withActiveProvenance({
      ...projection,
      state: "rolled_back",
      cleanup: undefined,
      rollback: {
        plan: {
          ref: ref("rollback_plan", "todos", "3"),
          targetRef: ref("commit", "repos", "b"),
          createdAt
        },
        outcome: {
          ref: ref("rollback_outcome", "repos", "c"),
          planRef: ref("rollback_plan", "todos", "3"),
          targetRef: ref("commit", "repos", "b"),
          status: "succeeded",
          finishedAt: createdAt,
          evidenceRefs: [evidence("ev_rollback", "d")]
        }
      }
    });
    expect(TaskToPrProjectionSchema.safeParse(rolledBack).success).toBe(true);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...rolledBack,
        rollback: { outcome: rolledBack.rollback.outcome }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...rolledBack,
        rollback: {
          ...rolledBack.rollback,
          plan: {
            ...rolledBack.rollback.plan,
            targetRef: ref("worktree", "repos", "f", "partial")
          }
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...rolledBack,
        rollback: {
          ...rolledBack.rollback,
          outcome: {
            ...rolledBack.rollback.outcome,
            planRef: ref("rollback_plan", "todos", "f")
          }
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...rolledBack,
        rollback: {
          ...rolledBack.rollback,
          plan: {
            ...rolledBack.rollback.plan,
            createdAt: "2026-07-23T15:09:59.000Z"
          }
        }
      }).success
    ).toBe(false);
  });

  test("accepts local and cloud extensions only as redacted referenced digests", () => {
    const projection = validProjection();
    expect(TaskToPrProjectionSchema.parse(projection).adapterExtensions.map((extension) => extension.mode)).toEqual(["local", "cloud"]);
    expect(TaskToPrAdapterExtensionSchema.safeParse(projection.adapterExtensions[0]).success).toBe(true);
    for (const schema of Object.values(SCHEMA_IDS)) {
      expect(
        TaskToPrAdapterExtensionSchema.safeParse({
          ...projection.adapterExtensions[0],
          schema
        }).success
      ).toBe(false);
    }
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        adapterExtensions: [projection.adapterExtensions[0], projection.adapterExtensions[0]]
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        adapterExtensions: [
          {
            ...projection.adapterExtensions[0],
            schema: "hasna.task_to_pr_projection.extension.v1"
          }
        ]
      }).success
    ).toBe(false);

    const { adapterExtensions: _ignored, ...core } = projection;
    const local = parseProjection({ ...core, adapterExtensions: [projection.adapterExtensions[0]] });
    const cloud = parseProjection({ ...core, adapterExtensions: [projection.adapterExtensions[1]] });
    expect(validateTaskToPrAdapterCoreEquivalence(local, cloud)).toEqual({ success: true, issues: [] });
    expect(validateTaskToPrAdapterCoreEquivalence(cloud, local).success).toBe(false);
    expect(validateTaskToPrAdapterCoreEquivalence({ ...local, adapterExtensions: [] }, cloud).success).toBe(false);
    expect(validateTaskToPrAdapterCoreEquivalence(local, { ...cloud, adapterExtensions: [] }).success).toBe(false);
    expect(
      validateTaskToPrAdapterCoreEquivalence(
        { ...local, adapterExtensions: [projection.adapterExtensions[0], projection.adapterExtensions[1]] },
        cloud
      ).success
    ).toBe(false);
    expect(
      validateTaskToPrAdapterCoreEquivalence(local, {
        ...cloud,
        events: {
          ...cloud.events,
          sequence: cloud.events.sequence + 1,
          replayCursorRef: ref("replay_cursor", "todos", "9"),
          prefixDigest: sha("8")
        }
      }).success
    ).toBe(false);
    expect(
      validateTaskToPrAdapterCoreEquivalence(local, {
        ...cloud,
        provenanceLedger: [
          ...cloud.provenanceLedger,
          {
            category: "recovery",
            ref: ref("recovery", "todos", "adapter-history")
          }
        ]
      }).success
    ).toBe(false);
    expect(validateTaskToPrAdapterCoreEquivalence(local, { ...cloud, mutableProviderPayload: true }).success).toBe(false);
  });

  test("binds the expected and provider-observed PR base through exact-head, review, guard, and outcome facts", () => {
    const projection = validProjection();
    expect("expectedBase" in projection.exactHead).toBe(true);
    expect("providerPullRequestBase" in projection.exactHead).toBe(true);
    expect("base" in projection.reviews[0]!).toBe(true);
    expect("expectedBase" in projection.merge.guard).toBe(true);
    expect("expectedBase" in projection.merge.outcome).toBe(true);
    expect("observedBase" in projection.merge.outcome).toBe(true);
    const otherBase = head("c");
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        exactHead: {
          ...projection.exactHead,
          providerPullRequestBase: otherBase
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        reviews: projection.reviews.map((review, index) =>
          index === 0 ? { ...review, base: otherBase } : review
        )
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        merge: {
          ...projection.merge,
          guard: { ...projection.merge.guard, expectedBase: otherBase }
        }
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        merge: {
          ...projection.merge,
          outcome: { ...projection.merge.outcome, observedBase: otherBase }
        }
      }).success
    ).toBe(false);
  });

  test("keeps one canonical projection id and rejects identity-only snapshots without owner-event advancement", () => {
    const projection = validProjection();
    const previous = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "running",
      pullRequestRef: undefined,
      exactHead: undefined,
      handoff: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      repair: {
        ref: ref("repair_cycle", "todos", "identity-stable"),
        cycle: 0,
        cap: 2,
        exhausted: false
      },
      provenanceLedger: [],
      evidenceRefs: []
    });
    const identityOnly = parseProjection({
      ...previous,
      id: projectionId("identity-rotated"),
    });
    expect(validateTaskToPrProjectionTransition(previous, identityOnly).success).toBe(false);

    const eventAdvanced = parseProjection({
      ...previous,
      id: projectionId("identity-rotated-with-event"),
      events: {
        ...previous.events,
        replayCursorRef: ref("replay_cursor", "todos", "identity-advanced"),
        sequence: previous.events.sequence + 1,
        prefixDigest: sha("6")
      }
    });
    expect(validateTaskToPrProjectionTransition(previous, eventAdvanced).success).toBe(false);
  });

  test("enforces the bidirectional state, merge-guard, and merge-outcome matrix", () => {
    const projection = validProjection();
    const cancellation = {
      ref: ref("cancellation", "todos", "matrix-cancel"),
      cancelledAttemptRef: projection.attempt.ref,
      preservedStateRefs: [
        projection.workRunRef,
        projection.rootRequestRef,
        projection.prGroupRef,
        projection.leafTaskRef,
        projection.attempt.ref,
        projection.repository.repoRef,
        projection.repository.worktreeRef,
        projection.repository.branchRef,
        projection.events.streamRef,
        projection.pullRequestRef
      ],
      evidenceRefs: [evidence("matrix_cancel", "7")]
    };
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "cancelled",
        merge: { guard: projection.merge.guard },
        cleanup: undefined,
        cancellation
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "failed",
        cleanup: undefined,
        evidenceRefs: [evidence("matrix_failed", "8")]
      }).success
    ).toBe(false);
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "merge_ready",
        merge: {
          ...projection.merge,
          outcome: projection.merge.outcome
        },
        cleanup: undefined
      }).success
    ).toBe(false);
  });

  test("preserves eligible merge-guard lineage through revocation or consumption", () => {
    const terminalProjection = validProjection();
    const previous = parseProjection({
      ...terminalProjection,
      state: "merge_ready",
      terminalDispositionRef: undefined,
      cleanup: undefined,
      merge: {
        guard: {
          ...terminalProjection.merge.guard,
          decision: "eligible"
        }
      },
      provenanceLedger: []
    });
    const nextEvents = (seed: string) => ({
      ...previous.events,
      replayCursorRef: ref("replay_cursor", "todos", `guard-lineage-${seed}`),
      sequence: previous.events.sequence + 1,
      prefixDigest: createHash("sha256").update(`guard-lineage-${seed}`, "utf8").digest("hex")
    });
    const terminalDispositionRef = ref("terminal_disposition", "todos", "guard-lineage-terminal");
    const consumedGuard = {
      ...previous.merge!.guard,
      ref: ref("merge_guard", "todos", "guard-lineage-consumed"),
      decision: "consumed" as const
    };
    const merged = parseProjection({
      ...previous,
      state: "merged",
      events: nextEvents("consumed"),
      terminalDispositionRef,
      merge: {
        guard: consumedGuard,
        outcome: {
          ...terminalProjection.merge.outcome,
          guardRef: consumedGuard.ref
        }
      },
      provenanceLedger: previous.provenanceLedger
    });
    expect(validateTaskToPrProjectionTransition(previous, merged)).toEqual({
      success: true,
      issues: []
    });

    const unrelatedGuard = {
      ...consumedGuard,
      ref: ref("merge_guard", "todos", "guard-lineage-unrelated"),
      operatorRef: ref("merge_operator", "merge_provider", "guard-lineage-unrelated", "partial")
    };
    const unrelatedMerged = parseProjection({
      ...merged,
      events: nextEvents("unrelated"),
      merge: {
        guard: unrelatedGuard,
        outcome: {
          ...merged.merge!.outcome!,
          guardRef: unrelatedGuard.ref
        }
      },
      provenanceLedger: previous.provenanceLedger
    });
    expect(validateTaskToPrProjectionTransition(previous, unrelatedMerged).success).toBe(false);

    const failedWithoutRevocation = parseProjection({
      ...previous,
      state: "failed",
      events: nextEvents("dropped"),
      terminalDispositionRef,
      merge: undefined,
      provenanceLedger: previous.provenanceLedger,
      evidenceRefs: [evidence("guard_lineage_dropped", "4")]
    });
    expect(validateTaskToPrProjectionTransition(previous, failedWithoutRevocation).success).toBe(false);

    const revokedGuard = {
      ...previous.merge!.guard,
      ref: ref("merge_guard", "todos", "guard-lineage-revoked"),
      decision: "revoked" as const
    };
    const failedWithRevocation = parseProjection({
      ...previous,
      state: "failed",
      events: nextEvents("revoked"),
      terminalDispositionRef,
      merge: { guard: revokedGuard },
      provenanceLedger: previous.provenanceLedger,
      evidenceRefs: [evidence("guard_lineage_revoked", "5")]
    });
    expect(validateTaskToPrProjectionTransition(previous, failedWithRevocation)).toEqual({
      success: true,
      issues: []
    });
  });

  test("treats failed and blocked dispositions as terminal rather than advertising impossible recovery edges", () => {
    const terminalProjection = validProjection();
    const failed = parseProjection({
      ...terminalProjection,
      state: "failed",
      pullRequestRef: undefined,
      exactHead: undefined,
      handoff: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      repair: {
        ref: ref("repair_cycle", "todos", "terminal-recovery"),
        cycle: 0,
        cap: 2,
        exhausted: false
      },
      terminalDispositionRef: ref("terminal_disposition", "todos", "terminal-recovery"),
      provenanceLedger: [],
      evidenceRefs: [evidence("terminal_recovery_failed", "6")]
    });
    const nextAttempt = {
      ...failed.attempt,
      ref: ref("attempt", "todos", "terminal-recovery-next"),
      nonce: attemptNonce("terminal-recovery-next"),
      admissionRef: ref("admission", "codewith", "terminal-recovery-next", "partial"),
      workerRef: ref("worker", "codewith", "terminal-recovery-next", "partial"),
      runtimeRef: ref("runtime", "codewith", "terminal-recovery-next", "partial"),
      writerGenerationRef: ref("writer_generation", "todos", "terminal-recovery-next"),
      writerLeaseRef: ref("writer_lease", "repos", "terminal-recovery-next", "partial"),
      writerFenceRef: ref("writer_fence", "repos", "terminal-recovery-next", "full"),
      providerProfileRef: ref("provider_profile", "codewith", "terminal-recovery-next", "full"),
      providerRouteRef: ref("provider_route", "codewith", "terminal-recovery-next", "partial")
    };
    const recovering = parseProjection({
      ...failed,
      state: "recovering",
      workRunRef: ref("work_run", "codewith", "terminal-recovery-next"),
      attempt: nextAttempt,
      events: {
        ...failed.events,
        replayCursorRef: ref("replay_cursor", "todos", "terminal-recovery-next"),
        sequence: failed.events.sequence + 1,
        prefixDigest: createHash("sha256").update("terminal-recovery-next", "utf8").digest("hex")
      },
      recovery: {
        ref: ref("recovery", "todos", "terminal-recovery-next"),
        priorAttemptRef: failed.attempt.ref,
        priorWriterGenerationRef: failed.attempt.writerGenerationRef,
        priorWorkRunRef: failed.workRunRef,
        successorAttemptNonce: nextAttempt.nonce,
        successorWriterGenerationRef: nextAttempt.writerGenerationRef,
        preservedStateRefs: [
          failed.workRunRef,
          failed.rootRequestRef,
          failed.prGroupRef,
          failed.leafTaskRef,
          failed.repository.repoRef,
          failed.repository.worktreeRef,
          failed.repository.branchRef,
          failed.events.streamRef
        ],
        stopEvidenceRef: evidence("terminal_recovery_stop", "7"),
        leaseRevocationEvidenceRef: evidence("terminal_recovery_revoke", "8")
      },
      terminalDispositionRef: undefined,
      provenanceLedger: failed.provenanceLedger,
      evidenceRefs: []
    });
    const result = validateTaskToPrProjectionTransition(failed, recovering);
    expect(result.success).toBe(false);
    expect(result.issues.some((issue) => issue.path === "state")).toBe(true);
  });

  test("requires terminal owner, lease-revocation, and consumed-event facts before deleted cleanup", () => {
    const projection = validProjection();
    const previous = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "running",
      pullRequestRef: undefined,
      exactHead: undefined,
      handoff: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      repair: {
        ref: ref("repair_cycle", "todos", "cleanup-running"),
        cycle: 0,
        cap: 2,
        exhausted: false
      },
      provenanceLedger: [],
      evidenceRefs: []
    });
    const deleted = withActiveProvenance({
      ...previous,
      id: projectionId("valid-projection"),
      state: "cleanup_complete",
      events: {
        ...previous.events,
        replayCursorRef: ref("replay_cursor", "todos", "cleanup-consumed"),
        sequence: previous.events.sequence + 1,
        prefixDigest: sha("9")
      },
      cleanup: {
        eligibility: {
          ref: ref("cleanup_eligibility", "repos", "cleanup-gate"),
          status: "eligible",
          targetWorktreeRef: previous.repository.worktreeRef,
          eventCursorRef: ref("replay_cursor", "todos", "cleanup-consumed"),
          evaluatedAt: createdAt,
          evidenceRefs: [evidence("cleanup_gate_without_terminal", "a")]
        },
        outcome: {
          ref: ref("cleanup_outcome", "repos", "cleanup-deleted"),
          eligibilityRef: ref("cleanup_eligibility", "repos", "cleanup-gate"),
          targetWorktreeRef: previous.repository.worktreeRef,
          status: "deleted",
          finishedAt: createdAt,
          evidenceRefs: [evidence("cleanup_deleted_without_terminal", "b")]
        }
      }
    });
    expect(TaskToPrProjectionSchema.safeParse(deleted).success).toBe(false);
  });

  test("consumes exactly one repair cycle on entry and freezes repair state after terminal disposition", () => {
    const projection = validProjection();
    const exhausted = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "running",
      pullRequestRef: undefined,
      exactHead: undefined,
      handoff: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      repair: {
        ref: ref("repair_cycle", "todos", "repair-exhausted-state"),
        cycle: 2,
        cap: 2,
        exhausted: true,
        latestRepairRef: ref("repair_cycle", "todos", "repair-exhausted-latest")
      },
      provenanceLedger: [],
      evidenceRefs: []
    });
    const reentered = parseProjection({
      ...exhausted,
      id: projectionId("valid-projection"),
      state: "repairing",
      events: {
        ...exhausted.events,
        replayCursorRef: ref("replay_cursor", "todos", "repair-reentry"),
        sequence: exhausted.events.sequence + 1,
        prefixDigest: sha("a")
      }
    });
    expect(validateTaskToPrProjectionTransition(exhausted, reentered).success).toBe(false);

    const terminal = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "merged",
      cleanup: undefined
    });
    const terminalRepairMutation = parseProjection({
      ...terminal,
      id: projectionId("valid-projection"),
      events: {
        ...terminal.events,
        replayCursorRef: ref("replay_cursor", "todos", "repair-terminal"),
        sequence: terminal.events.sequence + 1,
        prefixDigest: sha("b")
      },
      repair: {
        ref: ref("repair_cycle", "todos", "repair-terminal-state"),
        cycle: terminal.repair.cycle + 1,
        cap: 2,
        exhausted: true,
        latestRepairRef: ref("repair_cycle", "todos", "repair-terminal-latest")
      }
    });
    expect(validateTaskToPrProjectionTransition(terminal, terminalRepairMutation).success).toBe(false);
  });

  test("requires fresh admission and worker-assignment refs on every successor attempt", () => {
    const projection = validProjection();
    const previous = parseProjection({
      ...projection,
      id: projectionId("valid-projection"),
      state: "running",
      pullRequestRef: undefined,
      exactHead: undefined,
      handoff: undefined,
      reviews: [],
      merge: undefined,
      cleanup: undefined,
      repair: {
        ref: ref("repair_cycle", "todos", "attempt-previous"),
        cycle: 0,
        cap: 2,
        exhausted: false
      },
      provenanceLedger: [],
      evidenceRefs: []
    });
    const nextAttempt = {
      ...previous.attempt,
      ref: ref("attempt", "todos", "attempt-next"),
      nonce: attemptNonce("attempt-next"),
      runtimeRef: ref("runtime", "codewith", "attempt-next", "partial"),
      writerGenerationRef: ref("writer_generation", "todos", "attempt-next"),
      writerLeaseRef: ref("writer_lease", "repos", "attempt-next", "partial"),
      writerFenceRef: ref("writer_fence", "repos", "attempt-next", "full"),
      providerProfileRef: ref("provider_profile", "codewith", "attempt-next", "full"),
      providerRouteRef: ref("provider_route", "codewith", "attempt-next", "partial")
    };
    const successor = parseProjection({
      ...previous,
      id: projectionId("valid-projection"),
      state: "recovering",
      workRunRef: ref("work_run", "codewith", "attempt-next"),
      attempt: nextAttempt,
      events: {
        ...previous.events,
        replayCursorRef: ref("replay_cursor", "todos", "attempt-next"),
        sequence: previous.events.sequence + 1,
        prefixDigest: sha("c")
      },
      recovery: {
        ref: ref("recovery", "todos", "attempt-next"),
        priorAttemptRef: previous.attempt.ref,
        priorWriterGenerationRef: previous.attempt.writerGenerationRef,
        priorWorkRunRef: previous.workRunRef,
        successorAttemptNonce: nextAttempt.nonce,
        successorWriterGenerationRef: nextAttempt.writerGenerationRef,
        preservedStateRefs: [
          previous.workRunRef,
          previous.rootRequestRef,
          previous.prGroupRef,
          previous.leafTaskRef,
          previous.repository.repoRef,
          previous.repository.worktreeRef,
          previous.repository.branchRef,
          previous.events.streamRef
        ],
        stopEvidenceRef: evidence("attempt_next_stopped", "d"),
        leaseRevocationEvidenceRef: evidence("attempt_next_revoked", "e")
      }
    });
    expect(validateTaskToPrProjectionTransition(previous, successor).success).toBe(false);
  });

  test("versions canonical identity and binds branch plus worktree while retaining the v1 derivation path", () => {
    const projection = validProjection();
    const original = deriveTaskToPrIdentityDigest({
      canonicalizationVersion: 2,
      rootRequestRef: projection.rootRequestRef,
      prGroupRef: projection.prGroupRef,
      leafTaskRef: projection.leafTaskRef,
      repoRef: projection.repository.repoRef,
      worktreeRef: projection.repository.worktreeRef,
      branchRef: projection.repository.branchRef,
      baseHead: projection.repository.baseHead,
      frozenScopeDigest: projection.frozenScopeDigest
    });
    const aliased = deriveTaskToPrIdentityDigest({
      canonicalizationVersion: 2,
      rootRequestRef: projection.rootRequestRef,
      prGroupRef: projection.prGroupRef,
      leafTaskRef: projection.leafTaskRef,
      repoRef: projection.repository.repoRef,
      worktreeRef: ref("worktree", "repos", "identity-alias", "partial"),
      branchRef: ref("branch", "repos", "identity-alias"),
      baseHead: projection.repository.baseHead,
      frozenScopeDigest: projection.frozenScopeDigest
    });
    expect(aliased).not.toBe(original);

    const legacyIdentityDigest = deriveTaskToPrIdentityDigest({
      canonicalizationVersion: 1,
      rootRequestRef: projection.rootRequestRef,
      prGroupRef: projection.prGroupRef,
      leafTaskRef: projection.leafTaskRef,
      repoRef: projection.repository.repoRef,
      baseHead: projection.repository.baseHead,
      frozenScopeDigest: projection.frozenScopeDigest
    });
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        canonicalizationVersion: 1,
        identityDigest: legacyIdentityDigest
      }).success
    ).toBe(true);
  });

  test("reserves the v1 adapter-extension namespace independently of unrelated schema registration", () => {
    const projection = validProjection();
    expect(
      TaskToPrAdapterExtensionSchema.safeParse({
        ...projection.adapterExtensions[0],
        schema: "hasna.unrelated_future_contract.v1"
      }).success
    ).toBe(false);
    expect(TaskToPrAdapterExtensionSchema.safeParse(projection.adapterExtensions[0]).success).toBe(true);
  });

  test("rejects duplicate and conflicting same-role recovery or cancellation preservation refs", () => {
    const recoveryProjection = validRecoveryProjection();
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...recoveryProjection,
        recovery: {
          ...recoveryProjection.recovery,
          preservedStateRefs: [
            ...recoveryProjection.recovery.preservedStateRefs,
            ref("root_request", "todos", "conflicting-root")
          ]
        }
      }).success
    ).toBe(false);

    const projection = validProjection();
    const cancellation = {
      ref: ref("cancellation", "todos", "duplicate-preservation"),
      cancelledAttemptRef: projection.attempt.ref,
      preservedStateRefs: [
        projection.workRunRef,
        projection.rootRequestRef,
        projection.rootRequestRef,
        projection.prGroupRef,
        projection.leafTaskRef,
        projection.attempt.ref,
        projection.repository.repoRef,
        projection.repository.worktreeRef,
        projection.repository.branchRef,
        projection.events.streamRef,
        projection.pullRequestRef
      ],
      evidenceRefs: [evidence("duplicate_preservation", "f")]
    };
    expect(
      TaskToPrProjectionSchema.safeParse({
        ...projection,
        state: "cancelled",
        merge: undefined,
        exactHead: undefined,
        reviews: [],
        cleanup: undefined,
        cancellation
      }).success
    ).toBe(false);
  });

  test("requires distinct stop and lease-revocation evidence identities", () => {
    const projection = validProjection();
    expect(
      TaskToPrHandoffSchema.safeParse({
        ...projection.handoff,
        leaseRevocationEvidenceRef: projection.handoff.stopEvidenceRef
      }).success
    ).toBe(false);
    const recoveryProjection = validRecoveryProjection();
    expect(
      TaskToPrRecoverySchema.safeParse({
        ...recoveryProjection.recovery,
        leaseRevocationEvidenceRef: recoveryProjection.recovery.stopEvidenceRef
      }).success
    ).toBe(false);
  });

  test("rejects event cursor sequences beyond Number.MAX_SAFE_INTEGER", () => {
    const projection = validProjection();
    expect(
      TaskToPrProjectionSchema.safeParse(
        withActiveProvenance({
          ...projection,
          events: {
            ...projection.events,
            sequence: Number.MAX_SAFE_INTEGER + 1
          }
        })
      ).success
    ).toBe(false);
  });

  test("requires structurally nonsemantic owner-resolvable reference ids", () => {
    expect(
      TaskToPrRefSchema.safeParse({
        ...ref("root_request", "todos", "semantic"),
        id: "root_request:opaque-project-alpha-customer-42"
      }).success
    ).toBe(false);
  });

  test("preserves v1 WorkRun parsing and refuses silent v1 widening", () => {
    const legacyWorkRun = {
      schema: "hasna.work_run.v1",
      id: "run_legacy",
      createdAt,
      objective: "Legacy compatible run",
      status: "running",
      actor: { kind: "agent", id: "worker_legacy" }
    };
    const parsed = WorkRunSchema.parse(legacyWorkRun);
    expect(parsed.schema).toBe("hasna.work_run.v1");
    expect(validateContract(SCHEMA_IDS.workRun, legacyWorkRun).success).toBe(true);
    expect(
      validateContract(SCHEMA_IDS.workRun, {
        ...legacyWorkRun,
        taskToPrProjection: validProjection()
      }).success
    ).toBe(false);
    expect(validateContract(SCHEMA_IDS.taskToPrProjection, validProjection()).success).toBe(true);
  });
});
