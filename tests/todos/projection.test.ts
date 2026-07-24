import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  TaskToPrProjectionSchema,
  TodosGitObjectIdSchema,
  createTaskToPrProjection,
  sha256TodosText,
  validateTaskToPrProjectionHistory,
  validateTaskToPrProjectionTransition,
  type TaskToPrOwnerRef,
  type TaskToPrProjection,
  type TaskToPrProjectionUnsigned,
} from "../../src/todos";

const fixtureRoot = join(import.meta.dir, "..", "..", "generated", "todos", "v1", "fixtures");

function projectionFixture(): TaskToPrProjection {
  return TaskToPrProjectionSchema.parse(JSON.parse(readFileSync(join(fixtureRoot, "projection.valid.json"), "utf8")));
}

function successor(
  previous: TaskToPrProjection,
  overrides: Partial<TaskToPrProjectionUnsigned> = {},
): TaskToPrProjection {
  return createTaskToPrProjection({
    schema: previous.schema,
    id: previous.id,
    owner: previous.owner,
    version: previous.version + 1,
    sequence: previous.sequence + 1,
    predecessor: {
      kind: "task_to_pr_projection",
      projectionId: previous.id,
      owner: previous.owner,
      version: previous.version,
      digest: previous.digest,
    },
    identity: previous.identity,
    pullRequestRef: previous.pullRequestRef,
    head: previous.head,
    proofs: previous.proofs,
    derivedAt: "2026-07-24T00:01:00.000Z",
    ...overrides,
  });
}

function freshRef<const T extends TaskToPrOwnerRef>(ref: T, suffix: string): T {
  return {
    ...ref,
    id: `${ref.id}-${suffix}`,
    digest: sha256TodosText(`${ref.owner}:${ref.kind}:${ref.id}:${suffix}`),
  } as T;
}

function successorWithHead(
  previous: TaskToPrProjection,
  value: string,
  suffix: string,
): TaskToPrProjection {
  const head = { algorithm: "sha1" as const, value: value.repeat(40) };
  return successor(previous, {
    head: {
      branchHead: head,
      publishedHead: head,
      providerObservedHead: head,
      equalityProof: {
        ...previous.head.equalityProof!,
        ref: freshRef(previous.head.equalityProof!.ref, `${suffix}-head`),
        head,
      },
    },
    proofs: previous.proofs.map((proof, index) => ({
      ...proof,
      ref: freshRef(proof.ref, `${suffix}-${index}`),
      head,
    })),
  });
}

describe("TaskToPrProjection", () => {
  test("uses the hasna.todos namespace, owner-qualified refs, and validated Git ids", () => {
    const projection = projectionFixture();
    expect(projection.schema.startsWith("hasna.todos.")).toBe(true);
    expect(projection).not.toHaveProperty("authority");
    expect(projection.identity.repositoryRef.owner).toBeTruthy();
    expect(TodosGitObjectIdSchema.safeParse({ algorithm: "sha1", value: "a".repeat(40) }).success).toBe(true);
    expect(TodosGitObjectIdSchema.safeParse({ algorithm: "sha1", value: "a".repeat(64) }).success).toBe(false);
    expect(TodosGitObjectIdSchema.safeParse({ algorithm: "sha256", value: "a".repeat(64) }).success).toBe(true);
  });

  test("accepts a valid predecessor transition and an exact duplicate replay", () => {
    const previous = projectionFixture();
    const current = successor(previous);
    expect(validateTaskToPrProjectionTransition(previous, current)).toEqual({
      success: true,
      replayed: false,
    });
    expect(validateTaskToPrProjectionTransition(previous, previous)).toEqual({
      success: true,
      replayed: true,
    });
  });

  test("rejects immutable identity changes", () => {
    const previous = projectionFixture();
    const changedBranchRef = {
      ...previous.identity.branchRef,
      id: "branch-2",
      digest: sha256TodosText("branch-2"),
    };
    const current = successor(previous, {
      identity: {
        ...previous.identity,
        branchRef: changedBranchRef,
      },
    });
    const result = validateTaskToPrProjectionTransition(previous, current);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.issues.some((issue) => issue.path === "identity")).toBe(true);
    }
  });

  test("rejects predecessor conflicts and non-monotonic versions", () => {
    const invalidPair = JSON.parse(
      readFileSync(join(fixtureRoot, "projection-transition.invalid.json"), "utf8"),
    ) as { previous: TaskToPrProjection; current: TaskToPrProjection };
    const predecessor = validateTaskToPrProjectionTransition(invalidPair.previous, invalidPair.current);
    expect(predecessor.success).toBe(false);
    if (!predecessor.success) {
      expect(predecessor.error.code).toBe("TODOS_PROJECTION_PREDECESSOR_CONFLICT");
      expect(predecessor.issues.some((issue) => issue.path === "predecessor")).toBe(true);
    }

    const previous = projectionFixture();
    const skippedVersion = successor(previous, {
      version: previous.version + 2,
      predecessor: {
        kind: "task_to_pr_projection",
        projectionId: previous.id,
        owner: previous.owner,
        version: previous.version + 1,
        digest: sha256TodosText("intermediate"),
      },
    });
    const monotonic = validateTaskToPrProjectionTransition(previous, skippedVersion);
    expect(monotonic.success).toBe(false);
    if (!monotonic.success) {
      expect(monotonic.issues.some((issue) => issue.path === "version")).toBe(true);
    }
  });

  test("rejects same-head proof drift", () => {
    const previous = projectionFixture();
    const replacement = {
      ...previous.head.equalityProof!,
      ref: {
        ...previous.head.equalityProof!.ref,
        id: "proof-head-equality-2",
        digest: sha256TodosText("proof-head-equality-2"),
      },
    };
    const current = successor(previous, {
      head: {
        ...previous.head,
        equalityProof: replacement,
      },
    });
    const result = validateTaskToPrProjectionTransition(previous, current);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.issues.some((issue) => issue.path === "head")).toBe(true);
    }
  });

  test("requires fresh proof identities and digests after head changes", () => {
    const previous = projectionFixture();
    const nextHead = { algorithm: "sha1" as const, value: "c".repeat(40) };
    const current = successor(previous, {
      head: {
        branchHead: nextHead,
        publishedHead: nextHead,
        providerObservedHead: nextHead,
        equalityProof: {
          ...previous.head.equalityProof!,
          head: nextHead,
        },
      },
      proofs: previous.proofs.map((proof) => ({ ...proof, head: nextHead })),
    });
    const result = validateTaskToPrProjectionTransition(previous, current);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.issues.some((issue) => issue.reason.includes("fresh proof"))).toBe(true);
    }
  });

  test("validates the complete predecessor history and expected head", () => {
    const first = projectionFixture();
    const second = successor(first);
    const third = successorWithHead(second, "c", "third");
    expect(validateTaskToPrProjectionHistory([first, second, third], {
      expectedOwner: first.owner,
      expectedHead: third.head.branchHead,
    })).toEqual({
      success: true,
      head: third,
    });

    const stale = validateTaskToPrProjectionHistory([first, second, third], {
      expectedHead: { algorithm: "sha1", value: "d".repeat(40) },
    });
    expect(stale.success).toBe(false);
    if (!stale.success) {
      expect(stale.issues.some((issue) => issue.path === "history.head")).toBe(true);
    }
  });

  test("rejects a missing middle record and a swapped same-version predecessor", () => {
    const first = projectionFixture();
    const second = successor(first);
    const third = successorWithHead(second, "c", "third");
    const missingMiddle = validateTaskToPrProjectionHistory([first, third]);
    expect(missingMiddle.success).toBe(false);

    const alternateSecond = successor(first, {
      derivedAt: "2026-07-24T00:01:30.000Z",
    });
    const swappedPredecessor = createTaskToPrProjection({
      ...((({ digest: _digest, ...unsigned }) => unsigned)(third)),
      predecessor: {
        kind: "task_to_pr_projection",
        projectionId: alternateSecond.id,
        owner: alternateSecond.owner,
        version: alternateSecond.version,
        digest: alternateSecond.digest,
      },
    });
    const swapped = validateTaskToPrProjectionHistory([
      first,
      second,
      swappedPredecessor,
    ]);
    expect(swapped.success).toBe(false);
    if (!swapped.success) {
      expect(swapped.issues.some((issue) => issue.path.includes("predecessor"))).toBe(true);
    }
  });

  test("rejects repeated records, owner drift, duplicate proof refs, and ABA heads", () => {
    const first = projectionFixture();
    const second = successorWithHead(first, "c", "second");

    const repeated = validateTaskToPrProjectionHistory([first, second, second]);
    expect(repeated.success).toBe(false);
    if (!repeated.success) {
      expect(repeated.issues.some((issue) => issue.reason.includes("replay"))).toBe(true);
    }

    const changedOwner = "other.todos";
    const ownerDrift = createTaskToPrProjection({
      ...((({ digest: _digest, ...unsigned }) => unsigned)(second)),
      owner: changedOwner,
      predecessor: {
        ...second.predecessor!,
        owner: changedOwner,
      },
      identity: {
        ...second.identity,
        taskRef: { ...second.identity.taskRef, owner: changedOwner },
        repositoryRef: { ...second.identity.repositoryRef, owner: changedOwner },
        worktreeRef: { ...second.identity.worktreeRef, owner: changedOwner },
        branchRef: { ...second.identity.branchRef, owner: changedOwner },
      },
      pullRequestRef: { ...second.pullRequestRef!, owner: changedOwner },
      head: {
        ...second.head,
        equalityProof: {
          ...second.head.equalityProof!,
          ref: { ...second.head.equalityProof!.ref, owner: changedOwner },
        },
      },
      proofs: second.proofs.map((proof) => ({
        ...proof,
        ref: { ...proof.ref, owner: changedOwner },
      })),
    });
    const drift = validateTaskToPrProjectionHistory([first, ownerDrift]);
    expect(drift.success).toBe(false);
    if (!drift.success) {
      expect(drift.issues.some((issue) => issue.path.includes("owner"))).toBe(true);
    }

    expect(() => createTaskToPrProjection({
      ...((({ digest: _digest, ...unsigned }) => unsigned)(first)),
      proofs: [
        ...first.proofs,
        {
          ...first.proofs[0]!,
          kind: "review",
        },
      ],
    })).toThrow();

    const aba = successorWithHead(second, "a", "aba");
    const abaHistory = validateTaskToPrProjectionHistory([first, second, aba]);
    expect(abaHistory.success).toBe(false);
    if (!abaHistory.success) {
      expect(abaHistory.issues.some((issue) => issue.reason.includes("previously observed"))).toBe(true);
    }
  });

  test("rejects owner and kind mismatches anywhere in a three-hop history", () => {
    const first = projectionFixture();
    const second = successor(first);
    const third = successorWithHead(second, "c", "third");

    const repositoryOwner = structuredClone(second) as unknown as Record<string, any>;
    repositoryOwner.identity.repositoryRef.owner = "other.todos";
    const repositoryResult = validateTaskToPrProjectionHistory([
      first,
      repositoryOwner,
      third,
    ]);
    expect(repositoryResult.success).toBe(false);
    if (!repositoryResult.success) {
      expect(repositoryResult.issues.some(
        (issue) => issue.path.includes("identity.repositoryRef.owner"),
      )).toBe(true);
    }

    const repositoryKind = structuredClone(first) as unknown as Record<string, any>;
    repositoryKind.identity.repositoryRef.kind = "branch";
    const kindResult = validateTaskToPrProjectionHistory([
      repositoryKind,
      second,
      third,
    ]);
    expect(kindResult.success).toBe(false);
    if (!kindResult.success) {
      expect(kindResult.issues.some(
        (issue) => issue.path.includes("identity.repositoryRef.kind"),
      )).toBe(true);
    }

    const proofOwner = structuredClone(third) as unknown as Record<string, any>;
    proofOwner.proofs[0].ref.owner = "other.todos";
    const proofResult = validateTaskToPrProjectionHistory([
      first,
      second,
      proofOwner,
    ]);
    expect(proofResult.success).toBe(false);
    if (!proofResult.success) {
      expect(proofResult.issues.some((issue) => issue.path.includes("proofs")))
        .toBe(true);
    }

    const predecessorKind = structuredClone(second) as unknown as Record<string, any>;
    predecessorKind.predecessor.kind = "task";
    const predecessorResult = validateTaskToPrProjectionHistory([
      first,
      predecessorKind,
      third,
    ]);
    expect(predecessorResult.success).toBe(false);
    if (!predecessorResult.success) {
      expect(predecessorResult.issues.some((issue) => issue.path.includes("predecessor.kind")))
        .toBe(true);
    }
  });
});
