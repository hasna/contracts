import * as z from "zod/v4";
import {
  TodosEntityIdSchema,
  TodosOwnerIdSchema,
  TodosOwnerQualifiedRefSchema,
  TodosSha256DigestSchema,
  TodosTimestampSchema,
  sha256TodosValue,
  stableTodosJson,
} from "./common";
import {
  TodosGitObjectIdSchema,
  type TodosGitObjectId,
} from "./domain";
import {
  createTodosError,
  type TodosError,
} from "./errors";

export const TODOS_PROJECTION_SCHEMA_IDS = {
  projection: "hasna.todos.task_to_pr_projection.v1",
  transitionIssue: "hasna.todos.task_to_pr_transition_issue.v1",
} as const;

export const TaskToPrOwnerRefSchema = TodosOwnerQualifiedRefSchema.refine(
  (value) => !value.id.includes("/") && !value.id.includes("\\") && !value.id.includes("://"),
  {
    message: "Projection refs must be opaque owner-qualified identifiers",
    path: ["id"],
  },
);
export type TaskToPrOwnerRef = z.infer<typeof TaskToPrOwnerRefSchema>;

function createTaskToPrKindRefSchema<const T extends string>(kind: T) {
  return TodosOwnerQualifiedRefSchema
    .extend({ kind: z.literal(kind) })
    .refine(
      (value) => !value.id.includes("/") && !value.id.includes("\\") && !value.id.includes("://"),
      {
        message: "Projection refs must be opaque owner-qualified identifiers",
        path: ["id"],
      },
    );
}

export const TaskToPrTaskRefSchema = createTaskToPrKindRefSchema("task");
export const TaskToPrRepositoryRefSchema = createTaskToPrKindRefSchema("repository");
export const TaskToPrWorktreeRefSchema = createTaskToPrKindRefSchema("worktree");
export const TaskToPrBranchRefSchema = createTaskToPrKindRefSchema("branch");
export const TaskToPrPullRequestRefSchema = createTaskToPrKindRefSchema("pull_request");
export const TaskToPrProofRefSchema = createTaskToPrKindRefSchema("proof_bundle");

export const TaskToPrProjectionPredecessorSchema = z.strictObject({
  kind: z.literal("task_to_pr_projection"),
  projectionId: TodosEntityIdSchema,
  owner: TodosOwnerIdSchema,
  version: z.number().int().positive(),
  digest: TodosSha256DigestSchema,
});
export type TaskToPrProjectionPredecessor = z.infer<typeof TaskToPrProjectionPredecessorSchema>;

export const TaskToPrProjectionIdentitySchema = z.strictObject({
  taskRef: TaskToPrTaskRefSchema,
  repositoryRef: TaskToPrRepositoryRefSchema,
  worktreeRef: TaskToPrWorktreeRefSchema,
  branchRef: TaskToPrBranchRefSchema,
  baseHead: TodosGitObjectIdSchema,
});
export type TaskToPrProjectionIdentity = z.infer<typeof TaskToPrProjectionIdentitySchema>;

export const TaskToPrProofKindSchema = z.enum([
  "head_equality",
  "ci",
  "review",
]);

export const TaskToPrProofSchema = z.strictObject({
  ref: TaskToPrProofRefSchema,
  kind: TaskToPrProofKindSchema,
  head: TodosGitObjectIdSchema,
  observedAt: TodosTimestampSchema,
});
export type TaskToPrProof = z.infer<typeof TaskToPrProofSchema>;

// @todos-runtime-validator projection.head_binding
export const TaskToPrHeadBindingSchema = z.strictObject({
  branchHead: TodosGitObjectIdSchema,
  publishedHead: TodosGitObjectIdSchema.nullable(),
  providerObservedHead: TodosGitObjectIdSchema.nullable(),
  equalityProof: TaskToPrProofSchema.nullable(),
}).superRefine((value, ctx) => {
  const exactValues = [
    value.publishedHead,
    value.providerObservedHead,
    value.equalityProof,
  ];
  const hasAnyExactValue = exactValues.some((entry) => entry !== null);
  const hasEveryExactValue = exactValues.every((entry) => entry !== null);
  if (hasAnyExactValue && !hasEveryExactValue) {
    ctx.addIssue({
      code: "custom",
      message: "Exact-head binding requires published, provider-observed, and proof values together",
    });
    return;
  }
  if (
    value.publishedHead
    && value.providerObservedHead
    && value.equalityProof
  ) {
    if (
      !sameTodosGitObjectId(value.branchHead, value.publishedHead)
      || !sameTodosGitObjectId(value.branchHead, value.providerObservedHead)
      || !sameTodosGitObjectId(value.branchHead, value.equalityProof.head)
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Exact-head values must equal the branch head",
      });
    }
    if (value.equalityProof.kind !== "head_equality") {
      ctx.addIssue({
        code: "custom",
        message: "The exact-head proof must use kind head_equality",
        path: ["equalityProof", "kind"],
      });
    }
  }
});
export type TaskToPrHeadBinding = z.infer<typeof TaskToPrHeadBindingSchema>;

export interface TaskToPrProjectionUnsigned {
  schema: typeof TODOS_PROJECTION_SCHEMA_IDS.projection;
  id: string;
  owner: string;
  version: number;
  sequence: number;
  predecessor: TaskToPrProjectionPredecessor | null;
  identity: TaskToPrProjectionIdentity;
  pullRequestRef: TaskToPrOwnerRef | null;
  head: TaskToPrHeadBinding;
  proofs: TaskToPrProof[];
  derivedAt: string;
}

function unsignedProjection(value: TaskToPrProjection): TaskToPrProjectionUnsigned {
  return {
    schema: value.schema,
    id: value.id,
    owner: value.owner,
    version: value.version,
    sequence: value.sequence,
    predecessor: value.predecessor,
    identity: value.identity,
    pullRequestRef: value.pullRequestRef,
    head: value.head,
    proofs: value.proofs,
    derivedAt: value.derivedAt,
  };
}

// @todos-runtime-validator projection.record_binding
export const TaskToPrProjectionSchema: z.ZodType<TaskToPrProjection> = z.strictObject({
  schema: z.literal(TODOS_PROJECTION_SCHEMA_IDS.projection),
  id: TodosEntityIdSchema,
  owner: TodosOwnerIdSchema,
  version: z.number().int().positive(),
  sequence: z.number().int().positive(),
  predecessor: TaskToPrProjectionPredecessorSchema.nullable(),
  identity: TaskToPrProjectionIdentitySchema,
  pullRequestRef: TaskToPrPullRequestRefSchema.nullable(),
  head: TaskToPrHeadBindingSchema,
  proofs: z.array(TaskToPrProofSchema).max(10_000),
  derivedAt: TodosTimestampSchema,
  digest: TodosSha256DigestSchema,
}).superRefine((value, ctx) => {
  if (value.version === 1 && value.predecessor !== null) {
    ctx.addIssue({
      code: "custom",
      message: "The first projection version cannot have a predecessor",
      path: ["predecessor"],
    });
  }
  if (value.version > 1 && value.predecessor === null) {
    ctx.addIssue({
      code: "custom",
      message: "Projection versions after one require a predecessor",
      path: ["predecessor"],
    });
  }
  if (value.predecessor && value.predecessor.version !== value.version - 1) {
    ctx.addIssue({
      code: "custom",
      message: "Projection predecessor version must immediately precede the current version",
      path: ["predecessor", "version"],
    });
  }
  if (
    value.predecessor
    && (
      value.predecessor.projectionId !== value.id
      || value.predecessor.owner !== value.owner
    )
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Projection predecessor identity must match the projection",
      path: ["predecessor"],
    });
  }
  for (const [field, ref] of Object.entries(value.identity)) {
    if (field === "baseHead") continue;
    if ((ref as TaskToPrOwnerRef).owner !== value.owner) {
      ctx.addIssue({
        code: "custom",
        message: "Every projection identity ref must match the projection owner",
        path: ["identity", field, "owner"],
      });
    }
  }
  if (value.pullRequestRef && value.pullRequestRef.owner !== value.owner) {
    ctx.addIssue({
      code: "custom",
      message: "Projection pull request ownership must match the projection owner",
      path: ["pullRequestRef", "owner"],
    });
  }
  const hasExactHead = value.head.equalityProof !== null;
  if (value.pullRequestRef !== null && !hasExactHead) {
    ctx.addIssue({
      code: "custom",
      message: "Observed pull requests require a complete exact-head binding",
      path: ["head"],
    });
  }
  if (value.pullRequestRef === null && hasExactHead) {
    ctx.addIssue({
      code: "custom",
      message: "Exact-head bindings require an observed pull request",
      path: ["pullRequestRef"],
    });
  }

  const proofRefs = [
    ...(value.head.equalityProof ? [value.head.equalityProof] : []),
    ...value.proofs,
  ];
  const refKeys = proofRefs.map((proof) => stableTodosJson(proof.ref));
  if (new Set(refKeys).size !== refKeys.length) {
    ctx.addIssue({
      code: "custom",
      message: "Projection proof refs must be unique",
      path: ["proofs"],
    });
  }
  const proofDigests = proofRefs.map((proof) => proof.ref.digest);
  if (new Set(proofDigests).size !== proofDigests.length) {
    ctx.addIssue({
      code: "custom",
      message: "Projection proof digests must be unique",
      path: ["proofs"],
    });
  }
  for (const [index, proof] of proofRefs.entries()) {
    if (proof.ref.owner !== value.owner) {
      ctx.addIssue({
        code: "custom",
        message: "Projection proof ownership must match the projection owner",
        path: [
          ...(value.head.equalityProof && index === 0
            ? ["head", "equalityProof"]
            : ["proofs", value.head.equalityProof ? index - 1 : index]),
          "ref",
          "owner",
        ],
      });
    }
  }
  for (const [index, proof] of value.proofs.entries()) {
    if (proof.kind === "head_equality") {
      ctx.addIssue({
        code: "custom",
        message: "head_equality belongs in the head binding",
        path: ["proofs", index, "kind"],
      });
    }
    if (!sameTodosGitObjectId(proof.head, value.head.branchHead)) {
      ctx.addIssue({
        code: "custom",
        message: "Projection proofs must bind the current branch head",
        path: ["proofs", index, "head"],
      });
    }
  }

  const expectedDigest = sha256TodosValue(unsignedProjection(value));
  if (value.digest !== expectedDigest) {
    ctx.addIssue({
      code: "custom",
      message: "Projection digest does not match its canonical content",
      path: ["digest"],
    });
  }
});
export interface TaskToPrProjection extends TaskToPrProjectionUnsigned {
  digest: string;
}

export const TaskToPrTransitionIssueSchema = z.strictObject({
  path: z.string().min(1).max(512),
  reason: z.string().min(1).max(2048),
});
export type TaskToPrTransitionIssue = z.infer<typeof TaskToPrTransitionIssueSchema>;

export type TaskToPrTransitionResult =
  | { success: true; replayed: boolean }
  | {
    success: false;
    error: TodosError;
    issues: TaskToPrTransitionIssue[];
  };

export function sameTodosGitObjectId(left: TodosGitObjectId, right: TodosGitObjectId): boolean {
  return left.algorithm === right.algorithm && left.value === right.value;
}

export function computeTaskToPrProjectionDigest(value: TaskToPrProjectionUnsigned): string {
  return sha256TodosValue(value);
}

export function createTaskToPrProjection(value: TaskToPrProjectionUnsigned): TaskToPrProjection {
  const normalized: TaskToPrProjectionUnsigned = {
    ...value,
    proofs: [...value.proofs].sort((left, right) => stableTodosJson(left).localeCompare(stableTodosJson(right))),
  };
  return TaskToPrProjectionSchema.parse({
    ...normalized,
    digest: computeTaskToPrProjectionDigest(normalized),
  });
}

function addTransitionIssue(
  issues: TaskToPrTransitionIssue[],
  path: string,
  reason: string,
): void {
  issues.push({ path, reason });
}

function proofSet(value: TaskToPrProjection): TaskToPrProof[] {
  return [
    ...(value.head.equalityProof ? [value.head.equalityProof] : []),
    ...value.proofs,
  ];
}

function refIdentity(ref: TaskToPrOwnerRef): string {
  return `${ref.owner}\u0000${ref.kind}\u0000${ref.id}`;
}

// @todos-runtime-validator projection.transition
export function validateTaskToPrProjectionTransition(
  previousInput: unknown,
  currentInput: unknown,
): TaskToPrTransitionResult {
  const previousParsed = TaskToPrProjectionSchema.safeParse(previousInput);
  const currentParsed = TaskToPrProjectionSchema.safeParse(currentInput);
  const parseIssues: TaskToPrTransitionIssue[] = [];
  if (!previousParsed.success) {
    for (const issue of previousParsed.error.issues) {
      addTransitionIssue(parseIssues, `previous.${issue.path.join(".")}`, issue.message);
    }
  }
  if (!currentParsed.success) {
    for (const issue of currentParsed.error.issues) {
      addTransitionIssue(parseIssues, `current.${issue.path.join(".")}`, issue.message);
    }
  }
  if (!previousParsed.success || !currentParsed.success) {
    return {
      success: false,
      error: createTodosError(
        "TODOS_PROJECTION_PREDECESSOR_CONFLICT",
        "Projection transition contains invalid records",
      ),
      issues: parseIssues,
    };
  }

  const previous = previousParsed.data;
  const current = currentParsed.data;
  if (stableTodosJson(previous) === stableTodosJson(current)) {
    return { success: true, replayed: true };
  }

  const issues: TaskToPrTransitionIssue[] = [];
  if (current.id !== previous.id || current.owner !== previous.owner) {
    addTransitionIssue(issues, "id", "Projection identity is immutable");
  }
  if (current.version !== previous.version + 1) {
    addTransitionIssue(issues, "version", "Projection version must increase by exactly one");
  }
  if (current.sequence !== previous.sequence + 1) {
    addTransitionIssue(issues, "sequence", "Projection sequence must increase by exactly one");
  }
  if (
    current.predecessor === null
    || current.predecessor.kind !== "task_to_pr_projection"
    || current.predecessor.projectionId !== previous.id
    || current.predecessor.owner !== previous.owner
    || current.predecessor.version !== previous.version
    || current.predecessor.digest !== previous.digest
  ) {
    addTransitionIssue(issues, "predecessor", "Projection predecessor must exactly bind the prior record");
  }
  if (stableTodosJson(current.identity) !== stableTodosJson(previous.identity)) {
    addTransitionIssue(issues, "identity", "Task, repository, worktree, branch, and base binding are immutable");
  }
  if (
    previous.pullRequestRef !== null
    && stableTodosJson(current.pullRequestRef) !== stableTodosJson(previous.pullRequestRef)
  ) {
    addTransitionIssue(issues, "pullRequestRef", "Pull request identity is immutable after first observation");
  }

  const headChanged = !sameTodosGitObjectId(previous.head.branchHead, current.head.branchHead);
  const previousProofs = proofSet(previous);
  const currentProofs = proofSet(current);
  if (!headChanged) {
    if (stableTodosJson(current.head) !== stableTodosJson(previous.head)) {
      addTransitionIssue(issues, "head", "An unchanged branch head must retain the complete head binding");
    }
    for (const [index, proof] of previous.proofs.entries()) {
      if (stableTodosJson(current.proofs[index]) !== stableTodosJson(proof)) {
        addTransitionIssue(issues, `proofs.${index}`, "Existing same-head proofs form an immutable prefix");
      }
    }
  } else {
    if (previous.head.equalityProof !== null && current.head.equalityProof === null) {
      addTransitionIssue(issues, "head.equalityProof", "A changed head requires fresh exact-head proof");
    }
    const previousIdentities = new Set(previousProofs.map((proof) => refIdentity(proof.ref)));
    const previousDigests = new Set(previousProofs.map((proof) => proof.ref.digest));
    for (const [index, proof] of currentProofs.entries()) {
      if (previousIdentities.has(refIdentity(proof.ref))) {
        addTransitionIssue(issues, `proofs.${index}.ref`, "A changed head requires fresh proof identities");
      }
      if (previousDigests.has(proof.ref.digest)) {
        addTransitionIssue(issues, `proofs.${index}.ref.digest`, "A changed head requires fresh proof digests");
      }
    }
  }

  if (issues.length > 0) {
    return {
      success: false,
      error: createTodosError(
        "TODOS_PROJECTION_PREDECESSOR_CONFLICT",
        "Projection transition violates predecessor or immutability rules",
      ),
      issues,
    };
  }
  return { success: true, replayed: false };
}

export interface TaskToPrProjectionHistoryOptions {
  expectedOwner?: string;
  expectedHead?: TodosGitObjectId;
}

export type TaskToPrProjectionHistoryResult =
  | {
    success: true;
    head: TaskToPrProjection;
  }
  | {
    success: false;
    error: TodosError;
    issues: TaskToPrTransitionIssue[];
  };

function proofIdentityKey(proof: TaskToPrProof): string {
  return refIdentity(proof.ref);
}

// @todos-runtime-validator projection.history
export function validateTaskToPrProjectionHistory(
  historyInput: unknown,
  options: TaskToPrProjectionHistoryOptions = {},
): TaskToPrProjectionHistoryResult {
  if (!Array.isArray(historyInput) || historyInput.length === 0) {
    return {
      success: false,
      error: createTodosError(
        "TODOS_PROJECTION_PREDECESSOR_CONFLICT",
        "Projection history must contain at least one record",
      ),
      issues: [{ path: "history", reason: "Projection history must be a non-empty array" }],
    };
  }

  const history: TaskToPrProjection[] = [];
  const issues: TaskToPrTransitionIssue[] = [];
  for (const [index, input] of historyInput.entries()) {
    const parsed = TaskToPrProjectionSchema.safeParse(input);
    if (!parsed.success) {
      for (const issue of parsed.error.issues) {
        addTransitionIssue(
          issues,
          `history.${index}.${issue.path.join(".")}`,
          issue.message,
        );
      }
    } else {
      history.push(parsed.data);
    }
  }
  if (issues.length > 0 || history.length !== historyInput.length) {
    return {
      success: false,
      error: createTodosError(
        "TODOS_PROJECTION_PREDECESSOR_CONFLICT",
        "Projection history contains invalid records",
      ),
      issues,
    };
  }

  const first = history[0]!;
  if (first.version !== 1 || first.sequence !== 1 || first.predecessor !== null) {
    addTransitionIssue(
      issues,
      "history.0",
      "Projection history must start at version and sequence one without a predecessor",
    );
  }
  if (options.expectedOwner !== undefined && first.owner !== options.expectedOwner) {
    addTransitionIssue(issues, "history.0.owner", "Projection history owner does not match");
  }

  const versions = new Set<number>();
  const sequences = new Set<number>();
  const digests = new Set<string>();
  const headStates = new Set<string>();
  const proofByIdentity = new Map<string, string>();
  const proofIdentityByDigest = new Map<string, string>();
  const immutableIdentity = stableTodosJson(first.identity);

  for (const [index, projection] of history.entries()) {
    if (versions.has(projection.version)) {
      addTransitionIssue(issues, `history.${index}.version`, "Projection versions cannot be reused");
    }
    if (sequences.has(projection.sequence)) {
      addTransitionIssue(issues, `history.${index}.sequence`, "Projection sequences cannot be reused");
    }
    if (digests.has(projection.digest)) {
      addTransitionIssue(issues, `history.${index}.digest`, "Projection digests cannot be reused");
    }
    versions.add(projection.version);
    sequences.add(projection.sequence);
    digests.add(projection.digest);

    if (stableTodosJson(projection.identity) !== immutableIdentity) {
      addTransitionIssue(
        issues,
        `history.${index}.identity`,
        "Projection identity must remain immutable across the complete history",
      );
    }
    if (projection.owner !== first.owner || projection.id !== first.id) {
      addTransitionIssue(
        issues,
        `history.${index}.owner`,
        "Projection id and owner must remain immutable across the complete history",
      );
    }

    const headKey = stableTodosJson(projection.head.branchHead);
    const previous = history[index - 1];
    if (
      previous
      && !sameTodosGitObjectId(previous.head.branchHead, projection.head.branchHead)
      && headStates.has(headKey)
    ) {
      addTransitionIssue(
        issues,
        `history.${index}.head.branchHead`,
        "Projection history cannot return to a previously observed branch head",
      );
    }
    headStates.add(headKey);

    for (const proof of proofSet(projection)) {
      const identityKey = proofIdentityKey(proof);
      const proofJson = stableTodosJson(proof);
      const existingProof = proofByIdentity.get(identityKey);
      if (existingProof !== undefined && existingProof !== proofJson) {
        addTransitionIssue(
          issues,
          `history.${index}.proofs`,
          "A proof reference cannot be reused for different proof content",
        );
      }
      const existingIdentity = proofIdentityByDigest.get(proof.ref.digest);
      if (existingIdentity !== undefined && existingIdentity !== identityKey) {
        addTransitionIssue(
          issues,
          `history.${index}.proofs`,
          "A proof digest cannot be reused by a different proof reference",
        );
      }
      proofByIdentity.set(identityKey, proofJson);
      proofIdentityByDigest.set(proof.ref.digest, identityKey);
    }

    if (previous) {
      const transition = validateTaskToPrProjectionTransition(previous, projection);
      if (!transition.success) {
        for (const issue of transition.issues) {
          addTransitionIssue(issues, `history.${index}.${issue.path}`, issue.reason);
        }
      } else if (transition.replayed) {
        addTransitionIssue(
          issues,
          `history.${index}`,
          "Projection history cannot contain duplicate replay records",
        );
      }
    }
  }

  const head = history[history.length - 1]!;
  if (
    options.expectedHead
    && !sameTodosGitObjectId(head.head.branchHead, options.expectedHead)
  ) {
    addTransitionIssue(
      issues,
      "history.head",
      "Projection history head is stale relative to the expected branch head",
    );
  }
  if (issues.length > 0) {
    return {
      success: false,
      error: createTodosError(
        "TODOS_PROJECTION_PREDECESSOR_CONFLICT",
        "Projection history violates full-chain integrity",
      ),
      issues,
    };
  }
  return { success: true, head };
}

export const TODOS_PROJECTION_SCHEMAS = Object.freeze({
  [TODOS_PROJECTION_SCHEMA_IDS.projection]: TaskToPrProjectionSchema,
  [TODOS_PROJECTION_SCHEMA_IDS.transitionIssue]: TaskToPrTransitionIssueSchema,
});
