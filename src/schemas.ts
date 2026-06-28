import { z } from "zod";

export const CONTRACTS_PACKAGE_NAME = "@hasna/contracts";
export const CONTRACTS_PACKAGE_VERSION = "0.1.1";

export const SCHEMA_IDS = {
  actorRef: "hasna.actor_ref.v1",
  resourceRef: "hasna.resource_ref.v1",
  evidenceRef: "hasna.evidence_ref.v1",
  workRun: "hasna.work_run.v1",
  decisionEnvelope: "hasna.decision_envelope.v1",
  costEstimate: "hasna.cost_estimate.v1",
  capabilityCard: "hasna.capability_card.v1",
  contextPack: "hasna.context_pack.v1",
  agentTrajectory: "hasna.agent_trajectory.v1",
  validationPlan: "hasna.validation_plan.v1",
  proofBundle: "hasna.proof_bundle.v1"
} as const;

export const SchemaIdSchema = z
  .string()
  .regex(/^hasna\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*\.v[0-9]+$/);
export type SchemaId = z.infer<typeof SchemaIdSchema>;

export const TimestampSchema = z.string().datetime();
export const NonEmptyStringSchema = z.string().trim().min(1);
export const UriSchema = NonEmptyStringSchema.refine(
  (value) =>
    value.startsWith("artifact://") ||
    value.startsWith("repo://") ||
    value.startsWith("task://") ||
    value.startsWith("file://") ||
    value.startsWith("https://") ||
    value.startsWith("http://") ||
    value.startsWith("git+https://"),
  "URI must use artifact://, repo://, task://, file://, http(s)://, or git+https://"
);
export const Sha256DigestSchema = z.string().regex(/^[a-fA-F0-9]{64}$/);
export const HashStringSchema = z.string().regex(/^(sha256:)?[a-fA-F0-9]{64}$/);
export const MetadataSchema = z.record(z.unknown());
export const TagsSchema = z.array(z.string().min(1)).default([]);
export const OptionalTimestampSchema = TimestampSchema.nullable().optional();
const TerminalStatuses = new Set<ContractStatus>(["succeeded", "failed", "cancelled", "blocked", "skipped"]);

export const ContractStatusSchema = z.enum([
  "pending",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "blocked",
  "skipped",
  "unknown"
]);
export type ContractStatus = z.infer<typeof ContractStatusSchema>;

export function contractBaseSchema<TSchema extends string>(schema: TSchema) {
  return z
    .object({
      schema: z.literal(schema),
      id: z.string().min(1),
      createdAt: TimestampSchema,
      updatedAt: OptionalTimestampSchema,
      metadata: MetadataSchema.optional()
    })
    .strict();
}

export const ContractEnvelopeSchema = z
  .object({
    schema: SchemaIdSchema,
    id: z.string().min(1),
    createdAt: TimestampSchema,
    updatedAt: OptionalTimestampSchema,
    metadata: MetadataSchema.optional()
  })
  .strict();
export type ContractEnvelope = z.infer<typeof ContractEnvelopeSchema>;

export const ActorKindSchema = z.enum([
  "agent",
  "human",
  "service",
  "model",
  "workflow",
  "system"
]);
export type ActorKind = z.infer<typeof ActorKindSchema>;

export const ActorRefSchema = contractBaseSchema(SCHEMA_IDS.actorRef)
  .extend({
    kind: ActorKindSchema,
    name: z.string().min(1).optional(),
    provider: z.string().min(1).optional(),
    accountId: z.string().min(1).optional(),
    machineId: z.string().min(1).optional(),
    capabilities: z.array(z.string().min(1)).default([])
  })
  .strict();
export type ActorRef = z.infer<typeof ActorRefSchema>;

export const ActorPointerSchema = z
  .object({
    kind: ActorKindSchema,
    id: z.string().min(1),
    name: z.string().min(1).optional(),
    provider: z.string().min(1).optional(),
    accountId: z.string().min(1).optional(),
    machineId: z.string().min(1).optional()
  })
  .strict();
export type ActorPointer = z.infer<typeof ActorPointerSchema>;

export const ResourceKindSchema = z.enum([
  "task",
  "project",
  "repo",
  "run",
  "loop",
  "workflow",
  "action",
  "event",
  "session",
  "machine",
  "model",
  "tool",
  "file",
  "url",
  "artifact",
  "knowledge",
  "report",
  "commit",
  "branch",
  "pull_request",
  "issue",
  "comment",
  "verification",
  "finding",
  "context_pack",
  "proof_bundle",
  "memento",
  "eval",
  "budget",
  "cost",
  "alert",
  "incident",
  "unknown"
]);
export type ResourceKind = z.infer<typeof ResourceKindSchema>;

export const ResourceRefSchema = contractBaseSchema(SCHEMA_IDS.resourceRef)
  .extend({
    kind: ResourceKindSchema,
    name: z.string().min(1).optional(),
    uri: UriSchema.optional(),
    externalId: NonEmptyStringSchema.optional(),
    sourcePackage: NonEmptyStringSchema.optional(),
    tags: TagsSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    if (!value.uri && !(value.externalId && value.sourcePackage)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Resource refs require uri or both sourcePackage and externalId",
        path: ["uri"]
      });
    }
  });
export type ResourceRef = z.infer<typeof ResourceRefSchema>;

export const ResourcePointerSchema = z
  .object({
    kind: ResourceKindSchema,
    id: z.string().min(1),
    name: z.string().min(1).optional(),
    uri: UriSchema.optional(),
    externalId: NonEmptyStringSchema.optional(),
    sourcePackage: NonEmptyStringSchema.optional(),
    tags: TagsSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    if (!value.uri && (Boolean(value.externalId) !== Boolean(value.sourcePackage))) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Resource pointers with external package locators require both sourcePackage and externalId",
        path: value.externalId ? ["sourcePackage"] : ["externalId"]
      });
    }
  });
export type ResourcePointer = z.infer<typeof ResourcePointerSchema>;

export const EvidenceKindSchema = z.enum([
  "file",
  "command_output",
  "screenshot",
  "log",
  "diff",
  "report",
  "artifact",
  "url",
  "video",
  "har",
  "test_result",
  "metric",
  "trace",
  "other"
]);
export type EvidenceKind = z.infer<typeof EvidenceKindSchema>;

export const RedactionStateSchema = z.enum(["none", "partial", "full", "unknown"]);
export type RedactionState = z.infer<typeof RedactionStateSchema>;

export const EvidenceRefSchema = contractBaseSchema(SCHEMA_IDS.evidenceRef)
  .extend({
    kind: EvidenceKindSchema,
    uri: UriSchema,
    sha256: Sha256DigestSchema.optional(),
    summary: z.string().min(1).optional(),
    contentType: z.string().min(1).optional(),
    sizeBytes: z.number().int().nonnegative().optional(),
    redaction: RedactionStateSchema.default("unknown"),
    producer: ActorPointerSchema.optional(),
    resourceRefs: z.array(ResourcePointerSchema).default([]),
    tags: TagsSchema
  })
  .strict();
export type EvidenceRef = z.infer<typeof EvidenceRefSchema>;

export const EvidencePointerSchema = z
  .object({
    id: z.string().min(1),
    kind: EvidenceKindSchema.optional(),
    uri: UriSchema.optional(),
    sha256: Sha256DigestSchema.optional(),
    summary: z.string().min(1).optional()
  })
  .strict();
export type EvidencePointer = z.infer<typeof EvidencePointerSchema>;

export const CostEstimateSchema = contractBaseSchema(SCHEMA_IDS.costEstimate)
  .extend({
    currency: z.string().regex(/^[A-Z]{3}$/).default("USD"),
    amountMicros: z.number().int().nonnegative(),
    provider: z.string().min(1).optional(),
    model: z.string().min(1).optional(),
    accountId: z.string().min(1).optional(),
    promptTokens: z.number().int().nonnegative().optional(),
    completionTokens: z.number().int().nonnegative().optional(),
    totalTokens: z.number().int().nonnegative().optional(),
    basis: z.enum(["actual", "estimated", "budget", "limit"]).default("estimated"),
    resourceRefs: z.array(ResourcePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (
      value.promptTokens !== undefined &&
      value.completionTokens !== undefined &&
      value.totalTokens !== undefined &&
      value.totalTokens !== value.promptTokens + value.completionTokens
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "totalTokens must equal promptTokens plus completionTokens when all are present",
        path: ["totalTokens"]
      });
    }
  });
export type CostEstimate = z.infer<typeof CostEstimateSchema>;

export const DecisionStatusSchema = z.enum([
  "allowed",
  "denied",
  "warned",
  "approval_required",
  "selected",
  "skipped",
  "unknown"
]);
export type DecisionStatus = z.infer<typeof DecisionStatusSchema>;

export const DecisionEnvelopeSchema = contractBaseSchema(SCHEMA_IDS.decisionEnvelope)
  .extend({
    decisionType: z.enum([
      "guardrail",
      "model_route",
      "tool_select",
      "budget",
      "secret_access",
      "approval",
      "policy",
      "other"
    ]),
    status: DecisionStatusSchema,
    actor: ActorPointerSchema.optional(),
    traceId: z.string().min(1).optional(),
    inputHash: HashStringSchema.optional(),
    policyBundleId: z.string().min(1).optional(),
    selected: z.array(ResourcePointerSchema).default([]),
    skipped: z.array(ResourcePointerSchema).default([]),
    reason: z.string().min(1),
    obligations: z.array(z.string().min(1)).default([]),
    redactions: z.array(z.string().min(1)).default([]),
    costEstimate: CostEstimateSchema.optional(),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.status === "selected" && value.selected.length === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Selected decisions require at least one selected resource", path: ["selected"] });
    }
    if (value.status === "skipped" && value.skipped.length === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Skipped decisions require at least one skipped resource", path: ["skipped"] });
    }
    if (value.status === "denied") {
      if (value.selected.length > 0) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Denied decisions cannot include selected resources", path: ["selected"] });
      }
      if (!value.policyBundleId && value.evidenceRefs.length === 0 && value.obligations.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Denied decisions require policy, evidence, or obligations",
          path: ["policyBundleId"]
        });
      }
    }
    if (value.status === "approval_required" && value.obligations.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Approval-required decisions require actionable obligations",
        path: ["obligations"]
      });
    }
  });
export type DecisionEnvelope = z.infer<typeof DecisionEnvelopeSchema>;

export const CapabilityCardSchema = contractBaseSchema(SCHEMA_IDS.capabilityCard)
  .extend({
    kind: z.enum(["model", "tool", "machine", "agent", "lane", "connector", "service"]),
    name: z.string().min(1),
    version: z.string().min(1).optional(),
    status: z.enum(["available", "unavailable", "degraded", "unknown"]).default("unknown"),
    capabilities: z.array(z.string().min(1)).default([]),
    limitations: z.array(z.string().min(1)).default([]),
    riskLevel: z.enum(["low", "medium", "high", "critical", "unknown"]).default("unknown"),
    costEstimate: CostEstimateSchema.optional(),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict();
export type CapabilityCard = z.infer<typeof CapabilityCardSchema>;

export const ContextPackItemSchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1).optional(),
    summary: z.string().min(1),
    text: z.string().optional(),
    tokens: z.number().int().nonnegative().optional(),
    source: EvidencePointerSchema,
    resourceRefs: z.array(ResourcePointerSchema).default([])
  })
  .strict();
export type ContextPackItem = z.infer<typeof ContextPackItemSchema>;

export const ContextPackSchema = contractBaseSchema(SCHEMA_IDS.contextPack)
  .extend({
    objective: z.string().min(1),
    budget: z
      .object({
        maxTokens: z.number().int().positive().optional(),
        maxBytes: z.number().int().positive().optional()
      })
      .strict()
      .optional(),
    items: z.array(ContextPackItemSchema).default([]),
    citations: z.array(EvidencePointerSchema).default([]),
    freshness: z.enum(["fresh", "stale", "unknown"]).default("unknown"),
    permissions: z.array(z.string().min(1)).default([]),
    redactions: z.array(z.string().min(1)).default([]),
    conflicts: z.array(z.string().min(1)).default([]),
    uncertainty: z.string().min(1).optional()
  })
  .strict();
export type ContextPack = z.infer<typeof ContextPackSchema>;

export const ValidationCheckSchema = z
  .object({
    id: z.string().min(1),
    kind: z.enum(["command", "test", "typecheck", "lint", "eval", "security", "review", "deploy", "smoke", "manual", "other"]),
    required: z.boolean().default(true),
    command: z.string().min(1).optional(),
    expected: z.string().min(1).optional(),
    timeoutMs: z.number().int().positive().optional(),
    resourceRefs: z.array(ResourcePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    const actionableKinds = new Set(["command", "test", "typecheck", "lint", "smoke", "eval"]);
    if (actionableKinds.has(value.kind) && !value.command && !value.expected) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Actionable validation checks require command or expected",
        path: ["command"]
      });
    }
  });
export type ValidationCheck = z.infer<typeof ValidationCheckSchema>;

export const ValidationPlanSchema = contractBaseSchema(SCHEMA_IDS.validationPlan)
  .extend({
    objective: z.string().min(1),
    subject: ResourcePointerSchema.optional(),
    checks: z.array(ValidationCheckSchema).min(1),
    verifier: ActorPointerSchema.optional(),
    requiredEvidenceKinds: z.array(EvidenceKindSchema).default([])
  })
  .strict();
export type ValidationPlan = z.infer<typeof ValidationPlanSchema>;

export const ProofCheckResultSchema = z
  .object({
    checkId: z.string().min(1),
    status: ContractStatusSchema,
    summary: z.string().min(1).optional(),
    startedAt: OptionalTimestampSchema,
    finishedAt: OptionalTimestampSchema,
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict();
export type ProofCheckResult = z.infer<typeof ProofCheckResultSchema>;

export const ProofBundleSchema = contractBaseSchema(SCHEMA_IDS.proofBundle)
  .extend({
    subject: ResourcePointerSchema,
    validationPlanRef: ResourcePointerSchema.optional(),
    status: ContractStatusSchema,
    verdict: z.enum(["passed", "failed", "inconclusive", "not_run"]).default("inconclusive"),
    checks: z.array(ProofCheckResultSchema).default([]),
    verifier: ActorPointerSchema.optional(),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    residualRisks: z.array(z.string().min(1)).default([]),
    freshness: z.enum(["fresh", "stale", "unknown"]).default("unknown")
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.verdict === "passed") {
      if (value.status !== "succeeded") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Passed proof bundles must have status succeeded",
          path: ["status"]
        });
      }
      if (value.checks.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Passed proof bundles require at least one check result",
          path: ["checks"]
        });
      }
      value.checks.forEach((check, index) => {
        if (check.status !== "succeeded") {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Passed proof bundles require all checks to have status succeeded",
            path: ["checks", index, "status"]
          });
        }
      });
      const hasEvidence = value.evidenceRefs.length > 0 || value.checks.some((check) => check.evidenceRefs.length > 0);
      if (!hasEvidence) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Passed proof bundles require evidence",
          path: ["evidenceRefs"]
        });
      }
      if (!value.verifier) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Passed proof bundles require a verifier",
          path: ["verifier"]
        });
      }
    }
    if (value.verdict === "not_run" && value.checks.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Not-run proof bundles cannot include check results",
        path: ["checks"]
      });
    }
    if (value.verdict === "failed" && !value.checks.some((check) => check.status === "failed") && value.evidenceRefs.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Failed proof bundles require a failed check or evidence",
        path: ["checks"]
      });
    }
  });
export type ProofBundle = z.infer<typeof ProofBundleSchema>;

export const WorkRunSchema = contractBaseSchema(SCHEMA_IDS.workRun)
  .extend({
    objective: z.string().min(1),
    status: ContractStatusSchema,
    actor: ActorPointerSchema,
    traceId: z.string().min(1).optional(),
    startedAt: OptionalTimestampSchema,
    finishedAt: OptionalTimestampSchema,
    constraints: z.array(z.string().min(1)).default([]),
    resourceRefs: z.array(ResourcePointerSchema).default([]),
    decisions: z.array(DecisionEnvelopeSchema).default([]),
    costEstimates: z.array(CostEstimateSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    validationPlanRefs: z.array(ResourcePointerSchema).default([]),
    proofBundleRefs: z.array(ResourcePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.startedAt && value.finishedAt && Date.parse(value.finishedAt) < Date.parse(value.startedAt)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "finishedAt must be after or equal to startedAt",
        path: ["finishedAt"]
      });
    }
    if (TerminalStatuses.has(value.status) && !value.finishedAt) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Terminal work runs require finishedAt",
        path: ["finishedAt"]
      });
    }
    const hasEvidence = value.evidenceRefs.length > 0 || value.proofBundleRefs.length > 0;
    if (value.status === "succeeded" && !hasEvidence) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Succeeded work runs require evidence or a proof bundle",
        path: ["evidenceRefs"]
      });
    }
    if ((value.status === "failed" || value.status === "blocked") && !hasEvidence && value.decisions.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Failed or blocked work runs require evidence, a proof bundle, or a decision record",
        path: ["evidenceRefs"]
      });
    }
  });
export type WorkRun = z.infer<typeof WorkRunSchema>;

export const TrajectoryEventSchema = z
  .object({
    id: z.string().min(1),
    at: TimestampSchema,
    kind: z.enum(["message", "tool_call", "command", "file_change", "error", "test", "decision", "verification", "status", "other"]),
    summary: z.string().min(1),
    resourceRefs: z.array(ResourcePointerSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    costEstimate: CostEstimateSchema.optional()
  })
  .strict();
export type TrajectoryEvent = z.infer<typeof TrajectoryEventSchema>;

export const AgentTrajectorySchema = contractBaseSchema(SCHEMA_IDS.agentTrajectory)
  .extend({
    actor: ActorPointerSchema,
    workRunRef: ResourcePointerSchema.optional(),
    events: z.array(TrajectoryEventSchema).default([]),
    outcome: z.enum(["succeeded", "failed", "cancelled", "blocked", "unknown"]).default("unknown"),
    proofBundleRef: ResourcePointerSchema.optional()
  })
  .strict();
export type AgentTrajectory = z.infer<typeof AgentTrajectorySchema>;

export const ContractSchemaRegistry = {
  [SCHEMA_IDS.actorRef]: ActorRefSchema,
  [SCHEMA_IDS.resourceRef]: ResourceRefSchema,
  [SCHEMA_IDS.evidenceRef]: EvidenceRefSchema,
  [SCHEMA_IDS.workRun]: WorkRunSchema,
  [SCHEMA_IDS.decisionEnvelope]: DecisionEnvelopeSchema,
  [SCHEMA_IDS.costEstimate]: CostEstimateSchema,
  [SCHEMA_IDS.capabilityCard]: CapabilityCardSchema,
  [SCHEMA_IDS.contextPack]: ContextPackSchema,
  [SCHEMA_IDS.agentTrajectory]: AgentTrajectorySchema,
  [SCHEMA_IDS.validationPlan]: ValidationPlanSchema,
  [SCHEMA_IDS.proofBundle]: ProofBundleSchema
} as const;

export type KnownSchemaId = keyof typeof ContractSchemaRegistry;

export type ContractBySchemaId = {
  [SCHEMA_IDS.actorRef]: ActorRef;
  [SCHEMA_IDS.resourceRef]: ResourceRef;
  [SCHEMA_IDS.evidenceRef]: EvidenceRef;
  [SCHEMA_IDS.workRun]: WorkRun;
  [SCHEMA_IDS.decisionEnvelope]: DecisionEnvelope;
  [SCHEMA_IDS.costEstimate]: CostEstimate;
  [SCHEMA_IDS.capabilityCard]: CapabilityCard;
  [SCHEMA_IDS.contextPack]: ContextPack;
  [SCHEMA_IDS.agentTrajectory]: AgentTrajectory;
  [SCHEMA_IDS.validationPlan]: ValidationPlan;
  [SCHEMA_IDS.proofBundle]: ProofBundle;
};

export type ActorRefInput = z.input<typeof ActorRefSchema>;
export type ResourceRefInput = z.input<typeof ResourceRefSchema>;
export type EvidenceRefInput = z.input<typeof EvidenceRefSchema>;
export type WorkRunInput = z.input<typeof WorkRunSchema>;
export type DecisionEnvelopeInput = z.input<typeof DecisionEnvelopeSchema>;
export type CostEstimateInput = z.input<typeof CostEstimateSchema>;
export type CapabilityCardInput = z.input<typeof CapabilityCardSchema>;
export type ContextPackInput = z.input<typeof ContextPackSchema>;
export type AgentTrajectoryInput = z.input<typeof AgentTrajectorySchema>;
export type ValidationPlanInput = z.input<typeof ValidationPlanSchema>;
export type ProofBundleInput = z.input<typeof ProofBundleSchema>;
export type ActorPointerInput = z.input<typeof ActorPointerSchema>;
export type ResourcePointerInput = z.input<typeof ResourcePointerSchema>;
export type EvidencePointerInput = z.input<typeof EvidencePointerSchema>;

export type ContractInputBySchemaId = {
  [SCHEMA_IDS.actorRef]: ActorRefInput;
  [SCHEMA_IDS.resourceRef]: ResourceRefInput;
  [SCHEMA_IDS.evidenceRef]: EvidenceRefInput;
  [SCHEMA_IDS.workRun]: WorkRunInput;
  [SCHEMA_IDS.decisionEnvelope]: DecisionEnvelopeInput;
  [SCHEMA_IDS.costEstimate]: CostEstimateInput;
  [SCHEMA_IDS.capabilityCard]: CapabilityCardInput;
  [SCHEMA_IDS.contextPack]: ContextPackInput;
  [SCHEMA_IDS.agentTrajectory]: AgentTrajectoryInput;
  [SCHEMA_IDS.validationPlan]: ValidationPlanInput;
  [SCHEMA_IDS.proofBundle]: ProofBundleInput;
};
