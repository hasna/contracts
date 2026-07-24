import { createHash } from "node:crypto";
import { z } from "zod";

export const CONTRACTS_PACKAGE_NAME = "@hasna/contracts";
export const CONTRACTS_PACKAGE_VERSION = "0.7.0";

export const SCHEMA_IDS = {
  actorRef: "hasna.actor_ref.v1",
  resourceRef: "hasna.resource_ref.v1",
  evidenceRef: "hasna.evidence_ref.v1",
  workRun: "hasna.work_run.v1",
  taskToPrProjection: "hasna.task_to_pr_projection.v1",
  decisionEnvelope: "hasna.decision_envelope.v1",
  costEstimate: "hasna.cost_estimate.v1",
  capabilityCard: "hasna.capability_card.v1",
  providerLiveModeStandard: "hasna.provider_live_mode_standard.v1",
  contextPack: "hasna.context_pack.v1",
  integrationRef: "hasna.integration_ref.v1",
  projectManifest: "hasna.project_manifest.v1",
  projectPanel: "hasna.project_panel.v1",
  projectSnapshot: "hasna.project_snapshot.v1",
  renderManifest: "hasna.render_manifest.v1",
  agentTrajectory: "hasna.agent_trajectory.v1",
  validationPlan: "hasna.validation_plan.v1",
  proofBundle: "hasna.proof_bundle.v1",
  scaffoldManifest: "hasna.scaffold_manifest.v1",
  scaffoldInstallRecord: "hasna.scaffold_install_record.v1",
  appCloudManifest: "hasna.app_cloud_manifest.v1",
  noCloudEvidencePack: "hasna.no_cloud_evidence_pack.v1",
  secureLocalStorePolicy: "hasna.secure_local_store_policy.v1",
  serviceContract: "hasna.service_contract.v1",
  commsEventEnvelope: "hasna.comms_event_envelope.v1",
  commsChannelMetadata: "hasna.comms_channel_metadata.v1",
  commsMessageMetadata: "hasna.comms_message_metadata.v1",
  app: "hasna.app.v1",
  release: "hasna.release.v1",
  rolloutRecord: "hasna.rollout_record.v1",
  announcement: "hasna.announcement.v1",
  audience: "hasna.audience.v1"
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
    value.startsWith("project://") ||
    value.startsWith("dashboard://") ||
    value.startsWith("render://") ||
    value.startsWith("integration://") ||
    value.startsWith("task://") ||
    value.startsWith("todo://") ||
    value.startsWith("file://") ||
    value.startsWith("files://") ||
    value.startsWith("mailery://") ||
    value.startsWith("conversation://") ||
    value.startsWith("knowledge://") ||
    value.startsWith("memento://") ||
    value.startsWith("https://") ||
    value.startsWith("http://") ||
    value.startsWith("git+https://"),
  "URI must use artifact://, repo://, project://, dashboard://, render://, integration://, task://, todo://, file://, files://, mailery://, conversation://, knowledge://, memento://, http(s)://, or git+https://"
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
  "integration",
  "session",
  "machine",
  "model",
  "tool",
  "file",
  "document",
  "url",
  "artifact",
  "knowledge",
  "email",
  "conversation",
  "dashboard",
  "render",
  "panel",
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
  "app",
  "release",
  "rollout",
  "announcement",
  "audience",
  "feedback",
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

export const ProviderModeSchema = z.enum(["mock", "fixture", "sandbox", "read_only_live", "live_mutating"]);
export type ProviderMode = z.infer<typeof ProviderModeSchema>;

export const ProviderSideEffectClassSchema = z.enum([
  "none",
  "read_only",
  "external_notification",
  "external_mutation",
  "money_movement",
  "dns_or_domain_change",
  "bulk_message_or_call",
  "legal_or_filing",
  "compute_or_infra_mutation",
  "irreversible"
]);
export type ProviderSideEffectClass = z.infer<typeof ProviderSideEffectClassSchema>;

export const CredentialRequirementSchema = z
  .object({
    refName: NonEmptyStringSchema,
    requiredForModes: z.array(ProviderModeSchema).min(1),
    allowedSecretInputs: z.array(z.enum(["credential_ref", "lease_ref"])).min(1).default(["credential_ref"]),
    failClosedDiagnostic: NonEmptyStringSchema,
    revocationCheck: z.boolean().default(true)
  })
  .strict();
export type CredentialRequirement = z.infer<typeof CredentialRequirementSchema>;

export const ProviderOperationCardSchema = z
  .object({
    operation: NonEmptyStringSchema,
    supportedModes: z.array(ProviderModeSchema).min(1),
    sideEffectClass: ProviderSideEffectClassSchema,
    requiresApproval: z.boolean().default(false),
    requiresIdempotencyKey: z.boolean().default(false),
    requiresSandboxEvidence: z.boolean().default(false),
    requiresRollbackOrRevocation: z.boolean().default(false),
    rollbackOrRevocation: NonEmptyStringSchema.optional(),
    noSideEffectSmoke: NonEmptyStringSchema.optional(),
    reconciliation: NonEmptyStringSchema.optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.supportedModes.includes("live_mutating")) {
      if (value.sideEffectClass === "none" || value.sideEffectClass === "read_only") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "live_mutating operations must declare a side-effecting class",
          path: ["sideEffectClass"]
        });
      }
      if (!value.requiresApproval) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "live_mutating operations require approval",
          path: ["requiresApproval"]
        });
      }
      if (!value.requiresIdempotencyKey) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "live_mutating operations require idempotency keys",
          path: ["requiresIdempotencyKey"]
        });
      }
      if (!value.requiresSandboxEvidence) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "live_mutating operations require sandbox evidence before live proof",
          path: ["requiresSandboxEvidence"]
        });
      }
      if (!value.requiresRollbackOrRevocation || !value.rollbackOrRevocation) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "live_mutating operations require rollback or revocation instructions",
          path: ["rollbackOrRevocation"]
        });
      }
      if (!value.reconciliation) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "live_mutating operations require reconciliation behavior",
          path: ["reconciliation"]
        });
      }
    }
  });
export type ProviderOperationCard = z.infer<typeof ProviderOperationCardSchema>;

export const ProviderCapabilityCardSchema = z
  .object({
    providerId: NonEmptyStringSchema,
    appId: NonEmptyStringSchema,
    adapterId: NonEmptyStringSchema,
    ownerPackage: NonEmptyStringSchema,
    modes: z.array(ProviderModeSchema).min(1),
    defaultMode: ProviderModeSchema,
    credentialRequirements: z.array(CredentialRequirementSchema).default([]),
    operations: z.array(ProviderOperationCardSchema).min(1),
    rateLimitPosture: NonEmptyStringSchema,
    costPosture: NonEmptyStringSchema.optional(),
    auditEvents: z.array(NonEmptyStringSchema).default([]),
    redactionRules: z.array(NonEmptyStringSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (!value.modes.includes(value.defaultMode)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "defaultMode must be one of modes",
        path: ["defaultMode"]
      });
    }

    const operationModes = new Set(value.operations.flatMap((operation) => operation.supportedModes));
    for (const mode of operationModes) {
      if (!value.modes.includes(mode)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `operation mode ${mode} is not declared in provider modes`,
          path: ["operations"]
        });
      }
    }

    if (operationModes.has("live_mutating")) {
      const liveCredential = value.credentialRequirements.some((credential) => credential.requiredForModes.includes("live_mutating"));
      if (!liveCredential) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "live_mutating providers require at least one live credential reference requirement",
          path: ["credentialRequirements"]
        });
      }
      if (value.auditEvents.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "live_mutating providers require audit events",
          path: ["auditEvents"]
        });
      }
    }
  });
export type ProviderCapabilityCard = z.infer<typeof ProviderCapabilityCardSchema>;

export const ProviderLiveModeTargetSchema = z
  .object({
    appId: NonEmptyStringSchema,
    repo: NonEmptyStringSchema,
    priority: z.enum(["p0", "p1", "p2"]).default("p1"),
    requiredEvidence: z.array(NonEmptyStringSchema).min(1),
    firstOperations: z.array(NonEmptyStringSchema).min(1),
    blockedUntil: z.array(NonEmptyStringSchema).default([])
  })
  .strict();
export type ProviderLiveModeTarget = z.infer<typeof ProviderLiveModeTargetSchema>;

export const ProviderLiveModeStandardSchema = contractBaseSchema(SCHEMA_IDS.providerLiveModeStandard)
  .extend({
    name: NonEmptyStringSchema,
    version: NonEmptyStringSchema,
    modes: z.array(ProviderModeSchema).refine(
      (modes) => ["mock", "fixture", "sandbox", "read_only_live", "live_mutating"].every((mode) => modes.includes(mode as ProviderMode)),
      "provider live-mode standard must include every canonical provider mode"
    ),
    requiredCapabilityFields: z.array(NonEmptyStringSchema).min(1),
    liveMutationGate: z
      .object({
        requiredMode: z.literal("live_mutating"),
        requiredChecks: z.array(NonEmptyStringSchema).min(1),
        forbiddenBypassSignals: z.array(NonEmptyStringSchema).min(1),
        disabledLiveSmoke: NonEmptyStringSchema
      })
      .strict(),
    noSideEffectSmoke: z
      .object({
        requiredForModes: z.array(ProviderModeSchema).min(1),
        commandEvidence: z.array(NonEmptyStringSchema).min(1),
        secretOutputScan: z.boolean().default(true)
      })
      .strict(),
    credentialPolicy: z
      .object({
        acceptedInputs: z.array(z.enum(["credential_ref", "lease_ref"])).min(1),
        rawSecretInputsAllowed: z.literal(false),
        missingCredentialBehavior: z.literal("fail_closed"),
        revocationCheckRequired: z.boolean().default(true)
      })
      .strict(),
    operationCards: z.array(ProviderCapabilityCardSchema).min(1),
    firstAdoptionTargets: z.array(ProviderLiveModeTargetSchema).min(1),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    const firstTargetApps = new Set(value.firstAdoptionTargets.map((target) => target.appId));
    const operationApps = new Set(value.operationCards.map((card) => card.appId));
    for (const appId of firstTargetApps) {
      if (!operationApps.has(appId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `first adoption target ${appId} requires a provider capability card`,
          path: ["firstAdoptionTargets"]
        });
      }
    }
  });
export type ProviderLiveModeStandard = z.infer<typeof ProviderLiveModeStandardSchema>;

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

export const RelativeProjectPathSchema = NonEmptyStringSchema.refine(
  (value) => !value.startsWith("/") && !value.includes("\\") && !value.split("/").includes(".."),
  "Project paths must be relative and cannot contain parent-directory segments"
);
export type RelativeProjectPath = z.infer<typeof RelativeProjectPathSchema>;

export const ProjectSlugSchema = z
  .string()
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, "Project slugs must be lowercase dashed identifiers");
export type ProjectSlug = z.infer<typeof ProjectSlugSchema>;

export const ProjectClassificationSchema = z.enum(["public", "internal", "private", "sensitive"]);
export type ProjectClassification = z.infer<typeof ProjectClassificationSchema>;

export const ProjectStatusSchema = z.enum(["draft", "active", "paused", "archived"]);
export type ProjectStatus = z.infer<typeof ProjectStatusSchema>;

export const ProjectIntegrationKindSchema = z.enum([
  "todos",
  "files",
  "mailery",
  "conversations",
  "knowledge",
  "mementos",
  "reports",
  "actions",
  "render",
  "contracts",
  "custom"
]);
export type ProjectIntegrationKind = z.infer<typeof ProjectIntegrationKindSchema>;

export const IntegrationRefSchema = contractBaseSchema(SCHEMA_IDS.integrationRef)
  .extend({
    kind: ProjectIntegrationKindSchema,
    name: z.string().min(1),
    projectId: ProjectSlugSchema.optional(),
    sourcePackage: NonEmptyStringSchema.optional(),
    externalId: NonEmptyStringSchema.optional(),
    uri: UriSchema.optional(),
    enabled: z.boolean().default(true),
    readOnly: z.boolean().default(true),
    capabilities: z.array(z.string().min(1)).default([]),
    freshness: z.enum(["fresh", "stale", "unknown"]).default("unknown"),
    resourceRef: ResourcePointerSchema.optional(),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    config: MetadataSchema.optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (!value.uri && !(value.sourcePackage && value.externalId) && !value.resourceRef) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Integration refs require uri, resourceRef, or both sourcePackage and externalId",
        path: ["uri"]
      });
    }
  });
export type IntegrationRef = z.infer<typeof IntegrationRefSchema>;

export const ProjectLayoutSchema = z
  .object({
    schemaRoot: RelativeProjectPathSchema.default(".hasna/project"),
    dashboardManifest: RelativeProjectPathSchema.default(".hasna/project/dashboard.render.json"),
    snapshotsDir: RelativeProjectPathSchema.default(".hasna/project/snapshots"),
    documentsDir: RelativeProjectPathSchema.default("documents"),
    reportsDir: RelativeProjectPathSchema.default("reports"),
    evidenceDir: RelativeProjectPathSchema.default(".hasna/project/evidence"),
    privateDir: RelativeProjectPathSchema.default(".hasna/project/private")
  })
  .strict();
export type ProjectLayout = z.infer<typeof ProjectLayoutSchema>;

export const ProjectManifestSchema = contractBaseSchema(SCHEMA_IDS.projectManifest)
  .extend({
    projectId: ProjectSlugSchema,
    slug: ProjectSlugSchema,
    name: z.string().min(1),
    summary: z.string().min(1).optional(),
    status: ProjectStatusSchema.default("active"),
    classification: ProjectClassificationSchema.default("private"),
    owner: ActorPointerSchema.optional(),
    layout: ProjectLayoutSchema.default({}),
    integrations: z.array(IntegrationRefSchema).default([]),
    renderManifests: z.array(ResourcePointerSchema).default([]),
    resourceRefs: z.array(ResourcePointerSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    tags: TagsSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    const integrationIds = new Set<string>();
    const renderManifestIds = new Set<string>();
    if (value.projectId !== value.slug) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "projectId and slug must match for canonical project manifests",
        path: ["slug"]
      });
    }
    for (const [index, integration] of value.integrations.entries()) {
      if (integrationIds.has(integration.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Project manifest integration ids must be unique",
          path: ["integrations", index, "id"]
        });
      }
      integrationIds.add(integration.id);
      if (integration.projectId && integration.projectId !== value.projectId) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Integration projectId must match the manifest projectId",
          path: ["integrations", index, "projectId"]
        });
      }
    }
    for (const [index, renderManifest] of value.renderManifests.entries()) {
      if (renderManifest.kind !== "render") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Project renderManifests must use resource kind render",
          path: ["renderManifests", index, "kind"]
        });
      }
      if (renderManifestIds.has(renderManifest.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Project renderManifest refs must be unique",
          path: ["renderManifests", index, "id"]
        });
      }
      renderManifestIds.add(renderManifest.id);
    }
  });
export type ProjectManifest = z.infer<typeof ProjectManifestSchema>;

export const RenderImportKindSchema = z.enum(["local", "package", "provider", "url"]);
export type RenderImportKind = z.infer<typeof RenderImportKindSchema>;

export const RenderImportSchema = z
  .object({
    id: z.string().min(1),
    kind: RenderImportKindSchema,
    specifier: z.string().min(1),
    path: RelativeProjectPathSchema.optional(),
    packageName: z.string().min(1).optional(),
    uri: UriSchema.optional(),
    provider: ProjectIntegrationKindSchema.optional(),
    schemaId: SchemaIdSchema.optional(),
    integrity: HashStringSchema.optional(),
    resourceRef: ResourcePointerSchema.optional(),
    optional: z.boolean().default(false)
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.kind === "local" && !value.path) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Local render imports require path", path: ["path"] });
    }
    if (value.kind === "package" && !value.packageName) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Package render imports require packageName", path: ["packageName"] });
    }
    if (value.kind === "provider" && !value.provider) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Provider render imports require provider", path: ["provider"] });
    }
    if (value.kind === "url" && !value.uri) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "URL render imports require uri", path: ["uri"] });
    }
  });
export type RenderImport = z.infer<typeof RenderImportSchema>;

export const RenderViewKindSchema = z.enum(["dashboard", "canvas", "panel", "report", "document", "custom"]);
export type RenderViewKind = z.infer<typeof RenderViewKindSchema>;

export const RenderViewSchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1),
    kind: RenderViewKindSchema,
    default: z.boolean().default(false),
    entry: RelativeProjectPathSchema.optional(),
    imports: z.array(RenderImportSchema).default([]),
    panelRefs: z.array(ResourcePointerSchema).default([]),
    dataRefs: z.array(ResourcePointerSchema).default([]),
    layout: MetadataSchema.optional()
  })
  .strict();
export type RenderView = z.infer<typeof RenderViewSchema>;

export const RenderManifestSchema = contractBaseSchema(SCHEMA_IDS.renderManifest)
  .extend({
    projectId: ProjectSlugSchema,
    name: z.string().min(1),
    version: z.string().min(1),
    manifestPath: RelativeProjectPathSchema.default(".hasna/project/dashboard.render.json"),
    renderer: z.enum(["json_render", "react_flow", "markdown", "html", "custom"]).default("json_render"),
    views: z.array(RenderViewSchema).min(1),
    imports: z.array(RenderImportSchema).default([]),
    theme: MetadataSchema.optional(),
    compatibility: z
      .object({
        minProjectsVersion: z.string().min(1).optional(),
        minContractsVersion: z.string().min(1).optional()
      })
      .strict()
      .optional(),
    resourceRefs: z.array(ResourcePointerSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    const defaults = value.views.filter((view) => view.default);
    const viewIds = new Set<string>();
    const importIds = new Set<string>();
    if (defaults.length > 1) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Render manifests can have at most one default view", path: ["views"] });
    }
    for (const [index, importRef] of value.imports.entries()) {
      if (importIds.has(importRef.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Render manifest import ids must be unique",
          path: ["imports", index, "id"]
        });
      }
      importIds.add(importRef.id);
    }
    for (const [viewIndex, view] of value.views.entries()) {
      if (viewIds.has(view.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Render manifest view ids must be unique",
          path: ["views", viewIndex, "id"]
        });
      }
      viewIds.add(view.id);
      const viewImportIds = new Set<string>();
      for (const [importIndex, importRef] of view.imports.entries()) {
        if (viewImportIds.has(importRef.id)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Render view import ids must be unique",
            path: ["views", viewIndex, "imports", importIndex, "id"]
          });
        }
        viewImportIds.add(importRef.id);
      }
      for (const [panelIndex, panelRef] of view.panelRefs.entries()) {
        if (panelRef.kind !== "panel") {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Render view panelRefs must use resource kind panel",
            path: ["views", viewIndex, "panelRefs", panelIndex, "kind"]
          });
        }
      }
    }
  });
export type RenderManifest = z.infer<typeof RenderManifestSchema>;

export const ProjectPanelStateSchema = z.enum(["ready", "empty", "loading", "error", "auth_required", "unavailable", "stale"]);
export type ProjectPanelState = z.infer<typeof ProjectPanelStateSchema>;

export const ProjectPanelKindSchema = z.enum([
  "overview",
  "tasks",
  "files",
  "mailery",
  "conversations",
  "knowledge",
  "mementos",
  "reports",
  "actions",
  "timeline",
  "risks",
  "documents",
  "custom"
]);
export type ProjectPanelKind = z.infer<typeof ProjectPanelKindSchema>;

export const ProjectPanelMetricSchema = z
  .object({
    id: z.string().min(1),
    label: z.string().min(1),
    value: z.union([z.string(), z.number(), z.boolean()]),
    unit: z.string().min(1).optional(),
    status: z.enum(["good", "warning", "critical", "unknown"]).default("unknown"),
    resourceRefs: z.array(ResourcePointerSchema).default([])
  })
  .strict();
export type ProjectPanelMetric = z.infer<typeof ProjectPanelMetricSchema>;

export const ProjectPanelItemSchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1),
    summary: z.string().min(1).optional(),
    status: z.string().min(1).optional(),
    priority: z.enum(["low", "medium", "high", "critical", "unknown"]).default("unknown"),
    timestamp: TimestampSchema.optional(),
    resourceRefs: z.array(ResourcePointerSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    metadata: MetadataSchema.optional()
  })
  .strict();
export type ProjectPanelItem = z.infer<typeof ProjectPanelItemSchema>;

export const ProjectRenderFragmentSchema = z
  .object({
    renderer: z.enum(["json_render", "react_flow", "markdown", "html", "custom"]).default("json_render"),
    title: z.string().min(1).optional(),
    entry: RelativeProjectPathSchema.optional(),
    imports: z.array(RenderImportSchema).default([]),
    spec: MetadataSchema.default({})
  })
  .strict();
export type ProjectRenderFragment = z.infer<typeof ProjectRenderFragmentSchema>;

export const ProjectPanelSchema = contractBaseSchema(SCHEMA_IDS.projectPanel)
  .extend({
    projectId: ProjectSlugSchema,
    provider: z
      .object({
        kind: ProjectIntegrationKindSchema,
        id: z.string().min(1),
        name: z.string().min(1).optional(),
        sourcePackage: NonEmptyStringSchema.optional(),
        externalId: NonEmptyStringSchema.optional()
      })
      .strict(),
    kind: ProjectPanelKindSchema,
    title: z.string().min(1),
    summary: z.string().min(1).optional(),
    state: ProjectPanelStateSchema.default("ready"),
    stateReason: z.string().min(1).optional(),
    generatedAt: TimestampSchema,
    freshness: z.enum(["fresh", "stale", "unknown"]).default("unknown"),
    metrics: z.array(ProjectPanelMetricSchema).default([]),
    items: z.array(ProjectPanelItemSchema).default([]),
    actions: z.array(ResourcePointerSchema).default([]),
    resourceRefs: z.array(ResourcePointerSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    renderFragment: ProjectRenderFragmentSchema.optional(),
    warnings: z.array(z.string().min(1)).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    const reasonStates = new Set<ProjectPanelState>(["error", "auth_required", "unavailable", "stale"]);
    const metricIds = new Set<string>();
    const itemIds = new Set<string>();
    if (reasonStates.has(value.state) && !value.stateReason) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Non-ready provider states require stateReason",
        path: ["stateReason"]
      });
    }
    if (value.state === "ready" && value.metrics.length === 0 && value.items.length === 0 && !value.renderFragment) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Ready panels require metrics, items, or a renderFragment; use state=empty for empty panels",
        path: ["state"]
      });
    }
    for (const [index, metric] of value.metrics.entries()) {
      if (metricIds.has(metric.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Project panel metric ids must be unique",
          path: ["metrics", index, "id"]
        });
      }
      metricIds.add(metric.id);
    }
    for (const [index, item] of value.items.entries()) {
      if (itemIds.has(item.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Project panel item ids must be unique",
          path: ["items", index, "id"]
        });
      }
      itemIds.add(item.id);
    }
    for (const [index, action] of value.actions.entries()) {
      if (action.kind !== "action") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Project panel actions must use resource kind action",
          path: ["actions", index, "kind"]
        });
      }
    }
  });
export type ProjectPanel = z.infer<typeof ProjectPanelSchema>;

export const ProjectSnapshotSchema = contractBaseSchema(SCHEMA_IDS.projectSnapshot)
  .extend({
    projectId: ProjectSlugSchema,
    generatedAt: TimestampSchema,
    status: ContractStatusSchema.default("unknown"),
    manifestRef: ResourcePointerSchema,
    renderManifestRef: ResourcePointerSchema.optional(),
    panels: z.array(ProjectPanelSchema).default([]),
    contextPacks: z.array(ContextPackSchema).default([]),
    proofBundleRefs: z.array(ResourcePointerSchema).default([]),
    resourceRefs: z.array(ResourcePointerSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    warnings: z.array(z.string().min(1)).default([]),
    freshness: z.enum(["fresh", "stale", "unknown"]).default("unknown")
  })
  .strict()
  .superRefine((value, ctx) => {
    const panelIds = new Set<string>();
    const contextPackIds = new Set<string>();
    if (value.manifestRef.kind !== "project") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Project snapshot manifestRef must use resource kind project",
        path: ["manifestRef", "kind"]
      });
    }
    if (value.renderManifestRef && value.renderManifestRef.kind !== "render") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Project snapshot renderManifestRef must use resource kind render",
        path: ["renderManifestRef", "kind"]
      });
    }
    for (const [index, proofBundleRef] of value.proofBundleRefs.entries()) {
      if (proofBundleRef.kind !== "proof_bundle") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Project snapshot proofBundleRefs must use resource kind proof_bundle",
          path: ["proofBundleRefs", index, "kind"]
        });
      }
    }
    for (const [index, panel] of value.panels.entries()) {
      if (panel.projectId !== value.projectId) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Panel projectId must match snapshot projectId",
          path: ["panels", index, "projectId"]
        });
      }
      if (panelIds.has(panel.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Project snapshot panel ids must be unique",
          path: ["panels", index, "id"]
        });
      }
      panelIds.add(panel.id);
    }
    for (const [index, contextPack] of value.contextPacks.entries()) {
      if (contextPackIds.has(contextPack.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Project snapshot context pack ids must be unique",
          path: ["contextPacks", index, "id"]
        });
      }
      contextPackIds.add(contextPack.id);
    }
  });
export type ProjectSnapshot = z.infer<typeof ProjectSnapshotSchema>;

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

export const ScaffoldTypeSchema = z.enum([
  "open_source",
  "internal_app",
  "platform",
  "app",
  "agent",
  "content",
  "overlay",
  "other"
]);
export type ScaffoldType = z.infer<typeof ScaffoldTypeSchema>;

export const ScaffoldStatusSchema = z.enum(["draft", "active", "deprecated", "archived"]);
export type ScaffoldStatus = z.infer<typeof ScaffoldStatusSchema>;

export const ScaffoldCapabilitySchema = z.enum([
  "cli",
  "mcp",
  "library",
  "sdk",
  "rest_api",
  "dashboard",
  "database",
  "auth",
  "billing",
  "worker",
  "daemon",
  "native",
  "browser_extension",
  "ai_provider",
  "media_pipeline",
  "data_pipeline",
  "tests",
  "ci",
  "deployment",
  "docs",
  "other"
]);
export type ScaffoldCapability = z.infer<typeof ScaffoldCapabilitySchema>;

export const ScaffoldEnvVarSchema = z
  .object({
    key: z.string().regex(/^[A-Z][A-Z0-9_]*$/),
    description: z.string().min(1),
    required: z.boolean().default(false),
    ["secret"]: z.boolean().default(false),
    group: z.string().min(1).optional(),
    default: z.string().optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.secret && value.default !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Secret scaffold env vars cannot include defaults",
        path: ["default"]
      });
    }
  });
export type ScaffoldEnvVar = z.infer<typeof ScaffoldEnvVarSchema>;

export const ScaffoldScriptSchema = z
  .object({
    name: z.string().min(1),
    command: z.string().min(1),
    description: z.string().min(1).optional(),
    required: z.boolean().default(false)
  })
  .strict();
export type ScaffoldScript = z.infer<typeof ScaffoldScriptSchema>;

export const ScaffoldOutputShapeSchema = z
  .object({
    packageManager: z.enum(["bun", "npm", "pnpm", "yarn", "cargo", "pip", "other"]).optional(),
    languages: z.array(z.string().min(1)).default([]),
    requiredFiles: z.array(z.string().min(1)).default([]),
    requiredDirectories: z.array(z.string().min(1)).default([]),
    optionalDirectories: z.array(z.string().min(1)).default([])
  })
  .strict();
export type ScaffoldOutputShape = z.infer<typeof ScaffoldOutputShapeSchema>;

export const ScaffoldManifestSchema = contractBaseSchema(SCHEMA_IDS.scaffoldManifest)
  .extend({
    name: z.string().min(1),
    version: z.string().min(1),
    summary: z.string().min(1),
    type: ScaffoldTypeSchema,
    status: ScaffoldStatusSchema.default("draft"),
    capabilities: z.array(ScaffoldCapabilitySchema).default([]),
    techStack: z.array(z.string().min(1)).default([]),
    tags: TagsSchema,
    source: ResourcePointerSchema.optional(),
    output: ScaffoldOutputShapeSchema,
    env: z.array(ScaffoldEnvVarSchema).default([]),
    scripts: z.array(ScaffoldScriptSchema).default([]),
    validationChecks: z.array(ValidationCheckSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.source?.uri?.startsWith("file://")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Public scaffold manifest source refs cannot use local file:// URIs",
        path: ["source", "uri"]
      });
    }
    if (value.status === "active" && value.validationChecks.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Active scaffold manifests require validation checks",
        path: ["validationChecks"]
      });
    }
    if (value.status === "active" && value.output.requiredFiles.length === 0 && value.output.requiredDirectories.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Active scaffold manifests require at least one required file or directory",
        path: ["output"]
      });
    }
  });
export type ScaffoldManifest = z.infer<typeof ScaffoldManifestSchema>;

export const ScaffoldInstallStatusSchema = z.enum(["installed", "failed", "cancelled", "partial", "unknown"]);
export type ScaffoldInstallStatus = z.infer<typeof ScaffoldInstallStatusSchema>;

export const ScaffoldInstallRecordSchema = contractBaseSchema(SCHEMA_IDS.scaffoldInstallRecord)
  .extend({
    scaffoldId: z.string().min(1),
    scaffoldVersion: z.string().min(1).optional(),
    manifestRef: ResourcePointerSchema.optional(),
    target: ResourcePointerSchema,
    status: ScaffoldInstallStatusSchema,
    installedAt: TimestampSchema.optional(),
    installer: ActorPointerSchema.optional(),
    packageManager: z.enum(["bun", "npm", "pnpm", "yarn", "cargo", "pip", "other"]).optional(),
    options: MetadataSchema.optional(),
    generatedFiles: z.array(ResourcePointerSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    proofBundleRefs: z.array(ResourcePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.status === "installed" && !value.installedAt) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Installed scaffold records require installedAt",
        path: ["installedAt"]
      });
    }
    if (value.status === "installed" && value.generatedFiles.length === 0 && value.evidenceRefs.length === 0 && value.proofBundleRefs.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Installed scaffold records require generated files, evidence, or proof bundle refs",
        path: ["generatedFiles"]
      });
    }
    if ((value.status === "failed" || value.status === "partial") && value.evidenceRefs.length === 0 && value.proofBundleRefs.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Failed or partial scaffold records require evidence or proof bundle refs",
        path: ["evidenceRefs"]
      });
    }
  });
export type ScaffoldInstallRecord = z.infer<typeof ScaffoldInstallRecordSchema>;

// ---------------------------------------------------------------------------
// Distribution contracts (Hasna distribution apps plan)
//
// `hasna.app.v1` is the SINGLE canonical app-identity contract. Every other
// distribution document (releases, rollout records, announcements) and the
// pre-existing `hasna.app_cloud_manifest.v1` reference an app by its stable
// `appId` slug instead of re-declaring identity fields.
// ---------------------------------------------------------------------------

/** Stable lowercase dashed app identity slug, e.g. `open-todos`. */
export const AppIdSchema = z
  .string()
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, "App ids must be lowercase dashed identifiers");
export type AppId = z.infer<typeof AppIdSchema>;

/** npm package name, scoped or unscoped, e.g. `@hasna/todos`. */
export const NpmPackageNameSchema = z
  .string()
  .regex(/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/, "Must be a valid npm package name");
export type NpmPackageName = z.infer<typeof NpmPackageNameSchema>;

/** Semver version string, e.g. `1.2.3`, `1.2.3-beta.1`. */
export const SemverSchema = z
  .string()
  .regex(
    /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/,
    "Must be a semver version"
  );
export type Semver = z.infer<typeof SemverSchema>;

/** Lowercase git commit sha, abbreviated (>=7) or full (40). */
export const GitShaSchema = z.string().regex(/^[0-9a-f]{7,40}$/, "Must be a lowercase git sha (7-40 hex chars)");
export type GitSha = z.infer<typeof GitShaSchema>;

export const GithubUrlSchema = NonEmptyStringSchema.refine(
  (value) => value.startsWith("https://github.com/") || value.startsWith("git+https://github.com/"),
  "GitHub URLs must start with https://github.com/ or git+https://github.com/"
);

export const AppLifecycleSchema = z.enum(["active", "stub", "deprecated", "archived"]);
export type AppLifecycle = z.infer<typeof AppLifecycleSchema>;

export const ReleaseChannelSchema = z.enum(["stable", "beta", "canary", "internal"]);
export type ReleaseChannel = z.infer<typeof ReleaseChannelSchema>;

export const AppMcpSurfaceSchema = z
  .object({
    transport: z.enum(["http", "stdio"]).default("http"),
    bin: z.string().min(1).optional(),
    url: UriSchema.optional()
  })
  .strict();
export type AppMcpSurface = z.infer<typeof AppMcpSurfaceSchema>;

export const AppHttpSurfaceSchema = z
  .object({
    healthPath: z.string().min(1).default("/health"),
    port: z.number().int().positive().optional(),
    baseUrl: UriSchema.optional()
  })
  .strict();
export type AppHttpSurface = z.infer<typeof AppHttpSurfaceSchema>;

export const AppSurfacesSchema = z
  .object({
    bins: z.array(z.string().min(1)).default([]),
    mcp: AppMcpSurfaceSchema.optional(),
    http: AppHttpSurfaceSchema.optional()
  })
  .strict();
export type AppSurfaces = z.infer<typeof AppSurfacesSchema>;

export const AppSchema = contractBaseSchema(SCHEMA_IDS.app)
  .extend({
    appId: AppIdSchema,
    npmName: NpmPackageNameSchema,
    repoFolder: AppIdSchema,
    githubUrl: GithubUrlSchema,
    projectSlug: ProjectSlugSchema,
    surfaces: AppSurfacesSchema.default({}),
    lifecycle: AppLifecycleSchema,
    releaseChannel: ReleaseChannelSchema.default("stable"),
    summary: z.string().min(1).optional(),
    tags: TagsSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    const seenBins = new Set<string>();
    for (const [index, bin] of value.surfaces.bins.entries()) {
      if (seenBins.has(bin)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "App surface bins must be unique",
          path: ["surfaces", "bins", index]
        });
      }
      seenBins.add(bin);
    }
  });
export type App = z.infer<typeof AppSchema>;

export const PublishPathSchema = z.enum(["skill", "ci", "backfilled"]);
export type PublishPath = z.infer<typeof PublishPathSchema>;

export const ReleaseSchema = contractBaseSchema(SCHEMA_IDS.release)
  .extend({
    appId: AppIdSchema,
    package: NpmPackageNameSchema,
    version: SemverSchema,
    gitSha: GitShaSchema,
    publishedAt: TimestampSchema,
    publishPath: PublishPathSchema,
    /** Deferred changelog refs are legal: omit until the changelog entry exists. */
    changelogRef: ResourcePointerSchema.optional(),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.publishPath !== "backfilled" && value.evidenceRefs.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "skill and ci releases require publish evidence; only backfilled releases may omit it",
        path: ["evidenceRefs"]
      });
    }
  });
export type Release = z.infer<typeof ReleaseSchema>;

export const RolloutActionSchema = z.enum(["install", "update", "rollback", "freeze-blocked"]);
export type RolloutAction = z.infer<typeof RolloutActionSchema>;

export const RolloutVerificationSchema = z
  .object({
    cliVersion: z.string().min(1).optional(),
    mcpHealth: z.enum(["ok", "degraded", "unavailable", "not_checked"]).optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (!value.cliVersion && value.mcpHealth === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Rollout verification requires at least one concrete verifier field"
      });
    }
  });
export type RolloutVerification = z.infer<typeof RolloutVerificationSchema>;

export const RolloutRecordSchema = contractBaseSchema(SCHEMA_IDS.rolloutRecord)
  .extend({
    appId: AppIdSchema,
    package: NpmPackageNameSchema,
    version: SemverSchema,
    machine: NonEmptyStringSchema,
    action: RolloutActionSchema,
    result: ContractStatusSchema,
    verifiedBy: RolloutVerificationSchema.optional(),
    at: TimestampSchema,
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.action === "freeze-blocked" && value.result !== "blocked" && value.result !== "skipped") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "freeze-blocked rollout records must report result blocked or skipped",
        path: ["result"]
      });
    }
    const hasConcreteVerification =
      Boolean(value.verifiedBy?.cliVersion) ||
      (value.verifiedBy?.mcpHealth !== undefined && value.verifiedBy.mcpHealth !== "not_checked");
    const hasVerifierFields = value.verifiedBy ? Object.keys(value.verifiedBy).length > 0 : false;
    if (
      (value.action === "install" || value.action === "update") &&
      value.result === "succeeded" &&
      (!value.verifiedBy || (hasVerifierFields && !hasConcreteVerification))
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Succeeded install/update rollout records require concrete verification",
        path: ["verifiedBy"]
      });
    }
  });
export type RolloutRecord = z.infer<typeof RolloutRecordSchema>;

export const AnnouncementChannelKindSchema = z.enum([
  "email",
  "telegram",
  "slack",
  "discord",
  "x",
  "blog",
  "rss",
  "webhook",
  "github",
  "other"
]);
export type AnnouncementChannelKind = z.infer<typeof AnnouncementChannelKindSchema>;

export const AnnouncementDeliveryStatusSchema = z.enum([
  "pending",
  "queued",
  "sent",
  "failed",
  "skipped",
  "suppressed"
]);
export type AnnouncementDeliveryStatus = z.infer<typeof AnnouncementDeliveryStatusSchema>;

export const AnnouncementChannelSchema = z
  .object({
    channel: AnnouncementChannelKindSchema,
    status: AnnouncementDeliveryStatusSchema,
    deliveredAt: TimestampSchema.optional(),
    detail: z.string().min(1).optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.status === "sent" && !value.deliveredAt) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Sent announcement channels require deliveredAt",
        path: ["deliveredAt"]
      });
    }
    if (value.status === "failed" && !value.detail) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Failed announcement channels require detail",
        path: ["detail"]
      });
    }
  });
export type AnnouncementChannel = z.infer<typeof AnnouncementChannelSchema>;

export const AnnouncementSchema = contractBaseSchema(SCHEMA_IDS.announcement)
  .extend({
    campaignId: NonEmptyStringSchema,
    appId: AppIdSchema.optional(),
    releaseRef: ResourcePointerSchema.optional(),
    channels: z.array(AnnouncementChannelSchema).min(1),
    audienceRef: ResourcePointerSchema,
    sentAt: TimestampSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.releaseRef && value.releaseRef.kind !== "release") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Announcement releaseRef must use resource kind release",
        path: ["releaseRef", "kind"]
      });
    }
    if (value.audienceRef.kind !== "audience") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Announcement audienceRef must use resource kind audience",
        path: ["audienceRef", "kind"]
      });
    }
  });
export type Announcement = z.infer<typeof AnnouncementSchema>;

export const AudiencePredicateKindSchema = z.enum(["tag", "attribute", "group"]);
export type AudiencePredicateKind = z.infer<typeof AudiencePredicateKindSchema>;

export const AudiencePredicateOpSchema = z.enum(["eq", "neq", "in", "not_in", "exists", "not_exists"]);
export type AudiencePredicateOp = z.infer<typeof AudiencePredicateOpSchema>;

const AudiencePredicateValueSchema = z.union([z.string(), z.number(), z.boolean()]);

export const AudiencePredicateSchema = z
  .object({
    kind: AudiencePredicateKindSchema,
    /** Attribute key (required for attribute predicates), e.g. `machine`. */
    key: z.string().min(1).optional(),
    op: AudiencePredicateOpSchema.default("eq"),
    value: AudiencePredicateValueSchema.optional(),
    values: z.array(AudiencePredicateValueSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.kind === "attribute" && !value.key) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Attribute predicates require key",
        path: ["key"]
      });
    }
    if ((value.op === "eq" || value.op === "neq") && value.value === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "eq/neq predicates require value",
        path: ["value"]
      });
    }
    if ((value.op === "in" || value.op === "not_in") && value.values.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "in/not_in predicates require values",
        path: ["values"]
      });
    }
  });
export type AudiencePredicate = z.infer<typeof AudiencePredicateSchema>;

export const AudienceDefinitionSchema = z
  .object({
    match: z.enum(["all", "any"]).default("all"),
    predicates: z.array(AudiencePredicateSchema).min(1)
  })
  .strict();
export type AudienceDefinition = z.infer<typeof AudienceDefinitionSchema>;

export const ConsentPolicySchema = z.enum(["opt_in", "opt_out", "transactional", "none"]);
export type ConsentPolicy = z.infer<typeof ConsentPolicySchema>;

export const AudienceSchema = contractBaseSchema(SCHEMA_IDS.audience)
  .extend({
    audienceId: AppIdSchema,
    name: NonEmptyStringSchema,
    definition: AudienceDefinitionSchema,
    consentPolicy: ConsentPolicySchema,
    suppressionSyncedAt: OptionalTimestampSchema
  })
  .strict();
export type Audience = z.infer<typeof AudienceSchema>;

export const FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["@hasna/cloud", "open-cloud"] as const;

export const AppCloudProviderSchema = z.enum([
  "aws",
  "gcp",
  "azure",
  "cloudflare",
  "vercel",
  "neon",
  "supabase",
  "postgres",
  "s3",
  "rds",
  "other"
]);
export type AppCloudProvider = z.infer<typeof AppCloudProviderSchema>;

export const AppCloudResourceSchema = z
  .object({
    id: z.string().min(1),
    provider: AppCloudProviderSchema,
    kind: z.enum([
      "database",
      "bucket",
      "queue",
      "secret",
      "function",
      "worker",
      "cache",
      "topic",
      "scheduler",
      "object_store",
      "other"
    ]),
    ownerPackage: z.string().min(1),
    region: z.string().min(1).optional(),
    accountId: z.string().min(1).optional(),
    uri: UriSchema.optional(),
    machineScoped: z.boolean().default(false)
  })
  .strict();
export type AppCloudResource = z.infer<typeof AppCloudResourceSchema>;

// `hasna.app_cloud_manifest.v1` is NOT an identity schema. Canonical app
// identity lives in `hasna.app.v1`; this v1 field remains a compatible
// non-empty reference string instead of adopting the stricter AppIdSchema.
export const AppCloudManifestSchema = contractBaseSchema(SCHEMA_IDS.appCloudManifest)
  .extend({
    packageName: z.string().min(1),
    packageVersion: z.string().min(1).optional(),
    /** App identity reference; prefer AppIdSchema-compatible slugs for new manifests. */
    appId: z.string().min(1),
    repository: ResourcePointerSchema.optional(),
    storageMode: z.enum(["local_only", "app_owned_cloud", "hybrid_local_cache", "external_service"]),
    cloudBoundary: z.enum(["none", "app_owned", "external_service", "local_cache"]),
    cloudResources: z.array(AppCloudResourceSchema).default([]),
    localCache: z
      .object({
        path: z.string().min(1).optional(),
        pullMode: z.enum(["manual", "daemon", "ci", "none"]).default("manual"),
        conflictPolicy: z.enum(["cloud_wins", "local_wins", "merge", "manual_review"]).default("manual_review")
      })
      .strict()
      .optional(),
    forbiddenSharedRuntimes: z.array(z.string().min(1)).default([...FORBIDDEN_SHARED_CLOUD_RUNTIMES]),
    dependencies: z.array(z.string().min(1)).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    const effectiveForbiddenRuntimes = new Set<string>([...FORBIDDEN_SHARED_CLOUD_RUNTIMES, ...value.forbiddenSharedRuntimes]);
    if (effectiveForbiddenRuntimes.has(value.packageName)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "App-owned cloud manifests cannot be for a forbidden runtime",
        path: ["packageName"]
      });
    }
    for (const runtime of FORBIDDEN_SHARED_CLOUD_RUNTIMES) {
      if (!value.forbiddenSharedRuntimes.includes(runtime)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `forbiddenSharedRuntimes must include ${runtime}`,
          path: ["forbiddenSharedRuntimes"]
        });
      }
    }
    for (const runtime of effectiveForbiddenRuntimes) {
      if (value.dependencies.includes(runtime)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `App-owned cloud manifests cannot depend on ${runtime}`,
          path: ["dependencies"]
        });
      }
    }
    if (value.storageMode === "local_only" && value.cloudBoundary !== "none") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "local_only storage requires cloudBoundary none",
        path: ["cloudBoundary"]
      });
    }
    if (value.storageMode === "app_owned_cloud" && value.cloudBoundary !== "app_owned") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "app_owned_cloud storage requires cloudBoundary app_owned",
        path: ["cloudBoundary"]
      });
    }
    if (value.storageMode === "hybrid_local_cache") {
      if (value.cloudBoundary !== "local_cache") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "hybrid_local_cache storage requires cloudBoundary local_cache",
          path: ["cloudBoundary"]
        });
      }
      if (!value.localCache) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "hybrid_local_cache storage requires localCache settings",
          path: ["localCache"]
        });
      }
    }
    if (value.storageMode === "external_service") {
      if (value.cloudBoundary !== "external_service") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "external_service storage requires cloudBoundary external_service",
          path: ["cloudBoundary"]
        });
      }
      if (value.cloudResources.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "external_service storage must not declare app-owned cloudResources",
          path: ["cloudResources"]
        });
      }
    }
    if ((value.storageMode === "app_owned_cloud" || value.storageMode === "hybrid_local_cache") && value.cloudResources.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cloud-backed storage modes require explicit app-owned cloudResources",
        path: ["cloudResources"]
      });
    }
    if (value.cloudBoundary === "none" && value.cloudResources.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "cloudBoundary none cannot declare cloudResources",
        path: ["cloudResources"]
      });
    }
    value.cloudResources.forEach((resource, index) => {
      if (resource.ownerPackage !== value.packageName) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Cloud resources must be owned by the app package that declares the manifest",
          path: ["cloudResources", index, "ownerPackage"]
        });
      }
    });
  });
export type AppCloudManifest = z.infer<typeof AppCloudManifestSchema>;

export const NoCloudCheckKindSchema = z.enum([
  "package_manifest",
  "lockfile",
  "source_import",
  "runtime_config",
  "packed_artifact",
  "published_metadata",
  "app_cloud_manifest",
  "remote_config",
  "boundary_doc",
  "other"
]);
export type NoCloudCheckKind = z.infer<typeof NoCloudCheckKindSchema>;

export const NoCloudFindingSeveritySchema = z.enum(["low", "medium", "high", "critical"]);
export type NoCloudFindingSeverity = z.infer<typeof NoCloudFindingSeveritySchema>;

export const NoCloudFindingSchema = z
  .object({
    id: z.string().min(1),
    kind: NoCloudCheckKindSchema,
    severity: NoCloudFindingSeveritySchema,
    path: z.string().min(1).optional(),
    packageName: z.string().min(1).optional(),
    pattern: z.string().min(1),
    message: z.string().min(1),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict();
export type NoCloudFinding = z.infer<typeof NoCloudFindingSchema>;

export const NoCloudCheckResultSchema = z
  .object({
    id: z.string().min(1),
    kind: NoCloudCheckKindSchema,
    status: ContractStatusSchema,
    target: z.string().min(1),
    command: z.string().min(1).optional(),
    evidenceRefs: z.array(EvidencePointerSchema).default([]),
    findings: z.array(NoCloudFindingSchema).default([])
  })
  .strict();
export type NoCloudCheckResult = z.infer<typeof NoCloudCheckResultSchema>;

export const NoCloudEvidencePackSchema = contractBaseSchema(SCHEMA_IDS.noCloudEvidencePack)
  .extend({
    subject: ResourcePointerSchema,
    packageName: z.string().min(1).optional(),
    packageVersion: z.string().min(1).optional(),
    generatedBy: ActorPointerSchema.optional(),
    scanMode: z.enum(["source_tree", "packed_artifact", "published_metadata", "runtime_config", "workspace", "ci"]),
    status: ContractStatusSchema,
    verdict: z.enum(["passed", "failed", "warning", "not_run"]),
    appCloudManifest: AppCloudManifestSchema.optional(),
    checks: z.array(NoCloudCheckResultSchema).min(1),
    findings: z.array(NoCloudFindingSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    const allFindings = [...value.findings, ...value.checks.flatMap((check) => check.findings)];
    const blockingFindings = allFindings.filter((finding) => finding.severity === "high" || finding.severity === "critical");
    if (value.verdict === "passed") {
      if (value.status !== "succeeded") {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Passed no-cloud evidence requires succeeded status", path: ["status"] });
      }
      if (blockingFindings.length > 0) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Passed no-cloud evidence cannot include high or critical findings", path: ["findings"] });
      }
      if (value.checks.some((check) => check.status !== "succeeded")) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Passed no-cloud evidence requires every check to be succeeded", path: ["checks"] });
      }
    }
    if (value.verdict === "failed" && allFindings.length === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Failed no-cloud evidence requires findings", path: ["findings"] });
    }
    if (value.status === "succeeded" && value.checks.some((check) => check.status === "failed")) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Succeeded no-cloud evidence cannot contain failed checks", path: ["checks"] });
    }
    value.checks.forEach((check, index) => {
      const checkBlockingFindings = check.findings.filter((finding) => finding.severity === "high" || finding.severity === "critical");
      if (check.status === "succeeded" && checkBlockingFindings.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Succeeded no-cloud checks cannot contain high or critical findings",
          path: ["checks", index, "findings"]
        });
      }
    });
  });
export type NoCloudEvidencePack = z.infer<typeof NoCloudEvidencePackSchema>;

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

export const TASK_TO_PR_ROLE_AUTHORITIES = Object.freeze({
  work_run: Object.freeze(["codewith"] as const),
  root_request: Object.freeze(["todos"] as const),
  pr_group: Object.freeze(["todos"] as const),
  leaf_task: Object.freeze(["todos"] as const),
  attempt: Object.freeze(["todos"] as const),
  writer_generation: Object.freeze(["todos"] as const),
  writer_lease: Object.freeze(["repos"] as const),
  writer_fence: Object.freeze(["repos"] as const),
  provider_profile: Object.freeze(["codewith"] as const),
  provider_route: Object.freeze(["codewith"] as const),
  admission: Object.freeze(["codewith"] as const),
  worker_actor: Object.freeze(["codewith"] as const),
  worker: Object.freeze(["codewith"] as const),
  runtime: Object.freeze(["codewith"] as const),
  repo: Object.freeze(["repos"] as const),
  worktree: Object.freeze(["repos"] as const),
  branch: Object.freeze(["repos"] as const),
  event_stream: Object.freeze(["todos"] as const),
  replay_cursor: Object.freeze(["todos"] as const),
  handoff: Object.freeze(["todos"] as const),
  pull_request: Object.freeze(["todos"] as const),
  commit: Object.freeze(["repos"] as const),
  review: Object.freeze(["review"] as const),
  reviewer: Object.freeze(["review"] as const),
  review_run: Object.freeze(["review"] as const),
  proof_bundle: Object.freeze(["review"] as const),
  repair_cycle: Object.freeze(["todos"] as const),
  merge_guard: Object.freeze(["todos"] as const),
  merge_operator: Object.freeze(["merge_provider"] as const),
  merge_operator_run: Object.freeze(["merge_provider"] as const),
  merge_guard_receipt: Object.freeze(["merge_provider"] as const),
  merge_outcome: Object.freeze(["merge_provider"] as const),
  recovery: Object.freeze(["todos"] as const),
  cancellation: Object.freeze(["todos"] as const),
  cleanup_eligibility: Object.freeze(["repos"] as const),
  cleanup_outcome: Object.freeze(["repos"] as const),
  rollback_plan: Object.freeze(["todos"] as const),
  rollback_outcome: Object.freeze(["repos"] as const),
  terminal_disposition: Object.freeze(["todos"] as const),
  openloops_invocation: Object.freeze(["openloops"] as const),
  adapter_extension: Object.freeze(["adapter"] as const)
});

export const TaskToPrRefRoleSchema = z.enum([
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
]);
export type TaskToPrRefRole = z.infer<typeof TaskToPrRefRoleSchema>;

export const TaskToPrAuthoritySchema = z.enum([
  "todos",
  "codewith",
  "repos",
  "review",
  "merge_provider",
  "openloops",
  "adapter"
]);
export type TaskToPrAuthority = z.infer<typeof TaskToPrAuthoritySchema>;

const LowerSha256DigestSchema = z.string().regex(/^[a-f0-9]{64}$/);
const OpaqueTaskToPrIdSchema = z.string().trim().min(3).max(256);
const NonsemanticOpaqueSuffixPattern = /^[a-f0-9]{32}$/;
export function deriveTaskToPrRefId(
  role: TaskToPrRefRole,
  authority: TaskToPrAuthority,
  digest: string
): string {
  return `${role}:${authority}:opaque-${digest.slice(0, 32)}`;
}
export function deriveTaskToPrEvidenceId(digest: string): string {
  return `evidence:opaque-${digest.slice(0, 32)}`;
}
const TaskToPrProjectionIdSchema = OpaqueTaskToPrIdSchema.refine(
  (value) => {
    const prefix = "task_to_pr_projection:opaque-";
    const suffix = value.startsWith(prefix) ? value.slice(prefix.length) : "";
    return NonsemanticOpaqueSuffixPattern.test(suffix);
  },
  "Projection ids must use a nonsemantic 128-bit lowercase hexadecimal surrogate"
);
const TaskToPrAttemptNonceSchema = OpaqueTaskToPrIdSchema.refine(
  (value) => {
    const prefix = "attempt_nonce:opaque-";
    const suffix = value.startsWith(prefix) ? value.slice(prefix.length) : "";
    return NonsemanticOpaqueSuffixPattern.test(suffix);
  },
  "Attempt nonces must use a nonsemantic 128-bit lowercase hexadecimal surrogate"
);
const SensitiveTaskToPrRoles = new Set<TaskToPrRefRole>([
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
export const TaskToPrRefSchema = z
  .object({
    role: TaskToPrRefRoleSchema,
    authority: TaskToPrAuthoritySchema,
    id: OpaqueTaskToPrIdSchema,
    digest: LowerSha256DigestSchema,
    redaction: z.enum(["none", "partial", "full"])
  })
  .strict()
  .superRefine((value, ctx) => {
    const allowedAuthorities = TASK_TO_PR_ROLE_AUTHORITIES[value.role] as readonly TaskToPrAuthority[];
    if (!allowedAuthorities.includes(value.authority)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${value.role} refs must be owned by ${allowedAuthorities.join(" or ")}`,
        path: ["authority"]
      });
    }
    if (SensitiveTaskToPrRoles.has(value.role) && value.redaction === "none") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${value.role} refs must be redacted and cannot carry a raw locator or credential`,
        path: ["redaction"]
      });
    }
    const expectedId = deriveTaskToPrRefId(value.role, value.authority, value.digest);
    if (value.id !== expectedId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "Reference ids must be nonsemantic authority-bound surrogates derived from the canonical role, authority, and owner-record digest",
        path: ["id"]
      });
    }
  });
export type TaskToPrRef = z.infer<typeof TaskToPrRefSchema>;

export const TaskToPrEvidenceRefSchema = z
  .object({
    id: OpaqueTaskToPrIdSchema,
    digest: LowerSha256DigestSchema,
    redaction: z.enum(["partial", "full"])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.id !== deriveTaskToPrEvidenceId(value.digest)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "Evidence ids must be nonsemantic owner-resolvable surrogates derived from their canonical digest",
        path: ["id"]
      });
    }
  });
export type TaskToPrEvidenceRef = z.infer<typeof TaskToPrEvidenceRefSchema>;

function requireDistinctTaskToPrEvidenceRefs(
  stopEvidenceRef: TaskToPrEvidenceRef,
  leaseRevocationEvidenceRef: TaskToPrEvidenceRef,
  ctx: z.RefinementCtx,
  path: (string | number)[]
): void {
  if (
    stopEvidenceRef.id === leaseRevocationEvidenceRef.id ||
    stopEvidenceRef.digest === leaseRevocationEvidenceRef.digest
  ) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message:
        "Stop and lease-revocation facts require distinct evidence identities and digests",
      path
    });
  }
}

function taskToPrRefFor(role: TaskToPrRefRole) {
  return TaskToPrRefSchema.refine((value) => value.role === role, {
    message: `Reference must use role ${role}`,
    path: ["role"]
  });
}

function sameTaskToPrRef(left: TaskToPrRef, right: TaskToPrRef): boolean {
  return (
    left.role === right.role &&
    left.authority === right.authority &&
    left.id === right.id &&
    left.digest === right.digest &&
    left.redaction === right.redaction
  );
}

function sameTaskToPrCanonicalRefId(left: TaskToPrRef, right: TaskToPrRef): boolean {
  return left.role === right.role && left.authority === right.authority && left.id === right.id;
}

function requireFreshTaskToPrRef(
  prior: TaskToPrRef,
  successor: TaskToPrRef,
  ctx: z.RefinementCtx,
  path: (string | number)[],
  label: string
): void {
  if (sameTaskToPrCanonicalRefId(prior, successor)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `${label} requires a fresh canonical role/authority/id`,
      path
    });
  }
  if (prior.digest === successor.digest) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `${label} requires a fresh canonical digest`,
      path
    });
  }
}

function taskToPrCanonicalRefKey(ref: TaskToPrRef): string {
  return `${ref.role}\u0000${ref.authority}\u0000${ref.id}`;
}

function sameGitObjectId(
  left: z.infer<typeof TaskToPrGitObjectIdSchema>,
  right: z.infer<typeof TaskToPrGitObjectIdSchema>
): boolean {
  return left.algorithm === right.algorithm && left.value === right.value;
}

function sameTaskToPrMergeGuardLineageFacts(
  left: z.infer<typeof TaskToPrMergeGuardSchema>,
  right: z.infer<typeof TaskToPrMergeGuardSchema>
): boolean {
  return (
    sameTaskToPrRef(left.pullRequestRef, right.pullRequestRef) &&
    sameGitObjectId(left.expectedBase, right.expectedBase) &&
    sameGitObjectId(left.expectedHead, right.expectedHead) &&
    JSON.stringify(left.reviewRefs) === JSON.stringify(right.reviewRefs) &&
    JSON.stringify(left.proofBundleRefs) === JSON.stringify(right.proofBundleRefs) &&
    sameTaskToPrRef(left.operatorRef, right.operatorRef) &&
    sameTaskToPrRef(left.operatorRunRef, right.operatorRunRef) &&
    sameTaskToPrRef(left.providerGuardReceiptRef, right.providerGuardReceiptRef) &&
    left.mechanism === right.mechanism
  );
}

export const TaskToPrGitObjectIdSchema = z
  .object({
    algorithm: z.enum(["sha1", "sha256"]),
    value: z.string().regex(/^[a-f0-9]+$/)
  })
  .strict()
  .superRefine((value, ctx) => {
    const requiredLength = value.algorithm === "sha1" ? 40 : 64;
    if (value.value.length !== requiredLength) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${value.algorithm} object ids must contain exactly ${requiredLength} lowercase hex characters`,
        path: ["value"]
      });
    }
  });
export type TaskToPrGitObjectId = z.infer<typeof TaskToPrGitObjectIdSchema>;

export interface TaskToPrBindingV1Input {
  canonicalizationVersion: 1;
  rootRequestRef: TaskToPrRef;
  prGroupRef: TaskToPrRef;
  leafTaskRef: TaskToPrRef;
  repoRef: TaskToPrRef;
  baseHead: TaskToPrGitObjectId;
  frozenScopeDigest: string;
}

export interface TaskToPrBindingV2Input {
  canonicalizationVersion: 2;
  rootRequestRef: TaskToPrRef;
  prGroupRef: TaskToPrRef;
  leafTaskRef: TaskToPrRef;
  repoRef: TaskToPrRef;
  worktreeRef: TaskToPrRef;
  branchRef: TaskToPrRef;
  baseHead: TaskToPrGitObjectId;
  frozenScopeDigest: string;
}

export type TaskToPrBindingInput = TaskToPrBindingV1Input | TaskToPrBindingV2Input;

export function deriveTaskToPrIdentityDigest(input: TaskToPrBindingInput): string {
  if (input.canonicalizationVersion === 1) {
    const legacyCanonicalBinding = JSON.stringify([
      "hasna.task_to_pr_projection.binding.v1",
      input.canonicalizationVersion,
      input.rootRequestRef.id,
      input.rootRequestRef.digest,
      input.prGroupRef.id,
      input.prGroupRef.digest,
      input.leafTaskRef.id,
      input.leafTaskRef.digest,
      input.repoRef.id,
      input.repoRef.digest,
      input.baseHead.algorithm,
      input.baseHead.value,
      input.frozenScopeDigest
    ]);
    return createHash("sha256").update(legacyCanonicalBinding, "utf8").digest("hex");
  }
  const canonicalBinding = JSON.stringify([
    "hasna.task_to_pr_projection.binding.v2",
    input.canonicalizationVersion,
    ...[input.rootRequestRef, input.prGroupRef, input.leafTaskRef, input.repoRef, input.worktreeRef, input.branchRef]
      .flatMap((ref) => [ref.role, ref.authority, ref.id, ref.digest]),
    input.baseHead.algorithm,
    input.baseHead.value,
    input.frozenScopeDigest
  ]);
  return createHash("sha256").update(canonicalBinding, "utf8").digest("hex");
}

export const TaskToPrAttemptSchema = z
  .object({
    ref: taskToPrRefFor("attempt"),
    nonce: TaskToPrAttemptNonceSchema,
    admissionRef: taskToPrRefFor("admission"),
    admissionWriterGenerationRef: taskToPrRefFor("writer_generation"),
    workerActorRef: taskToPrRefFor("worker_actor"),
    workerRef: taskToPrRefFor("worker"),
    runtimeRef: taskToPrRefFor("runtime"),
    writerGenerationRef: taskToPrRefFor("writer_generation"),
    writerLeaseRef: taskToPrRefFor("writer_lease"),
    writerFenceRef: taskToPrRefFor("writer_fence"),
    providerProfileRef: taskToPrRefFor("provider_profile"),
    providerRouteRef: taskToPrRefFor("provider_route")
  })
  .strict();
export type TaskToPrAttempt = z.infer<typeof TaskToPrAttemptSchema>;

export const TaskToPrRepositoryBindingSchema = z
  .object({
    repoRef: taskToPrRefFor("repo"),
    worktreeRef: taskToPrRefFor("worktree"),
    branchRef: taskToPrRefFor("branch"),
    baseHead: TaskToPrGitObjectIdSchema,
    branchHead: TaskToPrGitObjectIdSchema
  })
  .strict();
export type TaskToPrRepositoryBinding = z.infer<typeof TaskToPrRepositoryBindingSchema>;

export const TaskToPrEventCursorSchema = z
  .object({
    streamRef: taskToPrRefFor("event_stream"),
    replayCursorRef: taskToPrRefFor("replay_cursor"),
    sequence: z.number().int().safe().nonnegative(),
    prefixDigest: LowerSha256DigestSchema
  })
  .strict();
export type TaskToPrEventCursor = z.infer<typeof TaskToPrEventCursorSchema>;

export const TaskToPrHandoffSchema = z
  .object({
    ref: taskToPrRefFor("handoff"),
    previousAttemptRef: taskToPrRefFor("attempt"),
    nextAttemptRef: taskToPrRefFor("attempt"),
    previousWriterGenerationRef: taskToPrRefFor("writer_generation"),
    nextWriterGenerationRef: taskToPrRefFor("writer_generation"),
    stoppedWorkRunRef: taskToPrRefFor("work_run"),
    stopEvidenceRef: TaskToPrEvidenceRefSchema,
    leaseRevocationEvidenceRef: TaskToPrEvidenceRefSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    requireFreshTaskToPrRef(
      value.previousAttemptRef,
      value.nextAttemptRef,
      ctx,
      ["nextAttemptRef"],
      "Handoff attempt rotation"
    );
    requireFreshTaskToPrRef(
      value.previousWriterGenerationRef,
      value.nextWriterGenerationRef,
      ctx,
      ["nextWriterGenerationRef"],
      "Handoff writer-generation rotation"
    );
    requireDistinctTaskToPrEvidenceRefs(
      value.stopEvidenceRef,
      value.leaseRevocationEvidenceRef,
      ctx,
      ["leaseRevocationEvidenceRef"]
    );
  });
export type TaskToPrHandoff = z.infer<typeof TaskToPrHandoffSchema>;

export const TaskToPrReviewBindingSchema = z
  .object({
    ref: taskToPrRefFor("review"),
    pullRequestRef: taskToPrRefFor("pull_request"),
    base: TaskToPrGitObjectIdSchema,
    head: TaskToPrGitObjectIdSchema,
    reviewerRef: taskToPrRefFor("reviewer"),
    reviewRunRef: taskToPrRefFor("review_run"),
    proofBundleRef: taskToPrRefFor("proof_bundle"),
    verdict: z.enum(["approved", "changes_requested", "blocked"]),
    reviewedAt: TimestampSchema
  })
  .strict();
export type TaskToPrReviewBinding = z.infer<typeof TaskToPrReviewBindingSchema>;

export const TaskToPrExactHeadBindingSchema = z
  .object({
    pullRequestRef: taskToPrRefFor("pull_request"),
    remoteBranchRef: taskToPrRefFor("branch"),
    expectedBase: TaskToPrGitObjectIdSchema,
    providerPullRequestBase: TaskToPrGitObjectIdSchema,
    localHead: TaskToPrGitObjectIdSchema,
    remoteHead: TaskToPrGitObjectIdSchema,
    providerPullRequestHead: TaskToPrGitObjectIdSchema,
    equalityProofRef: taskToPrRefFor("proof_bundle"),
    ciProofBundleRefs: z.array(taskToPrRefFor("proof_bundle")).min(1),
    verifiedAt: TimestampSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    if (!sameGitObjectId(value.expectedBase, value.providerPullRequestBase)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Expected and provider-observed pull-request bases must be exactly equal",
        path: ["providerPullRequestBase"]
      });
    }
    if (
      !sameGitObjectId(value.localHead, value.remoteHead) ||
      !sameGitObjectId(value.localHead, value.providerPullRequestHead)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Local, remote, and provider pull-request heads must be exactly equal",
        path: ["providerPullRequestHead"]
      });
    }
    const proofKeys = value.ciProofBundleRefs.map(taskToPrCanonicalRefKey);
    if (new Set(proofKeys).size !== proofKeys.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "CI proof bundle refs must have unique canonical identities",
        path: ["ciProofBundleRefs"]
      });
    }
    const proofDigests = value.ciProofBundleRefs.map((ref) => ref.digest);
    if (new Set(proofDigests).size !== proofDigests.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "CI proof bundle refs must have unique canonical digests",
        path: ["ciProofBundleRefs"]
      });
    }
    if (value.ciProofBundleRefs.some((ref) => sameTaskToPrCanonicalRefId(ref, value.equalityProofRef))) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Head-equality and CI proof refs must have distinct canonical identities",
        path: ["ciProofBundleRefs"]
      });
    }
    if (value.ciProofBundleRefs.some((ref) => ref.digest === value.equalityProofRef.digest)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Head-equality and CI proof refs must have distinct canonical digests",
        path: ["ciProofBundleRefs"]
      });
    }
  });
export type TaskToPrExactHeadBinding = z.infer<typeof TaskToPrExactHeadBindingSchema>;

export const TaskToPrRepairStateSchema = z
  .object({
    ref: taskToPrRefFor("repair_cycle"),
    cycle: z.number().int().min(0).max(2),
    cap: z.literal(2),
    exhausted: z.boolean(),
    latestRepairRef: taskToPrRefFor("repair_cycle").optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.exhausted !== (value.cycle === value.cap)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Repair exhaustion must equal the cumulative cycle cap",
        path: ["exhausted"]
      });
    }
    if (value.cycle === 0 && value.latestRepairRef) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cycle zero cannot reference a repair",
        path: ["latestRepairRef"]
      });
    }
    if (value.cycle > 0 && !value.latestRepairRef) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Non-zero repair state requires the latest immutable repair ref",
        path: ["latestRepairRef"]
      });
    }
    if (value.latestRepairRef && sameTaskToPrCanonicalRefId(value.ref, value.latestRepairRef)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Repair-state and latest-repair refs must be distinct canonical records",
        path: ["latestRepairRef"]
      });
    }
    if (value.latestRepairRef && value.ref.digest === value.latestRepairRef.digest) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Repair-state and latest-repair refs must have distinct canonical digests",
        path: ["latestRepairRef"]
      });
    }
  });
export type TaskToPrRepairState = z.infer<typeof TaskToPrRepairStateSchema>;

export const TaskToPrMergeGuardSchema = z
  .object({
    ref: taskToPrRefFor("merge_guard"),
    pullRequestRef: taskToPrRefFor("pull_request"),
    expectedBase: TaskToPrGitObjectIdSchema,
    expectedHead: TaskToPrGitObjectIdSchema,
    reviewRefs: z.array(taskToPrRefFor("review")).min(1),
    proofBundleRefs: z.array(taskToPrRefFor("proof_bundle")).min(1),
    operatorRef: taskToPrRefFor("merge_operator"),
    operatorRunRef: taskToPrRefFor("merge_operator_run"),
    providerGuardReceiptRef: taskToPrRefFor("merge_guard_receipt"),
    mechanism: z.enum(["compare_and_swap", "queue_expected_head"]),
    decision: z.enum(["eligible", "denied", "consumed", "revoked"]),
    evaluatedAt: TimestampSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    const uniqueReviews = new Set(value.reviewRefs.map((ref) => ref.id));
    if (uniqueReviews.size !== value.reviewRefs.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Merge guard review refs must be unique",
        path: ["reviewRefs"]
      });
    }
    const uniqueProofs = new Set(value.proofBundleRefs.map(taskToPrCanonicalRefKey));
    if (uniqueProofs.size !== value.proofBundleRefs.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Merge guard proof refs must have unique canonical identities",
        path: ["proofBundleRefs"]
      });
    }
    const uniqueProofDigests = new Set(value.proofBundleRefs.map((ref) => ref.digest));
    if (uniqueProofDigests.size !== value.proofBundleRefs.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Merge guard proof refs must have unique canonical digests",
        path: ["proofBundleRefs"]
      });
    }
  });
export type TaskToPrMergeGuard = z.infer<typeof TaskToPrMergeGuardSchema>;

export const TaskToPrMergeOutcomeSchema = z
  .object({
    ref: taskToPrRefFor("merge_outcome"),
    guardRef: taskToPrRefFor("merge_guard"),
    pullRequestRef: taskToPrRefFor("pull_request"),
    expectedBase: TaskToPrGitObjectIdSchema,
    observedBase: TaskToPrGitObjectIdSchema,
    expectedHead: TaskToPrGitObjectIdSchema,
    observedHead: TaskToPrGitObjectIdSchema,
    status: z.enum(["merged", "closed_unmerged", "refused", "head_drift", "base_drift"]),
    mergeCommitRef: taskToPrRefFor("commit").optional(),
    finishedAt: TimestampSchema,
    evidenceRefs: z.array(TaskToPrEvidenceRefSchema).min(1)
  })
  .strict()
  .superRefine((value, ctx) => {
    const baseMatches = sameGitObjectId(value.expectedBase, value.observedBase);
    const headMatches = sameGitObjectId(value.expectedHead, value.observedHead);
    if (value.status === "merged") {
      if (!baseMatches || !headMatches) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merged outcomes require observed base and head to equal the guarded values",
          path: [!baseMatches ? "observedBase" : "observedHead"]
        });
      }
      if (!value.mergeCommitRef) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merged outcomes require an immutable merge commit ref",
          path: ["mergeCommitRef"]
        });
      }
    } else if (value.mergeCommitRef) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Unmerged outcomes cannot claim a merge commit",
        path: ["mergeCommitRef"]
      });
    }
    if (value.status === "head_drift" && headMatches) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Head-drift outcomes require distinct expected and observed heads",
        path: ["observedHead"]
      });
    }
    if (value.status === "head_drift" && !baseMatches) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Head-drift outcomes cannot also carry an unclassified base drift",
        path: ["observedBase"]
      });
    }
    if (value.status === "base_drift" && baseMatches) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Base-drift outcomes require distinct expected and observed bases",
        path: ["observedBase"]
      });
    }
    if (value.status === "base_drift" && !headMatches) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Base-drift outcomes cannot also carry an unclassified head drift",
        path: ["observedHead"]
      });
    }
    if (!headMatches && value.status !== "head_drift") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Only a head_drift outcome may record an observed head that differs from the expected head",
        path: ["observedHead"]
      });
    }
    if (!baseMatches && value.status !== "base_drift") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "Only a base_drift outcome may record an observed base that differs from the expected base",
        path: ["observedBase"]
      });
    }
  });
export type TaskToPrMergeOutcome = z.infer<typeof TaskToPrMergeOutcomeSchema>;

export const TaskToPrMergeStateSchema = z
  .object({
    guard: TaskToPrMergeGuardSchema,
    outcome: TaskToPrMergeOutcomeSchema.optional()
  })
  .strict();
export type TaskToPrMergeState = z.infer<typeof TaskToPrMergeStateSchema>;

export const TaskToPrRecoverySchema = z
  .object({
    ref: taskToPrRefFor("recovery"),
    priorAttemptRef: taskToPrRefFor("attempt"),
    priorWriterGenerationRef: taskToPrRefFor("writer_generation"),
    priorWorkRunRef: taskToPrRefFor("work_run"),
    successorAttemptNonce: TaskToPrAttemptNonceSchema,
    successorWriterGenerationRef: taskToPrRefFor("writer_generation"),
    preservedStateRefs: z.array(TaskToPrRefSchema).min(1),
    stopEvidenceRef: TaskToPrEvidenceRefSchema,
    leaseRevocationEvidenceRef: TaskToPrEvidenceRefSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    requireFreshTaskToPrRef(
      value.priorWriterGenerationRef,
      value.successorWriterGenerationRef,
      ctx,
      ["successorWriterGenerationRef"],
      "Recovery writer-generation rotation"
    );
    requireDistinctTaskToPrEvidenceRefs(
      value.stopEvidenceRef,
      value.leaseRevocationEvidenceRef,
      ctx,
      ["leaseRevocationEvidenceRef"]
    );
  });
export type TaskToPrRecovery = z.infer<typeof TaskToPrRecoverySchema>;

export const TaskToPrCancellationSchema = z
  .object({
    ref: taskToPrRefFor("cancellation"),
    cancelledAttemptRef: taskToPrRefFor("attempt"),
    preservedStateRefs: z.array(TaskToPrRefSchema).min(1),
    evidenceRefs: z.array(TaskToPrEvidenceRefSchema).min(1)
  })
  .strict();
export type TaskToPrCancellation = z.infer<typeof TaskToPrCancellationSchema>;

export const TaskToPrCleanupEligibilitySchema = z
  .object({
    ref: taskToPrRefFor("cleanup_eligibility"),
    status: z.enum(["not_ready", "preserved", "blocked", "eligible"]),
    targetWorktreeRef: taskToPrRefFor("worktree"),
    eventCursorRef: taskToPrRefFor("replay_cursor"),
    terminalDispositionRef: taskToPrRefFor("terminal_disposition"),
    writerLeaseRef: taskToPrRefFor("writer_lease"),
    leaseRevocationEvidenceRef: TaskToPrEvidenceRefSchema,
    consumedEventEvidenceRef: TaskToPrEvidenceRefSchema,
    evaluatedAt: TimestampSchema,
    evidenceRefs: z.array(TaskToPrEvidenceRefSchema).min(1)
  })
  .strict()
  .superRefine((value, ctx) => {
    if (
      value.leaseRevocationEvidenceRef.id === value.consumedEventEvidenceRef.id ||
      value.leaseRevocationEvidenceRef.digest === value.consumedEventEvidenceRef.digest
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "Cleanup lease-revocation and consumed-event facts require distinct evidence identities and digests",
        path: ["consumedEventEvidenceRef"]
      });
    }
  });
export type TaskToPrCleanupEligibility = z.infer<typeof TaskToPrCleanupEligibilitySchema>;

export const TaskToPrCleanupOutcomeSchema = z
  .object({
    ref: taskToPrRefFor("cleanup_outcome"),
    eligibilityRef: taskToPrRefFor("cleanup_eligibility"),
    targetWorktreeRef: taskToPrRefFor("worktree"),
    status: z.enum(["preserved", "deleted", "failed", "skipped"]),
    finishedAt: TimestampSchema,
    evidenceRefs: z.array(TaskToPrEvidenceRefSchema).min(1)
  })
  .strict();
export type TaskToPrCleanupOutcome = z.infer<typeof TaskToPrCleanupOutcomeSchema>;

export const TaskToPrCleanupStateSchema = z
  .object({
    eligibility: TaskToPrCleanupEligibilitySchema,
    outcome: TaskToPrCleanupOutcomeSchema.optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (
      value.outcome &&
      !sameTaskToPrRef(value.outcome.eligibilityRef, value.eligibility.ref)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cleanup outcomes must bind the exact eligibility decision",
        path: ["outcome", "eligibilityRef"]
      });
    }
    if (
      value.outcome &&
      !sameTaskToPrRef(value.outcome.targetWorktreeRef, value.eligibility.targetWorktreeRef)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cleanup eligibility and outcome must bind the same target worktree",
        path: ["outcome", "targetWorktreeRef"]
      });
    }
    if (value.outcome?.status === "deleted" && value.eligibility.status !== "eligible") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Deletion requires an eligible cleanup decision",
        path: ["outcome", "status"]
      });
    }
  });
export type TaskToPrCleanupState = z.infer<typeof TaskToPrCleanupStateSchema>;

export const TaskToPrRollbackSchema = z
  .object({
    plan: z
      .object({
        ref: taskToPrRefFor("rollback_plan"),
        targetRef: z.union([taskToPrRefFor("commit"), taskToPrRefFor("branch")]),
        createdAt: TimestampSchema
      })
      .strict(),
    outcome: z
      .object({
        ref: taskToPrRefFor("rollback_outcome"),
        planRef: taskToPrRefFor("rollback_plan"),
        targetRef: z.union([taskToPrRefFor("commit"), taskToPrRefFor("branch")]),
        status: z.enum(["not_run", "succeeded", "failed", "cancelled"]),
        finishedAt: TimestampSchema,
        evidenceRefs: z.array(TaskToPrEvidenceRefSchema).min(1)
      })
      .strict()
      .optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.outcome && !sameTaskToPrRef(value.outcome.planRef, value.plan.ref)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Rollback outcomes must bind the exact rollback plan",
        path: ["outcome", "planRef"]
      });
    }
    if (value.outcome && !sameTaskToPrRef(value.outcome.targetRef, value.plan.targetRef)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Rollback outcomes must bind the exact rollback target",
        path: ["outcome", "targetRef"]
      });
    }
    if (value.outcome && Date.parse(value.outcome.finishedAt) < Date.parse(value.plan.createdAt)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Rollback outcomes cannot finish before their plan was created",
        path: ["outcome", "finishedAt"]
      });
    }
  });
export type TaskToPrRollback = z.infer<typeof TaskToPrRollbackSchema>;

export type TaskToPrProvenanceEntry =
  | {
      category:
        | "work_run"
        | "attempt"
        | "admission"
        | "worker_actor"
        | "worker_assignment"
        | "runtime"
        | "writer_generation"
        | "writer_lease"
        | "writer_fence"
        | "provider_profile"
        | "provider_route"
        | "replay_cursor"
        | "repair_state"
        | "latest_repair"
        | "handoff"
        | "recovery"
        | "merge_guard"
        | "cleanup_eligibility"
        | "rollback_plan"
        | "terminal_disposition";
      ref: TaskToPrRef;
    }
  | {
      category:
        | "equality_proof"
        | "ci_proof"
        | "review_proof"
        | "review_record"
        | "review_run"
        | "provider_guard_receipt";
      ref: TaskToPrRef;
      base: TaskToPrGitObjectId;
      head: TaskToPrGitObjectId;
    }
  | {
      category: "projection_id";
      projectionId: string;
    }
  | {
      category: "attempt_nonce";
      nonce: string;
    }
  | {
      category: "replay_prefix";
      sequence: number;
      prefixDigest: string;
    };

export const TaskToPrProvenanceEntrySchema: z.ZodType<TaskToPrProvenanceEntry> = z.discriminatedUnion("category", [
  z
    .object({
      category: z.literal("projection_id"),
      projectionId: TaskToPrProjectionIdSchema
    })
    .strict(),
  z
    .object({
      category: z.literal("work_run"),
      ref: taskToPrRefFor("work_run")
    })
    .strict(),
  z
    .object({
      category: z.literal("attempt"),
      ref: taskToPrRefFor("attempt")
    })
    .strict(),
  z
    .object({
      category: z.literal("admission"),
      ref: taskToPrRefFor("admission")
    })
    .strict(),
  z
    .object({
      category: z.literal("worker_actor"),
      ref: taskToPrRefFor("worker_actor")
    })
    .strict(),
  z
    .object({
      category: z.literal("worker_assignment"),
      ref: taskToPrRefFor("worker")
    })
    .strict(),
  z
    .object({
      category: z.literal("attempt_nonce"),
      nonce: TaskToPrAttemptNonceSchema
    })
    .strict(),
  z
    .object({
      category: z.literal("runtime"),
      ref: taskToPrRefFor("runtime")
    })
    .strict(),
  z
    .object({
      category: z.literal("writer_generation"),
      ref: taskToPrRefFor("writer_generation")
    })
    .strict(),
  z
    .object({
      category: z.literal("writer_lease"),
      ref: taskToPrRefFor("writer_lease")
    })
    .strict(),
  z
    .object({
      category: z.literal("writer_fence"),
      ref: taskToPrRefFor("writer_fence")
    })
    .strict(),
  z
    .object({
      category: z.literal("provider_profile"),
      ref: taskToPrRefFor("provider_profile")
    })
    .strict(),
  z
    .object({
      category: z.literal("provider_route"),
      ref: taskToPrRefFor("provider_route")
    })
    .strict(),
  z
    .object({
      category: z.literal("replay_cursor"),
      ref: taskToPrRefFor("replay_cursor")
    })
    .strict(),
  z
    .object({
      category: z.literal("replay_prefix"),
      sequence: z.number().int().safe().nonnegative(),
      prefixDigest: LowerSha256DigestSchema
    })
    .strict(),
  z
    .object({
      category: z.literal("repair_state"),
      ref: taskToPrRefFor("repair_cycle")
    })
    .strict(),
  z
    .object({
      category: z.literal("latest_repair"),
      ref: taskToPrRefFor("repair_cycle")
    })
    .strict(),
  z
    .object({
      category: z.literal("handoff"),
      ref: taskToPrRefFor("handoff")
    })
    .strict(),
  z
    .object({
      category: z.literal("recovery"),
      ref: taskToPrRefFor("recovery")
    })
    .strict(),
  z
    .object({
      category: z.literal("merge_guard"),
      ref: taskToPrRefFor("merge_guard")
    })
    .strict(),
  z
    .object({
      category: z.literal("cleanup_eligibility"),
      ref: taskToPrRefFor("cleanup_eligibility")
    })
    .strict(),
  z
    .object({
      category: z.literal("rollback_plan"),
      ref: taskToPrRefFor("rollback_plan")
    })
    .strict(),
  z
    .object({
      category: z.literal("terminal_disposition"),
      ref: taskToPrRefFor("terminal_disposition")
    })
    .strict(),
  z
    .object({
      category: z.literal("equality_proof"),
      ref: taskToPrRefFor("proof_bundle"),
      base: TaskToPrGitObjectIdSchema,
      head: TaskToPrGitObjectIdSchema
    })
    .strict(),
  z
    .object({
      category: z.literal("ci_proof"),
      ref: taskToPrRefFor("proof_bundle"),
      base: TaskToPrGitObjectIdSchema,
      head: TaskToPrGitObjectIdSchema
    })
    .strict(),
  z
    .object({
      category: z.literal("review_proof"),
      ref: taskToPrRefFor("proof_bundle"),
      base: TaskToPrGitObjectIdSchema,
      head: TaskToPrGitObjectIdSchema
    })
    .strict(),
  z
    .object({
      category: z.literal("review_record"),
      ref: taskToPrRefFor("review"),
      base: TaskToPrGitObjectIdSchema,
      head: TaskToPrGitObjectIdSchema
    })
    .strict(),
  z
    .object({
      category: z.literal("review_run"),
      ref: taskToPrRefFor("review_run"),
      base: TaskToPrGitObjectIdSchema,
      head: TaskToPrGitObjectIdSchema
    })
    .strict(),
  z
    .object({
      category: z.literal("provider_guard_receipt"),
      ref: taskToPrRefFor("merge_guard_receipt"),
      base: TaskToPrGitObjectIdSchema,
      head: TaskToPrGitObjectIdSchema
    })
    .strict()
]);

type TaskToPrProvenanceProjectionView = {
  id: string;
  workRunRef: TaskToPrRef;
  attempt: TaskToPrAttempt;
  events: TaskToPrEventCursor;
  repair: TaskToPrRepairState;
  handoff?: TaskToPrHandoff | undefined;
  recovery?: TaskToPrRecovery | undefined;
  exactHead?: TaskToPrExactHeadBinding | undefined;
  reviews: TaskToPrReviewBinding[];
  merge?: TaskToPrMergeState | undefined;
  cleanup?: TaskToPrCleanupState | undefined;
  rollback?: TaskToPrRollback | undefined;
  terminalDispositionRef?: TaskToPrRef | undefined;
};

function taskToPrActiveProvenanceEntries(
  projection: TaskToPrProvenanceProjectionView
): TaskToPrProvenanceEntry[] {
  return [
    {
      category: "projection_id" as const,
      projectionId: projection.id
    },
    {
      category: "work_run" as const,
      ref: projection.workRunRef
    },
    {
      category: "attempt" as const,
      ref: projection.attempt.ref
    },
    {
      category: "admission" as const,
      ref: projection.attempt.admissionRef
    },
    {
      category: "worker_actor" as const,
      ref: projection.attempt.workerActorRef
    },
    {
      category: "worker_assignment" as const,
      ref: projection.attempt.workerRef
    },
    {
      category: "attempt_nonce" as const,
      nonce: projection.attempt.nonce
    },
    {
      category: "runtime" as const,
      ref: projection.attempt.runtimeRef
    },
    {
      category: "writer_generation" as const,
      ref: projection.attempt.writerGenerationRef
    },
    {
      category: "writer_lease" as const,
      ref: projection.attempt.writerLeaseRef
    },
    {
      category: "writer_fence" as const,
      ref: projection.attempt.writerFenceRef
    },
    {
      category: "provider_profile" as const,
      ref: projection.attempt.providerProfileRef
    },
    {
      category: "provider_route" as const,
      ref: projection.attempt.providerRouteRef
    },
    {
      category: "replay_cursor" as const,
      ref: projection.events.replayCursorRef
    },
    {
      category: "replay_prefix" as const,
      sequence: projection.events.sequence,
      prefixDigest: projection.events.prefixDigest
    },
    {
      category: "repair_state" as const,
      ref: projection.repair.ref
    },
    ...(projection.repair.latestRepairRef
      ? [
          {
            category: "latest_repair" as const,
            ref: projection.repair.latestRepairRef
          }
        ]
      : []),
    ...(projection.handoff
      ? [{ category: "handoff" as const, ref: projection.handoff.ref }]
      : []),
    ...(projection.recovery
      ? [{ category: "recovery" as const, ref: projection.recovery.ref }]
      : []),
    ...(projection.exactHead
      ? [
          {
            category: "equality_proof" as const,
            ref: projection.exactHead.equalityProofRef,
            base: projection.exactHead.expectedBase,
            head: projection.exactHead.localHead
          },
          ...projection.exactHead.ciProofBundleRefs.map((ref) => ({
            category: "ci_proof" as const,
            ref,
            base: projection.exactHead!.expectedBase,
            head: projection.exactHead!.localHead
          }))
        ]
      : []),
    ...projection.reviews.flatMap((review) => [
      {
        category: "review_proof" as const,
        ref: review.proofBundleRef,
        base: review.base,
        head: review.head
      },
      {
        category: "review_record" as const,
        ref: review.ref,
        base: review.base,
        head: review.head
      },
      {
        category: "review_run" as const,
        ref: review.reviewRunRef,
        base: review.base,
        head: review.head
      }
    ]),
    ...(projection.merge
      ? [
          {
            category: "merge_guard" as const,
            ref: projection.merge.guard.ref
          },
          {
            category: "provider_guard_receipt" as const,
            ref: projection.merge.guard.providerGuardReceiptRef,
            base: projection.merge.guard.expectedBase,
            head: projection.merge.guard.expectedHead
          }
        ]
      : []),
    ...(projection.cleanup
      ? [
          {
            category: "cleanup_eligibility" as const,
            ref: projection.cleanup.eligibility.ref
          }
        ]
      : []),
    ...(projection.rollback
      ? [
          {
            category: "rollback_plan" as const,
            ref: projection.rollback.plan.ref
          }
        ]
      : []),
    ...(projection.terminalDispositionRef
      ? [
          {
            category: "terminal_disposition" as const,
            ref: projection.terminalDispositionRef
          }
        ]
      : [])
  ];
}

function sameTaskToPrProvenanceEntry(
  left: TaskToPrProvenanceEntry,
  right: TaskToPrProvenanceEntry
): boolean {
  if (left.category !== right.category) {
    return false;
  }
  if (left.category === "projection_id" && right.category === "projection_id") {
    return left.projectionId === right.projectionId;
  }
  if (left.category === "attempt_nonce" && right.category === "attempt_nonce") {
    return left.nonce === right.nonce;
  }
  if (left.category === "replay_prefix" && right.category === "replay_prefix") {
    return left.sequence === right.sequence && left.prefixDigest === right.prefixDigest;
  }
  if (!("ref" in left) || !("ref" in right)) {
    return false;
  }
  return (
    sameTaskToPrRef(left.ref, right.ref) &&
    (("head" in left &&
      "head" in right &&
      "base" in left &&
      "base" in right &&
      sameGitObjectId(left.base, right.base) &&
      sameGitObjectId(left.head, right.head)) ||
      (!("head" in left) && !("head" in right) && !("base" in left) && !("base" in right)))
  );
}

export const TASK_TO_PR_V1_ADAPTER_EXTENSION_SCHEMA_PREFIX =
  "hasna.task_to_pr_adapter_extension.";

export const TaskToPrAdapterExtensionSchema = z
  .object({
    mode: z.enum(["local", "cloud"]),
    schema: SchemaIdSchema,
    ref: taskToPrRefFor("adapter_extension"),
    digest: LowerSha256DigestSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    if (!value.schema.startsWith(TASK_TO_PR_V1_ADAPTER_EXTENSION_SCHEMA_PREFIX)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "Adapter extension schema ids must use the permanently reserved task-to-PR adapter-extension namespace",
        path: ["schema"]
      });
    }
  });
export type TaskToPrAdapterExtension = z.infer<typeof TaskToPrAdapterExtensionSchema>;

export const TaskToPrProjectionStateSchema = z.enum([
  "admitted",
  "running",
  "handed_off",
  "reviewing",
  "repairing",
  "merge_ready",
  "merged",
  "closed_unmerged",
  "failed",
  "blocked",
  "cancelled",
  "recovering",
  "cleanup_complete",
  "rolled_back"
]);
export type TaskToPrProjectionState = z.infer<typeof TaskToPrProjectionStateSchema>;

const TaskToPrStatesWithoutReviewAuthority = new Set<TaskToPrProjectionState>([
  "admitted",
  "running",
  "handed_off"
]);
const TaskToPrTerminalStates = new Set<TaskToPrProjectionState>([
  "merged",
  "closed_unmerged",
  "failed",
  "blocked",
  "cancelled",
  "cleanup_complete",
  "rolled_back"
]);
const TASK_TO_PR_STATE_MERGE_MATRIX: Record<
  TaskToPrProjectionState,
  ReadonlySet<string>
> = {
  admitted: new Set(["absent", "denied:none", "revoked:none"]),
  running: new Set(["absent", "denied:none", "revoked:none"]),
  handed_off: new Set(["absent", "denied:none", "revoked:none"]),
  reviewing: new Set(["absent", "denied:none", "revoked:none"]),
  repairing: new Set(["absent", "denied:none", "revoked:none"]),
  merge_ready: new Set(["eligible:none"]),
  merged: new Set(["consumed:merged"]),
  closed_unmerged: new Set([
    "consumed:closed_unmerged",
    "consumed:refused",
    "consumed:head_drift",
    "consumed:base_drift"
  ]),
  failed: new Set(["absent", "revoked:none"]),
  blocked: new Set(["absent", "revoked:none"]),
  cancelled: new Set(["absent", "revoked:none"]),
  recovering: new Set(["absent", "denied:none", "revoked:none"]),
  cleanup_complete: new Set([
    "absent",
    "revoked:none",
    "consumed:merged",
    "consumed:closed_unmerged",
    "consumed:refused",
    "consumed:head_drift",
    "consumed:base_drift"
  ]),
  rolled_back: new Set(["consumed:merged"])
};

export const TaskToPrProjectionSchema = z
  .object({
    schema: z.literal(SCHEMA_IDS.taskToPrProjection),
    id: TaskToPrProjectionIdSchema,
    createdAt: TimestampSchema,
    canonicalizationVersion: z.union([z.literal(1), z.literal(2)]),
    identityDigest: LowerSha256DigestSchema,
    frozenScopeDigest: LowerSha256DigestSchema,
    state: TaskToPrProjectionStateSchema,
    workRunRef: taskToPrRefFor("work_run"),
    rootRequestRef: taskToPrRefFor("root_request"),
    prGroupRef: taskToPrRefFor("pr_group"),
    leafTaskRef: taskToPrRefFor("leaf_task"),
    attempt: TaskToPrAttemptSchema,
    repository: TaskToPrRepositoryBindingSchema,
    events: TaskToPrEventCursorSchema,
    openLoopsInvocationRef: taskToPrRefFor("openloops_invocation").optional(),
    pullRequestRef: taskToPrRefFor("pull_request").optional(),
    exactHead: TaskToPrExactHeadBindingSchema.optional(),
    handoff: TaskToPrHandoffSchema.optional(),
    reviews: z.array(TaskToPrReviewBindingSchema).default([]),
    repair: TaskToPrRepairStateSchema,
    merge: TaskToPrMergeStateSchema.optional(),
    recovery: TaskToPrRecoverySchema.optional(),
    cancellation: TaskToPrCancellationSchema.optional(),
    cleanup: TaskToPrCleanupStateSchema.optional(),
    rollback: TaskToPrRollbackSchema.optional(),
    terminalDispositionRef: taskToPrRefFor("terminal_disposition").optional(),
    provenanceLedger: z.array(TaskToPrProvenanceEntrySchema),
    adapterExtensions: z.array(TaskToPrAdapterExtensionSchema).default([]),
    evidenceRefs: z.array(TaskToPrEvidenceRefSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    const derivedIdentityDigest =
      value.canonicalizationVersion === 1
        ? deriveTaskToPrIdentityDigest({
            canonicalizationVersion: 1,
            rootRequestRef: value.rootRequestRef,
            prGroupRef: value.prGroupRef,
            leafTaskRef: value.leafTaskRef,
            repoRef: value.repository.repoRef,
            baseHead: value.repository.baseHead,
            frozenScopeDigest: value.frozenScopeDigest
          })
        : deriveTaskToPrIdentityDigest({
            canonicalizationVersion: 2,
            rootRequestRef: value.rootRequestRef,
            prGroupRef: value.prGroupRef,
            leafTaskRef: value.leafTaskRef,
            repoRef: value.repository.repoRef,
            worktreeRef: value.repository.worktreeRef,
            branchRef: value.repository.branchRef,
            baseHead: value.repository.baseHead,
            frozenScopeDigest: value.frozenScopeDigest
          });
    if (value.identityDigest !== derivedIdentityDigest) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "identityDigest must equal the selected v1 compatibility or v2 branch/worktree-bound canonical identity digest",
        path: ["identityDigest"]
      });
    }
    const provenanceIds = new Set<string>();
    const provenanceDigests = new Set<string>();
    const provenanceProjectionIds = new Set<string>();
    const provenanceAttemptNonces = new Set<string>();
    const provenanceReplayPrefixes = new Set<string>();
    const provenanceReplaySequences = new Set<number>();
    for (const [index, entry] of value.provenanceLedger.entries()) {
      if ("ref" in entry) {
        if (provenanceIds.has(entry.ref.id)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Provenance entries cannot reuse a canonical owner id across categories or generations",
            path: ["provenanceLedger", index, "ref", "id"]
          });
        }
        provenanceIds.add(entry.ref.id);
        if (provenanceDigests.has(entry.ref.digest)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Provenance entries cannot reuse a canonical digest across categories or generations",
            path: ["provenanceLedger", index, "ref", "digest"]
          });
        }
        provenanceDigests.add(entry.ref.digest);
        continue;
      }
      if (entry.category === "projection_id") {
        if (provenanceProjectionIds.has(entry.projectionId)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Projection identity provenance tombstones must be globally unique",
            path: ["provenanceLedger", index, "projectionId"]
          });
        }
        provenanceProjectionIds.add(entry.projectionId);
        continue;
      }
      if (entry.category === "attempt_nonce") {
        if (provenanceAttemptNonces.has(entry.nonce)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Attempt nonce provenance tombstones must be globally unique",
            path: ["provenanceLedger", index, "nonce"]
          });
        }
        provenanceAttemptNonces.add(entry.nonce);
        continue;
      }
      if (provenanceReplayPrefixes.has(entry.prefixDigest)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Replay prefix provenance tombstones must be globally unique",
          path: ["provenanceLedger", index, "prefixDigest"]
        });
      }
      provenanceReplayPrefixes.add(entry.prefixDigest);
      if (provenanceReplaySequences.has(entry.sequence)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Replay prefix provenance entries must bind globally unique replay sequences",
          path: ["provenanceLedger", index, "sequence"]
        });
      }
      provenanceReplaySequences.add(entry.sequence);
    }
    for (const activeEntry of taskToPrActiveProvenanceEntries(value)) {
      if (!value.provenanceLedger.some((entry) => sameTaskToPrProvenanceEntry(entry, activeEntry))) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `The active ${activeEntry.category} identity must be represented exactly in the monotonic provenance ledger`,
          path: ["provenanceLedger"]
        });
      }
    }
    const requiredCanonicalPreservationRefs = [
      value.rootRequestRef,
      value.prGroupRef,
      value.leafTaskRef,
      value.repository.repoRef,
      value.repository.worktreeRef,
      value.repository.branchRef,
      value.events.streamRef,
      ...(value.pullRequestRef ? [value.pullRequestRef] : [])
    ];
    const requirePreservedRefs = (
      preservedStateRefs: TaskToPrRef[],
      requiredRefs: TaskToPrRef[],
      path: (string | number)[],
      label: string
    ) => {
      const requiredRoles = new Set(requiredRefs.map((requiredRef) => requiredRef.role));
      const seenRoles = new Set<TaskToPrRefRole>();
      for (const [index, preservedRef] of preservedStateRefs.entries()) {
        if (!requiredRoles.has(preservedRef.role)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `${label} cannot preserve an unrecognized ${preservedRef.role} role`,
            path: [...path, index]
          });
        }
        if (seenRoles.has(preservedRef.role)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `${label} must preserve exactly one canonical ref per role`,
            path: [...path, index]
          });
        }
        seenRoles.add(preservedRef.role);
      }
      if (preservedStateRefs.length !== requiredRefs.length) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${label} preservation refs must exactly equal the required canonical role set`,
          path
        });
      }
      for (const requiredRef of requiredRefs) {
        if (!preservedStateRefs.some((preservedRef) => sameTaskToPrRef(preservedRef, requiredRef))) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `${label} must preserve ${requiredRef.role}`,
            path
          });
        }
      }
    };
    if (value.handoff && !sameTaskToPrRef(value.handoff.nextWriterGenerationRef, value.attempt.writerGenerationRef)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Handoff next generation must be the current attempt writer generation",
        path: ["handoff", "nextWriterGenerationRef"]
      });
    }
    if (value.handoff && !sameTaskToPrRef(value.handoff.nextAttemptRef, value.attempt.ref)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Handoff next attempt must be the current attempt",
        path: ["handoff", "nextAttemptRef"]
      });
    }
    if (value.handoff) {
      requireFreshTaskToPrRef(
        value.handoff.stoppedWorkRunRef,
        value.workRunRef,
        ctx,
        ["handoff", "stoppedWorkRunRef"],
        "Handoff WorkRun rotation"
      );
    }
    if (value.recovery) {
      if (value.recovery.successorAttemptNonce !== value.attempt.nonce) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Recovery successor nonce must equal the current attempt nonce",
          path: ["recovery", "successorAttemptNonce"]
        });
      }
      if (!sameTaskToPrRef(value.recovery.successorWriterGenerationRef, value.attempt.writerGenerationRef)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Recovery successor generation must equal the current writer generation",
          path: ["recovery", "successorWriterGenerationRef"]
        });
      }
      requireFreshTaskToPrRef(
        value.recovery.priorAttemptRef,
        value.attempt.ref,
        ctx,
        ["recovery", "priorAttemptRef"],
        "Recovery attempt rotation"
      );
      requireFreshTaskToPrRef(
        value.recovery.priorWorkRunRef,
        value.workRunRef,
        ctx,
        ["recovery", "priorWorkRunRef"],
        "Recovery WorkRun rotation"
      );
      requirePreservedRefs(
        value.recovery.preservedStateRefs,
        [value.recovery.priorWorkRunRef, ...requiredCanonicalPreservationRefs],
        ["recovery", "preservedStateRefs"],
        "Recovery"
      );
    }
    if (value.cancellation && !sameTaskToPrRef(value.cancellation.cancelledAttemptRef, value.attempt.ref)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cancellation must bind the current attempt",
        path: ["cancellation", "cancelledAttemptRef"]
      });
    }
    if (value.cancellation) {
      requirePreservedRefs(
        value.cancellation.preservedStateRefs,
        [value.workRunRef, value.attempt.ref, ...requiredCanonicalPreservationRefs],
        ["cancellation", "preservedStateRefs"],
        "Cancellation"
      );
    }
    if (value.cancellation && value.recovery) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "A projection cannot be both the cancellation and recovery snapshot",
        path: ["recovery"]
      });
    }
    if (value.handoff && value.recovery) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "A projection cannot be both the handoff and recovery snapshot",
        path: ["recovery"]
      });
    }
    if (value.cleanup && !sameTaskToPrRef(value.cleanup.eligibility.eventCursorRef, value.events.replayCursorRef)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cleanup eligibility must bind the current canonical replay cursor",
        path: ["cleanup", "eligibility", "eventCursorRef"]
      });
    }
    if (
      value.cleanup &&
      (!value.terminalDispositionRef ||
        !sameTaskToPrRef(
          value.cleanup.eligibility.terminalDispositionRef,
          value.terminalDispositionRef
        ))
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cleanup eligibility must bind the exact durable terminal owner fact",
        path: ["cleanup", "eligibility", "terminalDispositionRef"]
      });
    }
    if (
      value.cleanup &&
      !sameTaskToPrRef(value.cleanup.eligibility.writerLeaseRef, value.attempt.writerLeaseRef)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cleanup eligibility must bind the exact writer lease being revoked",
        path: ["cleanup", "eligibility", "writerLeaseRef"]
      });
    }
    if (
      value.cleanup &&
      !sameTaskToPrRef(value.cleanup.eligibility.targetWorktreeRef, value.repository.worktreeRef)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cleanup eligibility must bind the canonical worktree",
        path: ["cleanup", "eligibility", "targetWorktreeRef"]
      });
    }
    if (value.pullRequestRef) {
      if (value.exactHead && !sameTaskToPrRef(value.exactHead.pullRequestRef, value.pullRequestRef)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Exact-head proof must bind the canonical pull request ref",
          path: ["exactHead", "pullRequestRef"]
        });
      }
      for (const [reviewIndex, review] of value.reviews.entries()) {
        if (!sameTaskToPrRef(review.pullRequestRef, value.pullRequestRef)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Every review must bind the canonical pull request ref",
            path: ["reviews", reviewIndex, "pullRequestRef"]
          });
        }
      }
      if (value.merge && !sameTaskToPrRef(value.merge.guard.pullRequestRef, value.pullRequestRef)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge guard must bind the canonical pull request ref",
          path: ["merge", "guard", "pullRequestRef"]
        });
      }
      if (value.merge?.outcome && !sameTaskToPrRef(value.merge.outcome.pullRequestRef, value.pullRequestRef)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge outcome must bind the canonical pull request ref",
          path: ["merge", "outcome", "pullRequestRef"]
        });
      }
    } else if (value.exactHead || value.reviews.length > 0 || value.merge) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Review and merge state require a canonical pull request ref",
        path: ["pullRequestRef"]
      });
    }
    if (value.exactHead && !sameGitObjectId(value.exactHead.localHead, value.repository.branchHead)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Exact local head must equal the canonical branch head",
        path: ["exactHead", "localHead"]
      });
    }
    if (value.exactHead && !sameGitObjectId(value.exactHead.expectedBase, value.repository.baseHead)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Exact-head expected base must equal the canonical repository base",
        path: ["exactHead", "expectedBase"]
      });
    }
    if (value.exactHead && !sameTaskToPrRef(value.exactHead.remoteBranchRef, value.repository.branchRef)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Exact-head remote branch ref must equal the canonical repository branch ref",
        path: ["exactHead", "remoteBranchRef"]
      });
    }
    if (value.exactHead && Date.parse(value.exactHead.verifiedAt) < Date.parse(value.createdAt)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Exact-head verification cannot precede the projection timestamp",
        path: ["exactHead", "verifiedAt"]
      });
    }
    if (value.reviews.length > 0 && !value.exactHead) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Reviews require local/remote/provider exact-head proof",
        path: ["exactHead"]
      });
    }
    if (value.exactHead) {
      const proofObligations: Array<{ ref: TaskToPrRef; path: (string | number)[] }> = [
        { ref: value.exactHead.equalityProofRef, path: ["exactHead", "equalityProofRef"] },
        ...value.exactHead.ciProofBundleRefs.map((ref, index) => ({
          ref,
          path: ["exactHead", "ciProofBundleRefs", index]
        })),
        ...value.reviews.map((review, index) => ({
          ref: review.proofBundleRef,
          path: ["reviews", index, "proofBundleRef"]
        }))
      ];
      const proofObligationKeys = new Set<string>();
      const proofObligationDigests = new Set<string>();
      for (const obligation of proofObligations) {
        const key = taskToPrCanonicalRefKey(obligation.ref);
        if (proofObligationKeys.has(key)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Exact-head equality, CI, and review proof obligations require globally unique canonical identities",
            path: obligation.path
          });
        }
        proofObligationKeys.add(key);
        if (proofObligationDigests.has(obligation.ref.digest)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Exact-head equality, CI, and review proof obligations require globally unique canonical digests",
            path: obligation.path
          });
        }
        proofObligationDigests.add(obligation.ref.digest);
      }
    }
    const reviewKeys = new Set<string>();
    const reviewDigests = new Set<string>();
    const reviewerKeys = new Set<string>();
    const reviewerDigests = new Set<string>();
    const reviewRunKeys = new Set<string>();
    const reviewRunDigests = new Set<string>();
    const reviewProofKeys = new Set<string>();
    const reviewProofDigests = new Set<string>();
    for (const [reviewIndex, review] of value.reviews.entries()) {
      if (!sameGitObjectId(review.base, value.repository.baseHead)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Review base must equal the exact canonical pull-request base",
          path: ["reviews", reviewIndex, "base"]
        });
      }
      if (!sameGitObjectId(review.head, value.repository.branchHead)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Review head must equal the exact canonical branch head",
          path: ["reviews", reviewIndex, "head"]
        });
      }
      for (const [key, seen, path] of [
        [review.ref.id, reviewKeys, "ref"],
        [review.reviewerRef.id, reviewerKeys, "reviewerRef"],
        [review.reviewRunRef.id, reviewRunKeys, "reviewRunRef"]
      ] as const) {
        if (seen.has(key)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Review, reviewer, and review-run refs must each be unique",
            path: ["reviews", reviewIndex, path]
          });
        }
        seen.add(key);
      }
      if (reviewDigests.has(review.ref.digest)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Review refs must resolve to distinct canonical record digests",
          path: ["reviews", reviewIndex, "ref"]
        });
      }
      reviewDigests.add(review.ref.digest);
      if (reviewerDigests.has(review.reviewerRef.digest)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Reviewer refs must resolve to distinct canonical actor digests",
          path: ["reviews", reviewIndex, "reviewerRef"]
        });
      }
      reviewerDigests.add(review.reviewerRef.digest);
      if (reviewRunDigests.has(review.reviewRunRef.digest)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Review-run refs must resolve to distinct canonical run digests",
          path: ["reviews", reviewIndex, "reviewRunRef"]
        });
      }
      reviewRunDigests.add(review.reviewRunRef.digest);
      const reviewProofKey = taskToPrCanonicalRefKey(review.proofBundleRef);
      if (reviewProofKeys.has(reviewProofKey)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Review proof bundles must have unique canonical identities",
          path: ["reviews", reviewIndex, "proofBundleRef"]
        });
      }
      reviewProofKeys.add(reviewProofKey);
      if (reviewProofDigests.has(review.proofBundleRef.digest)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Review proof bundles must have unique canonical digests",
          path: ["reviews", reviewIndex, "proofBundleRef"]
        });
      }
      reviewProofDigests.add(review.proofBundleRef.digest);
      if (review.reviewerRef.digest === value.attempt.workerRef.digest) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Worker and reviewer identities must resolve to distinct canonical digests",
          path: ["reviews", reviewIndex, "reviewerRef"]
        });
      }
      if (review.reviewRunRef.digest === value.attempt.runtimeRef.digest) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Worker runtime and review run must resolve to distinct canonical digests",
          path: ["reviews", reviewIndex, "reviewRunRef"]
        });
      }
      if (
        value.exactHead &&
        Date.parse(review.reviewedAt) < Date.parse(value.exactHead.verifiedAt)
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Reviews cannot precede exact-head verification",
          path: ["reviews", reviewIndex, "reviewedAt"]
        });
      }
    }
    if (value.merge) {
      if (!value.exactHead) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge state requires local/remote/provider exact-head proof",
          path: ["exactHead"]
        });
      }
      if (!sameGitObjectId(value.merge.guard.expectedBase, value.repository.baseHead)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge guard expected base must equal the exact canonical pull-request base",
          path: ["merge", "guard", "expectedBase"]
        });
      }
      if (!sameGitObjectId(value.merge.guard.expectedHead, value.repository.branchHead)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge guard expected head must equal the exact canonical branch head",
          path: ["merge", "guard", "expectedHead"]
        });
      }
      if (value.exactHead && Date.parse(value.merge.guard.evaluatedAt) < Date.parse(value.exactHead.verifiedAt)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge guards cannot precede exact-head verification",
          path: ["merge", "guard", "evaluatedAt"]
        });
      }
      if (value.reviews.some((review) => Date.parse(value.merge!.guard.evaluatedAt) < Date.parse(review.reviewedAt))) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge guards cannot precede their bound reviews",
          path: ["merge", "guard", "evaluatedAt"]
        });
      }
      if (value.merge.guard.operatorRef.digest === value.attempt.workerRef.digest) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Worker and merge operator identities must resolve to distinct canonical digests",
          path: ["merge", "guard", "operatorRef"]
        });
      }
      if (value.merge.guard.operatorRunRef.digest === value.attempt.runtimeRef.digest) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Worker runtime and merge-operator run must resolve to distinct canonical digests",
          path: ["merge", "guard", "operatorRunRef"]
        });
      }
      for (const [reviewIndex, review] of value.reviews.entries()) {
        if (value.merge.guard.operatorRef.digest === review.reviewerRef.digest) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Reviewer and merge operator identities must resolve to distinct canonical digests",
            path: ["reviews", reviewIndex, "reviewerRef"]
          });
        }
        if (value.merge.guard.operatorRunRef.digest === review.reviewRunRef.digest) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Review and merge-operator runs must resolve to distinct canonical digests",
            path: ["reviews", reviewIndex, "reviewRunRef"]
          });
        }
      }
      if (
        value.merge.guard.decision === "eligible" ||
        value.merge.guard.decision === "consumed"
      ) {
        if (value.reviews.length === 0 || value.reviews.some((review) => review.verdict !== "approved")) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Eligible merge guards require at least one review and all reviews approved",
            path: ["merge", "guard", "decision"]
          });
        }
        if (
          value.merge.guard.reviewRefs.length !== value.reviews.length ||
          value.merge.guard.reviewRefs.some(
            (reviewRef) => !value.reviews.some((review) => sameTaskToPrRef(reviewRef, review.ref))
          )
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message:
              "Eligible merge guard review refs must exactly equal the projected approved review refs as a canonical set",
            path: ["merge", "guard", "reviewRefs"]
          });
        }
        for (const review of value.reviews) {
          if (!value.merge.guard.proofBundleRefs.some((proofRef) => sameTaskToPrRef(proofRef, review.proofBundleRef))) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: "Eligible merge guards must bind every exact review proof bundle",
              path: ["merge", "guard", "proofBundleRefs"]
            });
          }
        }
        if (
          value.exactHead &&
          !value.merge.guard.proofBundleRefs.some((proofRef) => sameTaskToPrRef(proofRef, value.exactHead!.equalityProofRef))
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Eligible merge guards must bind the exact-head equality proof",
            path: ["merge", "guard", "proofBundleRefs"]
          });
        }
        if (
          value.exactHead &&
          value.exactHead.ciProofBundleRefs.some(
            (ciProofRef) => !value.merge!.guard.proofBundleRefs.some((proofRef) => sameTaskToPrRef(proofRef, ciProofRef))
          )
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Eligible merge guards must bind every exact-head CI proof",
            path: ["merge", "guard", "proofBundleRefs"]
          });
        }
      }
    }
    if (value.merge?.outcome) {
      if (!sameTaskToPrRef(value.merge.outcome.guardRef, value.merge.guard.ref)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge outcome must bind the exact immutable merge guard",
          path: ["merge", "outcome", "guardRef"]
        });
      }
      if (!sameGitObjectId(value.merge.outcome.expectedHead, value.merge.guard.expectedHead)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge outcome expected head must equal the guarded expected head",
          path: ["merge", "outcome", "expectedHead"]
        });
      }
      if (!sameGitObjectId(value.merge.outcome.expectedBase, value.merge.guard.expectedBase)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge outcome expected base must equal the guarded expected base",
          path: ["merge", "outcome", "expectedBase"]
        });
      }
      if (value.merge.guard.decision !== "consumed") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Every merge outcome requires an explicitly consumed merge guard",
          path: ["merge", "guard", "decision"]
        });
      }
      if (Date.parse(value.merge.outcome.finishedAt) < Date.parse(value.merge.guard.evaluatedAt)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Merge outcomes cannot precede guard evaluation",
          path: ["merge", "outcome", "finishedAt"]
        });
      }
    }
    if (value.cleanup) {
      const cleanupFloor = value.merge?.outcome?.finishedAt ?? value.createdAt;
      if (Date.parse(value.cleanup.eligibility.evaluatedAt) < Date.parse(cleanupFloor)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Cleanup eligibility cannot precede the terminal merge outcome or projection",
          path: ["cleanup", "eligibility", "evaluatedAt"]
        });
      }
      if (
        value.cleanup.outcome &&
        Date.parse(value.cleanup.outcome.finishedAt) < Date.parse(value.cleanup.eligibility.evaluatedAt)
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Cleanup outcomes cannot precede cleanup eligibility",
          path: ["cleanup", "outcome", "finishedAt"]
        });
      }
    }
    if (
      value.rollback?.outcome &&
      value.merge?.outcome &&
      Date.parse(value.rollback.outcome.finishedAt) < Date.parse(value.merge.outcome.finishedAt)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Rollback outcomes cannot precede the merge outcome they remediate",
        path: ["rollback", "outcome", "finishedAt"]
      });
    }
    if (value.rollback) {
      const rollbackFloor = value.merge?.outcome?.finishedAt ?? value.createdAt;
      if (Date.parse(value.rollback.plan.createdAt) < Date.parse(rollbackFloor)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Rollback plans cannot precede the terminal merge outcome or projection",
          path: ["rollback", "plan", "createdAt"]
        });
      }
    }
    if (value.state === "handed_off" && !value.handoff) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Handed-off projections require a handoff ref", path: ["handoff"] });
    }
    if (TaskToPrStatesWithoutReviewAuthority.has(value.state) && value.reviews.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${value.state} projections cannot carry review bindings before review authority is active`,
        path: ["reviews"]
      });
    }
    if (
      (TaskToPrStatesWithoutReviewAuthority.has(value.state) || value.state === "recovering") &&
      (value.merge?.guard.reviewRefs.length ?? 0) > 0
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${value.state} projections cannot hide review bindings in a merge guard before review authority is active`,
        path: ["merge", "guard", "reviewRefs"]
      });
    }
    const mergeMatrixKey = value.merge
      ? `${value.merge.guard.decision}:${value.merge.outcome?.status ?? "none"}`
      : "absent";
    if (!TASK_TO_PR_STATE_MERGE_MATRIX[value.state].has(mergeMatrixKey)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `State ${value.state} is incompatible with merge authority ${mergeMatrixKey}`,
        path: ["merge"]
      });
    }
    if (TaskToPrTerminalStates.has(value.state) && !value.terminalDispositionRef) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${value.state} projections require a durable Todos terminal-disposition owner ref`,
        path: ["terminalDispositionRef"]
      });
    }
    if (!TaskToPrTerminalStates.has(value.state) && value.terminalDispositionRef) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${value.state} projections cannot carry a terminal-disposition owner ref`,
        path: ["terminalDispositionRef"]
      });
    }
    if (value.state === "reviewing" && value.reviews.length === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Reviewing projections require review refs", path: ["reviews"] });
    }
    if (value.state === "cancelled" && !value.cancellation) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Cancelled projections require preservation state", path: ["cancellation"] });
    }
    if (value.cancellation && value.merge?.outcome) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cancellation cannot coexist with a terminal merge outcome",
        path: ["cancellation"]
      });
    }
    if (value.state === "recovering" && !value.recovery) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Recovering projections require recovery state", path: ["recovery"] });
    }
    if (value.state === "repairing" && value.repair.cycle === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Repairing projections require a non-zero repair cycle", path: ["repair", "cycle"] });
    }
    if (
      value.merge &&
      (value.merge.guard.decision === "eligible" || value.merge.guard.decision === "consumed") &&
      !sameTaskToPrRef(value.attempt.admissionWriterGenerationRef, value.attempt.writerGenerationRef)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Merge eligibility requires admission from the current writer generation",
        path: ["attempt", "admissionWriterGenerationRef"]
      });
    }
    if (value.state === "merge_ready" && value.merge?.guard.decision !== "eligible") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Merge-ready projections require an eligible guard", path: ["merge"] });
    }
    if (value.state === "merged" && value.merge?.outcome?.status !== "merged") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Merged projections require a merged immutable outcome", path: ["merge"] });
    }
    if (
      value.state === "closed_unmerged" &&
      !value.merge?.outcome?.status.match(/^(closed_unmerged|refused|head_drift|base_drift)$/)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Closed-unmerged projections require a non-merged terminal outcome",
        path: ["merge"]
      });
    }
    if (
      value.state === "cleanup_complete" &&
      (!value.cleanup?.outcome || !["deleted", "preserved", "skipped"].includes(value.cleanup.outcome.status))
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Cleanup-complete projections require an immutable cleanup outcome",
        path: ["cleanup"]
      });
    }
    if (value.state === "rolled_back" && value.rollback?.outcome?.status !== "succeeded") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Rolled-back projections require a successful rollback outcome",
        path: ["rollback"]
      });
    }
    if ((value.state === "failed" || value.state === "blocked") && value.evidenceRefs.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Failed and blocked projections require redacted evidence refs",
        path: ["evidenceRefs"]
      });
    }
    if (
      ["admitted", "running", "handed_off", "reviewing", "repairing", "merge_ready", "recovering"].includes(value.state) &&
      (value.merge?.outcome || value.cancellation || value.cleanup?.outcome || value.rollback?.outcome)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Non-terminal projections cannot carry terminal owner outcomes",
        path: ["state"]
      });
    }
    const extensionKeys = new Set<string>();
    for (const [index, extension] of value.adapterExtensions.entries()) {
      const key = `${extension.mode}:${extension.schema}`;
      if (extensionKeys.has(key)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Adapter extensions must be unique per local/cloud mode and schema",
          path: ["adapterExtensions", index]
        });
      }
      extensionKeys.add(key);
    }
  });
export type TaskToPrProjection = z.infer<typeof TaskToPrProjectionSchema>;

export interface TaskToPrTransitionIssue {
  path: string;
  message: string;
}

export type TaskToPrTransitionResult =
  | { success: true; issues: [] }
  | { success: false; issues: TaskToPrTransitionIssue[] };

type TaskToPrHeadBoundEvidenceCategory =
  | "equality_proof"
  | "ci_proof"
  | "review_proof"
  | "review_record"
  | "review_run";

interface TaskToPrHeadBoundEvidenceBinding {
  category: TaskToPrHeadBoundEvidenceCategory;
  ref: TaskToPrRef;
  path: string;
}

function taskToPrHeadBoundEvidenceBindings(
  projection: TaskToPrProjection
): TaskToPrHeadBoundEvidenceBinding[] {
  return [
    ...(projection.exactHead
      ? [
          {
            category: "equality_proof" as const,
            ref: projection.exactHead.equalityProofRef,
            path: "exactHead.equalityProofRef"
          },
          ...projection.exactHead.ciProofBundleRefs.map((ref, index) => ({
            category: "ci_proof" as const,
            ref,
            path: `exactHead.ciProofBundleRefs.${index}`
          }))
        ]
      : []),
    ...projection.reviews.flatMap((review, index) => [
      {
        category: "review_proof" as const,
        ref: review.proofBundleRef,
        path: `reviews.${index}.proofBundleRef`
      },
      {
        category: "review_record" as const,
        ref: review.ref,
        path: `reviews.${index}.ref`
      },
      {
        category: "review_run" as const,
        ref: review.reviewRunRef,
        path: `reviews.${index}.reviewRunRef`
      }
    ])
  ];
}

const TASK_TO_PR_CHANGED_HEAD_EVIDENCE_IDENTITY_MESSAGE =
  "A changed branch head requires every head-bound evidence ref to use a fresh canonical identity";
const TASK_TO_PR_CHANGED_HEAD_EVIDENCE_DIGEST_MESSAGE =
  "A changed branch head requires every head-bound evidence ref to use a fresh digest";

const TASK_TO_PR_LEGAL_STATE_TRANSITIONS: Record<TaskToPrProjectionState, readonly TaskToPrProjectionState[]> = {
  admitted: ["admitted", "running", "failed", "blocked", "cancelled", "recovering"],
  running: [
    "running",
    "handed_off",
    "reviewing",
    "repairing",
    "merge_ready",
    "failed",
    "blocked",
    "cancelled",
    "recovering"
  ],
  handed_off: ["handed_off", "running", "reviewing", "repairing", "failed", "blocked", "cancelled", "recovering"],
  reviewing: ["reviewing", "repairing", "merge_ready", "failed", "blocked", "cancelled", "recovering", "closed_unmerged"],
  repairing: ["repairing", "running", "reviewing", "merge_ready", "failed", "blocked", "cancelled", "recovering", "closed_unmerged"],
  merge_ready: ["merge_ready", "repairing", "merged", "closed_unmerged", "failed", "blocked", "cancelled"],
  merged: ["merged", "cleanup_complete", "rolled_back"],
  closed_unmerged: ["closed_unmerged", "cleanup_complete"],
  failed: ["failed", "cleanup_complete", "rolled_back"],
  blocked: ["blocked", "cancelled", "cleanup_complete"],
  cancelled: ["cancelled", "cleanup_complete"],
  recovering: ["recovering", "running", "handed_off", "failed", "blocked", "cancelled"],
  cleanup_complete: ["cleanup_complete"],
  rolled_back: ["rolled_back"]
};

function taskToPrParseIssues(
  prefix: "previous" | "current" | "local" | "cloud",
  issues: z.ZodIssue[]
): TaskToPrTransitionIssue[] {
  return issues.map((issue) => ({
    path: [prefix, ...issue.path].join("."),
    message: issue.message
  }));
}

export function validateTaskToPrProjectionTransition(
  previousInput: unknown,
  currentInput: unknown
): TaskToPrTransitionResult {
  const issues: TaskToPrTransitionIssue[] = [];
  const addIssue = (path: string, message: string) => issues.push({ path, message });
  const parsedPrevious = TaskToPrProjectionSchema.safeParse(previousInput);
  const parsedCurrent = TaskToPrProjectionSchema.safeParse(currentInput);
  if (!parsedPrevious.success) {
    issues.push(...taskToPrParseIssues("previous", parsedPrevious.error.issues));
  }
  if (!parsedCurrent.success) {
    issues.push(...taskToPrParseIssues("current", parsedCurrent.error.issues));
  }
  if (!parsedPrevious.success || !parsedCurrent.success) {
    return { success: false, issues };
  }
  const previous = parsedPrevious.data;
  const current = parsedCurrent.data;
  const previousActiveProvenance = taskToPrActiveProvenanceEntries(previous);
  const currentActiveProvenance = taskToPrActiveProvenanceEntries(current);
  if (
    current.provenanceLedger.length < previous.provenanceLedger.length ||
    previous.provenanceLedger.some(
      (entry, index) =>
        !current.provenanceLedger[index] ||
        !sameTaskToPrProvenanceEntry(entry, current.provenanceLedger[index]!)
    )
  ) {
    addIssue(
      "provenanceLedger",
      "The provenance ledger is append-only and must retain the previous ledger as an exact immutable prefix"
    );
  }
  const appendedProvenance = current.provenanceLedger.slice(previous.provenanceLedger.length);
  for (const [index, entry] of appendedProvenance.entries()) {
    if (!currentActiveProvenance.some((activeEntry) => sameTaskToPrProvenanceEntry(activeEntry, entry))) {
      addIssue(
        `provenanceLedger.${previous.provenanceLedger.length + index}`,
        "A newly appended provenance entry must represent an active identity in the current snapshot"
      );
    }
  }
  for (const activeEntry of currentActiveProvenance) {
    const existedBefore = previous.provenanceLedger.some((entry) =>
      sameTaskToPrProvenanceEntry(entry, activeEntry)
    );
    const wasActiveBefore = previousActiveProvenance.some((entry) =>
      sameTaskToPrProvenanceEntry(entry, activeEntry)
    );
    if (existedBefore && !wasActiveBefore) {
      addIssue(
        "provenanceLedger",
        `The ${activeEntry.category} identity cannot reactivate after becoming inactive`
      );
    }
  }
  const validateOwnerRecordTransition = (
    path: string,
    previousRecord: { ref: TaskToPrRef } | undefined,
    currentRecord: { ref: TaskToPrRef } | undefined
  ): void => {
    if (
      !previousRecord ||
      !currentRecord ||
      JSON.stringify(previousRecord) === JSON.stringify(currentRecord)
    ) {
      return;
    }
    if (sameTaskToPrCanonicalRefId(previousRecord.ref, currentRecord.ref)) {
      addIssue(
        path,
        "An owner record must remain exactly immutable while its canonical ref identity is unchanged"
      );
      return;
    }
    if (previousRecord.ref.digest === currentRecord.ref.digest) {
      addIssue(path, "A rotated owner record requires both a fresh canonical ref identity and a fresh digest");
    }
  };

  if (previous.id !== current.id) {
    addIssue("id", "The canonical top-level projection id is immutable across legal transitions");
  }
  if (Date.parse(current.createdAt) < Date.parse(previous.createdAt)) {
    addIssue("createdAt", "Projection timestamps cannot move backwards");
  }
  const {
    id: _previousId,
    createdAt: _previousCreatedAt,
    events: _previousEvents,
    provenanceLedger: _previousProvenanceLedger,
    ...previousSemanticState
  } = previous;
  const {
    id: _currentId,
    createdAt: _currentCreatedAt,
    events: _currentEvents,
    provenanceLedger: _currentProvenanceLedger,
    ...currentSemanticState
  } = current;
  if (
    JSON.stringify(previousSemanticState) !== JSON.stringify(currentSemanticState) &&
    current.events.sequence <= previous.events.sequence
  ) {
    addIssue("events.sequence", "Semantic lifecycle drift requires replay sequence and cursor advancement");
  }
  for (const [path, left, right] of [
    ["identityDigest", previous.identityDigest, current.identityDigest],
    ["frozenScopeDigest", previous.frozenScopeDigest, current.frozenScopeDigest],
    ["rootRequestRef", JSON.stringify(previous.rootRequestRef), JSON.stringify(current.rootRequestRef)],
    ["prGroupRef", JSON.stringify(previous.prGroupRef), JSON.stringify(current.prGroupRef)],
    ["leafTaskRef", JSON.stringify(previous.leafTaskRef), JSON.stringify(current.leafTaskRef)],
    ["repository.repoRef", JSON.stringify(previous.repository.repoRef), JSON.stringify(current.repository.repoRef)],
    ["repository.worktreeRef", JSON.stringify(previous.repository.worktreeRef), JSON.stringify(current.repository.worktreeRef)],
    ["repository.branchRef", JSON.stringify(previous.repository.branchRef), JSON.stringify(current.repository.branchRef)],
    ["repository.baseHead", JSON.stringify(previous.repository.baseHead), JSON.stringify(current.repository.baseHead)],
    ["events.streamRef", JSON.stringify(previous.events.streamRef), JSON.stringify(current.events.streamRef)]
  ] as const) {
    if (left !== right) {
      addIssue(path, "Canonical task-to-PR identity cannot change between projections");
    }
  }

  if (
    previous.pullRequestRef &&
    (!current.pullRequestRef || !sameTaskToPrRef(previous.pullRequestRef, current.pullRequestRef))
  ) {
    addIssue("pullRequestRef", "An established canonical pull-request identity cannot change or disappear");
  }

  if (sameGitObjectId(previous.repository.branchHead, current.repository.branchHead)) {
    if (
      previous.exactHead &&
      JSON.stringify(current.exactHead) !== JSON.stringify(previous.exactHead)
    ) {
      addIssue(
        "exactHead",
        "An established same-head exact-head fact is immutable and cannot change or disappear"
      );
    }
    if (
      current.reviews.length < previous.reviews.length ||
      previous.reviews.some(
        (previousReview, index) =>
          JSON.stringify(current.reviews[index]) !== JSON.stringify(previousReview)
      )
    ) {
      addIssue(
        "reviews",
        "Same-head review history is an exact immutable prefix; existing review bindings cannot move, change, or disappear"
      );
    }
  } else {
    const previousHeadBoundEvidence = taskToPrHeadBoundEvidenceBindings(previous);
    const currentHeadBoundEvidence = taskToPrHeadBoundEvidenceBindings(current);
    const previousHeadBoundEvidenceKeys = new Set(
      previousHeadBoundEvidence.map(({ ref }) => taskToPrCanonicalRefKey(ref))
    );
    const previousHeadBoundEvidenceDigests = new Set(
      previousHeadBoundEvidence.map(({ ref }) => ref.digest)
    );
    for (const { ref, path } of currentHeadBoundEvidence) {
      if (previousHeadBoundEvidenceKeys.has(taskToPrCanonicalRefKey(ref))) {
        addIssue(path, TASK_TO_PR_CHANGED_HEAD_EVIDENCE_IDENTITY_MESSAGE);
      }
      if (previousHeadBoundEvidenceDigests.has(ref.digest)) {
        addIssue(path, TASK_TO_PR_CHANGED_HEAD_EVIDENCE_DIGEST_MESSAGE);
      }
    }
  }
  if (current.state === "recovering" && (current.exactHead || current.reviews.length > 0)) {
    if (
      !sameGitObjectId(previous.repository.branchHead, current.repository.branchHead) ||
      JSON.stringify(previous.exactHead) !== JSON.stringify(current.exactHead) ||
      JSON.stringify(previous.reviews) !== JSON.stringify(current.reviews)
    ) {
      addIssue(
        "recovery",
        "Recovery may retain exact-head and review facts only unchanged from the immediately prior same-head snapshot"
      );
    }
  }

  if (current.events.sequence < previous.events.sequence) {
    addIssue("events.sequence", "Replay sequence cannot decrease");
  } else if (current.events.sequence === previous.events.sequence) {
    if (
      current.events.prefixDigest !== previous.events.prefixDigest ||
      !sameTaskToPrRef(current.events.replayCursorRef, previous.events.replayCursorRef)
    ) {
      addIssue("events", "An unchanged replay sequence must retain the same cursor and prefix digest");
    }
  } else {
    if (sameTaskToPrCanonicalRefId(current.events.replayCursorRef, previous.events.replayCursorRef)) {
      addIssue("events.replayCursorRef", "An advanced replay sequence requires a fresh canonical replay cursor ref");
    }
    if (current.events.replayCursorRef.digest === previous.events.replayCursorRef.digest) {
      addIssue("events.replayCursorRef", "An advanced replay sequence requires a fresh replay cursor digest");
    }
    if (current.events.prefixDigest === previous.events.prefixDigest) {
      addIssue("events.prefixDigest", "An advanced replay sequence requires a fresh prefix digest");
    }
  }

  if (current.repair.cycle < previous.repair.cycle || current.repair.cycle > previous.repair.cycle + 1) {
    addIssue("repair.cycle", "Repair cycles are cumulative, monotonic, and append at most one cycle per transition");
  }
  if (current.repair.cycle === previous.repair.cycle + 1) {
    const previousRepairRefs = [
      previous.repair.ref,
      ...(previous.repair.latestRepairRef ? [previous.repair.latestRepairRef] : [])
    ];
    for (const previousRepairRef of previousRepairRefs) {
      if (sameTaskToPrCanonicalRefId(current.repair.ref, previousRepairRef)) {
        addIssue("repair.ref", "An advanced repair cycle requires a repair-state ref fresh from both prior repair slots");
      }
      if (current.repair.ref.digest === previousRepairRef.digest) {
        addIssue("repair.ref", "An advanced repair cycle requires a repair-state digest fresh from both prior repair slots");
      }
    }
    if (!current.repair.latestRepairRef) {
      addIssue("repair.latestRepairRef", "An advanced repair cycle requires a fresh latest-repair ref");
    } else {
      for (const previousRepairRef of previousRepairRefs) {
        if (sameTaskToPrCanonicalRefId(current.repair.latestRepairRef, previousRepairRef)) {
          addIssue(
            "repair.latestRepairRef",
            "An advanced repair cycle requires a latest-repair ref fresh from both prior repair slots"
          );
        }
        if (current.repair.latestRepairRef.digest === previousRepairRef.digest) {
          addIssue(
            "repair.latestRepairRef",
            "An advanced repair cycle requires a latest-repair digest fresh from both prior repair slots"
          );
        }
      }
    }
  } else if (
    current.repair.cycle === previous.repair.cycle &&
    JSON.stringify(current.repair) !== JSON.stringify(previous.repair)
  ) {
    addIssue("repair", "An unchanged repair cycle must retain the same immutable repair refs");
  }
  const enteringRepair = previous.state !== "repairing" && current.state === "repairing";
  if (enteringRepair && current.repair.cycle !== previous.repair.cycle + 1) {
    addIssue("repair.cycle", "Every entry into repairing must consume exactly one repair cycle");
  }
  if (enteringRepair && previous.repair.exhausted) {
    addIssue("repair.exhausted", "An exhausted repair budget cannot enter repairing");
  }
  if (
    TaskToPrTerminalStates.has(previous.state) &&
    JSON.stringify(current.repair) !== JSON.stringify(previous.repair)
  ) {
    addIssue("repair", "Repair state is frozen after terminal disposition");
  }

  const attemptChanged = !sameTaskToPrCanonicalRefId(previous.attempt.ref, current.attempt.ref);
  const nonceChanged = previous.attempt.nonce !== current.attempt.nonce;
  const generationChanged = !sameTaskToPrCanonicalRefId(
    previous.attempt.writerGenerationRef,
    current.attempt.writerGenerationRef
  );
  const workRunChanged = !sameTaskToPrCanonicalRefId(previous.workRunRef, current.workRunRef);
  if (new Set([attemptChanged, nonceChanged, generationChanged, workRunChanged]).size !== 1) {
    addIssue(
      "attempt",
      "Attempt ref, nonce, writer generation, and WorkRun must either all remain stable or all advance together"
    );
  }
  if (attemptChanged && (!current.recovery && !current.handoff)) {
    addIssue("attempt", "A fresh attempt requires an explicit recovery or handoff transition ref");
  }
  if (attemptChanged && current.recovery && current.handoff) {
    addIssue("attempt", "A fresh attempt must use exactly one recovery or handoff transition");
  }
  if (!attemptChanged && (current.recovery || current.handoff) && !previous.recovery && !previous.handoff) {
    addIssue("attempt", "Recovery and handoff transitions require a fresh attempt");
  }
  if (!attemptChanged && JSON.stringify(previous.handoff) !== JSON.stringify(current.handoff)) {
    addIssue(
      "handoff",
      "An unchanged attempt must retain its exact immutable handoff provenance"
    );
  }
  if (!attemptChanged && JSON.stringify(previous.recovery) !== JSON.stringify(current.recovery)) {
    addIssue(
      "recovery",
      "An unchanged attempt must retain its exact immutable recovery provenance"
    );
  }
  if (!attemptChanged && JSON.stringify(previous.attempt) !== JSON.stringify(current.attempt)) {
    addIssue("attempt", "An unchanged attempt identity cannot mutate attempt-scoped owner refs");
  }
  if (
    !generationChanged &&
    !sameTaskToPrRef(previous.attempt.writerGenerationRef, current.attempt.writerGenerationRef)
  ) {
    addIssue("attempt.writerGenerationRef", "An unchanged writer-generation identity cannot mutate its digest");
  }
  if (!workRunChanged && !sameTaskToPrRef(previous.workRunRef, current.workRunRef)) {
    addIssue("workRunRef", "An unchanged WorkRun identity cannot mutate its digest");
  }

  if (attemptChanged) {
    if (current.attempt.ref.digest === previous.attempt.ref.digest) {
      addIssue("attempt.ref", "A fresh attempt requires a fresh attempt digest");
    }
    if (current.attempt.writerGenerationRef.digest === previous.attempt.writerGenerationRef.digest) {
      addIssue("attempt.writerGenerationRef", "A fresh attempt requires a fresh writer-generation digest");
    }
    if (current.workRunRef.digest === previous.workRunRef.digest) {
      addIssue("workRunRef", "A fresh attempt requires a fresh WorkRun digest");
    }
    for (const field of [
      "admissionRef",
      "workerRef",
      "runtimeRef",
      "writerLeaseRef",
      "writerFenceRef",
      "providerProfileRef",
      "providerRouteRef"
    ] as const) {
      if (
        sameTaskToPrCanonicalRefId(previous.attempt[field], current.attempt[field]) ||
        previous.attempt[field].digest === current.attempt[field].digest
      ) {
        addIssue(`attempt.${field}`, `A fresh attempt requires a fresh ${field}`);
      }
    }
    if (current.recovery) {
      if (!sameTaskToPrRef(current.recovery.priorAttemptRef, previous.attempt.ref)) {
        addIssue("recovery.priorAttemptRef", "Recovery must bind the immediately prior attempt");
      }
      if (!sameTaskToPrRef(current.recovery.priorWriterGenerationRef, previous.attempt.writerGenerationRef)) {
        addIssue("recovery.priorWriterGenerationRef", "Recovery must bind the immediately prior writer generation");
      }
      if (!sameTaskToPrRef(current.recovery.priorWorkRunRef, previous.workRunRef)) {
        addIssue("recovery.priorWorkRunRef", "Recovery must bind the immediately prior WorkRun");
      }
    }
    if (current.handoff) {
      if (!sameTaskToPrRef(current.handoff.previousAttemptRef, previous.attempt.ref)) {
        addIssue("handoff.previousAttemptRef", "Handoff must bind the immediately prior attempt");
      }
      if (!sameTaskToPrRef(current.handoff.nextAttemptRef, current.attempt.ref)) {
        addIssue("handoff.nextAttemptRef", "Handoff must bind the successor attempt");
      }
      if (!sameTaskToPrRef(current.handoff.previousWriterGenerationRef, previous.attempt.writerGenerationRef)) {
        addIssue("handoff.previousWriterGenerationRef", "Handoff must bind the immediately prior writer generation");
      }
      if (!sameTaskToPrRef(current.handoff.stoppedWorkRunRef, previous.workRunRef)) {
        addIssue("handoff.stoppedWorkRunRef", "Handoff must bind the immediately prior WorkRun");
      }
    }
  }

  if (!TASK_TO_PR_LEGAL_STATE_TRANSITIONS[previous.state].includes(current.state)) {
    addIssue("state", `Illegal task-to-PR lifecycle transition from ${previous.state} to ${current.state}`);
  }

  if (previous.merge?.guard.decision === "eligible" && current.state !== "merge_ready") {
    if (!current.merge) {
      addIssue(
        "merge",
        "Leaving merge_ready requires an explicit revoked or consumed successor for the eligible guard"
      );
    } else {
      const expectedDecision = current.merge.outcome ? "consumed" : "revoked";
      if (current.merge.guard.decision !== expectedDecision) {
        addIssue(
          "merge.guard.decision",
          `Leaving merge_ready requires the eligible guard to become ${expectedDecision}`
        );
      }
      if (!sameTaskToPrMergeGuardLineageFacts(previous.merge.guard, current.merge.guard)) {
        addIssue(
          "merge.guard",
          "A revoked or consumed successor guard must preserve the eligible guard's exact authority facts"
        );
      }
      if (Date.parse(current.merge.guard.evaluatedAt) < Date.parse(previous.merge.guard.evaluatedAt)) {
        addIssue(
          "merge.guard.evaluatedAt",
          "A revoked or consumed successor guard cannot precede the eligible guard"
        );
      }
    }
  }

  validateOwnerRecordTransition("handoff", previous.handoff, current.handoff);
  validateOwnerRecordTransition("recovery", previous.recovery, current.recovery);
  validateOwnerRecordTransition("merge.guard", previous.merge?.guard, current.merge?.guard);
  if (
    previous.merge &&
    current.merge &&
    (!sameGitObjectId(previous.merge.guard.expectedBase, current.merge.guard.expectedBase) ||
      !sameGitObjectId(previous.merge.guard.expectedHead, current.merge.guard.expectedHead))
  ) {
    if (
      sameTaskToPrCanonicalRefId(
        previous.merge.guard.providerGuardReceiptRef,
        current.merge.guard.providerGuardReceiptRef
      )
    ) {
      addIssue(
        "merge.guard.providerGuardReceiptRef",
        "A changed guarded base or head requires a fresh provider guard receipt identity"
      );
    }
    if (
      previous.merge.guard.providerGuardReceiptRef.digest ===
      current.merge.guard.providerGuardReceiptRef.digest
    ) {
      addIssue(
        "merge.guard.providerGuardReceiptRef",
        "A changed guarded base or head requires a fresh provider guard receipt digest"
      );
    }
  }
  validateOwnerRecordTransition(
    "cleanup.eligibility",
    previous.cleanup?.eligibility,
    current.cleanup?.eligibility
  );
  validateOwnerRecordTransition("rollback.plan", previous.rollback?.plan, current.rollback?.plan);
  if (
    previous.terminalDispositionRef &&
    (!current.terminalDispositionRef ||
      !sameTaskToPrRef(previous.terminalDispositionRef, current.terminalDispositionRef))
  ) {
    addIssue(
      "terminalDispositionRef",
      "A durable terminal-disposition owner fact cannot change or disappear"
    );
  }

  for (const [path, left, right] of [
    ["merge", previous.merge?.outcome ? previous.merge : undefined, current.merge],
    ["cancellation", previous.cancellation, current.cancellation],
    ["cleanup", previous.cleanup?.outcome ? previous.cleanup : undefined, current.cleanup],
    ["rollback", previous.rollback?.outcome ? previous.rollback : undefined, current.rollback]
  ] as const) {
    if (left && JSON.stringify(left) !== JSON.stringify(right)) {
      addIssue(path, "Complete immutable terminal owner facts cannot change or disappear");
    }
  }

  return issues.length === 0 ? { success: true, issues: [] } : { success: false, issues };
}

export function validateTaskToPrAdapterCoreEquivalence(
  localInput: unknown,
  cloudInput: unknown
): TaskToPrTransitionResult {
  const issues: TaskToPrTransitionIssue[] = [];
  const parsedLocal = TaskToPrProjectionSchema.safeParse(localInput);
  const parsedCloud = TaskToPrProjectionSchema.safeParse(cloudInput);
  if (!parsedLocal.success) {
    issues.push(...taskToPrParseIssues("local", parsedLocal.error.issues));
  }
  if (!parsedCloud.success) {
    issues.push(...taskToPrParseIssues("cloud", parsedCloud.error.issues));
  }
  if (!parsedLocal.success || !parsedCloud.success) {
    return { success: false, issues };
  }
  if (
    parsedLocal.data.adapterExtensions.length === 0 ||
    parsedLocal.data.adapterExtensions.some((extension) => extension.mode !== "local")
  ) {
    issues.push({
      path: "local.adapterExtensions",
      message: "The first adapter projection must contain one or more local-only extensions"
    });
  }
  if (
    parsedCloud.data.adapterExtensions.length === 0 ||
    parsedCloud.data.adapterExtensions.some((extension) => extension.mode !== "cloud")
  ) {
    issues.push({
      path: "cloud.adapterExtensions",
      message: "The second adapter projection must contain one or more cloud-only extensions"
    });
  }
  if (issues.length > 0) {
    return { success: false, issues };
  }
  const { adapterExtensions: _localExtensions, ...localCore } = parsedLocal.data;
  const { adapterExtensions: _cloudExtensions, ...cloudCore } = parsedCloud.data;
  if (JSON.stringify(localCore) !== JSON.stringify(cloudCore)) {
    return {
      success: false,
      issues: [
        {
          path: "core",
          message: "Local and cloud adapters must serialize byte-equivalent task-to-PR core projections"
        }
      ]
    };
  }
  return { success: true, issues: [] };
}

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

// ---------------------------------------------------------------------------
// Hasna Service Contract v1 (`hasna.contract.json` repo self-description)
//
// A repo's `hasna.contract.json` declares its name, repo class, the contract
// version it targets, the contract-kit version it tracks, its customer-facing
// hosting stories, runtime placements, four product surfaces, declared bins,
// and its storage boundary. Runtime placement (`local | self_hosted | cloud`)
// is intentionally separate from storage routing (`local | cloud`): a
// self-hosted server uses the cloud storage router against operator-owned
// Postgres, while `cloud` placement is reserved for Hasna SaaS.
// ---------------------------------------------------------------------------

export const SERVICE_CONTRACT_VERSION = "v1";

export const RepoClassSchema = z.enum(["library", "cli-with-store", "service", "saas"]);
export type RepoClass = z.infer<typeof RepoClassSchema>;

export const DEPLOYMENT_MODES = ["local", "self_hosted", "cloud"] as const;
export const DEPRECATED_DEPLOYMENT_MODE_ALIASES = ["self-hosted"] as const;
export const DeploymentModeSchema = z
  .enum([...DEPLOYMENT_MODES, ...DEPRECATED_DEPLOYMENT_MODE_ALIASES])
  .transform((value) => (value === "self-hosted" ? "self_hosted" : value));
export type DeploymentMode = z.infer<typeof DeploymentModeSchema>;

export const HOSTING_MODES = ["user-hosted", "hasna-saas"] as const;
export const HostingModeSchema = z.enum(HOSTING_MODES);
export type HostingMode = z.infer<typeof HostingModeSchema>;

export const SERVICE_SURFACE_KINDS = ["api", "sdk", "mcp", "cli"] as const;
export const ServiceSurfaceKindSchema = z.enum(SERVICE_SURFACE_KINDS);
export type ServiceSurfaceKind = z.infer<typeof ServiceSurfaceKindSchema>;

export const ServiceSurfaceStatusSchema = z.enum(["supported", "deferred", "unsupported"]);
export type ServiceSurfaceStatus = z.infer<typeof ServiceSurfaceStatusSchema>;

export const ServiceAuthModeSchema = z.enum(["none", "local-only", "api-key", "session", "service-token", "custom"]);
export type ServiceAuthMode = z.infer<typeof ServiceAuthModeSchema>;

export const ServiceEndpointSchema = z
  .object({
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
    path: z.string().regex(/^\/[A-Za-z0-9_./:*-]*$/, "Endpoint paths must be absolute HTTP paths"),
    public: z.boolean().default(false),
    description: z.string().min(1).optional()
  })
  .strict();
export type ServiceEndpoint = z.infer<typeof ServiceEndpointSchema>;

export const DeploymentReadinessGateSchema = z
  .object({
    id: z.string().min(1),
    kind: z.enum(["auth", "storage", "secret-ref", "migration", "health", "readiness", "redaction", "smoke", "operator", "other"]),
    required: z.boolean().default(true),
    command: z.string().min(1).optional(),
    evidenceRef: EvidencePointerSchema.optional(),
    status: z.enum(["pending", "passed", "failed", "blocked", "deferred"]).default("pending"),
    summary: z.string().min(1).optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if ((value.status === "passed" || value.status === "failed" || value.status === "blocked") && !value.command && !value.evidenceRef && !value.summary) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Terminal readiness gates require command, evidenceRef, or summary",
        path: ["status"]
      });
    }
  });
export type DeploymentReadinessGate = z.infer<typeof DeploymentReadinessGateSchema>;

export const ServiceSurfaceSchema = z
  .object({
    name: z.string().min(1),
    kind: ServiceSurfaceKindSchema.optional(),
    status: ServiceSurfaceStatusSchema,
    bin: z.string().min(1).optional(),
    mcpBin: z.string().min(1).optional(),
    authMode: ServiceAuthModeSchema,
    deploymentModes: z.array(DeploymentModeSchema).min(1),
    health: ServiceEndpointSchema.optional(),
    readiness: ServiceEndpointSchema.optional(),
    version: ServiceEndpointSchema.optional(),
    apiBasePath: z.string().regex(/^\/v[0-9]+$/, "Stable API base path must be /vN").optional(),
    openApiPath: z.string().regex(/^\/[A-Za-z0-9_./:-]*$/).optional(),
    exportSubpath: z.string().regex(/^\.(?:\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*)?$/, "SDK export subpaths must be package export keys such as . or ./sdk").optional(),
    generatedFrom: z.string().regex(/^\/[A-Za-z0-9_./:-]*$/, "SDK generatedFrom must reference an absolute OpenAPI path").optional(),
    clientClassName: z.string().regex(/^[A-Za-z_$][A-Za-z0-9_$]*$/).optional(),
    deferReason: z.string().min(1).optional(),
    readinessGates: z.array(DeploymentReadinessGateSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.status === "supported") {
      if (!value.kind || value.kind === "api") {
        if (!value.bin) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported API surfaces require a serve bin", path: ["bin"] });
        }
        if (!value.health) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported API surfaces require a health endpoint", path: ["health"] });
        }
        if (!value.readiness) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported API surfaces require a readiness endpoint", path: ["readiness"] });
        }
        if (!value.version) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported API surfaces require a version endpoint", path: ["version"] });
        }
      }
      if (value.kind === "cli" && !value.bin) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported CLI surfaces require a bin", path: ["bin"] });
      }
      if (value.kind === "mcp" && !value.mcpBin) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported MCP surfaces require an mcpBin", path: ["mcpBin"] });
      }
      if (value.kind === "sdk" && !value.exportSubpath) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported SDK surfaces require an exportSubpath", path: ["exportSubpath"] });
      }
    }
    if ((value.status === "deferred" || value.status === "unsupported") && !value.deferReason) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Deferred or unsupported service surfaces require a deferReason",
        path: ["deferReason"]
      });
    }
    if (value.health && value.health.path !== "/health") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Health endpoint must be /health", path: ["health", "path"] });
    }
    if (value.health && value.health.method !== "GET") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Health endpoint must use GET", path: ["health", "method"] });
    }
    if (value.readiness && value.readiness.path !== "/ready") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Readiness endpoint must be /ready", path: ["readiness", "path"] });
    }
    if (value.readiness && value.readiness.method !== "GET") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Readiness endpoint must use GET", path: ["readiness", "method"] });
    }
    if (value.version && value.version.path !== "/version") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Version endpoint must be /version", path: ["version", "path"] });
    }
    if (value.version && value.version.method !== "GET") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Version endpoint must use GET", path: ["version", "method"] });
    }
  });
export type ServiceSurface = z.infer<typeof ServiceSurfaceSchema>;

export const SurfaceConformanceWaiverSchema = z
  .object({
    kind: ServiceSurfaceKindSchema,
    reason: z.string().trim().min(1)
  })
  .strict();
export type SurfaceConformanceWaiver = z.infer<typeof SurfaceConformanceWaiverSchema>;

export const ServiceContractMetadataSchema = z
  .object({
    conformance: z
      .object({
        waivedSurfaces: z.array(SurfaceConformanceWaiverSchema).default([]),
        /** Explicit exception profile for non-Node monorepos. Libraries are eligible without a profile. */
        waiverProfile: z.literal("non-node-monorepo").optional()
      })
      .catchall(z.unknown())
      .optional()
  })
  .catchall(z.unknown());
export type ServiceContractMetadata = z.infer<typeof ServiceContractMetadataSchema>;

/** Runtime storage enum. `local | cloud` ONLY (Amendment A1: PURE REMOTE). */
export const STORAGE_MODES = ["local", "cloud"] as const;
export const StorageModeSchema = z.enum(STORAGE_MODES);
export type StorageMode = z.infer<typeof StorageModeSchema>;

export const STORAGE_ENGINES = ["sqlite", "postgres"] as const;
export const StorageEngineSchema = z.enum(STORAGE_ENGINES);
export type StorageEngine = z.infer<typeof StorageEngineSchema>;

/** Deprecated storage-mode aliases accepted at parse time and mapped to cloud. */
export const DEPRECATED_STORAGE_MODE_ALIASES = ["remote", "hybrid", "self_hosted"] as const;
export type DeprecatedStorageModeAlias = (typeof DEPRECATED_STORAGE_MODE_ALIASES)[number];

/** Lowercase dashed app short-name, e.g. `todos`, `mailery`, `loops`. */
export const AppNameSchema = z
  .string()
  .regex(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/, "App names must be lowercase dashed identifiers");
export type AppName = z.infer<typeof AppNameSchema>;

/** Bin suffixes an app may ship without a per-repo allowlist waiver. */
export const ALLOWED_BIN_SUFFIXES = [
  "",
  "-cli",
  "-mcp",
  "-serve",
  "-worker",
  "-runner",
  "-daemon",
  "-migrate",
  "-doctor"
] as const;

/** All bin names an app named `name` may declare by default. */
export function allowedBinsForName(name: string): string[] {
  return ALLOWED_BIN_SUFFIXES.map((suffix) => `${name}${suffix}`);
}

/**
 * Legacy/private-tier secret ref helper.
 *
 * Public OSS manifests must not persist this value; use `storage.envPrefix`
 * there and keep concrete secret bindings in private deployment config.
 */
export function databaseUrlSecretRefFor(name: string): string {
  return `hasna/oss/${name}/database-url`;
}

/** Canonical local sqlite path for an app: `~/.hasna/<name>/<name>.db`. */
export function defaultSqlitePathFor(name: string): string {
  return `~/.hasna/${name}/${name}.db`;
}

export const StorageContractSchema = z
  .object({
    mode: StorageModeSchema,
    /** Supported storage engines. This capability matrix is independent of runtime mode. */
    engines: z.array(StorageEngineSchema).min(1).optional(),
    /** Primary env prefix, e.g. `HASNA_TODOS_`. Defaults to `HASNA_<NAME>_`. */
    envPrefix: z.string().regex(/^HASNA_[A-Z][A-Z0-9]*_$/).optional(),
    /** Optional short alias env prefix, e.g. `TODOS_`. */
    aliasEnvPrefix: z.string().regex(/^[A-Z][A-Z0-9]*_$/).optional(),
    /** Legacy/private-tier secret ref. Public conformance rejects this field. */
    databaseUrlSecretRef: z
      .string()
      .regex(/^hasna\/oss\/[a-z0-9-]+\/database-url$/)
      .optional(),
    /** Local sqlite path (`~/.hasna/<name>/<name>.db`). */
    sqlitePath: z.string().min(1).endsWith(".db", "storage.sqlitePath must end in .db").optional(),
    /** Live PostgreSQL proof gate. The DSN environment variable is test-only. */
    pgTestGate: z
      .object({
        envVar: z.string().regex(/^[A-Z][A-Z0-9_]*_TEST_DATABASE_URL$/),
        command: z.string().trim().min(1)
      })
      .strict()
      .optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.engines && new Set(value.engines).size !== value.engines.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "storage.engines must not contain duplicates",
        path: ["engines"]
      });
    }
    if (value.engines?.includes("postgres") && !value.envPrefix) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "storage.engines containing postgres requires envPrefix for the HASNA_<NAME>_DATABASE_URL contract",
        path: ["envPrefix"]
      });
    }
  });
export type StorageContract = z.infer<typeof StorageContractSchema>;

export const OwnerOnlyFileModeSchema = z.enum(["0600"]);
export type OwnerOnlyFileMode = z.infer<typeof OwnerOnlyFileModeSchema>;

export const OwnerOnlyDirectoryModeSchema = z.enum(["0700"]);
export type OwnerOnlyDirectoryMode = z.infer<typeof OwnerOnlyDirectoryModeSchema>;

export const LocalStoreRootSchema = z.enum([".hasna", ".codewith"]);
export type LocalStoreRoot = z.infer<typeof LocalStoreRootSchema>;

export const SecureLocalStoreArtifactClassSchema = z.enum([
  "directory",
  "file",
  "sqlite_db",
  "sqlite_wal",
  "sqlite_shm",
  "backup",
  "export",
  "report",
  "tmp",
  "log",
  "session",
  "snapshot"
]);
export type SecureLocalStoreArtifactClass = z.infer<typeof SecureLocalStoreArtifactClassSchema>;

export const SecureLocalStorePathPatternSchema = RelativeProjectPathSchema.refine(
  (value) => !value.startsWith("~"),
  "Local store path patterns must be relative to their declared root"
);

export const SecureLocalStoreActiveRecordExclusionSchema = z
  .object({
    id: z.string().min(1),
    source: z.enum(["sqlite", "manifest", "index", "runtime", "package_adapter"]),
    table: z.string().min(1).optional(),
    column: z.string().min(1).optional(),
    description: z.string().min(1),
    required: z.boolean().default(true)
  })
  .strict();
export type SecureLocalStoreActiveRecordExclusion = z.infer<typeof SecureLocalStoreActiveRecordExclusionSchema>;

export const SecureLocalStoreSqliteMaintenanceSchema = z
  .object({
    safeWhen: z.enum(["exclusive_access", "offline_only", "never"]),
    operations: z
      .array(z.enum(["wal_checkpoint_truncate", "incremental_vacuum", "optimize", "vacuum"]))
      .default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.safeWhen === "never" && value.operations.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "sqliteMaintenance.safeWhen=never cannot declare operations",
        path: ["operations"]
      });
    }
  });
export type SecureLocalStoreSqliteMaintenance = z.infer<typeof SecureLocalStoreSqliteMaintenanceSchema>;

export const SecureLocalStoreRetentionAdapterSchema = z
  .object({
    id: z.string().min(1),
    description: z.string().min(1),
    ttlDays: z.number().int().nonnegative().optional(),
    artifactClasses: z.array(SecureLocalStoreArtifactClassSchema).min(1),
    allowlistGlobs: z.array(SecureLocalStorePathPatternSchema).min(1),
    activeRecordExclusions: z.array(SecureLocalStoreActiveRecordExclusionSchema).default([]),
    sqliteMaintenance: SecureLocalStoreSqliteMaintenanceSchema.optional()
  })
  .strict();
export type SecureLocalStoreRetentionAdapter = z.infer<typeof SecureLocalStoreRetentionAdapterSchema>;

export const SecureLocalStoreDefinitionSchema = z
  .object({
    storeId: z.string().regex(/^[a-z][a-z0-9-]*$/),
    packageName: z.string().min(1),
    displayName: z.string().min(1),
    root: LocalStoreRootSchema,
    relativePath: SecureLocalStorePathPatternSchema,
    directoryMode: OwnerOnlyDirectoryModeSchema.default("0700"),
    fileMode: OwnerOnlyFileModeSchema.default("0600"),
    sqliteDatabaseGlobs: z.array(SecureLocalStorePathPatternSchema).default([]),
    sensitiveFileGlobs: z.array(SecureLocalStorePathPatternSchema).default([]),
    backupGlobs: z.array(SecureLocalStorePathPatternSchema).default([]),
    exportGlobs: z.array(SecureLocalStorePathPatternSchema).default([]),
    retentionAdapters: z.array(SecureLocalStoreRetentionAdapterSchema).default([]),
    notes: z.array(z.string().min(1)).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.relativePath.includes("*")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "store relativePath must be a concrete directory; use glob fields for files",
        path: ["relativePath"]
      });
    }
    const adapterIds = new Set<string>();
    for (const [index, adapter] of value.retentionAdapters.entries()) {
      if (adapterIds.has(adapter.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "retention adapter ids must be unique within a store",
          path: ["retentionAdapters", index, "id"]
        });
      }
      adapterIds.add(adapter.id);
    }
  });
export type SecureLocalStoreDefinition = z.infer<typeof SecureLocalStoreDefinitionSchema>;

export const SecureLocalStorePolicySchema = contractBaseSchema(SCHEMA_IDS.secureLocalStorePolicy)
  .extend({
    version: z.string().min(1),
    scope: z.array(LocalStoreRootSchema).min(1),
    defaults: z
      .object({
        directoryMode: OwnerOnlyDirectoryModeSchema.default("0700"),
        fileMode: OwnerOnlyFileModeSchema.default("0600"),
        dryRunDefault: z.literal(true),
        requireExplicitApply: z.literal(true),
        includeSqliteSidecars: z.literal(true),
        redactedEvidenceOnly: z.literal(true)
      })
      .strict(),
    stores: z.array(SecureLocalStoreDefinitionSchema).min(1),
    lifecycle: z
      .object({
        retentionDryRunDefault: z.literal(true),
        requireActiveRecordExclusionProof: z.literal(true),
        requireArtifactAllowlist: z.literal(true),
        sqliteMaintenanceRequiresExclusiveAccess: z.literal(true)
      })
      .strict(),
    warnings: z.array(z.string().min(1)).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    const stores = new Set<string>();
    for (const [index, store] of value.stores.entries()) {
      if (stores.has(store.storeId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "store ids must be unique",
          path: ["stores", index, "storeId"]
        });
      }
      stores.add(store.storeId);
      if (!value.scope.includes(store.root)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "store root must be listed in policy scope",
          path: ["stores", index, "root"]
        });
      }
    }
  });
export type SecureLocalStorePolicy = z.infer<typeof SecureLocalStorePolicySchema>;

export const ServiceContractManifestSchema = z
  .object({
    /** Optional editor hint pointing at the JSON Schema; ignored at runtime. */
    $schema: z.string().min(1).optional(),
    schema: z.literal(SCHEMA_IDS.serviceContract),
    name: AppNameSchema,
    class: RepoClassSchema,
    contractVersion: z.literal(SERVICE_CONTRACT_VERSION),
    /** Version of `@hasna/contracts` (the contract kit) the repo tracks. */
    kitVersion: z.string().min(1),
    description: z.string().min(1).optional(),
    bins: z.array(z.string().min(1)).default([]),
    storage: StorageContractSchema.optional(),
    hosting: z.array(HostingModeSchema).min(1).default(["user-hosted"]),
    deploymentModes: z.array(DeploymentModeSchema).default(["local"]),
    serviceSurfaces: z.array(ServiceSurfaceSchema).default([]),
    metadata: ServiceContractMetadataSchema.optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (new Set(value.hosting).size !== value.hosting.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "hosting must not contain duplicates",
        path: ["hosting"]
      });
    }
    if (new Set(value.deploymentModes).size !== value.deploymentModes.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "deploymentModes must not contain duplicates after alias normalization",
        path: ["deploymentModes"]
      });
    }
    const allowed = new Set(allowedBinsForName(value.name));
    const seenBins = new Set<string>();
    for (const [index, bin] of value.bins.entries()) {
      if (seenBins.has(bin)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Duplicate bin declaration", path: ["bins", index] });
      }
      seenBins.add(bin);
      if (!allowed.has(bin)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `Bin "${bin}" is not allowlisted for app "${value.name}"; allowed: ${[...allowed].join(", ")}`,
          path: ["bins", index]
        });
      }
    }

    const hasBin = (suffix: string) => seenBins.has(`${value.name}${suffix}`);

    if (value.storage) {
      const upper = value.name.toUpperCase().replace(/-/g, "_");
      if (value.storage.envPrefix && value.storage.envPrefix !== `HASNA_${upper}_`) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `storage.envPrefix must be HASNA_${upper}_`,
          path: ["storage", "envPrefix"]
        });
      }
      if (value.storage.databaseUrlSecretRef && value.storage.databaseUrlSecretRef !== databaseUrlSecretRefFor(value.name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `storage.databaseUrlSecretRef must be ${databaseUrlSecretRefFor(value.name)}`,
          path: ["storage", "databaseUrlSecretRef"]
        });
      }
    }

    if (value.class === "library") {
      if (value.storage) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "library repos must not declare storage", path: ["storage"] });
      }
      if (hasBin("-serve") || hasBin("-mcp")) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "library repos must not ship a -serve or -mcp bin",
          path: ["bins"]
        });
      }
    }

    if (value.class === "cli-with-store") {
      if (!value.storage) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "cli-with-store repos must declare storage", path: ["storage"] });
      } else {
        if (value.storage.mode === "local" && !value.storage.sqlitePath) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "local cli-with-store storage requires sqlitePath (~/.hasna/<name>/<name>.db)",
            path: ["storage", "sqlitePath"]
          });
        }
        if (value.storage.engines && (!value.storage.engines.includes("sqlite") || !value.storage.engines.includes("postgres"))) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "cli-with-store storage.engines must declare both sqlite and postgres",
            path: ["storage", "engines"]
          });
        }
      }
      if (!seenBins.has(value.name)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `cli-with-store repos must ship the "${value.name}" bin`, path: ["bins"] });
      }
    }

    if (value.class === "service") {
      if (!value.storage) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "service repos must declare storage", path: ["storage"] });
      } else if (value.storage.engines && (!value.storage.engines.includes("sqlite") || !value.storage.engines.includes("postgres"))) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "service storage.engines must declare both sqlite and postgres",
          path: ["storage", "engines"]
        });
      }
      if (!hasBin("-serve")) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `service repos must ship the "${value.name}-serve" bin`, path: ["bins"] });
      }
      if (value.serviceSurfaces.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "service repos must declare at least one service surface",
          path: ["serviceSurfaces"]
        });
      }
    }

    if (value.class === "saas") {
      if (!value.storage) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "saas repos must declare storage", path: ["storage"] });
      } else {
        if (value.storage.mode !== "cloud") {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: "saas repos must use cloud storage mode", path: ["storage", "mode"] });
        }
        if (!value.storage.envPrefix) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "saas storage requires envPrefix for the public DATABASE_URL contract",
            path: ["storage", "envPrefix"]
          });
        }
      }
      if (!hasBin("-serve")) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `saas repos must ship the "${value.name}-serve" bin`, path: ["bins"] });
      }
      if (value.serviceSurfaces.length === 0) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "saas repos must declare at least one service surface", path: ["serviceSurfaces"] });
      }
    }

    for (const [index, surface] of value.serviceSurfaces.entries()) {
      if (surface.bin && !seenBins.has(surface.bin)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `Service surface bin "${surface.bin}" must be declared in bins`,
          path: ["serviceSurfaces", index, "bin"]
        });
      }
      if (surface.mcpBin && !seenBins.has(surface.mcpBin)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `Service surface MCP bin "${surface.mcpBin}" must be declared in bins`,
          path: ["serviceSurfaces", index, "mcpBin"]
        });
      }
      for (const [modeIndex, deploymentMode] of surface.deploymentModes.entries()) {
        if (!value.deploymentModes.includes(deploymentMode)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Service surface deployment mode "${deploymentMode}" must be declared in deploymentModes`,
            path: ["serviceSurfaces", index, "deploymentModes", modeIndex]
          });
        }
      }
    }

    const waivedKinds = value.metadata?.conformance?.waivedSurfaces ?? [];
    const seenWaivers = new Set<ServiceSurfaceKind>();
    for (const [index, waiver] of waivedKinds.entries()) {
      if (seenWaivers.has(waiver.kind)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `Duplicate conformance waiver for ${waiver.kind}`,
          path: ["metadata", "conformance", "waivedSurfaces", index, "kind"]
        });
      }
      seenWaivers.add(waiver.kind);
    }
  });
export type ServiceContractManifest = z.infer<typeof ServiceContractManifestSchema>;

/** Shape of `GET /health` for a Hasna service (`{ status, version, mode }`). */
export const HealthResponseSchema = z
  .object({
    status: z.enum(["ok", "degraded", "unavailable"]),
    version: z.string().min(1),
    mode: StorageModeSchema
  })
  .strict();
export type HealthResponse = z.infer<typeof HealthResponseSchema>;

/** Shape of `GET /ready`. */
export const ReadyResponseSchema = z
  .object({
    ready: z.boolean(),
    reason: z.string().min(1).optional()
  })
  .strict();
export type ReadyResponse = z.infer<typeof ReadyResponseSchema>;

/** Shape of `GET /version`. */
export const VersionResponseSchema = z
  .object({
    version: z.string().min(1)
  })
  .strict();
export type VersionResponse = z.infer<typeof VersionResponseSchema>;

// ---------------------------------------------------------------------------
// Fleet comms wire schemas (Hasna fleet comms workflow v1.1)
//
// Machine-validatable wire shapes for the fleet communication protocol:
//   1. `hasna.comms_event_envelope.v1` — the event envelope carried in
//      conversations message `--metadata` (never parsed from message text).
//   2. `hasna.comms_channel_metadata.v1` — the object stored under a
//      conversations channel's `metadata.channel_schema` key.
//   3. `hasna.comms_message_metadata.v1` — structured metadata for
//      severity-tagged posts ([FREEZE]/[UNFREEZE]/[BREAKING]/[CUTOVER]/
//      [POLICY]/[RELEASE] exact-case first token).
//
// Naming: the comms-specific wire fields are snake_case (`affected_packages`,
// `affected_machines`, `action_required`, `ack_by`, `dedupe_key`) because they
// are the canonical keys deterministic sweepers and hooks read from message
// metadata with jq; the shared contract envelope fields (`schema`, `id`,
// `createdAt`) keep the registry-wide camelCase convention.
//
// The human-facing rules live in knowledge item `hasna-agent-comms-protocol`;
// the severity mapping documentation lives in `hasna-agent-comms-envelope`,
// which cross-references these schema ids as the machine-validatable source
// of truth.
// ---------------------------------------------------------------------------

/** Fleet comms severity ladder (one severity system fleet-wide). */
export const CommsSeveritySchema = z.enum(["info", "notice", "breaking", "critical"]);
export type CommsSeverity = z.infer<typeof CommsSeveritySchema>;

/**
 * Namespaced comms event type: `<source>.<entity>.<action>` style, 2-4
 * lowercase dot-separated segments (e.g. `fleet.freeze`, `release.published`,
 * `comms.protocol.bumped`, `cloud.cutover.step`).
 */
export const CommsEventTypeSchema = z
  .string()
  .regex(
    /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$/,
    "Comms event types must be 2-4 lowercase dot-separated segments (<source>.<entity>.<action>)"
  );
export type CommsEventType = z.infer<typeof CommsEventTypeSchema>;

/** Severity tags allowed as the exact-case first token of tagged posts. */
export const COMMS_SEVERITY_TAGS = ["FREEZE", "UNFREEZE", "BREAKING", "CUTOVER", "POLICY", "RELEASE"] as const;
export const CommsSeverityTagSchema = z.enum(COMMS_SEVERITY_TAGS);
export type CommsSeverityTag = z.infer<typeof CommsSeverityTagSchema>;

/**
 * The one channel-tag <-> severity <-> event-type mapping table for the known
 * fleet event types. `defaultSeverity` is the publisher default; only
 * `fleet.freeze`/`fleet.unfreeze` pin severity hard (always critical).
 * `tag` is the announcements severity tag a post for this event type carries
 * (null = the event posts without a severity tag, e.g. to incidents).
 */
export const COMMS_EVENT_TYPES: Readonly<
  Record<string, { readonly defaultSeverity: CommsSeverity; readonly tag: CommsSeverityTag | null }>
> = {
  "release.published": { defaultSeverity: "info", tag: "RELEASE" },
  "release.breaking": { defaultSeverity: "breaking", tag: "BREAKING" },
  "config.changed": { defaultSeverity: "notice", tag: null },
  "comms.protocol.bumped": { defaultSeverity: "breaking", tag: "POLICY" },
  "incident.opened": { defaultSeverity: "critical", tag: null },
  "incident.resolved": { defaultSeverity: "notice", tag: null },
  "cloud.cutover.step": { defaultSeverity: "notice", tag: "CUTOVER" },
  "fleet.freeze": { defaultSeverity: "critical", tag: "FREEZE" },
  "fleet.unfreeze": { defaultSeverity: "critical", tag: "UNFREEZE" },
  "fleet.directive": { defaultSeverity: "notice", tag: null }
} as const;

/** Default severity for a known comms event type, null when unregistered. */
export function defaultSeverityForCommsEventType(type: string): CommsSeverity | null {
  return COMMS_EVENT_TYPES[type]?.defaultSeverity ?? null;
}

/** Blast-radius scope of a comms event. */
export const CommsScopeSchema = z.enum(["fleet", "package", "machine"]);
export type CommsScope = z.infer<typeof CommsScopeSchema>;

export const CommsEventEnvelopeSchema = contractBaseSchema(SCHEMA_IDS.commsEventEnvelope)
  .extend({
    type: CommsEventTypeSchema,
    severity: CommsSeveritySchema,
    scope: CommsScopeSchema,
    summary: z.string().min(1).optional(),
    source: ActorPointerSchema.optional(),
    affected_packages: z.array(NonEmptyStringSchema).default([]),
    affected_machines: z.array(NonEmptyStringSchema).default([]),
    action_required: z.boolean().default(false),
    ack_by: TimestampSchema.optional(),
    dedupe_key: NonEmptyStringSchema,
    resourceRefs: z.array(ResourcePointerSchema).default([]),
    evidenceRefs: z.array(EvidencePointerSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.scope === "package" && value.affected_packages.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Package-scoped comms events require affected_packages",
        path: ["affected_packages"]
      });
    }
    if (value.scope === "machine" && value.affected_machines.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Machine-scoped comms events require affected_machines",
        path: ["affected_machines"]
      });
    }
    if (value.ack_by && !value.action_required) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Comms events with an ack_by deadline require action_required",
        path: ["action_required"]
      });
    }
    if (value.type === "fleet.freeze" || value.type === "fleet.unfreeze") {
      if (value.severity !== "critical") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${value.type} events are always critical`,
          path: ["severity"]
        });
      }
      if (value.scope !== "fleet") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${value.type} events are always fleet-scoped`,
          path: ["scope"]
        });
      }
      if (!value.action_required) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${value.type} events require action_required`,
          path: ["action_required"]
        });
      }
    }
  });
export type CommsEventEnvelope = z.infer<typeof CommsEventEnvelopeSchema>;

/** Channel classes from the fleet channel taxonomy. */
export const CommsChannelClassSchema = z.enum(["fleet", "package", "product", "loop-lane", "initiative", "personal"]);
export type CommsChannelClass = z.infer<typeof CommsChannelClassSchema>;

/** Noise classes: quiet (push-eligible) / work (digest-read) / firehose (never pushed). */
export const CommsChannelNoiseSchema = z.enum(["quiet", "work", "firehose"]);
export type CommsChannelNoise = z.infer<typeof CommsChannelNoiseSchema>;

/**
 * Machine-evaluatable channel horizon: an ISO date (`2026-08-01`), a UTC
 * timestamp, or a gate id (`gate:97610c99` — a todos task short id or uuid).
 * Free-form horizons ("soon") defeat the channel-hygiene loop, so they are
 * rejected at the wire.
 */
export const CommsUntilHorizonSchema = NonEmptyStringSchema.refine(
  (value) => /^(?:\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)?|gate:[0-9a-f][0-9a-f-]{7,35})$/.test(value),
  "until must be an ISO date (YYYY-MM-DD), a UTC timestamp, or a gate id (gate:<todos-id>)"
);
export type CommsUntilHorizon = z.infer<typeof CommsUntilHorizonSchema>;

/**
 * The object stored under a conversations channel's `metadata.channel_schema`
 * key. `id` is the channel name. Initiative channels must carry an owner and
 * an `until` horizon (an ISO date or a gate id such as `gate:97610c99`);
 * archived channels point at their successor channel.
 */
export const CommsChannelMetadataSchema = contractBaseSchema(SCHEMA_IDS.commsChannelMetadata)
  .extend({
    class: CommsChannelClassSchema,
    noise: CommsChannelNoiseSchema.optional(),
    owner: NonEmptyStringSchema.optional(),
    until: CommsUntilHorizonSchema.optional(),
    successor: NonEmptyStringSchema.optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.class === "initiative") {
      if (!value.owner) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Initiative channels require an owner",
          path: ["owner"]
        });
      }
      if (!value.until) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Initiative channels require an until horizon (date or gate id)",
          path: ["until"]
        });
      }
    }
  });
export type CommsChannelMetadata = z.infer<typeof CommsChannelMetadataSchema>;

/**
 * Per-tag severity constraints. `defaultSeverity` mirrors the mapping table;
 * `allowedSeverities` bounds what a tagged post may carry (`cloud.cutover.step`
 * is notice by default and breaking only for machines actually being cut).
 * `requiredEventType` pins tags that map to exactly one event type.
 */
export const COMMS_SEVERITY_TAG_INFO: Readonly<
  Record<
    CommsSeverityTag,
    {
      readonly defaultSeverity: CommsSeverity;
      readonly allowedSeverities: readonly CommsSeverity[];
      readonly requiredEventType: CommsEventType | null;
    }
  >
> = {
  FREEZE: { defaultSeverity: "critical", allowedSeverities: ["critical"], requiredEventType: "fleet.freeze" },
  UNFREEZE: { defaultSeverity: "critical", allowedSeverities: ["critical"], requiredEventType: "fleet.unfreeze" },
  BREAKING: { defaultSeverity: "breaking", allowedSeverities: ["breaking"], requiredEventType: null },
  CUTOVER: { defaultSeverity: "notice", allowedSeverities: ["notice", "breaking"], requiredEventType: null },
  POLICY: { defaultSeverity: "breaking", allowedSeverities: ["notice", "breaking"], requiredEventType: null },
  RELEASE: { defaultSeverity: "info", allowedSeverities: ["info", "notice"], requiredEventType: null }
} as const;

/**
 * Structured metadata a severity-tagged post carries in `--metadata`. The
 * message text must start with `[<tag>]` as its exact-case first token; the
 * event envelope rides inside the metadata, never parsed from text.
 */
export const CommsMessageMetadataSchema = contractBaseSchema(SCHEMA_IDS.commsMessageMetadata)
  .extend({
    tag: CommsSeverityTagSchema,
    envelope: CommsEventEnvelopeSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    const info = COMMS_SEVERITY_TAG_INFO[value.tag];
    if (!info.allowedSeverities.includes(value.envelope.severity)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `[${value.tag}] posts allow severities ${info.allowedSeverities.join(", ")}`,
        path: ["envelope", "severity"]
      });
    }
    if (info.requiredEventType && value.envelope.type !== info.requiredEventType) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `[${value.tag}] posts require event type ${info.requiredEventType}`,
        path: ["envelope", "type"]
      });
    }
    for (const [tag, tagInfo] of Object.entries(COMMS_SEVERITY_TAG_INFO)) {
      if (tagInfo.requiredEventType === value.envelope.type && value.tag !== tag) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${value.envelope.type} events must use the [${tag}] tag`,
          path: ["tag"]
        });
      }
    }
  });
export type CommsMessageMetadata = z.infer<typeof CommsMessageMetadataSchema>;

/** Renders the exact-case first token for a severity tag, e.g. `[FREEZE]`. */
export function commsSeverityTagToken(tag: CommsSeverityTag): string {
  return `[${tag}]`;
}

/**
 * Extracts the severity tag from a message text's first token. Exact case
 * only: `[FREEZE]` matches, `[freeze]`/`[Freeze]` and mid-text tags do not.
 * Leading whitespace is tolerated (tokenizers like `awk '{print $1}'` skip it).
 */
export function extractCommsSeverityTag(text: string): CommsSeverityTag | null {
  const firstWord = text.trimStart().split(/\s+/, 1)[0] ?? "";
  for (const tag of COMMS_SEVERITY_TAGS) {
    if (firstWord === `[${tag}]`) {
      return tag;
    }
  }
  return null;
}

export type CommsTaggedMessageValidationResult =
  | { success: true; tag: CommsSeverityTag; metadata: CommsMessageMetadata }
  | { success: false; tag: CommsSeverityTag | null; issues: z.ZodIssue[] };

/**
 * Validates a severity-tagged conversations post before it is sent: the text
 * must start with a known exact-case tag token, the structured metadata must
 * parse as `hasna.comms_message_metadata.v1`, and the metadata tag must match
 * the text token. Publishers, hooks, and loops call this before emit/post.
 */
export function validateCommsTaggedMessage(input: {
  text: string;
  metadata: unknown;
}): CommsTaggedMessageValidationResult {
  const tag = extractCommsSeverityTag(input.text);
  if (!tag) {
    return {
      success: false,
      tag: null,
      issues: [
        {
          code: z.ZodIssueCode.custom,
          message: `Severity-tagged posts must start with one of ${COMMS_SEVERITY_TAGS.map(commsSeverityTagToken).join(" ")} as the exact-case first token`,
          path: ["text"]
        }
      ]
    };
  }
  const parsed = CommsMessageMetadataSchema.safeParse(input.metadata);
  if (!parsed.success) {
    return { success: false, tag, issues: parsed.error.issues };
  }
  if (parsed.data.tag !== tag) {
    return {
      success: false,
      tag,
      issues: [
        {
          code: z.ZodIssueCode.custom,
          message: `Message text is tagged [${tag}] but metadata declares [${parsed.data.tag}]`,
          path: ["tag"]
        }
      ]
    };
  }
  return { success: true, tag, metadata: parsed.data };
}

export const ContractSchemaRegistry = {
  [SCHEMA_IDS.actorRef]: ActorRefSchema,
  [SCHEMA_IDS.resourceRef]: ResourceRefSchema,
  [SCHEMA_IDS.evidenceRef]: EvidenceRefSchema,
  [SCHEMA_IDS.workRun]: WorkRunSchema,
  [SCHEMA_IDS.taskToPrProjection]: TaskToPrProjectionSchema as z.ZodType<
    TaskToPrProjection,
    z.ZodTypeDef,
    TaskToPrProjectionInput
  >,
  [SCHEMA_IDS.decisionEnvelope]: DecisionEnvelopeSchema,
  [SCHEMA_IDS.costEstimate]: CostEstimateSchema,
  [SCHEMA_IDS.capabilityCard]: CapabilityCardSchema,
  [SCHEMA_IDS.providerLiveModeStandard]: ProviderLiveModeStandardSchema,
  [SCHEMA_IDS.contextPack]: ContextPackSchema,
  [SCHEMA_IDS.integrationRef]: IntegrationRefSchema,
  [SCHEMA_IDS.projectManifest]: ProjectManifestSchema,
  [SCHEMA_IDS.projectPanel]: ProjectPanelSchema,
  [SCHEMA_IDS.projectSnapshot]: ProjectSnapshotSchema,
  [SCHEMA_IDS.renderManifest]: RenderManifestSchema,
  [SCHEMA_IDS.agentTrajectory]: AgentTrajectorySchema,
  [SCHEMA_IDS.validationPlan]: ValidationPlanSchema,
  [SCHEMA_IDS.proofBundle]: ProofBundleSchema,
  [SCHEMA_IDS.scaffoldManifest]: ScaffoldManifestSchema,
  [SCHEMA_IDS.scaffoldInstallRecord]: ScaffoldInstallRecordSchema,
  [SCHEMA_IDS.appCloudManifest]: AppCloudManifestSchema,
  [SCHEMA_IDS.noCloudEvidencePack]: NoCloudEvidencePackSchema,
  [SCHEMA_IDS.secureLocalStorePolicy]: SecureLocalStorePolicySchema,
  [SCHEMA_IDS.serviceContract]: ServiceContractManifestSchema,
  [SCHEMA_IDS.commsEventEnvelope]: CommsEventEnvelopeSchema,
  [SCHEMA_IDS.commsChannelMetadata]: CommsChannelMetadataSchema,
  [SCHEMA_IDS.commsMessageMetadata]: CommsMessageMetadataSchema,
  [SCHEMA_IDS.app]: AppSchema,
  [SCHEMA_IDS.release]: ReleaseSchema,
  [SCHEMA_IDS.rolloutRecord]: RolloutRecordSchema,
  [SCHEMA_IDS.announcement]: AnnouncementSchema,
  [SCHEMA_IDS.audience]: AudienceSchema
} as const;

export type KnownSchemaId = keyof typeof ContractSchemaRegistry;

export type ContractBySchemaId = {
  [SCHEMA_IDS.actorRef]: ActorRef;
  [SCHEMA_IDS.resourceRef]: ResourceRef;
  [SCHEMA_IDS.evidenceRef]: EvidenceRef;
  [SCHEMA_IDS.workRun]: WorkRun;
  [SCHEMA_IDS.taskToPrProjection]: TaskToPrProjection;
  [SCHEMA_IDS.decisionEnvelope]: DecisionEnvelope;
  [SCHEMA_IDS.costEstimate]: CostEstimate;
  [SCHEMA_IDS.capabilityCard]: CapabilityCard;
  [SCHEMA_IDS.providerLiveModeStandard]: ProviderLiveModeStandard;
  [SCHEMA_IDS.contextPack]: ContextPack;
  [SCHEMA_IDS.integrationRef]: IntegrationRef;
  [SCHEMA_IDS.projectManifest]: ProjectManifest;
  [SCHEMA_IDS.projectPanel]: ProjectPanel;
  [SCHEMA_IDS.projectSnapshot]: ProjectSnapshot;
  [SCHEMA_IDS.renderManifest]: RenderManifest;
  [SCHEMA_IDS.agentTrajectory]: AgentTrajectory;
  [SCHEMA_IDS.validationPlan]: ValidationPlan;
  [SCHEMA_IDS.proofBundle]: ProofBundle;
  [SCHEMA_IDS.scaffoldManifest]: ScaffoldManifest;
  [SCHEMA_IDS.scaffoldInstallRecord]: ScaffoldInstallRecord;
  [SCHEMA_IDS.appCloudManifest]: AppCloudManifest;
  [SCHEMA_IDS.noCloudEvidencePack]: NoCloudEvidencePack;
  [SCHEMA_IDS.secureLocalStorePolicy]: SecureLocalStorePolicy;
  [SCHEMA_IDS.serviceContract]: ServiceContractManifest;
  [SCHEMA_IDS.commsEventEnvelope]: CommsEventEnvelope;
  [SCHEMA_IDS.commsChannelMetadata]: CommsChannelMetadata;
  [SCHEMA_IDS.commsMessageMetadata]: CommsMessageMetadata;
  [SCHEMA_IDS.app]: App;
  [SCHEMA_IDS.release]: Release;
  [SCHEMA_IDS.rolloutRecord]: RolloutRecord;
  [SCHEMA_IDS.announcement]: Announcement;
  [SCHEMA_IDS.audience]: Audience;
};

export type ActorRefInput = z.input<typeof ActorRefSchema>;
export type ResourceRefInput = z.input<typeof ResourceRefSchema>;
export type EvidenceRefInput = z.input<typeof EvidenceRefSchema>;
export type WorkRunInput = z.input<typeof WorkRunSchema>;
export type TaskToPrProjectionInput = z.input<typeof TaskToPrProjectionSchema>;
export type DecisionEnvelopeInput = z.input<typeof DecisionEnvelopeSchema>;
export type CostEstimateInput = z.input<typeof CostEstimateSchema>;
export type CapabilityCardInput = z.input<typeof CapabilityCardSchema>;
export type ProviderLiveModeStandardInput = z.input<typeof ProviderLiveModeStandardSchema>;
export type ContextPackInput = z.input<typeof ContextPackSchema>;
export type IntegrationRefInput = z.input<typeof IntegrationRefSchema>;
export type ProjectManifestInput = z.input<typeof ProjectManifestSchema>;
export type ProjectPanelInput = z.input<typeof ProjectPanelSchema>;
export type ProjectSnapshotInput = z.input<typeof ProjectSnapshotSchema>;
export type RenderManifestInput = z.input<typeof RenderManifestSchema>;
export type AgentTrajectoryInput = z.input<typeof AgentTrajectorySchema>;
export type ValidationPlanInput = z.input<typeof ValidationPlanSchema>;
export type ProofBundleInput = z.input<typeof ProofBundleSchema>;
export type ScaffoldManifestInput = z.input<typeof ScaffoldManifestSchema>;
export type ScaffoldInstallRecordInput = z.input<typeof ScaffoldInstallRecordSchema>;
export type AppCloudManifestInput = z.input<typeof AppCloudManifestSchema>;
export type NoCloudEvidencePackInput = z.input<typeof NoCloudEvidencePackSchema>;
export type SecureLocalStorePolicyInput = z.input<typeof SecureLocalStorePolicySchema>;
export type ServiceContractManifestInput = z.input<typeof ServiceContractManifestSchema>;
export type CommsEventEnvelopeInput = z.input<typeof CommsEventEnvelopeSchema>;
export type CommsChannelMetadataInput = z.input<typeof CommsChannelMetadataSchema>;
export type CommsMessageMetadataInput = z.input<typeof CommsMessageMetadataSchema>;
export type AppInput = z.input<typeof AppSchema>;
export type ReleaseInput = z.input<typeof ReleaseSchema>;
export type RolloutRecordInput = z.input<typeof RolloutRecordSchema>;
export type AnnouncementInput = z.input<typeof AnnouncementSchema>;
export type AudienceInput = z.input<typeof AudienceSchema>;
export type ActorPointerInput = z.input<typeof ActorPointerSchema>;
export type ResourcePointerInput = z.input<typeof ResourcePointerSchema>;
export type EvidencePointerInput = z.input<typeof EvidencePointerSchema>;

export type ContractInputBySchemaId = {
  [SCHEMA_IDS.actorRef]: ActorRefInput;
  [SCHEMA_IDS.resourceRef]: ResourceRefInput;
  [SCHEMA_IDS.evidenceRef]: EvidenceRefInput;
  [SCHEMA_IDS.workRun]: WorkRunInput;
  [SCHEMA_IDS.taskToPrProjection]: TaskToPrProjectionInput;
  [SCHEMA_IDS.decisionEnvelope]: DecisionEnvelopeInput;
  [SCHEMA_IDS.costEstimate]: CostEstimateInput;
  [SCHEMA_IDS.capabilityCard]: CapabilityCardInput;
  [SCHEMA_IDS.providerLiveModeStandard]: ProviderLiveModeStandardInput;
  [SCHEMA_IDS.contextPack]: ContextPackInput;
  [SCHEMA_IDS.integrationRef]: IntegrationRefInput;
  [SCHEMA_IDS.projectManifest]: ProjectManifestInput;
  [SCHEMA_IDS.projectPanel]: ProjectPanelInput;
  [SCHEMA_IDS.projectSnapshot]: ProjectSnapshotInput;
  [SCHEMA_IDS.renderManifest]: RenderManifestInput;
  [SCHEMA_IDS.agentTrajectory]: AgentTrajectoryInput;
  [SCHEMA_IDS.validationPlan]: ValidationPlanInput;
  [SCHEMA_IDS.proofBundle]: ProofBundleInput;
  [SCHEMA_IDS.scaffoldManifest]: ScaffoldManifestInput;
  [SCHEMA_IDS.scaffoldInstallRecord]: ScaffoldInstallRecordInput;
  [SCHEMA_IDS.appCloudManifest]: AppCloudManifestInput;
  [SCHEMA_IDS.noCloudEvidencePack]: NoCloudEvidencePackInput;
  [SCHEMA_IDS.secureLocalStorePolicy]: SecureLocalStorePolicyInput;
  [SCHEMA_IDS.serviceContract]: ServiceContractManifestInput;
  [SCHEMA_IDS.commsEventEnvelope]: CommsEventEnvelopeInput;
  [SCHEMA_IDS.commsChannelMetadata]: CommsChannelMetadataInput;
  [SCHEMA_IDS.commsMessageMetadata]: CommsMessageMetadataInput;
  [SCHEMA_IDS.app]: AppInput;
  [SCHEMA_IDS.release]: ReleaseInput;
  [SCHEMA_IDS.rolloutRecord]: RolloutRecordInput;
  [SCHEMA_IDS.announcement]: AnnouncementInput;
  [SCHEMA_IDS.audience]: AudienceInput;
};
