import { z } from "zod";

export const CONTRACTS_PACKAGE_NAME = "@hasna/contracts";
export const CONTRACTS_PACKAGE_VERSION = "0.4.1";

export const SCHEMA_IDS = {
  actorRef: "hasna.actor_ref.v1",
  resourceRef: "hasna.resource_ref.v1",
  evidenceRef: "hasna.evidence_ref.v1",
  workRun: "hasna.work_run.v1",
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
  serviceContract: "hasna.service_contract.v1"
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
    secret: z.boolean().default(false),
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

export const AppCloudManifestSchema = contractBaseSchema(SCHEMA_IDS.appCloudManifest)
  .extend({
    packageName: z.string().min(1),
    packageVersion: z.string().min(1).optional(),
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
// version it targets, the contract-kit version it tracks, its declared bins,
// and its storage boundary. Storage runtime enum is `local | cloud` ONLY per
// Amendment A1 (PURE REMOTE): `cloud` sends reads AND writes straight to a
// cloud Postgres owned by the app; there is no sync engine, no cache-as-mode,
// and no hybrid/remote/self_hosted runtime. Those legacy words are accepted
// only as deprecated *aliases* that normalize to `cloud` (see src/mode.ts).
// ---------------------------------------------------------------------------

export const SERVICE_CONTRACT_VERSION = "v1";

export const RepoClassSchema = z.enum(["library", "cli-with-store", "service", "saas"]);
export type RepoClass = z.infer<typeof RepoClassSchema>;

export const DEPLOYMENT_MODES = ["local", "self-hosted", "cloud"] as const;
export const DeploymentModeSchema = z.enum(DEPLOYMENT_MODES);
export type DeploymentMode = z.infer<typeof DeploymentModeSchema>;

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
    deferReason: z.string().min(1).optional(),
    readinessGates: z.array(DeploymentReadinessGateSchema).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.status === "supported") {
      if (!value.bin) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported service surfaces require a serve bin", path: ["bin"] });
      }
      if (!value.health) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported service surfaces require a health endpoint", path: ["health"] });
      }
      if (!value.version) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supported service surfaces require a version endpoint", path: ["version"] });
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
    if (value.readiness && value.readiness.path !== "/ready") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Readiness endpoint must be /ready", path: ["readiness", "path"] });
    }
    if (value.version && value.version.path !== "/version") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Version endpoint must be /version", path: ["version", "path"] });
    }
  });
export type ServiceSurface = z.infer<typeof ServiceSurfaceSchema>;

/** Runtime storage enum. `local | cloud` ONLY (Amendment A1: PURE REMOTE). */
export const STORAGE_MODES = ["local", "cloud"] as const;
export const StorageModeSchema = z.enum(STORAGE_MODES);
export type StorageMode = z.infer<typeof StorageModeSchema>;

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

/** Canonical secret ref for an app database URL: `hasna/oss/<name>/database-url`. */
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
    /** Primary env prefix, e.g. `HASNA_TODOS_`. Defaults to `HASNA_<NAME>_`. */
    envPrefix: z.string().regex(/^HASNA_[A-Z][A-Z0-9]*_$/).optional(),
    /** Optional short alias env prefix, e.g. `TODOS_`. */
    aliasEnvPrefix: z.string().regex(/^[A-Z][A-Z0-9]*_$/).optional(),
    /** Secret Manager ref for the cloud database URL. */
    databaseUrlSecretRef: z
      .string()
      .regex(/^hasna\/oss\/[a-z0-9-]+\/database-url$/)
      .optional(),
    /** Local sqlite path (`~/.hasna/<name>/<name>.db`). */
    sqlitePath: z.string().min(1).optional()
  })
  .strict();
export type StorageContract = z.infer<typeof StorageContractSchema>;

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
    deploymentModes: z.array(DeploymentModeSchema).default(["local"]),
    serviceSurfaces: z.array(ServiceSurfaceSchema).default([]),
    metadata: MetadataSchema.optional()
  })
  .strict()
  .superRefine((value, ctx) => {
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
      if (value.storage.mode === "cloud" && !value.storage.databaseUrlSecretRef) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "cloud storage requires a databaseUrlSecretRef (PURE REMOTE: reads and writes go to cloud Postgres)",
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
      } else if (value.storage.mode === "local" && !value.storage.sqlitePath) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "local cli-with-store storage requires sqlitePath (~/.hasna/<name>/<name>.db)",
          path: ["storage", "sqlitePath"]
        });
      }
      if (!seenBins.has(value.name)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `cli-with-store repos must ship the "${value.name}" bin`, path: ["bins"] });
      }
    }

    if (value.class === "service") {
      if (!value.storage) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "service repos must declare storage", path: ["storage"] });
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
      } else if (value.storage.mode !== "cloud") {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "saas repos must use cloud storage mode", path: ["storage", "mode"] });
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

export const ContractSchemaRegistry = {
  [SCHEMA_IDS.actorRef]: ActorRefSchema,
  [SCHEMA_IDS.resourceRef]: ResourceRefSchema,
  [SCHEMA_IDS.evidenceRef]: EvidenceRefSchema,
  [SCHEMA_IDS.workRun]: WorkRunSchema,
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
  [SCHEMA_IDS.serviceContract]: ServiceContractManifestSchema
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
  [SCHEMA_IDS.serviceContract]: ServiceContractManifest;
};

export type ActorRefInput = z.input<typeof ActorRefSchema>;
export type ResourceRefInput = z.input<typeof ResourceRefSchema>;
export type EvidenceRefInput = z.input<typeof EvidenceRefSchema>;
export type WorkRunInput = z.input<typeof WorkRunSchema>;
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
export type ServiceContractManifestInput = z.input<typeof ServiceContractManifestSchema>;
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
  [SCHEMA_IDS.serviceContract]: ServiceContractManifestInput;
};
