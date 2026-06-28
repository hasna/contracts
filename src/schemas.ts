import { z } from "zod";

export const CONTRACTS_PACKAGE_NAME = "@hasna/contracts";
export const CONTRACTS_PACKAGE_VERSION = "0.2.1";

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
  proofBundle: "hasna.proof_bundle.v1",
  scaffoldManifest: "hasna.scaffold_manifest.v1",
  scaffoldInstallRecord: "hasna.scaffold_install_record.v1",
  appCloudManifest: "hasna.app_cloud_manifest.v1",
  noCloudEvidencePack: "hasna.no_cloud_evidence_pack.v1"
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
  [SCHEMA_IDS.proofBundle]: ProofBundleSchema,
  [SCHEMA_IDS.scaffoldManifest]: ScaffoldManifestSchema,
  [SCHEMA_IDS.scaffoldInstallRecord]: ScaffoldInstallRecordSchema,
  [SCHEMA_IDS.appCloudManifest]: AppCloudManifestSchema,
  [SCHEMA_IDS.noCloudEvidencePack]: NoCloudEvidencePackSchema
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
  [SCHEMA_IDS.scaffoldManifest]: ScaffoldManifest;
  [SCHEMA_IDS.scaffoldInstallRecord]: ScaffoldInstallRecord;
  [SCHEMA_IDS.appCloudManifest]: AppCloudManifest;
  [SCHEMA_IDS.noCloudEvidencePack]: NoCloudEvidencePack;
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
export type ScaffoldManifestInput = z.input<typeof ScaffoldManifestSchema>;
export type ScaffoldInstallRecordInput = z.input<typeof ScaffoldInstallRecordSchema>;
export type AppCloudManifestInput = z.input<typeof AppCloudManifestSchema>;
export type NoCloudEvidencePackInput = z.input<typeof NoCloudEvidencePackSchema>;
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
  [SCHEMA_IDS.scaffoldManifest]: ScaffoldManifestInput;
  [SCHEMA_IDS.scaffoldInstallRecord]: ScaffoldInstallRecordInput;
  [SCHEMA_IDS.appCloudManifest]: AppCloudManifestInput;
  [SCHEMA_IDS.noCloudEvidencePack]: NoCloudEvidencePackInput;
};
