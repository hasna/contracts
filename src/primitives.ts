import { z } from "zod";

/**
 * Stable wire identifiers for the generic v1 contract primitives.
 *
 * An identifier is never repointed at a changed shape. Breaking wire changes
 * receive a new identifier and live beside v1 for an additive migration.
 */
export const CORE_SCHEMA_IDS = Object.freeze({
  error: "hasna.contracts.error.v1",
  principal: "hasna.contracts.principal.v1",
  tenantContext: "hasna.contracts.tenant_context.v1",
  idempotency: "hasna.contracts.idempotency.v1",
  eventEnvelope: "hasna.contracts.event_envelope.v1",
  blobRef: "hasna.contracts.blob_ref.v1",
  secretRef: "hasna.contracts.secret_ref.v1",
  compatibility: "hasna.contracts.compatibility.v1",
  operationDescriptor: "hasna.contracts.operation_descriptor.v1",
  capabilityDescriptor: "hasna.contracts.capability_descriptor.v1",
} as const);

export type CoreSchemaId = (typeof CORE_SCHEMA_IDS)[keyof typeof CORE_SCHEMA_IDS];

const NonEmptyStringSchema = z.string().trim().min(1);
const IdentifierSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$/);
const TimestampSchema = z.string().datetime({ offset: true });
const SemverSchema = z
  .string()
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/);
const Sha256Schema = z.string().regex(/^sha256:[a-f0-9]{64}$/);

function uniqueStrings(values: string[]): boolean {
  return new Set(values).size === values.length;
}

export const ErrorCategorySchema = z.enum([
  "validation",
  "authentication",
  "authorization",
  "not_found",
  "conflict",
  "rate_limit",
  "upstream",
  "internal",
]);
export type ErrorCategory = z.infer<typeof ErrorCategorySchema>;

export const ErrorSchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.error),
    code: IdentifierSchema,
    message: NonEmptyStringSchema,
    category: ErrorCategorySchema,
    retryable: z.boolean(),
    details: z.record(z.unknown()).optional(),
    correlationId: NonEmptyStringSchema.optional(),
  })
  .strict();
export type ContractError = z.infer<typeof ErrorSchema>;

export const PrincipalKindSchema = z.enum(["human", "service", "agent", "system"]);
export type PrincipalKind = z.infer<typeof PrincipalKindSchema>;

export const PrincipalSchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.principal),
    id: NonEmptyStringSchema.max(256),
    kind: PrincipalKindSchema,
    tenantId: NonEmptyStringSchema.max(256).optional(),
    displayName: NonEmptyStringSchema.max(256).optional(),
    roles: z.array(IdentifierSchema).default([]).refine(uniqueStrings, "roles must be unique"),
    scopes: z.array(IdentifierSchema).default([]).refine(uniqueStrings, "scopes must be unique"),
    claims: z.record(z.unknown()).optional(),
  })
  .strict();
export type Principal = z.infer<typeof PrincipalSchema>;

export const TenantContextSchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.tenantContext),
    tenantId: NonEmptyStringSchema.max(256),
    principal: PrincipalSchema,
    requestId: NonEmptyStringSchema.max(256),
    traceparent: z
      .string()
      .regex(/^[\da-f]{2}-[\da-f]{32}-[\da-f]{16}-[\da-f]{2}$/)
      .optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.principal.tenantId !== undefined && value.principal.tenantId !== value.tenantId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "principal tenantId must match the tenant context",
        path: ["principal", "tenantId"],
      });
    }
  });
export type TenantContext = z.infer<typeof TenantContextSchema>;

export const IdempotencySchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.idempotency),
    key: NonEmptyStringSchema.max(512),
    operationId: IdentifierSchema,
    requestDigest: Sha256Schema,
    createdAt: TimestampSchema,
    expiresAt: TimestampSchema.optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.expiresAt !== undefined && Date.parse(value.expiresAt) <= Date.parse(value.createdAt)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "expiresAt must be later than createdAt",
        path: ["expiresAt"],
      });
    }
  });
export type Idempotency = z.infer<typeof IdempotencySchema>;

export const EventEnvelopeSchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.eventEnvelope),
    specVersion: z.literal("1.0"),
    id: NonEmptyStringSchema.max(256),
    type: IdentifierSchema,
    source: z.string().url(),
    subject: NonEmptyStringSchema.max(512).optional(),
    time: TimestampSchema,
    dataSchema: z.string().url().optional(),
    dataContentType: NonEmptyStringSchema.max(256).optional(),
    tenant: TenantContextSchema.optional(),
    principal: PrincipalSchema.optional(),
    correlationId: NonEmptyStringSchema.max(256).optional(),
    causationId: NonEmptyStringSchema.max(256).optional(),
    idempotency: IdempotencySchema.optional(),
    data: z.unknown(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (
      value.tenant !== undefined
      && value.principal !== undefined
      && value.tenant.principal.id !== value.principal.id
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "top-level principal must match tenant principal",
        path: ["principal", "id"],
      });
    }
  });
export type EventEnvelope = z.infer<typeof EventEnvelopeSchema>;

export const BlobRefSchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.blobRef),
    uri: z.string().url(),
    digest: Sha256Schema,
    sizeBytes: z.number().int().nonnegative(),
    mediaType: NonEmptyStringSchema.max(256),
    fileName: NonEmptyStringSchema.max(1024).optional(),
    etag: NonEmptyStringSchema.max(512).optional(),
  })
  .strict();
export type BlobRef = z.infer<typeof BlobRefSchema>;

export const SecretRefSchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.secretRef),
    uri: z
      .string()
      .regex(/^(?:secret|vault|aws-sm|gcp-sm|azure-kv):\/\/[A-Za-z0-9][A-Za-z0-9._~!$&'()*+,;=:@/-]*$/),
    version: NonEmptyStringSchema.max(256).optional(),
    purpose: NonEmptyStringSchema.max(512).optional(),
  })
  .strict();
export type SecretRef = z.infer<typeof SecretRefSchema>;

export const CompatibilityStrategySchema = z.enum(["exact", "additive"]);
export type CompatibilityStrategy = z.infer<typeof CompatibilityStrategySchema>;

export const CompatibilitySchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.compatibility),
    contract: IdentifierSchema,
    currentVersion: SemverSchema,
    minimumVersion: SemverSchema,
    supportedVersions: z.array(SemverSchema).min(1).refine(uniqueStrings, "supportedVersions must be unique"),
    strategy: CompatibilityStrategySchema,
  })
  .strict()
  .superRefine((value, ctx) => {
    for (const [field, version] of [
      ["currentVersion", value.currentVersion],
      ["minimumVersion", value.minimumVersion],
    ] as const) {
      if (!value.supportedVersions.includes(version)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${field} must be listed in supportedVersions`,
          path: [field],
        });
      }
    }
  });
export type Compatibility = z.infer<typeof CompatibilitySchema>;

export const IdempotencyRequirementSchema = z.enum(["forbidden", "optional", "required"]);
export type IdempotencyRequirement = z.infer<typeof IdempotencyRequirementSchema>;
export const AuthorizationRequirementSchema = z.enum(["none", "principal", "tenant"]);
export type AuthorizationRequirement = z.infer<typeof AuthorizationRequirementSchema>;
export const OperationEffectSchema = z.enum(["none", "read", "write", "external"]);
export type OperationEffect = z.infer<typeof OperationEffectSchema>;
export const StabilitySchema = z.enum(["experimental", "stable", "deprecated"]);
export type Stability = z.infer<typeof StabilitySchema>;

export const OperationDescriptorSchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.operationDescriptor),
    id: IdentifierSchema,
    version: SemverSchema,
    summary: NonEmptyStringSchema.max(1024),
    inputSchema: NonEmptyStringSchema,
    outputSchema: NonEmptyStringSchema,
    errorSchemas: z.array(NonEmptyStringSchema).default([]).refine(uniqueStrings, "errorSchemas must be unique"),
    idempotency: IdempotencyRequirementSchema,
    authorization: AuthorizationRequirementSchema,
    effect: OperationEffectSchema,
    stability: StabilitySchema.default("stable"),
  })
  .strict();
export type OperationDescriptor = z.infer<typeof OperationDescriptorSchema>;

export const CapabilityDescriptorSchema = z
  .object({
    schema: z.literal(CORE_SCHEMA_IDS.capabilityDescriptor),
    id: IdentifierSchema,
    version: SemverSchema,
    summary: NonEmptyStringSchema.max(1024),
    operations: z.array(OperationDescriptorSchema).min(1),
    compatibility: CompatibilitySchema.optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const operationIds = value.operations.map((operation) => operation.id);
    if (!uniqueStrings(operationIds)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "operation ids must be unique within a capability",
        path: ["operations"],
      });
    }
  });
export type CapabilityDescriptor = z.infer<typeof CapabilityDescriptorSchema>;

export const CORE_SCHEMA_REGISTRY = Object.freeze({
  [CORE_SCHEMA_IDS.error]: ErrorSchema,
  [CORE_SCHEMA_IDS.principal]: PrincipalSchema,
  [CORE_SCHEMA_IDS.tenantContext]: TenantContextSchema,
  [CORE_SCHEMA_IDS.idempotency]: IdempotencySchema,
  [CORE_SCHEMA_IDS.eventEnvelope]: EventEnvelopeSchema,
  [CORE_SCHEMA_IDS.blobRef]: BlobRefSchema,
  [CORE_SCHEMA_IDS.secretRef]: SecretRefSchema,
  [CORE_SCHEMA_IDS.compatibility]: CompatibilitySchema,
  [CORE_SCHEMA_IDS.operationDescriptor]: OperationDescriptorSchema,
  [CORE_SCHEMA_IDS.capabilityDescriptor]: CapabilityDescriptorSchema,
} as const);

export type CoreContractBySchemaId = {
  [CORE_SCHEMA_IDS.error]: ContractError;
  [CORE_SCHEMA_IDS.principal]: Principal;
  [CORE_SCHEMA_IDS.tenantContext]: TenantContext;
  [CORE_SCHEMA_IDS.idempotency]: Idempotency;
  [CORE_SCHEMA_IDS.eventEnvelope]: EventEnvelope;
  [CORE_SCHEMA_IDS.blobRef]: BlobRef;
  [CORE_SCHEMA_IDS.secretRef]: SecretRef;
  [CORE_SCHEMA_IDS.compatibility]: Compatibility;
  [CORE_SCHEMA_IDS.operationDescriptor]: OperationDescriptor;
  [CORE_SCHEMA_IDS.capabilityDescriptor]: CapabilityDescriptor;
};

export class CoreValidationError extends Error {
  readonly schemaId: string;
  readonly issues: z.ZodIssue[];

  constructor(schemaId: string, issues: z.ZodIssue[]) {
    super(`Core contract validation failed for ${schemaId}`);
    this.name = "CoreValidationError";
    this.schemaId = schemaId;
    this.issues = issues;
  }
}

export function validateCoreContract<TSchemaId extends CoreSchemaId>(
  schemaId: TSchemaId,
  value: unknown,
): z.SafeParseReturnType<unknown, CoreContractBySchemaId[TSchemaId]> {
  return CORE_SCHEMA_REGISTRY[schemaId].safeParse(value) as z.SafeParseReturnType<
    unknown,
    CoreContractBySchemaId[TSchemaId]
  >;
}

export function parseCoreContract<TSchemaId extends CoreSchemaId>(
  schemaId: TSchemaId,
  value: unknown,
): CoreContractBySchemaId[TSchemaId] {
  const result = validateCoreContract(schemaId, value);
  if (!result.success) throw new CoreValidationError(schemaId, result.error.issues);
  return result.data;
}

export type EmbeddedCoreValidationResult =
  | { success: true; schemaId: CoreSchemaId; data: CoreContractBySchemaId[CoreSchemaId] }
  | { success: false; schemaId: string | null; issues: z.ZodIssue[] };

export function validateEmbeddedCoreContract(value: unknown): EmbeddedCoreValidationResult {
  const rawSchemaId = value !== null && typeof value === "object" && "schema" in value
    ? (value as { schema?: unknown }).schema
    : null;
  if (typeof rawSchemaId !== "string" || !(rawSchemaId in CORE_SCHEMA_REGISTRY)) {
    return {
      success: false,
      schemaId: typeof rawSchemaId === "string" ? rawSchemaId : null,
      issues: [{ code: "custom", message: "Unknown or missing core schema id", path: ["schema"] }],
    };
  }
  const schemaId = rawSchemaId as CoreSchemaId;
  const result = validateCoreContract(schemaId, value);
  return result.success
    ? { success: true, schemaId, data: result.data }
    : { success: false, schemaId, issues: result.error.issues };
}
