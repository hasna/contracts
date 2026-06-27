import type { z } from "zod";
import { ContractSchemaRegistry, type ContractBySchemaId, type KnownSchemaId } from "./schemas";

export type EmbeddedContractValidationResult =
  | {
      success: true;
      schemaId: KnownSchemaId;
      data: ContractBySchemaId[KnownSchemaId];
    }
  | {
      success: false;
      schemaId: string | null;
      issues: z.ZodIssue[];
    };

export class ContractValidationError extends Error {
  readonly schemaId: string;
  readonly issues: z.ZodIssue[];

  constructor(schemaId: string, issues: z.ZodIssue[]) {
    super(`Contract validation failed for ${schemaId}`);
    this.name = "ContractValidationError";
    this.schemaId = schemaId;
    this.issues = issues;
  }
}

export function getContractSchema<TSchemaId extends KnownSchemaId>(schemaId: TSchemaId): (typeof ContractSchemaRegistry)[TSchemaId] {
  return ContractSchemaRegistry[schemaId];
}

export function getEmbeddedSchemaId(value: unknown): KnownSchemaId | null {
  if (!value || typeof value !== "object" || !("schema" in value)) {
    return null;
  }
  const schemaId = (value as { schema?: unknown }).schema;
  return typeof schemaId === "string" && schemaId in ContractSchemaRegistry ? (schemaId as KnownSchemaId) : null;
}

export function parseContract<TSchemaId extends KnownSchemaId>(
  schemaId: TSchemaId,
  value: unknown
): ContractBySchemaId[TSchemaId] {
  const schema = ContractSchemaRegistry[schemaId];
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new ContractValidationError(schemaId, parsed.error.issues);
  }
  return parsed.data as ContractBySchemaId[TSchemaId];
}

export function validateContract<TSchemaId extends KnownSchemaId>(
  schemaId: TSchemaId,
  value: unknown
): z.SafeParseReturnType<unknown, ContractBySchemaId[TSchemaId]> {
  const schema = ContractSchemaRegistry[schemaId];
  return schema.safeParse(value) as z.SafeParseReturnType<unknown, ContractBySchemaId[TSchemaId]>;
}

export function validateEmbeddedContract(value: unknown): EmbeddedContractValidationResult {
  const rawSchemaId = value && typeof value === "object" && "schema" in value ? (value as { schema?: unknown }).schema : null;
  const schemaId = getEmbeddedSchemaId(value);
  if (!schemaId) {
    return {
      success: false,
      schemaId: typeof rawSchemaId === "string" ? rawSchemaId : null,
      issues: [
        {
          code: "custom",
          message: "Contract object must include a known embedded schema id",
          path: ["schema"]
        }
      ]
    };
  }

  const result = validateContract(schemaId, value);
  if (result.success) {
    return { success: true, schemaId, data: result.data };
  }

  return { success: false, schemaId, issues: result.error.issues };
}

export function parseEmbeddedContract(value: unknown): ContractBySchemaId[KnownSchemaId] {
  const result = validateEmbeddedContract(value);
  if (!result.success) {
    throw new ContractValidationError(result.schemaId ?? "unknown", result.issues);
  }
  return result.data;
}
