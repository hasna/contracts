import * as z from "zod/v4";
import {
  sha256TodosValue,
} from "./common";
import {
  TODOS_AUTHORITY_SCHEMAS,
} from "./authority";
import {
  TODOS_CAPABILITY_SCHEMAS,
} from "./capability-schema";
import {
  TODOS_CONTRACT_SCHEMAS,
} from "./contract-schema";
import {
  TODOS_DOMAIN_SCHEMAS,
} from "./domain";
import {
  TODOS_IDENTITY_SCHEMA_ID,
  TodosIdentityContextSchema,
} from "./identity";
import {
  todosInvariantIdsForSchema,
} from "./invariants";
import {
  TODOS_OPERATION_INVOCATION_SCHEMA_ID,
  TodosOperationInvocationEnvelopeSchema,
} from "./invocation-envelope";
import {
  TODOS_COMMON_SCHEMAS,
  TODOS_REQUEST_SCHEMAS,
  TODOS_RESPONSE_SCHEMAS,
} from "./operation-schemas";
import {
  TODOS_OPERATION_SCHEMAS,
} from "./operations";
import {
  TODOS_PROJECTION_SCHEMAS,
} from "./projection";
import {
  TODOS_PROVENANCE_SCHEMAS,
} from "./provenance";
import {
  TODOS_TRANSFER_SCHEMAS,
} from "./transfer-schema";

export const TODOS_SCHEMA_FOUNDATION_REGISTRY: Readonly<Record<string, z.ZodType>> =
  Object.freeze({
    ...TODOS_AUTHORITY_SCHEMAS,
    ...TODOS_CAPABILITY_SCHEMAS,
    ...TODOS_CONTRACT_SCHEMAS,
    ...TODOS_DOMAIN_SCHEMAS,
    [TODOS_IDENTITY_SCHEMA_ID]: TodosIdentityContextSchema,
    [TODOS_OPERATION_INVOCATION_SCHEMA_ID]: TodosOperationInvocationEnvelopeSchema,
    ...TODOS_COMMON_SCHEMAS,
    ...TODOS_REQUEST_SCHEMAS,
    ...TODOS_RESPONSE_SCHEMAS,
    ...TODOS_OPERATION_SCHEMAS,
    ...TODOS_PROJECTION_SCHEMAS,
    ...TODOS_PROVENANCE_SCHEMAS,
    ...TODOS_TRANSFER_SCHEMAS,
  });

export function buildTodosJsonSchemas(
  registry: Readonly<Record<string, z.ZodType>>,
): Record<string, Record<string, unknown>> {
  return Object.fromEntries(
    Object.entries(registry)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([schemaId, schema]) => {
        const jsonSchema = z.toJSONSchema(schema, {
          unrepresentable: "any",
          cycles: "ref",
          reused: "ref",
        }) as Record<string, unknown>;
        const invariantIds = todosInvariantIdsForSchema(schemaId);
        return [
          schemaId,
          {
            ...jsonSchema,
            $id: schemaId,
            ...(invariantIds.length > 0
              ? { "x-hasna-invariants": invariantIds }
              : {}),
          },
        ];
      }),
  );
}

export const TODOS_SCHEMA_FOUNDATION = Object.freeze(
  buildTodosJsonSchemas(TODOS_SCHEMA_FOUNDATION_REGISTRY),
);

export const TODOS_SCHEMA_BUNDLE_DIGEST = sha256TodosValue(TODOS_SCHEMA_FOUNDATION);
