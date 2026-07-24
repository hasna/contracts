import * as z from "zod/v4";
import {
  TODOS_CONTRACT_VERSION,
  TODOS_MANIFEST_VERSION,
} from "./common";
import {
  TodosAuthorityHandshakeSchema,
  type TodosAuthorityDescriptor,
  type TodosAuthorityHandshake,
} from "./authority";
import {
  TODOS_CAPABILITY_MANIFEST,
} from "./capabilities";
import {
  TODOS_CONTRACT_DIGEST,
} from "./contract";
import {
  TODOS_OPERATION_MANIFEST_DIGEST,
} from "./operations";

export const TODOS_CANONICAL_CAPABILITY_IDS = Object.freeze(
  TODOS_CAPABILITY_MANIFEST.capabilities
    .map((capability) => capability.id)
    .sort((left, right) => left.localeCompare(right)),
);

function canonicalAuthorityIssues(
  value: TodosAuthorityHandshake,
  ctx: z.RefinementCtx,
): void {
  if (value.contractDigest !== TODOS_CONTRACT_DIGEST) {
    ctx.addIssue({
      code: "custom",
      message: "Authority contract digest does not match this contract",
      path: ["contractDigest"],
    });
  }
  if (value.manifestDigest !== TODOS_OPERATION_MANIFEST_DIGEST) {
    ctx.addIssue({
      code: "custom",
      message: "Authority manifest digest does not match this operation manifest",
      path: ["manifestDigest"],
    });
  }
  if (
    value.capabilityIds.length !== TODOS_CANONICAL_CAPABILITY_IDS.length
    || value.capabilityIds.some(
      (capabilityId, index) => capabilityId !== TODOS_CANONICAL_CAPABILITY_IDS[index],
    )
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Authority capability ids must exactly equal the sorted canonical capability inventory",
      path: ["capabilityIds"],
    });
  }
}

// @todos-runtime-validator authority.canonical_binding
export const TodosCanonicalAuthorityHandshakeSchema =
  TodosAuthorityHandshakeSchema.superRefine(canonicalAuthorityIssues);

export interface CreateTodosAuthorityHandshakeInput {
  mode: "local" | "cloud";
  authority: TodosAuthorityDescriptor;
  issuedAt: string;
}

export function createTodosAuthorityHandshake(
  input: CreateTodosAuthorityHandshakeInput,
): TodosAuthorityHandshake {
  return TodosCanonicalAuthorityHandshakeSchema.parse({
    mode: input.mode,
    authority: input.authority,
    contractVersion: TODOS_CONTRACT_VERSION,
    contractDigest: TODOS_CONTRACT_DIGEST,
    manifestVersion: TODOS_MANIFEST_VERSION,
    manifestDigest: TODOS_OPERATION_MANIFEST_DIGEST,
    capabilityIds: TODOS_CANONICAL_CAPABILITY_IDS,
    issuedAt: input.issuedAt,
  });
}

// @todos-runtime-validator authority.validate_canonical_handshake
export function validateCanonicalTodosAuthorityHandshake(
  input: unknown,
): input is TodosAuthorityHandshake {
  return TodosCanonicalAuthorityHandshakeSchema.safeParse(input).success;
}
