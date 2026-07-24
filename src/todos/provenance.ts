import * as z from "zod/v4";
import {
  TodosSha256DigestSchema,
  sha256TodosValue,
} from "./common";

export const TODOS_PROVENANCE_SCHEMA_ID = "hasna.todos.contract_provenance.v1" as const;

const TodosFrozenSourceSchema = z.strictObject({
  repository: z.string().min(1).max(160),
  commitSha: z.string().regex(/^[a-f0-9]{40}$/),
  role: z.enum([
    "contract_base",
    "open_todos_evidence",
    "platform_todos_evidence",
    "e_00115_projection_evidence",
  ]),
});

export const TodosSourceFreezeSchema = z.strictObject({
  contracts: TodosFrozenSourceSchema,
  openTodos: TodosFrozenSourceSchema,
  platformTodos: TodosFrozenSourceSchema,
  e00115: TodosFrozenSourceSchema,
});
export type TodosSourceFreeze = z.infer<typeof TodosSourceFreezeSchema>;

export const TODOS_SOURCE_FREEZE: TodosSourceFreeze = TodosSourceFreezeSchema.parse({
  contracts: {
    repository: "hasna/contracts",
    commitSha: "0c8c5b4205ceaf16b1cee26c30199249055c934e",
    role: "contract_base",
  },
  openTodos: {
    repository: "hasna/todos",
    commitSha: "a18a8b797eb1b05e92964dbf8b036dde972c2314",
    role: "open_todos_evidence",
  },
  platformTodos: {
    repository: "hasna/platform-todos",
    commitSha: "3d0bb21d586eed553e9010fc1187b19415958394",
    role: "platform_todos_evidence",
  },
  e00115: {
    repository: "hasna/contracts",
    commitSha: "142e650c7f13d05ac145bd37e986e68909d571d2",
    role: "e_00115_projection_evidence",
  },
});

export const TodosContractProvenanceSchema = z.strictObject({
  schema: z.literal(TODOS_PROVENANCE_SCHEMA_ID),
  sourceFreeze: TodosSourceFreezeSchema,
  surfaceMappings: z.strictObject({
    status: z.literal("required_target"),
    producerImplementationStatus: z.literal("not_attested"),
    evidenceUse: z.literal("design_input_only"),
    sharedHttpPrefix: z.literal("/v1"),
    localTopologyHttpSurface: z.null(),
    operatorAudienceIncluded: z.literal(false),
  }),
});
export type TodosContractProvenance = z.infer<typeof TodosContractProvenanceSchema>;

export const TODOS_CONTRACT_PROVENANCE: TodosContractProvenance =
  TodosContractProvenanceSchema.parse({
    schema: TODOS_PROVENANCE_SCHEMA_ID,
    sourceFreeze: TODOS_SOURCE_FREEZE,
    surfaceMappings: {
      status: "required_target",
      producerImplementationStatus: "not_attested",
      evidenceUse: "design_input_only",
      sharedHttpPrefix: "/v1",
      localTopologyHttpSurface: null,
      operatorAudienceIncluded: false,
    },
  });

export const TODOS_PROVENANCE_DIGEST = sha256TodosValue(TODOS_CONTRACT_PROVENANCE);

export const TODOS_PROVENANCE_SCHEMAS = Object.freeze({
  [TODOS_PROVENANCE_SCHEMA_ID]: TodosContractProvenanceSchema,
});
