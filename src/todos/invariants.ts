import {
  TODOS_MANIFEST_VERSION,
  sha256TodosValue,
} from "./common";

export const TODOS_INVARIANT_REGISTRY_SCHEMA_ID = "hasna.todos.invariant_registry.v1" as const;

export interface TodosRuntimeInvariant {
  id: string;
  category:
    | "common"
    | "identity"
    | "authority"
    | "domain"
    | "response"
    | "operation"
    | "invocation"
    | "contract"
    | "transfer"
    | "projection"
    | "artifacts";
  schemaIds: readonly string[];
  description: string;
  jsonSchemaExpressible: boolean;
  runtimeValidatorIds: readonly string[];
}

function invariant(value: TodosRuntimeInvariant): TodosRuntimeInvariant {
  return Object.freeze(value);
}

const PAGE_SCHEMA_IDS = [
  "hasna.todos.response.capability_page.v1",
  "hasna.todos.response.task_page.v1",
  "hasna.todos.response.activity_page.v1",
  "hasna.todos.response.comment_page.v1",
  "hasna.todos.response.dependency_page.v1",
  "hasna.todos.response.project_page.v1",
  "hasna.todos.response.task_list_page.v1",
  "hasna.todos.response.plan_page.v1",
  "hasna.todos.response.agent_page.v1",
  "hasna.todos.response.saved_view_page.v1",
  "hasna.todos.response.verification_page.v1",
  "hasna.todos.response.task_file_page.v1",
  "hasna.todos.response.run_page.v1",
  "hasna.todos.response.run_event_page.v1",
  "hasna.todos.response.run_command_page.v1",
  "hasna.todos.response.run_file_page.v1",
  "hasna.todos.response.run_artifact_page.v1",
  "hasna.todos.response.git_commit_page.v1",
  "hasna.todos.response.git_ref_page.v1",
  "hasna.todos.response.projection_page.v1",
  "hasna.todos.response.migration_receipt_page.v1",
  "hasna.todos.response.deletion_record_page.v1",
  "hasna.todos.response.approval_page.v1",
  "hasna.todos.response.task_template_page.v1",
] as const;

export const TODOS_RUNTIME_INVARIANTS: readonly TodosRuntimeInvariant[] = Object.freeze([
  invariant({
    id: "todos.common.relative_path",
    category: "common",
    schemaIds: [
      "hasna.todos.task_file.v1",
      "hasna.todos.run_file.v1",
      "hasna.todos.git_commit.v1",
      "hasna.todos.request.task_file_record.v1",
      "hasna.todos.request.run_file_create.v1",
      "hasna.todos.request.git_commit_link.v1",
    ],
    description: "Non-portable domain paths are relative, traversal-free, and never absolute.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["common.relative_path_semantics"],
  }),
  invariant({
    id: "todos.identity.context_semantics",
    category: "identity",
    schemaIds: ["hasna.todos.identity_context.v1"],
    description: "Identity roles and scopes are unique and administrative audiences carry the administrative role.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["identity.context_semantics"],
  }),
  invariant({
    id: "todos.identity.authorization_binding",
    category: "identity",
    schemaIds: ["hasna.todos.identity_context.v1"],
    description: "Identity tenant, audience, scopes, and idempotency satisfy the requested operation.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["identity.authorization_binding"],
  }),
  invariant({
    id: "todos.authority.mode_binding",
    category: "authority",
    schemaIds: [
      "hasna.todos.authority_config.v1",
      "hasna.todos.authority_handshake.v1",
    ],
    description: "Local authorities have no endpoint and cloud authorities require one HTTPS endpoint.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "authority.config_semantics",
      "authority.handshake_semantics",
    ],
  }),
  invariant({
    id: "todos.authority.capability_uniqueness",
    category: "authority",
    schemaIds: [
      "hasna.todos.authority_config.v1",
      "hasna.todos.authority_handshake.v1",
    ],
    description: "Authority capability identifiers are unique.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "authority.config_semantics",
      "authority.handshake_semantics",
    ],
  }),
  invariant({
    id: "todos.authority.canonical_binding",
    category: "authority",
    schemaIds: ["hasna.todos.authority_handshake.v1"],
    description: "Authority handshakes bind exact current digests and the sorted capability inventory.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "authority.canonical_binding",
      "authority.validate_canonical_handshake",
    ],
  }),
  invariant({
    id: "todos.domain.task_record",
    category: "domain",
    schemaIds: ["hasna.todos.task.v1"],
    description: "Task tags are unique and completed tasks carry a completion timestamp.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["domain.task_record_semantics"],
  }),
  invariant({
    id: "todos.domain.task_status_transition",
    category: "domain",
    schemaIds: ["hasna.todos.task.v1"],
    description: "Task status transitions follow the closed lifecycle and terminal states do not reopen.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["domain.task_status_transition"],
  }),
  invariant({
    id: "todos.domain.agent_role_uniqueness",
    category: "domain",
    schemaIds: ["hasna.todos.agent.v1"],
    description: "Agent role identifiers are unique.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["domain.agent_role_uniqueness"],
  }),
  invariant({
    id: "todos.domain.dependency_self_reference",
    category: "domain",
    schemaIds: ["hasna.todos.dependency.v1"],
    description: "A dependency cannot point a task at itself.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["domain.dependency_self_reference"],
  }),
  invariant({
    id: "todos.domain.git_object_id",
    category: "domain",
    schemaIds: ["hasna.todos.git_object_id.v1"],
    description: "Git object identifiers have the exact hexadecimal length required by their algorithm.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["domain.git_object_id"],
  }),
  invariant({
    id: "todos.response.page_count",
    category: "response",
    schemaIds: PAGE_SCHEMA_IDS,
    description: "Every page count equals the exact number of returned items.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["response.page_count"],
  }),
  invariant({
    id: "todos.operation.manifest_semantics",
    category: "operation",
    schemaIds: ["hasna.todos.operation_manifest.v1"],
    description: "Operation identifiers and surfaces are unique, derived, mode-correct, and semantically complete.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["operation.manifest_semantics"],
  }),
  invariant({
    id: "todos.operation.task_update_nonempty",
    category: "operation",
    schemaIds: ["hasna.todos.request.task_update.v1"],
    description: "Task update requests contain at least one changed field.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["operation.task_update_nonempty"],
  }),
  invariant({
    id: "todos.operation.transfer_checkpoint_binding",
    category: "operation",
    schemaIds: ["hasna.todos.request.transfer_import_execute.v1"],
    description: "Transfer execution checkpoints bind the source, target, bundle, plan, and canonical digests.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["operation.transfer_checkpoint_binding"],
  }),
  invariant({
    id: "todos.invocation.canonical_digests",
    category: "invocation",
    schemaIds: ["hasna.todos.operation_invocation.v1"],
    description: "Operation invocations bind exact current contract and manifest digests.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "invocation.operation_binding",
      "invocation.validate_operation",
    ],
  }),
  invariant({
    id: "todos.invocation.authority_identity_binding",
    category: "invocation",
    schemaIds: ["hasna.todos.operation_invocation.v1"],
    description: "Invocation authority equals the validated organization and tenant identity.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "invocation.operation_binding",
      "invocation.validate_operation",
    ],
  }),
  invariant({
    id: "todos.invocation.operation_mode_scope_request",
    category: "invocation",
    schemaIds: ["hasna.todos.operation_invocation.v1"],
    description: "The operation, mode, scopes, idempotency, and typed request all match the manifest.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "invocation.operation_binding",
      "invocation.validate_operation",
    ],
  }),
  invariant({
    id: "todos.contract.digest_closure",
    category: "contract",
    schemaIds: ["hasna.todos.contract.v1"],
    description: "The descriptor closes over current manifest, capability, schema, invariant, provenance, and generator digests.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "contract.digest_closure",
      "contract.verify_digest_closure",
    ],
  }),
  invariant({
    id: "todos.transfer.source_authority",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_bundle.v1"],
    description: "Every section, record, nested reference, projection, closure, attachment, and inventory entry has one source authority.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.bundle_owner_binding"],
  }),
  invariant({
    id: "todos.transfer.canonical_digests",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_bundle.v1"],
    description: "Public transfer validation binds exact current contract and manifest digests.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.canonical_digests"],
  }),
  invariant({
    id: "todos.transfer.execution_canonical_digests",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_import_execution.v1"],
    description: "Public import execution binds exact current contract and manifest digests.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.canonical_execution"],
  }),
  invariant({
    id: "todos.transfer.section_integrity",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_bundle.v1"],
    description: "Every section count and digest and the bundle checksum match canonical content.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.integrity"],
  }),
  invariant({
    id: "todos.transfer.classification",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_bundle.v1"],
    description: "Portable records exclude raw commands, arguments, paths, credentials, and execution internals.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.integrity"],
  }),
  invariant({
    id: "todos.transfer.reference_closure",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_bundle.v1"],
    description: "Every portable record participates in a complete transitive reference closure; projection predecessors resolve by exact owner, kind, id, version, and digest.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.integrity"],
  }),
  invariant({
    id: "todos.transfer.dependency_closure",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_bundle.v1"],
    description: "Task dependency closure is complete, deterministic, and acyclic.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.integrity"],
  }),
  invariant({
    id: "todos.transfer.attachment_content_addressing",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_bundle.v1"],
    description: "Evidence, command output, file, and artifact payloads are represented only by SHA-256 content references.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.integrity"],
  }),
  invariant({
    id: "todos.transfer.deletion_redaction",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_bundle.v1"],
    description: "Deletion history contains digest-only full-redaction tombstones and no raw payload.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.integrity"],
  }),
  invariant({
    id: "todos.transfer.import_plan",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_import_preview.v1"],
    description: "Import plans carry a deterministic id plus a content digest binding source and target authorities, canonical digests, bundle content, conflicts, and counts.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.import_plan_digest"],
  }),
  invariant({
    id: "todos.transfer.checkpoint_binding",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_checkpoint.v1"],
    description: "Checkpoints bind source, target, bundle id and digest, import-plan id and digest, contract and manifest digests, and idempotency.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.checkpoint_record"],
  }),
  invariant({
    id: "todos.transfer.checkpoint_monotonicity",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_checkpoint.v1"],
    description: "Checkpoint progress advances one canonical section at a time to one terminal state.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.checkpoint_transition"],
  }),
  invariant({
    id: "todos.transfer.execution_request_binding",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_import_execution.v1"],
    description: "Execution requests and optional checkpoints bind every source, target, digest, plan, bundle, and idempotency field.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.execution_request"],
  }),
  invariant({
    id: "todos.transfer.execution_context_closed",
    category: "transfer",
    schemaIds: ["hasna.todos.transfer_execution_context.v1"],
    description: "Execution context is exactly uncommitted or committed with one valid receipt; all unknown states fail closed.",
    jsonSchemaExpressible: true,
    runtimeValidatorIds: ["transfer.execution_context"],
  }),
  invariant({
    id: "todos.transfer.receipt_binding",
    category: "transfer",
    schemaIds: ["hasna.todos.migration_receipt.v1"],
    description: "Receipts bind source, target, bundle id and digest, import-plan id and digest, contract and manifest digests, counts, and one terminal checkpoint.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.receipt_record"],
  }),
  invariant({
    id: "todos.transfer.receipt_chain",
    category: "transfer",
    schemaIds: ["hasna.todos.migration_receipt.v1"],
    description: "Migration receipts form one strict digest-linked chain where each idempotency key has one canonical import tuple and terminal result; exact receipt replay never appends.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "transfer.receipt_chain",
      "transfer.public_receipt_chain",
    ],
  }),
  invariant({
    id: "todos.transfer.public_canonical_boundaries",
    category: "transfer",
    schemaIds: [
      "hasna.todos.request.transfer_import_execute.v1",
      "hasna.todos.response.migration_receipt.v1",
      "hasna.todos.response.migration_receipt_page.v1",
      "hasna.todos.transfer_checkpoint.v1",
      "hasna.todos.transfer_import_execution.v1",
      "hasna.todos.migration_receipt.v1",
    ],
    description: "Every public checkpoint, execution, receipt, transition, receipt-chain, and operation-map boundary rejects historical contract or manifest digests; version-neutral foundation, registry, and generated schemas remain internal structural inputs.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "operation.public_transfer_import_execute_canonical",
      "transfer.public_checkpoint_canonical",
      "transfer.public_receipt_canonical",
      "transfer.public_execution_request_canonical",
      "transfer.public_checkpoint_transition",
      "transfer.public_receipt_chain",
    ],
  }),
  invariant({
    id: "todos.transfer.replay_binding",
    category: "transfer",
    schemaIds: [
      "hasna.todos.transfer_import_execution.v1",
      "hasna.todos.transfer_execution_context.v1",
    ],
    description: "Only an identical committed import replays; conflicts and unknown context reject.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["transfer.execution_replay"],
  }),
  invariant({
    id: "todos.projection.opaque_refs",
    category: "projection",
    schemaIds: ["hasna.todos.task_to_pr_projection.v1"],
    description: "Projection references are opaque identifiers, never paths or URLs.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["projection.record_binding"],
  }),
  invariant({
    id: "todos.projection.owner_kind_binding",
    category: "projection",
    schemaIds: ["hasna.todos.task_to_pr_projection.v1"],
    description: "All identity, pull-request, proof, and predecessor refs match the projection owner and required kind.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["projection.record_binding"],
  }),
  invariant({
    id: "todos.projection.exact_head",
    category: "projection",
    schemaIds: ["hasna.todos.task_to_pr_projection.v1"],
    description: "Published, provider-observed, and equality-proof heads are complete and equal to the branch head.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["projection.head_binding"],
  }),
  invariant({
    id: "todos.projection.proof_identity",
    category: "projection",
    schemaIds: ["hasna.todos.task_to_pr_projection.v1"],
    description: "Proof references and digests are unique, owner-bound, kind-bound, and tied to the current head.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["projection.record_binding"],
  }),
  invariant({
    id: "todos.projection.digest_predecessor",
    category: "projection",
    schemaIds: ["hasna.todos.task_to_pr_projection.v1"],
    description: "Projection digests cover canonical content and successors bind exact immediate predecessors.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: [
      "projection.record_binding",
      "projection.transition",
    ],
  }),
  invariant({
    id: "todos.projection.full_history",
    category: "projection",
    schemaIds: ["hasna.todos.task_to_pr_projection.v1"],
    description: "Full histories reject missing links, ABA heads, repeats, substitutions, owner or kind drift, and stale heads.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["projection.history"],
  }),
  invariant({
    id: "todos.artifacts.canonical_bytes",
    category: "artifacts",
    schemaIds: ["hasna.todos.contract.v1"],
    description: "Checked-in artifacts match canonical regenerated bytes even when checksums are internally recomputed.",
    jsonSchemaExpressible: false,
    runtimeValidatorIds: ["artifacts.canonical_bytes"],
  }),
]);

export const TODOS_INVARIANT_REGISTRY = Object.freeze({
  schema: TODOS_INVARIANT_REGISTRY_SCHEMA_ID,
  version: TODOS_MANIFEST_VERSION,
  runtimeValidationRequired: true,
  invariants: TODOS_RUNTIME_INVARIANTS,
});

export const TODOS_INVARIANT_REGISTRY_DIGEST = sha256TodosValue(TODOS_INVARIANT_REGISTRY);

export function todosInvariantIdsForSchema(schemaId: string): string[] {
  return TODOS_RUNTIME_INVARIANTS
    .filter((entry) => entry.schemaIds.includes(schemaId))
    .map((entry) => entry.id)
    .sort((left, right) => left.localeCompare(right));
}
