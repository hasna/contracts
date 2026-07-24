import {
  TODOS_CONTRACT_VERSION,
  TODOS_MANIFEST_VERSION,
  canonicalizeTodosValue,
  sha256TodosText,
  sha256TodosValue,
  stableTodosJson,
} from "./common";
import {
  TODOS_CAPABILITY_MANIFEST,
} from "./capabilities";
import {
  TODOS_CONTRACT_DESCRIPTOR,
  TODOS_CONTRACT_DIGEST,
  validateTodosContractDescriptor,
} from "./contract";
import {
  buildTodosGeneratorProvenance,
  TODOS_GENERATOR_IDENTITY_DIGEST,
} from "./generator-provenance";
import {
  TODOS_INVARIANT_REGISTRY,
  TODOS_INVARIANT_REGISTRY_DIGEST,
} from "./invariants";
import {
  TodosIdentityContextSchema,
  TODOS_IDENTITY_SCHEMA_ID,
} from "./identity";
import {
  TODOS_OPERATION_INVOCATION_SCHEMA_ID,
} from "./invocation";
import {
  TODOS_OPERATION_MANIFEST,
  TODOS_OPERATION_MANIFEST_DIGEST,
  type TodosOperation,
} from "./operations";
import {
  createTaskToPrProjection,
  type TaskToPrOwnerRef,
  type TaskToPrProjection,
  type TaskToPrProjectionUnsigned,
} from "./projection";
import {
  buildTodosSchemaBundle,
} from "./schema-registry";
import {
  TODOS_SCHEMA_BUNDLE_DIGEST,
} from "./schema-foundation";
import {
  TODOS_TRANSFER_CLASSIFICATION,
  TODOS_TRANSFER_SECTION_NAMES,
  createTodosTransferBundle,
  type TodosTransferBundle,
  type TodosTransferBundleInput,
} from "./transfer";
import type {
  TodosDependency,
  TodosExternalOwnerRef,
  TodosProject,
  TodosTask,
} from "./domain";
import {
  createTodosAuthorityHandshake,
} from "./canonical-authority";
import {
  TODOS_CONTRACT_PROVENANCE,
  TODOS_PROVENANCE_DIGEST,
  TODOS_SOURCE_FREEZE,
} from "./provenance";

export const TODOS_GENERATED_ARTIFACT_ROOT = "generated/todos/v1" as const;

function prettyTodosJson(value: unknown): string {
  return `${JSON.stringify(canonicalizeTodosValue(value), null, 2)}\n`;
}

function schemaRef(schemaId: string): Record<string, string> {
  return { $ref: `#/components/schemas/${schemaId}` };
}

function schemaPropertyRef(schemaId: string, field: string): Record<string, string> {
  return {
    $ref: `#/components/schemas/${schemaId}/properties/${field}`,
  };
}

function jsonSchemaKind(
  schema: Record<string, unknown>,
  root: Record<string, unknown>,
  seen = new Set<string>(),
): "array" | "object" | "scalar" {
  if (schema.type === "array") return "array";
  if (schema.type === "object") return "object";
  if (typeof schema.$ref === "string" && schema.$ref.startsWith("#/")) {
    if (seen.has(schema.$ref)) return "scalar";
    seen.add(schema.$ref);
    const target = schema.$ref
      .slice(2)
      .split("/")
      .reduce<unknown>((value, segment) => (
        value && typeof value === "object"
          ? (value as Record<string, unknown>)[segment.replaceAll("~1", "/").replaceAll("~0", "~")]
          : undefined
      ), root);
    if (target && typeof target === "object") {
      return jsonSchemaKind(target as Record<string, unknown>, root, seen);
    }
  }
  for (const branchKey of ["anyOf", "oneOf"] as const) {
    const branches = schema[branchKey];
    if (Array.isArray(branches)) {
      for (const branch of branches) {
        if (branch && typeof branch === "object") {
          const kind = jsonSchemaKind(branch as Record<string, unknown>, root, seen);
          if (kind !== "scalar") return kind;
        }
      }
    }
  }
  return "scalar";
}

function requestParameters(
  operation: TodosOperation,
  schemas: Record<string, Record<string, unknown>>,
): Array<Record<string, unknown>> {
  const http = operation.surfaces.http;
  if (!http) return [];
  const requestSchema = schemas[operation.requestSchemaId];
  if (!requestSchema) {
    throw new Error(`Operation ${operation.id} request schema is missing from the schema bundle`);
  }
  const properties = (requestSchema.properties ?? {}) as Record<string, Record<string, unknown>>;
  const required = new Set(
    Array.isArray(requestSchema.required)
      ? requestSchema.required.filter((value): value is string => typeof value === "string")
      : [],
  );
  const pathFields = new Set(
    [...http.path.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((match) => match[1]!),
  );
  const parameters: Array<Record<string, unknown>> = [];
  for (const field of pathFields) {
    if (!properties[field]) {
      throw new Error(`Operation ${operation.id} path field ${field} is absent from its request schema`);
    }
    parameters.push({
      name: field,
      in: "path",
      required: true,
      schema: schemaPropertyRef(operation.requestSchemaId, field),
    });
  }
  if (http.method !== "GET") return parameters;
  for (const [field, propertySchema] of Object.entries(properties)) {
    if (pathFields.has(field)) continue;
    const base = {
      name: field,
      in: "query",
      required: required.has(field),
    };
    const propertyRef = schemaPropertyRef(operation.requestSchemaId, field);
    const kind = jsonSchemaKind(propertySchema, requestSchema);
    if (kind === "object") {
      parameters.push({
        ...base,
        content: {
          "application/json": {
            schema: propertyRef,
          },
        },
      });
    } else if (kind === "array") {
      parameters.push({
        ...base,
        style: "form",
        explode: true,
        schema: propertyRef,
      });
    } else {
      parameters.push({
        ...base,
        schema: propertyRef,
      });
    }
  }
  return parameters;
}

function invocationHeaderParameters(operation: TodosOperation) {
  const parameters: Array<Record<string, unknown>> = [
    {
      name: "X-Todos-Mode",
      in: "header",
      required: true,
      schema: { type: "string", enum: operation.supportedModes },
    },
    {
      name: "X-Todos-Authority-Id",
      in: "header",
      required: true,
      schema: { type: "string", pattern: "^[a-z][a-z0-9.-]*$" },
    },
    {
      name: "X-Todos-Contract-Digest",
      in: "header",
      required: true,
      schema: { type: "string", const: TODOS_CONTRACT_DIGEST },
    },
    {
      name: "X-Todos-Manifest-Digest",
      in: "header",
      required: true,
      schema: { type: "string", const: TODOS_OPERATION_MANIFEST_DIGEST },
    },
    {
      name: "X-Todos-Operation-Id",
      in: "header",
      required: true,
      schema: { type: "string", const: operation.id },
    },
    {
      name: "X-Todos-Request-Id",
      in: "header",
      required: true,
      schema: {
        type: "string",
        minLength: 8,
        maxLength: 160,
        pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]*$",
      },
    },
  ];
  if (operation.idempotency !== "none") {
    parameters.push({
      name: "Idempotency-Key",
      in: "header",
      required: operation.idempotency === "required",
      schema: {
        type: "string",
        minLength: 8,
        maxLength: 160,
        pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]*$",
      },
    });
  }
  return parameters;
}

function invocationContextBindings(operation: TodosOperation) {
  const http = operation.surfaces.http;
  if (!http) {
    throw new Error(`Operation ${operation.id} does not declare an HTTP surface`);
  }
  return {
    schema: schemaRef(TODOS_OPERATION_INVOCATION_SCHEMA_ID),
    fields: {
      mode: {
        source: { in: "header", name: "X-Todos-Mode" },
        target: "mode",
      },
      authorityId: {
        source: { in: "header", name: "X-Todos-Authority-Id" },
        target: "authorityId",
      },
      contractDigest: {
        source: { in: "header", name: "X-Todos-Contract-Digest" },
        target: "contractDigest",
      },
      manifestDigest: {
        source: { in: "header", name: "X-Todos-Manifest-Digest" },
        target: "manifestDigest",
      },
      operationId: {
        source: { in: "header", name: "X-Todos-Operation-Id" },
        target: "operationId",
      },
      identity: {
        source: { in: "security", name: "bearerAuth" },
        target: "identity",
        validated: true,
      },
      requestId: {
        source: { in: "header", name: "X-Todos-Request-Id" },
        target: "identity.requestId",
      },
      idempotencyKey: operation.idempotency === "none"
        ? null
        : {
          source: { in: "header", name: "Idempotency-Key" },
          target: "identity.idempotencyKey",
          required: operation.idempotency === "required",
        },
      request: {
        source: {
          in: http.method === "GET" ? "query" : "body",
          ...(http.method === "GET" ? {} : { mediaType: "application/json" }),
        },
        target: "request",
      },
    },
  };
}

export function buildTodosOpenApi(): Record<string, unknown> {
  const schemaBundle = buildTodosSchemaBundle();
  const paths: Record<string, Record<string, unknown>> = {};
  for (const operation of TODOS_OPERATION_MANIFEST.operations) {
    const http = operation.surfaces.http;
    if (!http) {
      continue;
    }
    const method = http.method.toLowerCase();
    paths[http.path] ??= {};
    paths[http.path]![method] = {
      operationId: operation.id,
      summary: `${operation.resource}.${operation.action}`,
      tags: [operation.capabilityId],
      security: [{ bearerAuth: [] }],
      parameters: [
        ...requestParameters(operation, schemaBundle.schemas),
        ...invocationHeaderParameters(operation),
      ],
      ...(http.method === "GET"
        ? {
          "x-todos-request-schema": schemaRef(operation.requestSchemaId),
        }
        : {
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: schemaRef(operation.requestSchemaId),
              },
            },
          },
        }),
      responses: {
        "200": {
          description: "Typed Todos response",
          content: {
            "application/json": {
              schema: schemaRef(operation.responseSchemaId),
            },
          },
        },
        default: {
          description: "Typed Todos error",
          content: {
            "application/json": {
              schema: schemaRef(operation.errorSchemaId),
            },
          },
        },
      },
      "x-todos-audience": operation.audience,
      "x-todos-modes": operation.supportedModes,
      "x-todos-required-scopes": operation.requiredScopes,
      "x-todos-identity-context-schema": schemaRef(TODOS_IDENTITY_SCHEMA_ID),
      "x-todos-invocation-context-schema": schemaRef(TODOS_OPERATION_INVOCATION_SCHEMA_ID),
      "x-todos-invocation-bindings": invocationContextBindings(operation),
      "x-todos-idempotency": operation.idempotency,
      "x-todos-concurrency": operation.concurrency,
    };
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "@hasna/contracts Todos",
      version: TODOS_CONTRACT_VERSION,
      description: "Pure customer contract for Todos local and cloud authorities.",
    },
    servers: [{ url: "/" }],
    security: [{ bearerAuth: [] }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "TodosIdentityContext",
        },
      },
      schemas: schemaBundle.schemas,
    },
    "x-hasna-invariants": TODOS_INVARIANT_REGISTRY,
    "x-todos-schema-digest": schemaBundle.schemaDigest,
    "x-todos-invariant-registry-digest": schemaBundle.invariantRegistryDigest,
    "x-todos-runtime-validation-required": true,
    paths,
  };
}

export function buildTodosSurfaceMap(): Record<string, unknown> {
  return {
    schema: "hasna.todos.surface_map.v1",
    version: TODOS_MANIFEST_VERSION,
    provenance: TODOS_CONTRACT_PROVENANCE,
    provenanceDigest: TODOS_PROVENANCE_DIGEST,
    operations: TODOS_OPERATION_MANIFEST.operations.map((operation) => ({
      id: operation.id,
      cli: operation.surfaces.cli,
      mcp: operation.surfaces.mcp,
      sdk: operation.surfaces.sdk,
      http: operation.surfaces.http,
    })),
  };
}

export function buildTodosConformanceProfile(): Record<string, unknown> {
  const shared = TODOS_OPERATION_MANIFEST.operations
    .filter((operation) => operation.classification === "shared_customer")
    .map((operation) => operation.id);
  const localTopology = TODOS_OPERATION_MANIFEST.operations
    .filter((operation) => operation.classification === "local_topology_only")
    .map((operation) => operation.id);
  return {
    schema: "hasna.todos.local_cloud_conformance.v1",
    contractVersion: TODOS_CONTRACT_VERSION,
    manifestVersion: TODOS_MANIFEST_VERSION,
    modes: ["local", "cloud"],
    authority: {
      count: 1,
    },
    sharedCustomerOperationIds: shared,
    localTopologyOperationIds: localTopology,
    invariants: {
      modeSelection: "explicit",
      sharedHttpPrefix: "/v1/",
      localTopologyHttpSurface: null,
      customerAudiences: ["customer", "tenant_admin"],
      capabilitySource: "operation_manifest",
      errorVocabulary: "typed",
    },
  };
}

function sampleOwnerRef<const T extends string>(
  kind: T,
  id: string,
  owner = "hasna.todos",
): TaskToPrOwnerRef & { kind: T } {
  return {
    owner,
    kind,
    id,
    digest: sha256TodosText(`${owner}:${kind}:${id}`),
  };
}

function sampleExternalOwnerRef(id: string): TodosExternalOwnerRef {
  return {
    owner: "tenant-a",
    id,
    digest: sha256TodosText(`tenant-a:${id}`),
  };
}

function sampleProjection(): TaskToPrProjection {
  const branchHead = { algorithm: "sha1" as const, value: "a".repeat(40) };
  const equalityProof = {
    ref: sampleOwnerRef("proof_bundle", "proof-head-equality"),
    kind: "head_equality" as const,
    head: branchHead,
    observedAt: "2026-07-24T00:00:00.000Z",
  };
  return createTaskToPrProjection({
    schema: "hasna.todos.task_to_pr_projection.v1",
    id: "projection-1",
    owner: "hasna.todos",
    version: 1,
    sequence: 1,
    predecessor: null,
    identity: {
      taskRef: sampleOwnerRef("task", "task-1"),
      repositoryRef: sampleOwnerRef("repository", "repo-1"),
      worktreeRef: sampleOwnerRef("worktree", "worktree-1"),
      branchRef: sampleOwnerRef("branch", "branch-1"),
      baseHead: { algorithm: "sha1", value: "b".repeat(40) },
    },
    pullRequestRef: sampleOwnerRef("pull_request", "pr-1"),
    head: {
      branchHead,
      publishedHead: branchHead,
      providerObservedHead: branchHead,
      equalityProof,
    },
    proofs: [{
      ref: sampleOwnerRef("proof_bundle", "proof-ci-1"),
      kind: "ci",
      head: branchHead,
      observedAt: "2026-07-24T00:00:00.000Z",
    }],
    derivedAt: "2026-07-24T00:00:00.000Z",
  });
}

function invalidProjectionSuccessor(previous: TaskToPrProjection): TaskToPrProjection {
  const unsigned: TaskToPrProjectionUnsigned = {
    schema: previous.schema,
    id: previous.id,
    owner: previous.owner,
    version: 2,
    sequence: 2,
    predecessor: {
      kind: "task_to_pr_projection",
      projectionId: previous.id,
      owner: previous.owner,
      version: previous.version,
      digest: sha256TodosText("wrong-predecessor"),
    },
    identity: previous.identity,
    pullRequestRef: previous.pullRequestRef,
    head: previous.head,
    proofs: previous.proofs,
    derivedAt: "2026-07-24T00:01:00.000Z",
  };
  return createTaskToPrProjection(unsigned);
}

function transferRecords(): TodosTransferBundleInput["records"] {
  const createdAt = "2026-07-24T00:00:00.000Z";
  const project: TodosProject = {
    id: "project-1",
    owner: "tenant-a",
    version: 1,
    createdAt,
    updatedAt: createdAt,
    slug: "contract-fixture",
    name: "Contract fixture",
    description: "Small transfer fixture",
    repositoryRef: sampleExternalOwnerRef("repository-1"),
    archivedAt: null,
  };
  const taskBase = {
    owner: "tenant-a",
    version: 1,
    createdAt,
    updatedAt: createdAt,
    shortId: null,
    description: null,
    status: "pending" as const,
    priority: "medium" as const,
    projectId: project.id,
    taskListId: null,
    planId: null,
    parentTaskId: null,
    assignedAgentId: null,
    fingerprint: null,
    tags: [],
    acceptanceCriteria: [],
    dueAt: null,
    completedAt: null,
    externalOwnerRefs: [],
  };
  const tasks: TodosTask[] = [
    { ...taskBase, id: "task-1", title: "Prepare contract" },
    { ...taskBase, id: "task-2", title: "Verify contract" },
  ];
  const dependency: TodosDependency = {
    id: "dependency-1",
    owner: "tenant-a",
    version: 1,
    createdAt,
    updatedAt: createdAt,
    sourceTaskId: "task-2",
    targetTaskId: "task-1",
    kind: "requires",
  };
  const taskFile: TodosTransferBundleInput["records"]["task_files"][number] = {
    id: "task-file-1",
    owner: "tenant-a",
    version: 1,
    createdAt,
    updatedAt: createdAt,
    taskId: "task-1",
    logicalName: "contract.json",
    contentRef: {
      algorithm: "sha256",
      digest: sha256TodosText("contract-fixture-content"),
      mediaType: "application/json",
      byteLength: 128,
    },
    purpose: "deliverable",
  };
  return {
    projects: [project],
    task_lists: [],
    plans: [],
    tasks,
    comments: [],
    dependencies: [dependency],
    activities: [],
    verification_evidence: [],
    task_files: [taskFile],
    runs: [],
    run_events: [],
    run_commands: [],
    run_files: [],
    run_artifacts: [],
    git_commits: [],
    git_refs: [],
    traceability: [],
    task_to_pr_projections: [],
    saved_views: [],
    task_templates: [],
    approvals: [],
    deletion_records: [{
      id: "deletion-1",
      owner: "tenant-a",
      entityKind: "task",
      entityIdDigest: sha256TodosText("deleted-task"),
      priorRecordDigest: sha256TodosText("deleted-task-record"),
      tombstoneVersion: 1,
      redaction: "full",
      reasonCode: "customer_request",
      deletedAt: createdAt,
    }],
  };
}

function sampleTransferBundle(): TodosTransferBundle {
  return createTodosTransferBundle({
    bundleId: "bundle-1",
    createdAt: "2026-07-24T00:00:00.000Z",
    source: {
      authorityId: "tenant-a",
      mode: "local",
    },
    records: transferRecords(),
  });
}

export function buildTodosFixtures(): Record<string, unknown> {
  const localAuthority = createTodosAuthorityHandshake({
    mode: "local",
    authority: {
      id: "tenant-a-local",
      kind: "local_installation",
      endpoint: null,
    },
    issuedAt: "2026-07-24T00:00:00.000Z",
  });
  const cloudAuthority = createTodosAuthorityHandshake({
    mode: "cloud",
    authority: {
      id: "tenant-a-cloud",
      kind: "cloud_tenant",
      endpoint: "https://todos.example.invalid/v1",
    },
    issuedAt: "2026-07-24T00:00:00.000Z",
  });
  const identity = TodosIdentityContextSchema.parse({
    issuer: "https://identity.example.invalid",
    audience: "customer",
    subject: "user-1",
    organizationId: "tenant-a",
    tenantId: "tenant-a",
    roles: ["customer_member"],
    scopes: ["todos:*"],
    keyId: "key-1",
    tokenId: "token-1",
    requestId: "request-1",
    agentId: null,
    sessionId: null,
    projectId: "project-1",
    taskListId: null,
    idempotencyKey: "request-key-1",
  });
  const invalidIdentity = { ...identity } as Record<string, unknown>;
  delete invalidIdentity.tenantId;

  const transfer = sampleTransferBundle();
  const invalidTransfer = structuredClone(transfer);
  invalidTransfer.sections.tasks.count += 1;

  const projection = sampleProjection();
  return {
    "fixtures/authority.local.valid.json": localAuthority,
    "fixtures/authority.cloud.valid.json": cloudAuthority,
    "fixtures/identity.valid.json": identity,
    "fixtures/identity.invalid.json": invalidIdentity,
    "fixtures/transfer.valid.json": transfer,
    "fixtures/transfer.invalid.json": invalidTransfer,
    "fixtures/projection.valid.json": projection,
    "fixtures/projection-transition.invalid.json": {
      previous: projection,
      current: invalidProjectionSuccessor(projection),
    },
  };
}

function baseArtifactValues(): Record<string, unknown> {
  return {
    "contract.json": {
      descriptor: TODOS_CONTRACT_DESCRIPTOR,
      digest: TODOS_CONTRACT_DIGEST,
    },
    "operation-manifest.json": TODOS_OPERATION_MANIFEST,
    "capability-manifest.json": TODOS_CAPABILITY_MANIFEST,
    "invariant-registry.json": TODOS_INVARIANT_REGISTRY,
    "generator-provenance.json": buildTodosGeneratorProvenance(TODOS_CONTRACT_DIGEST),
    "openapi.json": buildTodosOpenApi(),
    "schema-bundle.json": buildTodosSchemaBundle(),
    "surface-map.json": buildTodosSurfaceMap(),
    "transfer-classification.json": TODOS_TRANSFER_CLASSIFICATION,
    "local-cloud-conformance-profile.json": buildTodosConformanceProfile(),
    "source-freeze.json": TODOS_SOURCE_FREEZE,
    ...buildTodosFixtures(),
  };
}

export interface TodosRenderedArtifactVerification {
  valid: boolean;
  issues: string[];
}

// @todos-runtime-validator artifacts.canonical_bytes
export function verifyTodosRenderedArtifacts(
  rendered: Readonly<Record<string, string>>,
): TodosRenderedArtifactVerification {
  const issues: string[] = [];
  const canonical = renderTodosArtifacts();
  const canonicalPaths = [...new Set([
    ...Object.keys(canonical),
    ...Object.keys(rendered),
  ])].sort((left, right) => left.localeCompare(right));
  for (const path of canonicalPaths) {
    if (rendered[path] !== canonical[path]) {
      issues.push(`Canonical artifact mismatch: ${path}`);
    }
  }
  const checksumsText = rendered["checksums.json"];
  if (!checksumsText) {
    return { valid: false, issues: ["checksums.json is missing"] };
  }
  let checksums: {
    files?: Record<string, string>;
    aggregateDigest?: string;
  };
  try {
    checksums = JSON.parse(checksumsText) as typeof checksums;
  } catch {
    return { valid: false, issues: ["checksums.json is not valid JSON"] };
  }
  const expectedPaths = Object.keys(rendered)
    .filter((path) => path !== "checksums.json")
    .sort((left, right) => left.localeCompare(right));
  const checksumPaths = Object.keys(checksums.files ?? {})
    .sort((left, right) => left.localeCompare(right));
  if (stableTodosJson(expectedPaths) !== stableTodosJson(checksumPaths)) {
    issues.push("Checksum file list does not cover every artifact exactly");
  }
  for (const path of expectedPaths) {
    if (checksums.files?.[path] !== sha256TodosText(rendered[path]!)) {
      issues.push(`Checksum mismatch: ${path}`);
    }
  }
  if (checksums.aggregateDigest !== sha256TodosValue(checksums.files ?? {})) {
    issues.push("Checksum aggregate digest is invalid");
  }

  const parse = (path: string): Record<string, unknown> | null => {
    const content = rendered[path];
    if (!content) {
      issues.push(`${path} is missing`);
      return null;
    }
    try {
      return JSON.parse(content) as Record<string, unknown>;
    } catch {
      issues.push(`${path} is not valid JSON`);
      return null;
    }
  };
  const contract = parse("contract.json");
  if (
    !contract
    || contract.digest !== TODOS_CONTRACT_DIGEST
    || !validateTodosContractDescriptor(contract.descriptor)
  ) {
    issues.push("Contract descriptor or digest is invalid");
  }
  const manifest = parse("operation-manifest.json");
  if (!manifest || sha256TodosValue(manifest) !== TODOS_OPERATION_MANIFEST_DIGEST) {
    issues.push("Operation manifest digest is invalid");
  }
  const capabilities = parse("capability-manifest.json");
  if (
    !capabilities
    || sha256TodosValue(capabilities) !== TODOS_CONTRACT_DESCRIPTOR.capabilityManifestDigest
  ) {
    issues.push("Capability manifest digest is invalid");
  }
  const schemaBundle = parse("schema-bundle.json");
  if (
    !schemaBundle
    || schemaBundle.schemaDigest !== TODOS_SCHEMA_BUNDLE_DIGEST
    || sha256TodosValue(schemaBundle.schemas) !== TODOS_SCHEMA_BUNDLE_DIGEST
  ) {
    issues.push("Schema bundle digest is invalid");
  }
  const invariants = parse("invariant-registry.json");
  if (!invariants || sha256TodosValue(invariants) !== TODOS_INVARIANT_REGISTRY_DIGEST) {
    issues.push("Invariant registry digest is invalid");
  }
  const provenance = parse("generator-provenance.json");
  const {
    identityDigest: provenanceIdentityDigest,
    outputContractDigest: provenanceContractDigest,
    ...generatorIdentity
  } = provenance ?? {};
  if (
    !provenance
    || provenanceIdentityDigest !== TODOS_GENERATOR_IDENTITY_DIGEST
    || sha256TodosValue(generatorIdentity) !== TODOS_GENERATOR_IDENTITY_DIGEST
    || provenanceContractDigest !== TODOS_CONTRACT_DIGEST
  ) {
    issues.push("Generator provenance is invalid");
  }
  const sourceFreeze = parse("source-freeze.json");
  if (
    !sourceFreeze
    || stableTodosJson(sourceFreeze) !== stableTodosJson(TODOS_SOURCE_FREEZE)
  ) {
    issues.push("Source freeze is invalid");
  }
  const surfaceMap = parse("surface-map.json");
  if (
    !surfaceMap
    || surfaceMap.provenanceDigest !== TODOS_PROVENANCE_DIGEST
    || stableTodosJson(surfaceMap.provenance) !== stableTodosJson(TODOS_CONTRACT_PROVENANCE)
  ) {
    issues.push("Surface-map provenance is invalid");
  }
  return {
    valid: issues.length === 0,
    issues,
  };
}

export function renderTodosArtifacts(): Record<string, string> {
  const values = baseArtifactValues();
  const rendered = Object.fromEntries(
    Object.entries(values)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([path, value]) => [path, prettyTodosJson(value)]),
  );
  const checksums = Object.fromEntries(
    Object.entries(rendered)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([path, content]) => [path, sha256TodosText(content)]),
  );
  return {
    ...rendered,
    "checksums.json": prettyTodosJson({
      schema: "hasna.todos.artifact_checksums.v1",
      algorithm: "sha256",
      files: checksums,
      aggregateDigest: sha256TodosValue(checksums),
    }),
  };
}
