import { describe, expect, test } from "bun:test";
import {
  TODOS_CAPABILITY_IDS,
  TODOS_CAPABILITY_MANIFEST,
  TODOS_CONTRACT_PROVENANCE,
  TODOS_DOMAIN_FIELD_CLASSIFICATION,
  TODOS_ERROR_CODES,
  TODOS_OPERATION_MANIFEST,
  TODOS_REQUEST_SCHEMA_IDS,
  TODOS_REQUEST_SCHEMAS,
  TODOS_RESPONSE_SCHEMA_IDS,
  TODOS_SOURCE_FREEZE,
  deriveTodosCapabilities,
  validateTodosTaskStatusTransition,
} from "../../src/todos";
import {
  TODOS_SCHEMA_REGISTRY,
  buildTodosSchemaBundle,
} from "../../src/todos/schema-registry";

function group(resource: string, actions: readonly string[]): string[] {
  return actions.map((action) => `todos.${resource}.${action}`);
}

const EXPECTED_SHARED_OPERATION_IDS = [
  ...group("service", ["health", "ready", "version"]),
  ...group("authority", ["get"]),
  ...group("manifest", ["get"]),
  ...group("openapi", ["get"]),
  ...group("capabilities", ["list", "get"]),
  ...group("tasks", [
    "list",
    "count",
    "exists_many",
    "create",
    "upsert",
    "get",
    "update",
    "delete",
    "batch",
    "start",
    "complete",
    "fail",
    "claim_next",
    "next",
    "list_ready",
    "list_active",
    "list_changed",
    "lock",
    "unlock",
    "get_context",
  ]),
  ...group("history", ["list"]),
  ...group("comments", ["list", "create"]),
  ...group("dependencies", ["list", "list_all", "create", "delete"]),
  ...group("projects", ["list", "create", "get", "update", "rename", "delete"]),
  ...group("task_lists", ["list", "create", "get", "update", "delete"]),
  ...group("plans", ["list", "create", "get", "update", "delete"]),
  ...group("agents", ["list", "register", "get", "heartbeat", "release"]),
  ...group("activity", ["list"]),
  ...group("stats", ["get"]),
  ...group("search", ["execute"]),
  ...group("saved_views", ["list", "create", "get", "update", "delete", "execute"]),
  ...group("verification_evidence", ["list", "create", "get", "export"]),
  ...group("task_files", ["list", "record"]),
  ...group("runs", ["list", "start", "get", "finish", "get_ledger"]),
  ...group("run_events", ["list", "create"]),
  ...group("run_commands", ["list", "create"]),
  ...group("run_files", ["list", "create"]),
  ...group("run_artifacts", ["list", "create", "verify"]),
  ...group("git_commits", ["list", "link", "unlink", "find"]),
  ...group("git_refs", ["list", "link", "find"]),
  ...group("traceability", ["get"]),
  ...group("task_to_pr_projection", ["list", "get"]),
  ...group("transfer", ["export", "validate", "import_preview", "import_execute"]),
  ...group("migration_receipts", ["list", "get"]),
  ...group("deletion_records", ["list", "get"]),
  ...group("approvals", ["list", "get", "request", "approve", "reject", "expire"]),
  ...group("task_templates", ["list", "create", "get", "update", "delete", "instantiate"]),
  ...group("reports", ["generate"]),
];

const EXPECTED_LOCAL_OPERATION_IDS = [
  ...group("workspace", ["bootstrap"]),
  ...group("server", ["start"]),
  ...group("database", ["backup", "restore", "check", "compact"]),
  ...group("offline_upgrade", ["validate", "execute"]),
  ...group("task_to_pr_projection", ["rebuild"]),
];

describe("Todos operation manifest", () => {
  test("freezes the complete requested inventory", () => {
    const shared = TODOS_OPERATION_MANIFEST.operations
      .filter((operation) => operation.classification === "shared_customer")
      .map((operation) => operation.id);
    const local = TODOS_OPERATION_MANIFEST.operations
      .filter((operation) => operation.classification === "local_topology_only")
      .map((operation) => operation.id);

    expect(shared).toEqual(EXPECTED_SHARED_OPERATION_IDS);
    expect(local).toEqual(EXPECTED_LOCAL_OPERATION_IDS);
    expect(TODOS_OPERATION_MANIFEST.operations).toHaveLength(125);
    expect(shared).toHaveLength(116);
    expect(local).toHaveLength(9);
  });

  test("has unique complete schema, error, and surface references", () => {
    const operationIds = TODOS_OPERATION_MANIFEST.operations.map((operation) => operation.id);
    const cliCommands = TODOS_OPERATION_MANIFEST.operations.map((operation) => operation.surfaces.cli.command);
    const mcpTools = TODOS_OPERATION_MANIFEST.operations.map((operation) => operation.surfaces.mcp.tool);
    const sdkMethods = TODOS_OPERATION_MANIFEST.operations.map((operation) => operation.surfaces.sdk.method);

    expect(new Set(operationIds).size).toBe(operationIds.length);
    expect(new Set(cliCommands).size).toBe(cliCommands.length);
    expect(new Set(mcpTools).size).toBe(mcpTools.length);
    expect(new Set(sdkMethods).size).toBe(sdkMethods.length);

    for (const operation of TODOS_OPERATION_MANIFEST.operations) {
      expect(TODOS_SCHEMA_REGISTRY[operation.requestSchemaId]).toBeDefined();
      expect(TODOS_SCHEMA_REGISTRY[operation.responseSchemaId]).toBeDefined();
      expect(TODOS_SCHEMA_REGISTRY[operation.errorSchemaId]).toBeDefined();
      expect(operation.requiredScopes.length).toBeGreaterThan(0);
      expect(operation.requiredScopes.every((scope) => scope.startsWith("todos:"))).toBe(true);
      expect(operation.surfaces.cli).toMatchObject({
        status: "required_target",
        producerImplementationStatus: "not_attested",
      });
      expect(operation.surfaces.mcp).toMatchObject({
        status: "required_target",
        producerImplementationStatus: "not_attested",
      });
      expect(operation.surfaces.sdk).toMatchObject({
        status: "required_target",
        producerImplementationStatus: "not_attested",
      });
      if (operation.surfaces.http) {
        expect(operation.surfaces.http).toMatchObject({
          status: "required_target",
          producerImplementationStatus: "not_attested",
        });
      }
    }
  });

  test("records target-only surface provenance against the exact frozen evidence commits", () => {
    expect(TODOS_OPERATION_MANIFEST.provenance).toEqual(TODOS_CONTRACT_PROVENANCE);
    expect(TODOS_CONTRACT_PROVENANCE).toEqual({
      schema: "hasna.todos.contract_provenance.v1",
      sourceFreeze: {
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
      },
      surfaceMappings: {
        status: "required_target",
        producerImplementationStatus: "not_attested",
        evidenceUse: "design_input_only",
        sharedHttpPrefix: "/v1",
        localTopologyHttpSurface: null,
        operatorAudienceIncluded: false,
      },
    });
    expect(TODOS_SOURCE_FREEZE).toEqual(TODOS_CONTRACT_PROVENANCE.sourceFreeze);
    expect(JSON.stringify(TODOS_OPERATION_MANIFEST)).not.toContain("platform_operator");
  });

  test("enforces shared and local-topology surface boundaries", () => {
    for (const operation of TODOS_OPERATION_MANIFEST.operations) {
      if (operation.classification === "shared_customer") {
        expect(operation.supportedModes).toEqual(["local", "cloud"]);
        expect(operation.surfaces.http).not.toBeNull();
        expect(operation.surfaces.http?.path.startsWith("/v1/")).toBe(true);
        expect(operation.surfaces.http?.path).not.toContain("/api");
      } else {
        expect(operation.supportedModes).toEqual(["local"]);
        expect(operation.surfaces.http).toBeNull();
      }
      expect(["customer", "tenant_admin"]).toContain(operation.audience);
    }

    const serialized = JSON.stringify(TODOS_OPERATION_MANIFEST);
    for (const excluded of [
      "machine_paths",
      "dashboards",
      "doctor",
      "shell_completion",
      "encryption_profiles",
      "webhooks",
      "billing",
      "hosted_worker",
      "raw_snapshot_import",
    ]) {
      expect(serialized).not.toContain(excluded);
    }
  });

  test("never represents an operation success as false or an empty envelope", () => {
    const responseIds = new Set(TODOS_OPERATION_MANIFEST.operations.map((operation) => operation.responseSchemaId));
    for (const schemaId of responseIds) {
      const schema = TODOS_SCHEMA_REGISTRY[schemaId]!;
      expect(schema.safeParse(false).success, schemaId).toBe(false);
      expect(schema.safeParse({}).success, schemaId).toBe(false);
      expect(schema.safeParse({ ok: true, requestId: "request-1" }).success, schemaId).toBe(false);
      expect(schema.safeParse({ ok: false, requestId: "request-1" }).success, schemaId).toBe(false);
    }
  });

  test("mechanically binds mutation, concurrency, transition, and server-start metadata", () => {
    const schemas = buildTodosSchemaBundle().schemas;
    for (const operation of TODOS_OPERATION_MANIFEST.operations) {
      const request = schemas[operation.requestSchemaId] as {
        properties?: Record<string, unknown>;
        required?: string[];
      };
      const required = new Set(request.required ?? []);
      if (operation.mutability === "read") {
        expect(operation.idempotency, operation.id).toBe("none");
      } else {
        expect(operation.idempotency, operation.id).toBe("required");
      }
      if (operation.concurrency === "none") {
        expect(operation.concurrencyFields, operation.id).toEqual([]);
      } else {
        expect(operation.concurrencyFields.length, operation.id).toBeGreaterThan(0);
        for (const field of operation.concurrencyFields) {
          expect(request.properties, `${operation.id}:${field}`).toHaveProperty(field);
          expect(required.has(field), `${operation.id}:${field}`).toBe(true);
        }
      }
      if (operation.concurrency === "version") {
        expect(operation.concurrencyFields, operation.id).toEqual(["expectedVersion"]);
      }
    }

    const transitions = TODOS_OPERATION_MANIFEST.operations
      .filter((operation) => operation.transition !== null)
      .map((operation) => ({
        id: operation.id,
        transition: operation.transition,
        requestSchemaId: operation.requestSchemaId,
      }));
    expect(transitions).toEqual([
      {
        id: "todos.tasks.start",
        transition: { machine: "task_status", targetStatus: "in_progress" },
        requestSchemaId: TODOS_REQUEST_SCHEMA_IDS.taskStart,
      },
      {
        id: "todos.tasks.complete",
        transition: { machine: "task_status", targetStatus: "completed" },
        requestSchemaId: TODOS_REQUEST_SCHEMA_IDS.taskComplete,
      },
      {
        id: "todos.tasks.fail",
        transition: { machine: "task_status", targetStatus: "failed" },
        requestSchemaId: TODOS_REQUEST_SCHEMA_IDS.taskFail,
      },
    ]);

    const requestBase = {
      ref: "task-1",
      expectedVersion: 1,
      summary: null,
    };
    expect(TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.taskStart].safeParse({
      ...requestBase,
      targetStatus: "in_progress",
    }).success).toBe(true);
    expect(TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.taskStart].safeParse({
      ...requestBase,
      targetStatus: "completed",
    }).success).toBe(false);
    expect(TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.taskComplete].safeParse({
      ...requestBase,
      targetStatus: "completed",
    }).success).toBe(true);
    expect(TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.taskFail].safeParse({
      ...requestBase,
      targetStatus: "failed",
    }).success).toBe(true);

    const serverStart = TODOS_OPERATION_MANIFEST.operations.find(
      (operation) => operation.id === "todos.server.start",
    )!;
    expect(serverStart).toMatchObject({
      classification: "local_topology_only",
      supportedModes: ["local"],
      concurrency: "precondition",
      concurrencyFields: ["expectedState"],
      requestSchemaId: TODOS_REQUEST_SCHEMA_IDS.serverStart,
      responseSchemaId: TODOS_RESPONSE_SCHEMA_IDS.serverStart,
      surfaces: { http: null },
    });
    const serverStartSchema = TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.serverStart];
    expect(serverStartSchema.safeParse({
      interface: "loopback",
      port: 4317,
      expectedState: "stopped",
    }).success).toBe(true);
    expect(serverStartSchema.safeParse({
      interface: "loopback",
      port: 4317,
      authorityId: "tenant-a",
    }).success).toBe(false);

    expect(validateTodosTaskStatusTransition("pending", "in_progress")).toEqual({
      success: true,
      replayed: false,
      terminal: false,
    });
    expect(validateTodosTaskStatusTransition("in_progress", "completed")).toEqual({
      success: true,
      replayed: false,
      terminal: true,
    });
    expect(validateTodosTaskStatusTransition("completed", "in_progress")).toEqual({
      success: false,
      reason: "terminal_status",
      allowedTargets: [],
    });
  });
});

describe("Todos capability inventory", () => {
  test("derives exactly from operation rows", () => {
    expect(deriveTodosCapabilities()).toEqual(TODOS_CAPABILITY_MANIFEST.capabilities);
    expect(TODOS_CAPABILITY_MANIFEST.capabilities.map((capability) => capability.id)).toEqual(
      [...TODOS_CAPABILITY_IDS].sort((left, right) => left.localeCompare(right)),
    );

    const byId = new Map(TODOS_CAPABILITY_MANIFEST.capabilities.map((capability) => [capability.id, capability]));
    expect(byId.get("cursor-pagination")?.operationIds).toEqual(
      TODOS_OPERATION_MANIFEST.operations
        .filter((operation) => operation.pagination === "cursor")
        .map((operation) => operation.id)
        .sort((left, right) => left.localeCompare(right)),
    );
    expect(byId.get("idempotency")?.operationIds).toEqual(
      TODOS_OPERATION_MANIFEST.operations
        .filter((operation) => operation.idempotency !== "none")
        .map((operation) => operation.id)
        .sort((left, right) => left.localeCompare(right)),
    );
    expect(byId.get("optimistic-concurrency")?.operationIds).toEqual(
      TODOS_OPERATION_MANIFEST.operations
        .filter((operation) => operation.concurrency === "version")
        .map((operation) => operation.id)
        .sort((left, right) => left.localeCompare(right)),
    );
    expect(byId.get("typed-errors")?.operationIds).toHaveLength(125);
    expect(byId.get("approvals")?.availability).toBe("gated");
    expect(byId.get("task-templates")?.availability).toBe("gated");
    expect(byId.get("reports")?.availability).toBe("gated");
  });
});

describe("Todos schema registry", () => {
  test("contains every declared request, response, and error schema once", () => {
    const declared = [
      ...Object.values(TODOS_REQUEST_SCHEMA_IDS),
      ...Object.values(TODOS_RESPONSE_SCHEMA_IDS),
    ];
    expect(new Set(declared).size).toBe(declared.length);
    expect(TODOS_ERROR_CODES.length).toBeGreaterThan(20);
    for (const schemaId of declared) {
      expect(TODOS_SCHEMA_REGISTRY[schemaId]).toBeDefined();
    }
  });

  test("classifies every public domain field", () => {
    const schemaBundle = buildTodosSchemaBundle();
    for (const [schemaId, classification] of Object.entries(TODOS_DOMAIN_FIELD_CLASSIFICATION)) {
      const jsonSchema = schemaBundle.schemas[schemaId] as { properties?: Record<string, unknown> };
      expect(Object.keys(classification).sort(), schemaId).toEqual(Object.keys(jsonSchema.properties ?? {}).sort());
      expect(Object.values(classification).every((value) => ["portable", "reference_only", "excluded"].includes(value))).toBe(true);
    }
  });
});
