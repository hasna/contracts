import { describe, expect, test } from "bun:test";
import { sha256TodosValue } from "../../src/todos/common";
import {
  TODOS_CAPABILITY_IDS,
  TODOS_OPERATION_MANIFEST,
  TODOS_OPERATION_MANIFEST_DIGEST,
  TODOS_OPERATION_MANIFEST_SCHEMA_ID,
  TODOS_OPERATION_SCHEMAS,
  TodosCapabilityIdSchema,
  TodosHttpSurfaceSchema,
  TodosOperationManifestSchema,
  TodosOperationSchema,
  getTodosOperation,
  type TodosOperation,
} from "../../src/todos/operations";

function operation(operationId: string): TodosOperation {
  const value = getTodosOperation(operationId);
  if (!value) throw new Error(`Missing test operation: ${operationId}`);
  return structuredClone(value);
}

function parseOperations(operations: TodosOperation[]) {
  return TodosOperationManifestSchema.safeParse({
    ...structuredClone(TODOS_OPERATION_MANIFEST),
    operations,
  });
}

function expectManifestIssue(operations: TodosOperation[], message: string): void {
  const result = parseOperations(operations);
  expect(result.success).toBe(false);
  if (result.success) return;
  expect(result.error.issues.map((issue) => issue.message)).toContain(message);
}

describe("Todos operations", () => {
  test("publishes a valid canonical manifest and its deterministic digest", () => {
    expect(TodosOperationManifestSchema.parse(structuredClone(TODOS_OPERATION_MANIFEST)))
      .toEqual(TODOS_OPERATION_MANIFEST);
    expect(TODOS_OPERATION_MANIFEST_DIGEST).toBe(sha256TodosValue(TODOS_OPERATION_MANIFEST));
    expect(TODOS_OPERATION_SCHEMAS[TODOS_OPERATION_MANIFEST_SCHEMA_ID])
      .toBe(TodosOperationManifestSchema);
  });

  test("looks up declared operations and returns undefined for absent ids", () => {
    expect(getTodosOperation("todos.tasks.create")).toMatchObject({
      resource: "tasks",
      action: "create",
      mutability: "write",
    });
    expect(getTodosOperation("todos.tasks.missing")).toBeUndefined();
    expect(getTodosOperation("")).toBeUndefined();
  });

  test("validates capability, HTTP surface, and operation boundaries", () => {
    const shared = operation("todos.service.health");

    expect(TodosCapabilityIdSchema.parse("tasks")).toBe("tasks");
    expect(TODOS_CAPABILITY_IDS).toContain("tasks");
    expect(TodosCapabilityIdSchema.safeParse("unknown").success).toBe(false);

    expect(TodosHttpSurfaceSchema.parse(shared.surfaces.http))
      .toEqual(shared.surfaces.http);
    expect(TodosHttpSurfaceSchema.safeParse(null).success).toBe(false);
    expect(TodosHttpSurfaceSchema.safeParse({
      ...shared.surfaces.http,
      unexpected: true,
    }).success).toBe(false);

    expect(TodosOperationSchema.parse(shared)).toEqual(shared);
    expect(TodosOperationSchema.safeParse({ ...shared, id: "tasks.health" }).success)
      .toBe(false);
    expect(TodosOperationSchema.safeParse(undefined).success).toBe(false);
    expect(parseOperations([]).success).toBe(false);
  });

  const semanticCases: Array<{
    name: string;
    message: string;
    operations: () => TodosOperation[];
  }> = [
    {
      name: "rejects duplicate operation ids",
      message: "Operation ids must be unique",
      operations: () => [operation("todos.service.health"), operation("todos.service.health")],
    },
    ...([
      ["CLI", "command"],
      ["MCP", "tool"],
      ["SDK", "method"],
    ] as const).map(([surface, field]) => ({
      name: `derives ${surface} mappings from the operation id`,
      message: `${surface} mapping must be derived from the canonical semantic operation id`,
      operations: () => {
        const value = operation("todos.service.health");
        value.surfaces[surface.toLowerCase() as "cli" | "mcp" | "sdk"][field] = "wrong";
        return [value];
      },
    })),
    ...([
      ["CLI", "cli", "command"],
      ["MCP", "mcp", "tool"],
      ["SDK", "sdk", "method"],
    ] as const).map(([label, surface, field]) => ({
      name: `rejects duplicate ${label} mappings`,
      message: `${label} mappings must be unique`,
      operations: () => {
        const first = operation("todos.service.health");
        const second = operation("todos.service.ready");
        second.surfaces[surface][field] = first.surfaces[surface][field];
        return [first, second];
      },
    })),
    {
      name: "rejects duplicate supported modes",
      message: "Supported modes must be unique",
      operations: () => {
        const value = operation("todos.service.health");
        value.supportedModes = ["local", "local"];
        return [value];
      },
    },
    {
      name: "rejects duplicate required scopes",
      message: "Required scopes must be unique",
      operations: () => {
        const value = operation("todos.service.health");
        value.requiredScopes.push(value.requiredScopes[0]!);
        return [value];
      },
    },
    {
      name: "requires shared operations to support local then cloud",
      message: "Shared customer operations must support local and cloud",
      operations: () => {
        const value = operation("todos.service.health");
        value.supportedModes = ["cloud", "local"];
        return [value];
      },
    },
    {
      name: "requires shared operations to expose an HTTP v1 path",
      message: "Shared customer operations require an HTTP path under /v1/",
      operations: () => {
        const value = operation("todos.service.health");
        value.surfaces.http = null;
        return [value];
      },
    },
    {
      name: "rejects duplicate HTTP method and path bindings",
      message: "HTTP method and path mappings must be unique",
      operations: () => {
        const first = operation("todos.service.health");
        const second = operation("todos.service.ready");
        second.surfaces.http = structuredClone(first.surfaces.http);
        return [first, second];
      },
    },
    {
      name: "rejects producer-specific API paths",
      message: "Customer HTTP mappings must not expose producer-specific /api routes",
      operations: () => {
        const value = operation("todos.service.health");
        value.surfaces.http!.path = "/v1/api/service/health";
        return [value];
      },
    },
    {
      name: "limits local-topology operations to local mode",
      message: "Local topology operations support local mode only",
      operations: () => {
        const value = operation("todos.server.start");
        value.supportedModes = ["local", "cloud"];
        return [value];
      },
    },
    {
      name: "forbids HTTP mappings on local-topology operations",
      message: "Local topology operations cannot have an HTTP mapping",
      operations: () => {
        const value = operation("todos.server.start");
        value.surfaces.http = structuredClone(operation("todos.service.health").surfaces.http);
        return [value];
      },
    },
    {
      name: "limits gated availability to declared gated capabilities",
      message: "Only declared gated capabilities may use gated availability",
      operations: () => {
        const value = operation("todos.service.health");
        value.availability = "gated";
        return [value];
      },
    },
    {
      name: "forbids mutation idempotency on reads",
      message: "Read operations do not require mutation idempotency",
      operations: () => {
        const value = operation("todos.service.health");
        value.idempotency = "required";
        return [value];
      },
    },
    {
      name: "forbids write scopes on reads",
      message: "Read operations cannot require write scopes",
      operations: () => {
        const value = operation("todos.service.health");
        value.requiredScopes = ["todos:authority:write"];
        return [value];
      },
    },
    {
      name: "requires idempotency on mutations",
      message: "Write, delete, and topology operations require idempotency",
      operations: () => {
        const value = operation("todos.tasks.create");
        value.idempotency = "none";
        return [value];
      },
    },
    {
      name: "forbids read-only scopes on mutations",
      message: "Mutating operations cannot use read-only scopes",
      operations: () => {
        const value = operation("todos.tasks.create");
        value.requiredScopes = ["todos:tasks:read"];
        return [value];
      },
    },
    {
      name: "forbids concurrency fields when concurrency is disabled",
      message: "Operations without concurrency controls cannot declare concurrency fields",
      operations: () => {
        const value = operation("todos.service.health");
        value.concurrencyFields = ["expectedVersion"];
        return [value];
      },
    },
    {
      name: "requires the expectedVersion field for version concurrency",
      message: "Version concurrency requires request.expectedVersion",
      operations: () => {
        const value = operation("todos.tasks.update");
        value.concurrencyFields = [];
        return [value];
      },
    },
    {
      name: "requires explicit fields for lock concurrency",
      message: "Lock and precondition concurrency require explicit request fields",
      operations: () => {
        const value = operation("todos.tasks.lock");
        value.concurrencyFields = [];
        return [value];
      },
    },
    {
      name: "requires a registered request schema",
      message: "Operation request schema is not registered",
      operations: () => {
        const value = operation("todos.service.health");
        value.requestSchemaId = "hasna.todos.request.missing.v1";
        return [value];
      },
    },
    {
      name: "requires concurrency fields to be required request properties",
      message: "Concurrency field missingField must be a required request property",
      operations: () => {
        const value = operation("todos.tasks.lock");
        value.concurrencyFields = ["missingField"];
        return [value];
      },
    },
    {
      name: "requires HTTP path parameters to be required request properties",
      message: "HTTP path parameter missingField must be a required request property",
      operations: () => {
        const value = operation("todos.service.health");
        value.surfaces.http!.path = "/v1/service/{missingField}";
        return [value];
      },
    },
    {
      name: "binds transition metadata to the matching task action",
      message: "Task transition metadata must bind start, complete, or fail with version concurrency",
      operations: () => {
        const value = operation("todos.tasks.start");
        value.transition = { machine: "task_status", targetStatus: "completed" };
        return [value];
      },
    },
  ];

  for (const semanticCase of semanticCases) {
    test(semanticCase.name, () => {
      expectManifestIssue(semanticCase.operations(), semanticCase.message);
    });
  }
});
