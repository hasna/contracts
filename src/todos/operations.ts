import * as z from "zod/v4";
import {
  TODOS_MANIFEST_VERSION,
  TodosAudienceSchema,
  TodosModeSchema,
  sha256TodosValue,
} from "./common";
import {
  TODOS_COMMON_SCHEMA_IDS,
  TODOS_REQUEST_SCHEMA_IDS,
  TODOS_REQUEST_SCHEMAS,
  TODOS_RESPONSE_SCHEMA_IDS,
} from "./operation-schemas";
import {
  TodosTaskStatusSchema,
} from "./domain";
import {
  TODOS_CONTRACT_PROVENANCE,
  TodosContractProvenanceSchema,
} from "./provenance";

export const TODOS_OPERATION_MANIFEST_SCHEMA_ID = "hasna.todos.operation_manifest.v1" as const;

export const TODOS_CAPABILITY_IDS = [
  "authority",
  "tasks",
  "projects",
  "task-lists",
  "plans",
  "agents",
  "comments",
  "dependencies",
  "activity",
  "search",
  "saved-views",
  "verification-evidence",
  "task-files",
  "runs",
  "git-traceability",
  "task-to-pr-projection",
  "transfer",
  "deletion-history",
  "cursor-pagination",
  "idempotency",
  "optimistic-concurrency",
  "typed-errors",
  "approvals",
  "task-templates",
  "reports",
] as const;

export const TodosCapabilityIdSchema = z.enum(TODOS_CAPABILITY_IDS);
export type TodosCapabilityId = z.infer<typeof TodosCapabilityIdSchema>;

const TodosTargetSurfaceStatusShape = {
  status: z.literal("required_target"),
  producerImplementationStatus: z.literal("not_attested"),
} as const;

export const TodosHttpSurfaceSchema = z.strictObject({
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
  path: z.string().min(1).max(512),
  ...TodosTargetSurfaceStatusShape,
});

export const TodosOperationSchema = z.strictObject({
  id: z.string().regex(/^todos\.[a-z0-9_]+(?:\.[a-z0-9_]+)+$/),
  resource: z.string().min(1).max(96).regex(/^[a-z][a-z0-9_]*$/),
  action: z.string().min(1).max(96).regex(/^[a-z][a-z0-9_]*$/),
  classification: z.enum(["shared_customer", "local_topology_only"]),
  supportedModes: z.array(TodosModeSchema).min(1),
  audience: TodosAudienceSchema,
  capabilityId: TodosCapabilityIdSchema,
  availability: z.enum(["core", "gated"]),
  mutability: z.enum(["read", "write", "delete", "topology"]),
  idempotency: z.enum(["none", "optional", "required"]),
  concurrency: z.enum(["none", "version", "lock", "precondition"]),
  concurrencyFields: z.array(z.string().regex(/^[a-z][A-Za-z0-9]*$/)).max(8),
  transition: z.strictObject({
    machine: z.literal("task_status"),
    targetStatus: z.enum(["in_progress", "completed", "failed"]),
  }).nullable(),
  pagination: z.enum(["none", "cursor"]),
  requestSchemaId: z.string().min(1),
  responseSchemaId: z.string().min(1),
  errorSchemaId: z.literal(TODOS_COMMON_SCHEMA_IDS.error),
  requiredScopes: z.array(z.string().regex(/^todos:[a-z0-9-]+:(?:read|write|admin)$/)).min(1),
  surfaces: z.strictObject({
    cli: z.strictObject({
      command: z.string().min(1).max(256),
      ...TodosTargetSurfaceStatusShape,
    }),
    mcp: z.strictObject({
      tool: z.string().min(1).max(256).regex(/^[a-z][a-z0-9_]*$/),
      ...TodosTargetSurfaceStatusShape,
    }),
    sdk: z.strictObject({
      method: z.string().min(1).max(256).regex(/^[a-z][A-Za-z0-9.]*$/),
      ...TodosTargetSurfaceStatusShape,
    }),
    http: TodosHttpSurfaceSchema.nullable(),
  }),
});
export type TodosOperation = z.infer<typeof TodosOperationSchema>;

// @todos-runtime-validator operation.manifest_semantics
export const TodosOperationManifestSchema = z.strictObject({
  schema: z.literal(TODOS_OPERATION_MANIFEST_SCHEMA_ID),
  version: z.literal(TODOS_MANIFEST_VERSION),
  provenance: TodosContractProvenanceSchema,
  operations: z.array(TodosOperationSchema).min(1),
}).superRefine((value, ctx) => {
  const operationIds = value.operations.map((operation) => operation.id);
  if (new Set(operationIds).size !== operationIds.length) {
    ctx.addIssue({ code: "custom", message: "Operation ids must be unique", path: ["operations"] });
  }
  const cliCommands = new Set<string>();
  const mcpTools = new Set<string>();
  const sdkMethods = new Set<string>();
  const httpBindings = new Set<string>();
  for (const [index, operation] of value.operations.entries()) {
    const expectedSurfaces = operationSurfaceNames(operation.id);
    if (operation.surfaces.cli.command !== expectedSurfaces.cli.command) {
      ctx.addIssue({
        code: "custom",
        message: "CLI mapping must be derived from the canonical semantic operation id",
        path: ["operations", index, "surfaces", "cli", "command"],
      });
    }
    if (operation.surfaces.mcp.tool !== expectedSurfaces.mcp.tool) {
      ctx.addIssue({
        code: "custom",
        message: "MCP mapping must be derived from the canonical semantic operation id",
        path: ["operations", index, "surfaces", "mcp", "tool"],
      });
    }
    if (operation.surfaces.sdk.method !== expectedSurfaces.sdk.method) {
      ctx.addIssue({
        code: "custom",
        message: "SDK mapping must be derived from the canonical semantic operation id",
        path: ["operations", index, "surfaces", "sdk", "method"],
      });
    }
    for (const [surfaceName, surfaceValue, seen] of [
      ["cli", operation.surfaces.cli.command, cliCommands],
      ["mcp", operation.surfaces.mcp.tool, mcpTools],
      ["sdk", operation.surfaces.sdk.method, sdkMethods],
    ] as const) {
      if (seen.has(surfaceValue)) {
        ctx.addIssue({
          code: "custom",
          message: `${surfaceName.toUpperCase()} mappings must be unique`,
          path: ["operations", index, "surfaces", surfaceName],
        });
      }
      seen.add(surfaceValue);
    }
    if (new Set(operation.supportedModes).size !== operation.supportedModes.length) {
      ctx.addIssue({
        code: "custom",
        message: "Supported modes must be unique",
        path: ["operations", index, "supportedModes"],
      });
    }
    if (new Set(operation.requiredScopes).size !== operation.requiredScopes.length) {
      ctx.addIssue({
        code: "custom",
        message: "Required scopes must be unique",
        path: ["operations", index, "requiredScopes"],
      });
    }
    if (operation.classification === "shared_customer") {
      if (
        operation.supportedModes.length !== 2
        || operation.supportedModes[0] !== "local"
        || operation.supportedModes[1] !== "cloud"
      ) {
        ctx.addIssue({
          code: "custom",
          message: "Shared customer operations must support local and cloud",
          path: ["operations", index, "supportedModes"],
        });
      }
      if (!operation.surfaces.http || !operation.surfaces.http.path.startsWith("/v1/")) {
        ctx.addIssue({
          code: "custom",
          message: "Shared customer operations require an HTTP path under /v1/",
          path: ["operations", index, "surfaces", "http"],
        });
      } else {
        const binding = `${operation.surfaces.http.method} ${operation.surfaces.http.path}`;
        if (httpBindings.has(binding)) {
          ctx.addIssue({
            code: "custom",
            message: "HTTP method and path mappings must be unique",
            path: ["operations", index, "surfaces", "http"],
          });
        }
        httpBindings.add(binding);
        if (operation.surfaces.http.path.includes("/api/")) {
          ctx.addIssue({
            code: "custom",
            message: "Customer HTTP mappings must not expose producer-specific /api routes",
            path: ["operations", index, "surfaces", "http", "path"],
          });
        }
      }
    } else {
      if (
        operation.supportedModes.length !== 1
        || operation.supportedModes[0] !== "local"
      ) {
        ctx.addIssue({
          code: "custom",
          message: "Local topology operations support local mode only",
          path: ["operations", index, "supportedModes"],
        });
      }
      if (operation.surfaces.http !== null) {
        ctx.addIssue({
          code: "custom",
          message: "Local topology operations cannot have an HTTP mapping",
          path: ["operations", index, "surfaces", "http"],
        });
      }
    }
    if (
      operation.availability === "gated"
      && !["approvals", "task-templates", "reports"].includes(operation.capabilityId)
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Only declared gated capabilities may use gated availability",
        path: ["operations", index, "availability"],
      });
    }
    if (operation.mutability === "read") {
      if (operation.idempotency !== "none") {
        ctx.addIssue({
          code: "custom",
          message: "Read operations do not require mutation idempotency",
          path: ["operations", index, "idempotency"],
        });
      }
      if (operation.requiredScopes.some((scope) => scope.endsWith(":write"))) {
        ctx.addIssue({
          code: "custom",
          message: "Read operations cannot require write scopes",
          path: ["operations", index, "requiredScopes"],
        });
      }
    } else {
      if (operation.idempotency !== "required") {
        ctx.addIssue({
          code: "custom",
          message: "Write, delete, and topology operations require idempotency",
          path: ["operations", index, "idempotency"],
        });
      }
      if (operation.requiredScopes.some((scope) => scope.endsWith(":read"))) {
        ctx.addIssue({
          code: "custom",
          message: "Mutating operations cannot use read-only scopes",
          path: ["operations", index, "requiredScopes"],
        });
      }
    }

    if (operation.concurrency === "none" && operation.concurrencyFields.length !== 0) {
      ctx.addIssue({
        code: "custom",
        message: "Operations without concurrency controls cannot declare concurrency fields",
        path: ["operations", index, "concurrencyFields"],
      });
    }
    if (operation.concurrency === "version") {
      if (
        operation.concurrencyFields.length !== 1
        || operation.concurrencyFields[0] !== "expectedVersion"
      ) {
        ctx.addIssue({
          code: "custom",
          message: "Version concurrency requires request.expectedVersion",
          path: ["operations", index, "concurrencyFields"],
        });
      }
    } else if (
      operation.concurrency !== "none"
      && operation.concurrencyFields.length === 0
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Lock and precondition concurrency require explicit request fields",
        path: ["operations", index, "concurrencyFields"],
      });
    }

    const requestSchema = TODOS_REQUEST_SCHEMAS[
      operation.requestSchemaId as keyof typeof TODOS_REQUEST_SCHEMAS
    ];
    if (!requestSchema) {
      ctx.addIssue({
        code: "custom",
        message: "Operation request schema is not registered",
        path: ["operations", index, "requestSchemaId"],
      });
    } else {
      const jsonSchema = z.toJSONSchema(requestSchema, {
        unrepresentable: "any",
        cycles: "ref",
        reused: "ref",
      }) as {
        properties?: Record<string, unknown>;
        required?: string[];
      };
      const properties = jsonSchema.properties ?? {};
      const required = new Set(jsonSchema.required ?? []);
      for (const field of operation.concurrencyFields) {
        if (!(field in properties) || !required.has(field)) {
          ctx.addIssue({
            code: "custom",
            message: `Concurrency field ${field} must be a required request property`,
            path: ["operations", index, "concurrencyFields"],
          });
        }
      }
      const http = operation.surfaces.http;
      if (http) {
        for (const match of http.path.matchAll(/\{([A-Za-z0-9_]+)\}/g)) {
          const field = match[1]!;
          if (!(field in properties) || !required.has(field)) {
            ctx.addIssue({
              code: "custom",
              message: `HTTP path parameter ${field} must be a required request property`,
              path: ["operations", index, "surfaces", "http", "path"],
            });
          }
        }
      }
    }

    if (operation.transition) {
      const expectedAction = {
        in_progress: "start",
        completed: "complete",
        failed: "fail",
      }[operation.transition.targetStatus];
      if (
        operation.transition.machine !== "task_status"
        || operation.resource !== "tasks"
        || operation.action !== expectedAction
        || operation.concurrency !== "version"
      ) {
        ctx.addIssue({
          code: "custom",
          message: "Task transition metadata must bind start, complete, or fail with version concurrency",
          path: ["operations", index, "transition"],
        });
      }
    }
  }
});
export type TodosOperationManifest = z.infer<typeof TodosOperationManifestSchema>;

interface OperationInput {
  resource: string;
  action: string;
  capabilityId: TodosCapabilityId;
  requestSchemaId: string;
  responseSchemaId: string;
  httpMethod?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  httpPath?: string;
  audience?: "customer" | "tenant_admin";
  availability?: "core" | "gated";
  mutability?: "read" | "write" | "delete" | "topology";
  idempotency?: "none" | "optional" | "required";
  concurrency?: "none" | "version" | "lock" | "precondition";
  concurrencyFields?: string[];
  transition?: {
    machine: "task_status";
    targetStatus: "in_progress" | "completed" | "failed";
  };
  pagination?: "none" | "cursor";
}

function operationSurfaceNames(id: string) {
  const parts = id.split(".").slice(1);
  const [head = "operation", ...tail] = parts;
  const sdkTail = tail.map((part) => part.replace(/_([a-z])/g, (_match, char: string) => char.toUpperCase()));
  return {
    cli: {
      command: `todos ${parts.join(" ").replaceAll("_", "-")}`,
      status: "required_target" as const,
      producerImplementationStatus: "not_attested" as const,
    },
    mcp: {
      tool: id.replaceAll(".", "_"),
      status: "required_target" as const,
      producerImplementationStatus: "not_attested" as const,
    },
    sdk: {
      method: [head.replace(/_([a-z])/g, (_match, char: string) => char.toUpperCase()), ...sdkTail].join("."),
      status: "required_target" as const,
      producerImplementationStatus: "not_attested" as const,
    },
  };
}

function scopeFor(
  capabilityId: TodosCapabilityId,
  mutability: NonNullable<OperationInput["mutability"]>,
  audience: NonNullable<OperationInput["audience"]>,
): string {
  if (audience === "tenant_admin") {
    return `todos:${capabilityId}:admin`;
  }
  return `todos:${capabilityId}:${mutability === "read" ? "read" : "write"}`;
}

function shared(input: OperationInput): TodosOperation {
  const id = `todos.${input.resource}.${input.action}`;
  const mutability = input.mutability ?? "read";
  const audience = input.audience ?? "customer";
  const surfaces = operationSurfaceNames(id);
  const concurrency = input.concurrency ?? "none";
  return TodosOperationSchema.parse({
    id,
    resource: input.resource,
    action: input.action,
    classification: "shared_customer",
    supportedModes: ["local", "cloud"],
    audience,
    capabilityId: input.capabilityId,
    availability: input.availability ?? "core",
    mutability,
    idempotency: input.idempotency ?? (mutability === "read" ? "none" : "required"),
    concurrency,
    concurrencyFields: input.concurrencyFields
      ?? (concurrency === "version" ? ["expectedVersion"] : []),
    transition: input.transition ?? null,
    pagination: input.pagination ?? "none",
    requestSchemaId: input.requestSchemaId,
    responseSchemaId: input.responseSchemaId,
    errorSchemaId: TODOS_COMMON_SCHEMA_IDS.error,
    requiredScopes: [scopeFor(input.capabilityId, mutability, audience)],
    surfaces: {
      ...surfaces,
      http: {
        method: input.httpMethod,
        path: input.httpPath,
        status: "required_target",
        producerImplementationStatus: "not_attested",
      },
    },
  });
}

function localTopology(input: Omit<OperationInput, "httpMethod" | "httpPath">): TodosOperation {
  const id = `todos.${input.resource}.${input.action}`;
  const mutability = input.mutability ?? "topology";
  const audience = input.audience ?? "tenant_admin";
  const concurrency = input.concurrency ?? "none";
  return TodosOperationSchema.parse({
    id,
    resource: input.resource,
    action: input.action,
    classification: "local_topology_only",
    supportedModes: ["local"],
    audience,
    capabilityId: input.capabilityId,
    availability: input.availability ?? "core",
    mutability,
    idempotency: input.idempotency ?? (mutability === "read" ? "none" : "required"),
    concurrency,
    concurrencyFields: input.concurrencyFields
      ?? (concurrency === "version" ? ["expectedVersion"] : []),
    transition: input.transition ?? null,
    pagination: input.pagination ?? "none",
    requestSchemaId: input.requestSchemaId,
    responseSchemaId: input.responseSchemaId,
    errorSchemaId: TODOS_COMMON_SCHEMA_IDS.error,
    requiredScopes: [scopeFor(input.capabilityId, mutability, audience)],
    surfaces: {
      ...operationSurfaceNames(id),
      http: null,
    },
  });
}

const RQ = TODOS_REQUEST_SCHEMA_IDS;
const RS = TODOS_RESPONSE_SCHEMA_IDS;

const operations: TodosOperation[] = [
  shared({ resource: "service", action: "health", capabilityId: "authority", requestSchemaId: RQ.empty, responseSchemaId: RS.serviceStatus, httpMethod: "GET", httpPath: "/v1/service/health" }),
  shared({ resource: "service", action: "ready", capabilityId: "authority", requestSchemaId: RQ.empty, responseSchemaId: RS.serviceStatus, httpMethod: "GET", httpPath: "/v1/service/ready" }),
  shared({ resource: "service", action: "version", capabilityId: "authority", requestSchemaId: RQ.empty, responseSchemaId: RS.artifactDocument, httpMethod: "GET", httpPath: "/v1/service/version" }),
  shared({ resource: "authority", action: "get", capabilityId: "authority", requestSchemaId: RQ.empty, responseSchemaId: RS.authority, httpMethod: "GET", httpPath: "/v1/authority" }),
  shared({ resource: "manifest", action: "get", capabilityId: "authority", requestSchemaId: RQ.empty, responseSchemaId: RS.artifactDocument, httpMethod: "GET", httpPath: "/v1/manifest" }),
  shared({ resource: "openapi", action: "get", capabilityId: "authority", requestSchemaId: RQ.empty, responseSchemaId: RS.artifactDocument, httpMethod: "GET", httpPath: "/v1/openapi" }),
  shared({ resource: "capabilities", action: "list", capabilityId: "authority", requestSchemaId: RQ.list, responseSchemaId: RS.capabilityPage, httpMethod: "GET", httpPath: "/v1/capabilities", pagination: "cursor" }),
  shared({ resource: "capabilities", action: "get", capabilityId: "authority", requestSchemaId: RQ.ref, responseSchemaId: RS.capability, httpMethod: "GET", httpPath: "/v1/capabilities/{ref}" }),

  shared({ resource: "tasks", action: "list", capabilityId: "tasks", requestSchemaId: RQ.list, responseSchemaId: RS.taskPage, httpMethod: "GET", httpPath: "/v1/tasks", pagination: "cursor" }),
  shared({ resource: "tasks", action: "count", capabilityId: "tasks", requestSchemaId: RQ.list, responseSchemaId: RS.count, httpMethod: "GET", httpPath: "/v1/tasks/count" }),
  shared({ resource: "tasks", action: "exists_many", capabilityId: "tasks", requestSchemaId: RQ.existsMany, responseSchemaId: RS.existsMany, httpMethod: "POST", httpPath: "/v1/tasks/exists-many" }),
  shared({ resource: "tasks", action: "create", capabilityId: "tasks", requestSchemaId: RQ.taskCreate, responseSchemaId: RS.task, httpMethod: "POST", httpPath: "/v1/tasks", mutability: "write" }),
  shared({ resource: "tasks", action: "upsert", capabilityId: "tasks", requestSchemaId: RQ.taskUpsert, responseSchemaId: RS.task, httpMethod: "PUT", httpPath: "/v1/tasks/upsert", mutability: "write", concurrency: "version" }),
  shared({ resource: "tasks", action: "get", capabilityId: "tasks", requestSchemaId: RQ.ref, responseSchemaId: RS.task, httpMethod: "GET", httpPath: "/v1/tasks/{ref}" }),
  shared({ resource: "tasks", action: "update", capabilityId: "tasks", requestSchemaId: RQ.taskUpdate, responseSchemaId: RS.task, httpMethod: "PATCH", httpPath: "/v1/tasks/{ref}", mutability: "write", concurrency: "version" }),
  shared({ resource: "tasks", action: "delete", capabilityId: "tasks", requestSchemaId: RQ.versionedRef, responseSchemaId: RS.mutation, httpMethod: "DELETE", httpPath: "/v1/tasks/{ref}", mutability: "delete", concurrency: "version" }),
  shared({ resource: "tasks", action: "batch", capabilityId: "tasks", requestSchemaId: RQ.taskBatch, responseSchemaId: RS.batch, httpMethod: "POST", httpPath: "/v1/tasks/batch", mutability: "write", concurrency: "precondition", concurrencyFields: ["operations"] }),
  shared({ resource: "tasks", action: "start", capabilityId: "tasks", requestSchemaId: RQ.taskStart, responseSchemaId: RS.task, httpMethod: "POST", httpPath: "/v1/tasks/{ref}/start", mutability: "write", concurrency: "version", transition: { machine: "task_status", targetStatus: "in_progress" } }),
  shared({ resource: "tasks", action: "complete", capabilityId: "tasks", requestSchemaId: RQ.taskComplete, responseSchemaId: RS.task, httpMethod: "POST", httpPath: "/v1/tasks/{ref}/complete", mutability: "write", concurrency: "version", transition: { machine: "task_status", targetStatus: "completed" } }),
  shared({ resource: "tasks", action: "fail", capabilityId: "tasks", requestSchemaId: RQ.taskFail, responseSchemaId: RS.task, httpMethod: "POST", httpPath: "/v1/tasks/{ref}/fail", mutability: "write", concurrency: "version", transition: { machine: "task_status", targetStatus: "failed" } }),
  shared({ resource: "tasks", action: "claim_next", capabilityId: "tasks", requestSchemaId: RQ.taskClaim, responseSchemaId: RS.task, httpMethod: "POST", httpPath: "/v1/tasks/claim-next", mutability: "write", concurrency: "lock", concurrencyFields: ["agentId"] }),
  shared({ resource: "tasks", action: "next", capabilityId: "tasks", requestSchemaId: RQ.list, responseSchemaId: RS.task, httpMethod: "GET", httpPath: "/v1/tasks/next" }),
  shared({ resource: "tasks", action: "list_ready", capabilityId: "tasks", requestSchemaId: RQ.list, responseSchemaId: RS.taskPage, httpMethod: "GET", httpPath: "/v1/tasks/ready", pagination: "cursor" }),
  shared({ resource: "tasks", action: "list_active", capabilityId: "tasks", requestSchemaId: RQ.list, responseSchemaId: RS.taskPage, httpMethod: "GET", httpPath: "/v1/tasks/active", pagination: "cursor" }),
  shared({ resource: "tasks", action: "list_changed", capabilityId: "tasks", requestSchemaId: RQ.taskChanged, responseSchemaId: RS.taskPage, httpMethod: "GET", httpPath: "/v1/tasks/changed", pagination: "cursor" }),
  shared({ resource: "tasks", action: "lock", capabilityId: "tasks", requestSchemaId: RQ.taskLock, responseSchemaId: RS.mutation, httpMethod: "POST", httpPath: "/v1/tasks/{ref}/lock", mutability: "write", concurrency: "lock", concurrencyFields: ["ownerRef", "expectedVersion"] }),
  shared({ resource: "tasks", action: "unlock", capabilityId: "tasks", requestSchemaId: RQ.taskLock, responseSchemaId: RS.mutation, httpMethod: "DELETE", httpPath: "/v1/tasks/{ref}/lock", mutability: "write", concurrency: "lock", concurrencyFields: ["ownerRef", "expectedVersion"] }),
  shared({ resource: "tasks", action: "get_context", capabilityId: "tasks", requestSchemaId: RQ.ref, responseSchemaId: RS.taskContext, httpMethod: "GET", httpPath: "/v1/tasks/{ref}/context" }),
  shared({ resource: "history", action: "list", capabilityId: "activity", requestSchemaId: RQ.refList, responseSchemaId: RS.activityPage, httpMethod: "GET", httpPath: "/v1/tasks/{ref}/history", pagination: "cursor" }),

  shared({ resource: "comments", action: "list", capabilityId: "comments", requestSchemaId: RQ.refList, responseSchemaId: RS.commentPage, httpMethod: "GET", httpPath: "/v1/tasks/{ref}/comments", pagination: "cursor" }),
  shared({ resource: "comments", action: "create", capabilityId: "comments", requestSchemaId: RQ.commentCreate, responseSchemaId: RS.comment, httpMethod: "POST", httpPath: "/v1/tasks/{taskRef}/comments", mutability: "write" }),
  shared({ resource: "dependencies", action: "list", capabilityId: "dependencies", requestSchemaId: RQ.refList, responseSchemaId: RS.dependencyPage, httpMethod: "GET", httpPath: "/v1/tasks/{ref}/dependencies", pagination: "cursor" }),
  shared({ resource: "dependencies", action: "list_all", capabilityId: "dependencies", requestSchemaId: RQ.list, responseSchemaId: RS.dependencyPage, httpMethod: "GET", httpPath: "/v1/dependencies", pagination: "cursor" }),
  shared({ resource: "dependencies", action: "create", capabilityId: "dependencies", requestSchemaId: RQ.dependencyCreate, responseSchemaId: RS.dependency, httpMethod: "POST", httpPath: "/v1/dependencies", mutability: "write" }),
  shared({ resource: "dependencies", action: "delete", capabilityId: "dependencies", requestSchemaId: RQ.dependencyDelete, responseSchemaId: RS.mutation, httpMethod: "DELETE", httpPath: "/v1/dependencies/{ref}", mutability: "delete", concurrency: "version" }),

  shared({ resource: "projects", action: "list", capabilityId: "projects", requestSchemaId: RQ.list, responseSchemaId: RS.projectPage, httpMethod: "GET", httpPath: "/v1/projects", pagination: "cursor" }),
  shared({ resource: "projects", action: "create", capabilityId: "projects", requestSchemaId: RQ.projectCreate, responseSchemaId: RS.project, httpMethod: "POST", httpPath: "/v1/projects", mutability: "write" }),
  shared({ resource: "projects", action: "get", capabilityId: "projects", requestSchemaId: RQ.ref, responseSchemaId: RS.project, httpMethod: "GET", httpPath: "/v1/projects/{ref}" }),
  shared({ resource: "projects", action: "update", capabilityId: "projects", requestSchemaId: RQ.projectUpdate, responseSchemaId: RS.project, httpMethod: "PATCH", httpPath: "/v1/projects/{ref}", mutability: "write", concurrency: "version" }),
  shared({ resource: "projects", action: "rename", capabilityId: "projects", requestSchemaId: RQ.projectRename, responseSchemaId: RS.project, httpMethod: "POST", httpPath: "/v1/projects/{ref}/rename", mutability: "write", concurrency: "version" }),
  shared({ resource: "projects", action: "delete", capabilityId: "projects", requestSchemaId: RQ.versionedRef, responseSchemaId: RS.mutation, httpMethod: "DELETE", httpPath: "/v1/projects/{ref}", mutability: "delete", concurrency: "version" }),

  shared({ resource: "task_lists", action: "list", capabilityId: "task-lists", requestSchemaId: RQ.list, responseSchemaId: RS.taskListPage, httpMethod: "GET", httpPath: "/v1/task-lists", pagination: "cursor" }),
  shared({ resource: "task_lists", action: "create", capabilityId: "task-lists", requestSchemaId: RQ.taskListCreate, responseSchemaId: RS.taskList, httpMethod: "POST", httpPath: "/v1/task-lists", mutability: "write" }),
  shared({ resource: "task_lists", action: "get", capabilityId: "task-lists", requestSchemaId: RQ.ref, responseSchemaId: RS.taskList, httpMethod: "GET", httpPath: "/v1/task-lists/{ref}" }),
  shared({ resource: "task_lists", action: "update", capabilityId: "task-lists", requestSchemaId: RQ.taskListUpdate, responseSchemaId: RS.taskList, httpMethod: "PATCH", httpPath: "/v1/task-lists/{ref}", mutability: "write", concurrency: "version" }),
  shared({ resource: "task_lists", action: "delete", capabilityId: "task-lists", requestSchemaId: RQ.versionedRef, responseSchemaId: RS.mutation, httpMethod: "DELETE", httpPath: "/v1/task-lists/{ref}", mutability: "delete", concurrency: "version" }),

  shared({ resource: "plans", action: "list", capabilityId: "plans", requestSchemaId: RQ.list, responseSchemaId: RS.planPage, httpMethod: "GET", httpPath: "/v1/plans", pagination: "cursor" }),
  shared({ resource: "plans", action: "create", capabilityId: "plans", requestSchemaId: RQ.planCreate, responseSchemaId: RS.plan, httpMethod: "POST", httpPath: "/v1/plans", mutability: "write" }),
  shared({ resource: "plans", action: "get", capabilityId: "plans", requestSchemaId: RQ.ref, responseSchemaId: RS.plan, httpMethod: "GET", httpPath: "/v1/plans/{ref}" }),
  shared({ resource: "plans", action: "update", capabilityId: "plans", requestSchemaId: RQ.planUpdate, responseSchemaId: RS.plan, httpMethod: "PATCH", httpPath: "/v1/plans/{ref}", mutability: "write", concurrency: "version" }),
  shared({ resource: "plans", action: "delete", capabilityId: "plans", requestSchemaId: RQ.versionedRef, responseSchemaId: RS.mutation, httpMethod: "DELETE", httpPath: "/v1/plans/{ref}", mutability: "delete", concurrency: "version" }),

  shared({ resource: "agents", action: "list", capabilityId: "agents", requestSchemaId: RQ.list, responseSchemaId: RS.agentPage, httpMethod: "GET", httpPath: "/v1/agents", pagination: "cursor" }),
  shared({ resource: "agents", action: "register", capabilityId: "agents", requestSchemaId: RQ.agentRegister, responseSchemaId: RS.agent, httpMethod: "POST", httpPath: "/v1/agents", mutability: "write" }),
  shared({ resource: "agents", action: "get", capabilityId: "agents", requestSchemaId: RQ.ref, responseSchemaId: RS.agent, httpMethod: "GET", httpPath: "/v1/agents/{ref}" }),
  shared({ resource: "agents", action: "heartbeat", capabilityId: "agents", requestSchemaId: RQ.agentHeartbeat, responseSchemaId: RS.agent, httpMethod: "POST", httpPath: "/v1/agents/{ref}/heartbeat", mutability: "write", concurrency: "version" }),
  shared({ resource: "agents", action: "release", capabilityId: "agents", requestSchemaId: RQ.agentRelease, responseSchemaId: RS.agent, httpMethod: "POST", httpPath: "/v1/agents/{ref}/release", mutability: "write", concurrency: "version" }),

  shared({ resource: "activity", action: "list", capabilityId: "activity", requestSchemaId: RQ.list, responseSchemaId: RS.activityPage, httpMethod: "GET", httpPath: "/v1/activity", pagination: "cursor" }),
  shared({ resource: "stats", action: "get", capabilityId: "activity", requestSchemaId: RQ.empty, responseSchemaId: RS.stats, httpMethod: "GET", httpPath: "/v1/stats" }),
  shared({ resource: "search", action: "execute", capabilityId: "search", requestSchemaId: RQ.search, responseSchemaId: RS.taskPage, httpMethod: "POST", httpPath: "/v1/search", pagination: "cursor" }),

  shared({ resource: "saved_views", action: "list", capabilityId: "saved-views", requestSchemaId: RQ.list, responseSchemaId: RS.savedViewPage, httpMethod: "GET", httpPath: "/v1/saved-views", pagination: "cursor" }),
  shared({ resource: "saved_views", action: "create", capabilityId: "saved-views", requestSchemaId: RQ.savedViewCreate, responseSchemaId: RS.savedView, httpMethod: "POST", httpPath: "/v1/saved-views", mutability: "write" }),
  shared({ resource: "saved_views", action: "get", capabilityId: "saved-views", requestSchemaId: RQ.ref, responseSchemaId: RS.savedView, httpMethod: "GET", httpPath: "/v1/saved-views/{ref}" }),
  shared({ resource: "saved_views", action: "update", capabilityId: "saved-views", requestSchemaId: RQ.savedViewUpdate, responseSchemaId: RS.savedView, httpMethod: "PATCH", httpPath: "/v1/saved-views/{ref}", mutability: "write", concurrency: "version" }),
  shared({ resource: "saved_views", action: "delete", capabilityId: "saved-views", requestSchemaId: RQ.versionedRef, responseSchemaId: RS.mutation, httpMethod: "DELETE", httpPath: "/v1/saved-views/{ref}", mutability: "delete", concurrency: "version" }),
  shared({ resource: "saved_views", action: "execute", capabilityId: "saved-views", requestSchemaId: RQ.savedViewExecute, responseSchemaId: RS.taskPage, httpMethod: "POST", httpPath: "/v1/saved-views/{ref}/execute", pagination: "cursor" }),

  shared({ resource: "verification_evidence", action: "list", capabilityId: "verification-evidence", requestSchemaId: RQ.list, responseSchemaId: RS.verificationPage, httpMethod: "GET", httpPath: "/v1/verification-evidence", pagination: "cursor" }),
  shared({ resource: "verification_evidence", action: "create", capabilityId: "verification-evidence", requestSchemaId: RQ.verificationCreate, responseSchemaId: RS.verification, httpMethod: "POST", httpPath: "/v1/verification-evidence", mutability: "write" }),
  shared({ resource: "verification_evidence", action: "get", capabilityId: "verification-evidence", requestSchemaId: RQ.ref, responseSchemaId: RS.verification, httpMethod: "GET", httpPath: "/v1/verification-evidence/{ref}" }),
  shared({ resource: "verification_evidence", action: "export", capabilityId: "verification-evidence", requestSchemaId: RQ.verificationExport, responseSchemaId: RS.verificationExport, httpMethod: "POST", httpPath: "/v1/verification-evidence/export" }),
  shared({ resource: "task_files", action: "list", capabilityId: "task-files", requestSchemaId: RQ.list, responseSchemaId: RS.taskFilePage, httpMethod: "GET", httpPath: "/v1/task-files", pagination: "cursor" }),
  shared({ resource: "task_files", action: "record", capabilityId: "task-files", requestSchemaId: RQ.taskFileRecord, responseSchemaId: RS.taskFile, httpMethod: "POST", httpPath: "/v1/task-files", mutability: "write" }),

  shared({ resource: "runs", action: "list", capabilityId: "runs", requestSchemaId: RQ.list, responseSchemaId: RS.runPage, httpMethod: "GET", httpPath: "/v1/runs", pagination: "cursor" }),
  shared({ resource: "runs", action: "start", capabilityId: "runs", requestSchemaId: RQ.runStart, responseSchemaId: RS.run, httpMethod: "POST", httpPath: "/v1/runs", mutability: "write" }),
  shared({ resource: "runs", action: "get", capabilityId: "runs", requestSchemaId: RQ.ref, responseSchemaId: RS.run, httpMethod: "GET", httpPath: "/v1/runs/{ref}" }),
  shared({ resource: "runs", action: "finish", capabilityId: "runs", requestSchemaId: RQ.runFinish, responseSchemaId: RS.run, httpMethod: "POST", httpPath: "/v1/runs/{ref}/finish", mutability: "write", concurrency: "version" }),
  shared({ resource: "runs", action: "get_ledger", capabilityId: "runs", requestSchemaId: RQ.ref, responseSchemaId: RS.runLedger, httpMethod: "GET", httpPath: "/v1/runs/{ref}/ledger" }),
  shared({ resource: "run_events", action: "list", capabilityId: "runs", requestSchemaId: RQ.refList, responseSchemaId: RS.runEventPage, httpMethod: "GET", httpPath: "/v1/runs/{ref}/events", pagination: "cursor" }),
  shared({ resource: "run_events", action: "create", capabilityId: "runs", requestSchemaId: RQ.runEventCreate, responseSchemaId: RS.runEvent, httpMethod: "POST", httpPath: "/v1/runs/{runId}/events", mutability: "write" }),
  shared({ resource: "run_commands", action: "list", capabilityId: "runs", requestSchemaId: RQ.refList, responseSchemaId: RS.runCommandPage, httpMethod: "GET", httpPath: "/v1/runs/{ref}/commands", pagination: "cursor" }),
  shared({ resource: "run_commands", action: "create", capabilityId: "runs", requestSchemaId: RQ.runCommandCreate, responseSchemaId: RS.runCommand, httpMethod: "POST", httpPath: "/v1/runs/{runId}/commands", mutability: "write" }),
  shared({ resource: "run_files", action: "list", capabilityId: "runs", requestSchemaId: RQ.refList, responseSchemaId: RS.runFilePage, httpMethod: "GET", httpPath: "/v1/runs/{ref}/files", pagination: "cursor" }),
  shared({ resource: "run_files", action: "create", capabilityId: "runs", requestSchemaId: RQ.runFileCreate, responseSchemaId: RS.runFile, httpMethod: "POST", httpPath: "/v1/runs/{runId}/files", mutability: "write" }),
  shared({ resource: "run_artifacts", action: "list", capabilityId: "runs", requestSchemaId: RQ.refList, responseSchemaId: RS.runArtifactPage, httpMethod: "GET", httpPath: "/v1/runs/{ref}/artifacts", pagination: "cursor" }),
  shared({ resource: "run_artifacts", action: "create", capabilityId: "runs", requestSchemaId: RQ.runArtifactCreate, responseSchemaId: RS.runArtifact, httpMethod: "POST", httpPath: "/v1/runs/{runId}/artifacts", mutability: "write" }),
  shared({ resource: "run_artifacts", action: "verify", capabilityId: "runs", requestSchemaId: RQ.runArtifactVerify, responseSchemaId: RS.runArtifact, httpMethod: "POST", httpPath: "/v1/runs/{runId}/artifacts/{ref}/verify", mutability: "write", concurrency: "version" }),

  shared({ resource: "git_commits", action: "list", capabilityId: "git-traceability", requestSchemaId: RQ.list, responseSchemaId: RS.gitCommitPage, httpMethod: "GET", httpPath: "/v1/git/commits", pagination: "cursor" }),
  shared({ resource: "git_commits", action: "link", capabilityId: "git-traceability", requestSchemaId: RQ.gitCommitLink, responseSchemaId: RS.gitCommit, httpMethod: "POST", httpPath: "/v1/git/commits", mutability: "write" }),
  shared({ resource: "git_commits", action: "unlink", capabilityId: "git-traceability", requestSchemaId: RQ.gitCommitUnlink, responseSchemaId: RS.mutation, httpMethod: "DELETE", httpPath: "/v1/git/commits/{commitRef}", mutability: "delete", concurrency: "version" }),
  shared({ resource: "git_commits", action: "find", capabilityId: "git-traceability", requestSchemaId: RQ.gitCommitFind, responseSchemaId: RS.gitCommit, httpMethod: "POST", httpPath: "/v1/git/commits/find" }),
  shared({ resource: "git_refs", action: "list", capabilityId: "git-traceability", requestSchemaId: RQ.list, responseSchemaId: RS.gitRefPage, httpMethod: "GET", httpPath: "/v1/git/refs", pagination: "cursor" }),
  shared({ resource: "git_refs", action: "link", capabilityId: "git-traceability", requestSchemaId: RQ.gitRefLink, responseSchemaId: RS.gitRef, httpMethod: "POST", httpPath: "/v1/git/refs", mutability: "write" }),
  shared({ resource: "git_refs", action: "find", capabilityId: "git-traceability", requestSchemaId: RQ.gitRefFind, responseSchemaId: RS.gitRef, httpMethod: "POST", httpPath: "/v1/git/refs/find" }),
  shared({ resource: "traceability", action: "get", capabilityId: "git-traceability", requestSchemaId: RQ.ref, responseSchemaId: RS.traceability, httpMethod: "GET", httpPath: "/v1/traceability/{ref}" }),
  shared({ resource: "task_to_pr_projection", action: "list", capabilityId: "task-to-pr-projection", requestSchemaId: RQ.list, responseSchemaId: RS.projectionPage, httpMethod: "GET", httpPath: "/v1/task-to-pr-projections", pagination: "cursor" }),
  shared({ resource: "task_to_pr_projection", action: "get", capabilityId: "task-to-pr-projection", requestSchemaId: RQ.ref, responseSchemaId: RS.projection, httpMethod: "GET", httpPath: "/v1/task-to-pr-projections/{ref}" }),

  shared({ resource: "transfer", action: "export", capabilityId: "transfer", requestSchemaId: RQ.transferExport, responseSchemaId: RS.transferBundle, httpMethod: "POST", httpPath: "/v1/transfer/export" }),
  shared({ resource: "transfer", action: "validate", capabilityId: "transfer", requestSchemaId: RQ.transferValidate, responseSchemaId: RS.transferValidation, httpMethod: "POST", httpPath: "/v1/transfer/validate" }),
  shared({ resource: "transfer", action: "import_preview", capabilityId: "transfer", requestSchemaId: RQ.transferImportPreview, responseSchemaId: RS.transferImportPreview, httpMethod: "POST", httpPath: "/v1/transfer/import/preview" }),
  shared({ resource: "transfer", action: "import_execute", capabilityId: "transfer", requestSchemaId: RQ.transferImportExecute, responseSchemaId: RS.migrationReceipt, httpMethod: "POST", httpPath: "/v1/transfer/import/execute", mutability: "write", concurrency: "precondition", concurrencyFields: ["importPlanId", "importPlanDigest"] }),
  shared({ resource: "migration_receipts", action: "list", capabilityId: "transfer", requestSchemaId: RQ.list, responseSchemaId: RS.migrationReceiptPage, httpMethod: "GET", httpPath: "/v1/migration-receipts", pagination: "cursor" }),
  shared({ resource: "migration_receipts", action: "get", capabilityId: "transfer", requestSchemaId: RQ.ref, responseSchemaId: RS.migrationReceipt, httpMethod: "GET", httpPath: "/v1/migration-receipts/{ref}" }),
  shared({ resource: "deletion_records", action: "list", capabilityId: "deletion-history", requestSchemaId: RQ.list, responseSchemaId: RS.deletionRecordPage, httpMethod: "GET", httpPath: "/v1/deletion-records", pagination: "cursor" }),
  shared({ resource: "deletion_records", action: "get", capabilityId: "deletion-history", requestSchemaId: RQ.ref, responseSchemaId: RS.deletionRecord, httpMethod: "GET", httpPath: "/v1/deletion-records/{ref}" }),

  shared({ resource: "approvals", action: "list", capabilityId: "approvals", requestSchemaId: RQ.list, responseSchemaId: RS.approvalPage, httpMethod: "GET", httpPath: "/v1/approvals", audience: "tenant_admin", availability: "gated", pagination: "cursor" }),
  shared({ resource: "approvals", action: "get", capabilityId: "approvals", requestSchemaId: RQ.ref, responseSchemaId: RS.approval, httpMethod: "GET", httpPath: "/v1/approvals/{ref}", audience: "tenant_admin", availability: "gated" }),
  shared({ resource: "approvals", action: "request", capabilityId: "approvals", requestSchemaId: RQ.approvalRequest, responseSchemaId: RS.approval, httpMethod: "POST", httpPath: "/v1/approvals", audience: "tenant_admin", availability: "gated", mutability: "write" }),
  shared({ resource: "approvals", action: "approve", capabilityId: "approvals", requestSchemaId: RQ.approvalDecision, responseSchemaId: RS.approval, httpMethod: "POST", httpPath: "/v1/approvals/{ref}/approve", audience: "tenant_admin", availability: "gated", mutability: "write", concurrency: "version" }),
  shared({ resource: "approvals", action: "reject", capabilityId: "approvals", requestSchemaId: RQ.approvalDecision, responseSchemaId: RS.approval, httpMethod: "POST", httpPath: "/v1/approvals/{ref}/reject", audience: "tenant_admin", availability: "gated", mutability: "write", concurrency: "version" }),
  shared({ resource: "approvals", action: "expire", capabilityId: "approvals", requestSchemaId: RQ.approvalExpire, responseSchemaId: RS.approval, httpMethod: "POST", httpPath: "/v1/approvals/{ref}/expire", audience: "tenant_admin", availability: "gated", mutability: "write", concurrency: "version" }),
  shared({ resource: "task_templates", action: "list", capabilityId: "task-templates", requestSchemaId: RQ.list, responseSchemaId: RS.taskTemplatePage, httpMethod: "GET", httpPath: "/v1/task-templates", availability: "gated", pagination: "cursor" }),
  shared({ resource: "task_templates", action: "create", capabilityId: "task-templates", requestSchemaId: RQ.taskTemplateCreate, responseSchemaId: RS.taskTemplate, httpMethod: "POST", httpPath: "/v1/task-templates", availability: "gated", mutability: "write" }),
  shared({ resource: "task_templates", action: "get", capabilityId: "task-templates", requestSchemaId: RQ.ref, responseSchemaId: RS.taskTemplate, httpMethod: "GET", httpPath: "/v1/task-templates/{ref}", availability: "gated" }),
  shared({ resource: "task_templates", action: "update", capabilityId: "task-templates", requestSchemaId: RQ.taskTemplateUpdate, responseSchemaId: RS.taskTemplate, httpMethod: "PATCH", httpPath: "/v1/task-templates/{ref}", availability: "gated", mutability: "write", concurrency: "version" }),
  shared({ resource: "task_templates", action: "delete", capabilityId: "task-templates", requestSchemaId: RQ.versionedRef, responseSchemaId: RS.mutation, httpMethod: "DELETE", httpPath: "/v1/task-templates/{ref}", availability: "gated", mutability: "delete", concurrency: "version" }),
  shared({ resource: "task_templates", action: "instantiate", capabilityId: "task-templates", requestSchemaId: RQ.taskTemplateInstantiate, responseSchemaId: RS.taskPage, httpMethod: "POST", httpPath: "/v1/task-templates/{ref}/instantiate", availability: "gated", mutability: "write" }),
  shared({ resource: "reports", action: "generate", capabilityId: "reports", requestSchemaId: RQ.reportGenerate, responseSchemaId: RS.report, httpMethod: "POST", httpPath: "/v1/reports/generate", availability: "gated", mutability: "write" }),

  localTopology({ resource: "workspace", action: "bootstrap", capabilityId: "projects", requestSchemaId: RQ.workspaceBootstrap, responseSchemaId: RS.project, concurrency: "none" }),
  localTopology({ resource: "server", action: "start", capabilityId: "authority", requestSchemaId: RQ.serverStart, responseSchemaId: RS.serverStart, concurrency: "precondition", concurrencyFields: ["expectedState"] }),
  localTopology({ resource: "database", action: "backup", capabilityId: "transfer", requestSchemaId: RQ.databaseBackup, responseSchemaId: RS.artifactDocument, concurrency: "none" }),
  localTopology({ resource: "database", action: "restore", capabilityId: "transfer", requestSchemaId: RQ.databaseRestore, responseSchemaId: RS.mutation, concurrency: "precondition", concurrencyFields: ["expectedCurrentDigest"] }),
  localTopology({ resource: "database", action: "check", capabilityId: "transfer", requestSchemaId: RQ.databaseCheck, responseSchemaId: RS.artifactDocument, mutability: "read", idempotency: "none", concurrency: "none" }),
  localTopology({ resource: "database", action: "compact", capabilityId: "transfer", requestSchemaId: RQ.databaseCompact, responseSchemaId: RS.mutation, concurrency: "precondition", concurrencyFields: ["expectedCurrentDigest"] }),
  localTopology({ resource: "offline_upgrade", action: "validate", capabilityId: "authority", requestSchemaId: RQ.upgradeValidate, responseSchemaId: RS.artifactDocument, mutability: "read", idempotency: "none", concurrency: "none" }),
  localTopology({ resource: "offline_upgrade", action: "execute", capabilityId: "authority", requestSchemaId: RQ.upgradeExecute, responseSchemaId: RS.mutation, concurrency: "precondition", concurrencyFields: ["validationDigest"] }),
  localTopology({ resource: "task_to_pr_projection", action: "rebuild", capabilityId: "task-to-pr-projection", requestSchemaId: RQ.projectionRebuild, responseSchemaId: RS.batch, concurrency: "precondition", concurrencyFields: ["expectedManifestDigest"] }),
];

export const TODOS_OPERATION_MANIFEST: TodosOperationManifest = TodosOperationManifestSchema.parse({
  schema: TODOS_OPERATION_MANIFEST_SCHEMA_ID,
  version: TODOS_MANIFEST_VERSION,
  provenance: TODOS_CONTRACT_PROVENANCE,
  operations,
});

export const TODOS_OPERATION_MANIFEST_DIGEST = sha256TodosValue(TODOS_OPERATION_MANIFEST);

export function getTodosOperation(operationId: string): TodosOperation | undefined {
  return TODOS_OPERATION_MANIFEST.operations.find((operation) => operation.id === operationId);
}

export const TODOS_OPERATION_SCHEMAS = Object.freeze({
  [TODOS_OPERATION_MANIFEST_SCHEMA_ID]: TodosOperationManifestSchema,
});
