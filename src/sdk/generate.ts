// SDK-from-OpenAPI generator helper.
//
// Given a serve app's OpenAPI 3 document, emit a typed, dependency-free TypeScript
// client (fetch-based) plus interfaces derived from `components.schemas`. This is
// the source of the per-app SDK: `<app>-serve` publishes its OpenAPI, and this
// helper turns it into the typed exports every consumer imports.
//
// The generated client speaks the Hasna auth convention out of the box: it sends
// the API key as `x-api-key` (configurable) so a self_hosted client only needs
// `<APP>_API_URL` + `<APP>_API_KEY`.
//
// Design notes: this is a pragmatic generator for the shapes real Hasna serve
// apps emit (health/ready/version + JSON CRUD). Unsupported constructs degrade to
// `unknown` (never a silent wrong type) and are collected in `warnings`.

export interface OpenApiDocument {
  openapi?: string;
  info?: { title?: string; version?: string };
  paths?: Record<string, PathItem>;
  components?: { schemas?: Record<string, JsonSchema> };
}

type PathItem = Record<string, Operation | unknown>;

interface Operation {
  operationId?: string;
  summary?: string;
  description?: string;
  parameters?: Parameter[];
  requestBody?: RequestBody;
  responses?: Record<string, ResponseObject>;
}

interface Parameter {
  name: string;
  in: "path" | "query" | "header" | "cookie";
  required?: boolean;
  schema?: JsonSchema;
}

interface RequestBody {
  required?: boolean;
  content?: Record<string, { schema?: JsonSchema }>;
}

interface ResponseObject {
  content?: Record<string, { schema?: JsonSchema }>;
}

export interface JsonSchema {
  $ref?: string;
  type?: string | string[];
  format?: string;
  enum?: unknown[];
  items?: JsonSchema;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  additionalProperties?: boolean | JsonSchema;
  allOf?: JsonSchema[];
  oneOf?: JsonSchema[];
  anyOf?: JsonSchema[];
  nullable?: boolean;
  description?: string;
}

const HTTP_METHODS = ["get", "put", "post", "delete", "patch", "options", "head"] as const;
type HttpMethod = (typeof HTTP_METHODS)[number];

export interface GenerateSdkOptions {
  /** Exported client class name. Default derived from `info.title` or `ApiClient`. */
  className?: string;
  /** Header used to send the API key. Default `x-api-key`. */
  apiKeyHeader?: string;
}

export interface GeneratedOperation {
  method: HttpMethod;
  path: string;
  operationId: string;
  functionName: string;
}

export interface GeneratedSdk {
  code: string;
  operations: GeneratedOperation[];
  warnings: string[];
}

function refName(ref: string): string {
  const parts = ref.split("/");
  return sanitizeTypeName(parts[parts.length - 1] ?? "Unknown");
}

function sanitizeTypeName(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9_]/g, "_");
  const prefixed = /^[A-Za-z_]/.test(cleaned) ? cleaned : `T_${cleaned}`;
  return prefixed.charAt(0).toUpperCase() + prefixed.slice(1);
}

function camelCase(input: string): string {
  const parts = input.split(/[^A-Za-z0-9]+/).filter(Boolean);
  if (parts.length === 0) return "op";
  const head = parts[0]!.charAt(0).toLowerCase() + parts[0]!.slice(1);
  const rest = parts.slice(1).map((p) => p.charAt(0).toUpperCase() + p.slice(1));
  const name = [head, ...rest].join("");
  return /^[A-Za-z_]/.test(name) ? name : `op${name}`;
}

class TypeEmitter {
  readonly warnings: string[] = [];

  tsType(schema: JsonSchema | undefined): string {
    if (!schema) return "unknown";
    if (schema.$ref) return refName(schema.$ref);
    if (schema.allOf && schema.allOf.length > 0) {
      return schema.allOf.map((s) => this.tsType(s)).join(" & ");
    }
    if (schema.oneOf && schema.oneOf.length > 0) {
      return schema.oneOf.map((s) => this.tsType(s)).join(" | ");
    }
    if (schema.anyOf && schema.anyOf.length > 0) {
      return schema.anyOf.map((s) => this.tsType(s)).join(" | ");
    }
    if (schema.enum && schema.enum.length > 0) {
      return schema.enum.map((v) => JSON.stringify(v)).join(" | ");
    }
    const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
    let base: string;
    switch (type) {
      case "string":
        base = "string";
        break;
      case "integer":
      case "number":
        base = "number";
        break;
      case "boolean":
        base = "boolean";
        break;
      case "null":
        base = "null";
        break;
      case "array":
        base = `Array<${this.tsType(schema.items)}>`;
        break;
      case "object":
        base = this.objectType(schema);
        break;
      default:
        if (schema.properties) {
          base = this.objectType(schema);
        } else {
          base = "unknown";
        }
    }
    if (schema.nullable) base = `${base} | null`;
    return base;
  }

  private objectType(schema: JsonSchema): string {
    const props = schema.properties ?? {};
    const required = new Set(schema.required ?? []);
    const entries = Object.entries(props).map(([key, value]) => {
      const optional = required.has(key) ? "" : "?";
      return `${JSON.stringify(key)}${optional}: ${this.tsType(value)}`;
    });
    if (entries.length === 0) {
      if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
        return `Record<string, ${this.tsType(schema.additionalProperties)}>`;
      }
      return "Record<string, unknown>";
    }
    let body = `{ ${entries.join("; ")} }`;
    if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
      body = `${body} & Record<string, ${this.tsType(schema.additionalProperties)}>`;
    }
    return body;
  }

  interfaceFor(name: string, schema: JsonSchema): string {
    const typeName = sanitizeTypeName(name);
    if (schema.type === "object" || schema.properties) {
      return `export interface ${typeName} ${this.objectType(schema)}\n`;
    }
    return `export type ${typeName} = ${this.tsType(schema)};\n`;
  }
}

function pickResponseSchema(op: Operation): JsonSchema | undefined {
  const responses = op.responses ?? {};
  const order = ["200", "201", "202", "2XX", "default"];
  for (const code of order) {
    const res = responses[code];
    const schema = res?.content?.["application/json"]?.schema;
    if (schema) return schema;
  }
  for (const code of Object.keys(responses)) {
    if (code.startsWith("2")) {
      const schema = responses[code]?.content?.["application/json"]?.schema;
      if (schema) return schema;
    }
  }
  return undefined;
}

function requestBodySchema(op: Operation): JsonSchema | undefined {
  return op.requestBody?.content?.["application/json"]?.schema;
}

function isOperation(value: unknown): value is Operation {
  return typeof value === "object" && value !== null;
}

/** Generate a typed fetch client + interfaces from an OpenAPI 3 document. */
export function generateSdkFromOpenApi(spec: OpenApiDocument, options: GenerateSdkOptions = {}): GeneratedSdk {
  if (!spec || typeof spec !== "object") {
    throw new Error("generateSdkFromOpenApi requires an OpenAPI document object.");
  }
  const emitter = new TypeEmitter();
  const apiKeyHeader = options.apiKeyHeader ?? "x-api-key";
  const className = sanitizeTypeName(options.className ?? spec.info?.title ?? "ApiClient");

  const schemas = spec.components?.schemas ?? {};
  const typeLines: string[] = [];
  for (const [name, schema] of Object.entries(schemas)) {
    typeLines.push(emitter.interfaceFor(name, schema));
  }

  const operations: GeneratedOperation[] = [];
  const methodLines: string[] = [];
  const usedNames = new Set<string>();

  const paths = spec.paths ?? {};
  for (const rawPath of Object.keys(paths).sort()) {
    const pathItem = paths[rawPath];
    if (!pathItem || typeof pathItem !== "object") continue;
    for (const method of HTTP_METHODS) {
      const op = (pathItem as Record<string, unknown>)[method];
      if (!isOperation(op)) continue;

      const derived = op.operationId ?? `${method}_${rawPath}`;
      let fnName = camelCase(derived);
      while (usedNames.has(fnName)) fnName = `${fnName}_`;
      usedNames.add(fnName);

      const params = op.parameters ?? [];
      const pathParams = params.filter((p) => p.in === "path");
      const queryParams = params.filter((p) => p.in === "query");
      const bodySchema = requestBodySchema(op);
      const responseSchema = pickResponseSchema(op);
      const returnType = responseSchema ? emitter.tsType(responseSchema) : "void";

      const args: string[] = [];
      for (const p of pathParams) {
        args.push(`${camelCase(p.name)}: ${emitter.tsType(p.schema) || "string"}`);
      }
      if (bodySchema) {
        const bodyRequired = op.requestBody?.required !== false;
        args.push(`body${bodyRequired ? "" : "?"}: ${emitter.tsType(bodySchema)}`);
      }
      if (queryParams.length > 0) {
        const queryType = queryParams
          .map((p) => `${JSON.stringify(p.name)}${p.required ? "" : "?"}: ${emitter.tsType(p.schema) || "string | number | boolean"}`)
          .join("; ");
        args.push(`query?: { ${queryType} }`);
      }
      args.push("init?: RequestInit");

      // Build the runtime path template.
      let pathExpr = "`" + rawPath.replace(/\{([^}]+)\}/g, (_m, name: string) => "${encodeURIComponent(String(" + camelCase(name) + "))}") + "`";
      const hasBody = Boolean(bodySchema);
      const hasQuery = queryParams.length > 0;

      const doc = op.summary || op.description ? `    /** ${(op.summary ?? op.description ?? "").replace(/\*\//g, "*\\/")} */\n` : "";
      methodLines.push(
        `${doc}    async ${fnName}(${args.join(", ")}): Promise<${returnType}> {\n` +
          `      return this.request(${JSON.stringify(method.toUpperCase())}, ${pathExpr}, {\n` +
          `        ${hasBody ? "body," : "body: undefined,"}\n` +
          `        ${hasQuery ? "query," : "query: undefined,"}\n` +
          `        init,\n` +
          `      });\n` +
          `    }`,
      );
      operations.push({ method, path: rawPath, operationId: derived, functionName: fnName });
    }
  }

  const header = `// @generated from OpenAPI by @hasna/contracts SDK generator — DO NOT EDIT.\n` +
    `// Source: ${spec.info?.title ?? "service"} ${spec.info?.version ?? ""}\n\n`;

  const runtime = `export interface ${className}Options {\n` +
    `  /** Base URL, e.g. process.env.APP_API_URL. */\n` +
    `  baseUrl: string;\n` +
    `  /** API key, e.g. process.env.APP_API_KEY. Sent as the '${apiKeyHeader}' header. */\n` +
    `  apiKey?: string;\n` +
    `  /** Custom fetch (defaults to global fetch). */\n` +
    `  fetch?: typeof fetch;\n` +
    `  /** Extra headers merged into every request. */\n` +
    `  headers?: Record<string, string>;\n` +
    `}\n\n` +
    `export class ApiError extends Error {\n` +
    `  constructor(readonly status: number, message: string, readonly body: unknown) {\n` +
    `    super(message);\n` +
    `    this.name = "ApiError";\n` +
    `  }\n` +
    `}\n\n` +
    `export class ${className} {\n` +
    `  private readonly baseUrl: string;\n` +
    `  private readonly apiKey: string | undefined;\n` +
    `  private readonly fetchImpl: typeof fetch;\n` +
    `  private readonly baseHeaders: Record<string, string>;\n\n` +
    `  constructor(options: ${className}Options) {\n` +
    `    if (!options.baseUrl) throw new Error("${className} requires a baseUrl.");\n` +
    `    this.baseUrl = options.baseUrl.replace(/\\/$/, "");\n` +
    `    this.apiKey = options.apiKey;\n` +
    `    this.fetchImpl = options.fetch ?? globalThis.fetch;\n` +
    `    this.baseHeaders = options.headers ?? {};\n` +
    `  }\n\n` +
    `  private async request<T>(method: string, path: string, opts: { body?: unknown; query?: Record<string, unknown>; init?: RequestInit }): Promise<T> {\n` +
    `    const url = new URL(this.baseUrl + path);\n` +
    `    if (opts.query) {\n` +
    `      for (const [key, value] of Object.entries(opts.query)) {\n` +
    `        if (value !== undefined && value !== null) url.searchParams.set(key, String(value));\n` +
    `      }\n` +
    `    }\n` +
    `    const headers: Record<string, string> = { Accept: "application/json", ...this.baseHeaders, ...(opts.init?.headers as Record<string, string> | undefined) };\n` +
    `    if (this.apiKey) headers[${JSON.stringify(apiKeyHeader)}] = this.apiKey;\n` +
    `    let payload: BodyInit | undefined;\n` +
    `    if (opts.body !== undefined) {\n` +
    `      headers["Content-Type"] = "application/json";\n` +
    `      payload = JSON.stringify(opts.body);\n` +
    `    }\n` +
    `    const response = await this.fetchImpl(url.toString(), { ...opts.init, method, headers, body: payload });\n` +
    `    const text = await response.text();\n` +
    `    const data = text ? (() => { try { return JSON.parse(text); } catch { return text; } })() : undefined;\n` +
    `    if (!response.ok) {\n` +
    `      throw new ApiError(response.status, \`\${method} \${path} failed: \${response.status}\`, data);\n` +
    `    }\n` +
    `    return data as T;\n` +
    `  }\n\n` +
    methodLines.join("\n\n") +
    `\n}\n`;

  const code = header + (typeLines.length > 0 ? typeLines.join("\n") + "\n" : "") + runtime;
  return { code, operations, warnings: emitter.warnings };
}
