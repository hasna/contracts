import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateSdkFromOpenApi, type OpenApiDocument } from "../src/sdk/generate";

const spec: OpenApiDocument = {
  openapi: "3.0.3",
  info: { title: "Todos Serve", version: "1.0.0" },
  components: {
    schemas: {
      Task: {
        type: "object",
        required: ["id", "title"],
        properties: {
          id: { type: "string" },
          title: { type: "string" },
          done: { type: "boolean" },
          priority: { type: "string", enum: ["low", "high"] },
        },
      },
      HealthStatus: {
        type: "object",
        required: ["status", "version", "mode"],
        properties: {
          status: { type: "string" },
          version: { type: "string" },
          mode: { type: "string" },
        },
      },
    },
  },
  paths: {
    "/health": {
      get: { operationId: "getHealth", summary: "Health probe", responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/HealthStatus" } } } } } },
    },
    "/tasks": {
      get: {
        operationId: "listTasks",
        parameters: [{ name: "limit", in: "query", required: false, schema: { type: "integer" } }],
        responses: { "200": { content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Task" } } } } } },
      },
      post: {
        operationId: "createTask",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/Task" } } } },
        responses: { "201": { content: { "application/json": { schema: { $ref: "#/components/schemas/Task" } } } } },
      },
    },
    "/tasks/{id}": {
      get: {
        operationId: "getTask",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/Task" } } } } },
      },
    },
  },
};

const tmp = mkdtempSync(join(tmpdir(), "hasna-sdk-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("SDK from OpenAPI generator", () => {
  test("emits interfaces, a client class, and one method per operation", () => {
    const sdk = generateSdkFromOpenApi(spec, { className: "TodosClient" });
    expect(sdk.code).toContain("export interface Task");
    expect(sdk.code).toContain("export interface HealthStatus");
    expect(sdk.code).toContain("export class TodosClient");
    expect(sdk.code).toContain('"low" | "high"');
    expect(sdk.operations.map((o) => o.functionName).sort()).toEqual(["createTask", "getHealth", "getTask", "listTasks"]);
    expect(sdk.warnings).toEqual([]);
  });

  test("generated client is valid and drives requests with a mocked fetch", async () => {
    const sdk = generateSdkFromOpenApi(spec, { className: "TodosClient" });
    const file = join(tmp, "client.ts");
    writeFileSync(file, sdk.code, "utf8");
    const mod: any = await import(file);
    expect(typeof mod.TodosClient).toBe("function");

    const calls: Array<{ url: string; method: string; headers: Record<string, string>; body: unknown }> = [];
    const fakeFetch = (async (url: string, init: any) => {
      calls.push({ url: String(url), method: init.method, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined });
      if (String(url).includes("/health")) {
        return new Response(JSON.stringify({ status: "ok", version: "1.0.0", mode: "self_hosted" }), { status: 200 });
      }
      return new Response(JSON.stringify({ id: "t1", title: "hello" }), { status: 200 });
    }) as unknown as typeof fetch;

    const client = new mod.TodosClient({ baseUrl: "https://todos.example.com/", apiKey: "hasna_todos_KEY", fetch: fakeFetch });

    const health = await client.getHealth();
    expect(health.status).toBe("ok");

    const task = await client.getTask("t 1");
    expect(task.id).toBe("t1");

    await client.listTasks({ limit: 5 });
    await client.createTask({ id: "t2", title: "new" });

    // API key header sent on every call.
    expect(calls.every((c) => c.headers["x-api-key"] === "hasna_todos_KEY")).toBe(true);
    // Path templating with encoding.
    expect(calls.find((c) => c.url.includes("/tasks/"))!.url).toContain("t%201");
    // Query serialization.
    expect(calls.find((c) => c.url.includes("limit="))!.url).toContain("limit=5");
    // POST body.
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.body).toEqual({ id: "t2", title: "new" });
  });

  test("throws on a non-object spec (no silent stub)", () => {
    // @ts-expect-error intentional bad input
    expect(() => generateSdkFromOpenApi(null)).toThrow();
  });
});
