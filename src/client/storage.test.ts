import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  appendQuery,
  createHasnaHttpTransport,
  HasnaHttpError,
  type HasnaRequestOptions,
} from "./transport.js";
import { createHasnaStorageClient, resolveStorageClient } from "./storage.js";

// A scriptable fetch stub that records requests and returns queued responses.
function makeFetch(handler: (req: { method: string; url: string; headers: Record<string, string>; body: unknown }) => { status: number; body?: unknown; text?: string }) {
  const calls: { method: string; url: string; headers: Record<string, string>; body: unknown }[] = [];
  const fetchImpl = async (input: string, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    if (init?.headers) for (const [k, v] of Object.entries(init.headers as Record<string, string>)) headers[k.toLowerCase()] = v;
    const body = init?.body ? JSON.parse(init.body as string) : undefined;
    const call = { method: init?.method ?? "GET", url: input, headers, body };
    calls.push(call);
    const r = handler(call);
    const text = r.text !== undefined ? r.text : r.body !== undefined ? JSON.stringify(r.body) : "";
    return new Response(text, { status: r.status, headers: { "content-type": "application/json" } });
  };
  return { fetchImpl, calls };
}

describe("appendQuery", () => {
  test("serializes scalars, arrays; drops nullish; respects existing query", () => {
    expect(appendQuery("/notes", { limit: 10, archived: false, skip: undefined, q: null })).toBe("/notes?limit=10&archived=false");
    expect(appendQuery("/notes", { tag: ["a", "b"] })).toBe("/notes?tag=a&tag=b");
    expect(appendQuery("/notes?x=1", { y: 2 })).toBe("/notes?x=1&y=2");
    expect(appendQuery("/notes")).toBe("/notes");
  });
});

describe("HasnaStorageClient CRUD mapping", () => {
  const sampleApiKey = "hasna_sample_key";

  function client(handler: Parameters<typeof makeFetch>[0]) {
    const { fetchImpl, calls } = makeFetch(handler);
    const transport = createHasnaHttpTransport({ name: "knowledge", baseUrl: "https://knowledge.hasna.xyz/v1", apiKey: sampleApiKey, fetchImpl, retry: false });
    return { store: createHasnaStorageClient("knowledge", transport), calls };
  }

  test("list -> GET /<resource>, extracts items + total from envelope", async () => {
    const { store, calls } = client(() => ({ status: 200, body: { items: [{ id: "1" }, { id: "2" }], total: 42 } }));
    const res = await store.list("notes", { query: { limit: 2 } });
    expect(res.items.map((i: any) => i.id)).toEqual(["1", "2"]);
    expect(res.total).toBe(42);
    expect(calls[0]!.method).toBe("GET");
    expect(calls[0]!.url).toBe("https://knowledge.hasna.xyz/v1/notes?limit=2");
    // key never in URL
    expect(calls[0]!.url).not.toContain("secret");
  });

  test("get -> GET /<resource>/<id>; 404 => null", async () => {
    const { store } = client((req) => (req.url.endsWith("/miss") ? { status: 404, body: { error: "not_found" } } : { status: 200, body: { id: "abc" } }));
    expect(await store.get("notes", "abc")).toEqual({ id: "abc" } as any);
    expect(await store.get("notes", "miss")).toBeNull();
  });

  test("create -> POST /<resource> with auto Idempotency-Key + bearer", async () => {
    const { store, calls } = client(() => ({ status: 201, body: { id: "new" } }));
    const out = await store.create("notes", { title: "t" });
    expect(out).toEqual({ id: "new" } as any);
    const c = calls[0]!;
    expect(c.method).toBe("POST");
    expect(c.headers["idempotency-key"]).toBeTruthy();
    expect(c.headers["authorization"]).toBe(`Bearer ${sampleApiKey}`);
    expect(c.headers["x-api-key"]).toBe(sampleApiKey);
    expect(c.body).toEqual({ title: "t" });
  });

  test("create honors a caller-supplied idempotency key", async () => {
    const { store, calls } = client(() => ({ status: 201, body: {} }));
    await store.create("notes", { title: "t" }, { idempotencyKey: "fixed-123" });
    expect(calls[0]!.headers["idempotency-key"]).toBe("fixed-123");
  });

  test("update -> PATCH by default, PUT on option", async () => {
    const { store, calls } = client(() => ({ status: 200, body: { ok: true } }));
    await store.update("notes", "id1", { tags: ["x"] });
    await store.update("notes", "id2", { tags: ["y"] }, { method: "PUT" });
    expect(calls[0]!.method).toBe("PATCH");
    expect(calls[0]!.url).toBe("https://knowledge.hasna.xyz/v1/notes/id1");
    expect(calls[1]!.method).toBe("PUT");
  });

  test("delete -> DELETE /<resource>/<id>; 204 and 404 both resolve", async () => {
    const { store, calls } = client((req) => (req.url.endsWith("/gone") ? { status: 404 } : { status: 204, text: "" }));
    await store.delete("notes", "id1");
    await store.delete("notes", "gone");
    expect(calls[0]!.method).toBe("DELETE");
  });

  test("non-2xx (non-404) surfaces HasnaHttpError with status + body", async () => {
    const { store } = client(() => ({ status: 400, body: { error: "bad_request", message: "title required" } }));
    await expect(store.create("notes", {})).rejects.toBeInstanceOf(HasnaHttpError);
    try {
      await store.create("notes", {});
    } catch (e) {
      const err = e as HasnaHttpError;
      expect(err.status).toBe(400);
      expect((err.body as any).message).toBe("title required");
    }
  });

  test("id path segments are URL-encoded", async () => {
    const { store, calls } = client(() => ({ status: 200, body: {} }));
    await store.get("notes", "a/b c");
    expect(calls[0]!.url).toBe("https://knowledge.hasna.xyz/v1/notes/a%2Fb%20c");
  });
});

describe("retries + idempotency", () => {
  const noSleep = async () => {};

  test("GET retries transient 503 then succeeds", async () => {
    let n = 0;
    const { fetchImpl, calls } = makeFetch(() => (++n < 3 ? { status: 503, body: { error: "unavailable" } } : { status: 200, body: { id: "ok" } }));
    const t = createHasnaHttpTransport({ name: "app", baseUrl: "https://x/v1", apiKey: "k", fetchImpl, sleepImpl: noSleep });
    expect(await t.get("/notes")).toEqual({ id: "ok" } as any);
    expect(calls.length).toBe(3);
  });

  test("POST without idempotency key is NOT retried (no duplicate writes)", async () => {
    let n = 0;
    const { fetchImpl, calls } = makeFetch(() => { n++; return { status: 503, body: { error: "unavailable" } }; });
    const t = createHasnaHttpTransport({ name: "app", baseUrl: "https://x/v1", apiKey: "k", fetchImpl, sleepImpl: noSleep });
    await expect(t.post("/notes", { title: "t" })).rejects.toBeInstanceOf(HasnaHttpError);
    expect(calls.length).toBe(1);
  });

  test("POST WITH idempotency key IS retried", async () => {
    let n = 0;
    const { fetchImpl, calls } = makeFetch(() => (++n < 2 ? { status: 503, body: {} } : { status: 201, body: { id: "z" } }));
    const t = createHasnaHttpTransport({ name: "app", baseUrl: "https://x/v1", apiKey: "k", fetchImpl, sleepImpl: noSleep });
    const opts: HasnaRequestOptions = { idempotencyKey: "abc" };
    expect(await t.post("/notes", { title: "t" }, opts)).toEqual({ id: "z" } as any);
    expect(calls.length).toBe(2);
  });

  test("4xx (non-retry status) is not retried", async () => {
    const { fetchImpl, calls } = makeFetch(() => ({ status: 400, body: { error: "bad" } }));
    const t = createHasnaHttpTransport({ name: "app", baseUrl: "https://x/v1", apiKey: "k", fetchImpl, sleepImpl: noSleep });
    await expect(t.get("/notes")).rejects.toBeInstanceOf(HasnaHttpError);
    expect(calls.length).toBe(1);
  });

  test("caller-initiated abort is NOT retried (propagates immediately)", async () => {
    const controller = new AbortController();
    const { fetchImpl, calls } = makeFetch(() => { controller.abort(); throw new DOMException("aborted", "AbortError"); });
    const t = createHasnaHttpTransport({ name: "app", baseUrl: "https://x/v1", apiKey: "k", fetchImpl, sleepImpl: noSleep });
    await expect(t.get("/notes", { signal: controller.signal })).rejects.toThrow();
    expect(calls.length).toBe(1);
  });

  test("retries give up after configured attempts", async () => {
    const { fetchImpl, calls } = makeFetch(() => ({ status: 500, body: {} }));
    const t = createHasnaHttpTransport({ name: "app", baseUrl: "https://x/v1", apiKey: "k", fetchImpl, sleepImpl: noSleep, retry: { retries: 3 } });
    await expect(t.get("/notes")).rejects.toBeInstanceOf(HasnaHttpError);
    expect(calls.length).toBe(4); // 1 + 3 retries
  });
});

// End-to-end: a demo app storage resolver picks the HTTP client on flip, local otherwise.
describe("resolveStorageClient — the resolver an app wires", () => {
  const KEY = "hasna_demo_resolver_secret";
  const cloud = new Map<string, { id: string; title: string }>();
  let server: ReturnType<typeof Bun.serve>;
  let baseUrl: string;

  beforeAll(() => {
    let seq = 0;
    server = Bun.serve({
      port: 0,
      async fetch(req) {
        const url = new URL(req.url);
        if ((req.headers.get("authorization") ?? "") !== `Bearer ${KEY}`) return Response.json({ error: "unauthorized" }, { status: 401 });
        const m = req.method;
        if (url.pathname === "/v1/things" && m === "GET") return Response.json({ items: [...cloud.values()], total: cloud.size });
        if (url.pathname === "/v1/things" && m === "POST") {
          const b = (await req.json()) as { title: string };
          const id = `t${++seq}`;
          const row = { id, title: b.title };
          cloud.set(id, row);
          return Response.json(row, { status: 201 });
        }
        const idm = url.pathname.match(/^\/v1\/things\/(.+)$/);
        if (idm) {
          const id = decodeURIComponent(idm[1]!);
          if (m === "GET") return cloud.has(id) ? Response.json(cloud.get(id)) : Response.json({ error: "not_found" }, { status: 404 });
          if (m === "PATCH") { const b = (await req.json()) as any; const row = { ...cloud.get(id)!, ...b }; cloud.set(id, row); return Response.json(row); }
          if (m === "DELETE") { cloud.delete(id); return new Response("", { status: 204 }); }
        }
        return Response.json({ error: "not_found" }, { status: 404 });
      },
    });
    baseUrl = `http://127.0.0.1:${server.port}`;
  });
  afterAll(() => server.stop(true));

  test("no env => local (client null)", () => {
    const r = resolveStorageClient("demo", {});
    expect(r.transport).toBe("local");
    expect(r.client).toBeNull();
  });

  test("self_hosted + url + key => cloud-http, full CRUD lands in cloud store", async () => {
    const env = { HASNA_DEMO_STORAGE_MODE: "self_hosted", HASNA_DEMO_API_URL: baseUrl, HASNA_DEMO_API_KEY: KEY };
    const r = resolveStorageClient("demo", env);
    expect(r.transport).toBe("cloud-http");
    const store = r.client!;
    const created = await store.create<{ id: string; title: string }>("things", { title: "first" });
    expect(created.id).toBeTruthy();
    expect(cloud.has(created.id)).toBe(true);
    expect(await store.get("things", created.id)).toEqual(created as any);
    const listed = await store.list("things");
    expect(listed.items.length).toBe(1);
    expect(listed.total).toBe(1);
    const updated = await store.update<{ title: string }>("things", created.id, { title: "second" });
    expect(updated.title).toBe("second");
    await store.delete("things", created.id);
    expect(await store.get("things", created.id)).toBeNull();
    expect(cloud.size).toBe(0);
  });

  test("cloud requested but no key => throws (never silent local drift)", () => {
    expect(() => resolveStorageClient("demo", { HASNA_DEMO_STORAGE_MODE: "cloud" })).toThrow();
  });
});
