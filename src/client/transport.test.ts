import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  clientTransportEnvKeys,
  createClientTransport,
  createHasnaHttpTransport,
  defaultCloudBaseUrl,
  resolveClientTransport,
  toV1BaseUrl,
} from "./transport.js";

describe("resolveClientTransport — the client-flip contract", () => {
  test("no env => local", () => {
    const r = resolveClientTransport("todos", {});
    expect(r.transport).toBe("local");
    expect(r.mode).toBe("local");
    expect(r.misconfigured).toBe(false);
  });

  test("explicit local mode never routes to cloud even with url+key", () => {
    const r = resolveClientTransport("todos", {
      HASNA_TODOS_STORAGE_MODE: "local",
      HASNA_TODOS_API_URL: "https://todos.hasna.xyz",
      HASNA_TODOS_API_KEY: "hasna_todos_x",
    });
    expect(r.transport).toBe("local");
  });

  test("cloud + url + key => cloud-http with /v1 base", () => {
    const r = resolveClientTransport("todos", {
      HASNA_TODOS_STORAGE_MODE: "cloud",
      HASNA_TODOS_API_URL: "https://todos.hasna.xyz",
      HASNA_TODOS_API_KEY: "hasna_todos_abc",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.baseUrl).toBe("https://todos.hasna.xyz/v1");
    expect(r.apiKeyPresent).toBe(true);
    // secret value is never surfaced
    expect(JSON.stringify(r)).not.toContain("hasna_todos_abc");
  });

  test("self_hosted alias normalizes to cloud and defaults the host", () => {
    const r = resolveClientTransport("knowledge", {
      HASNA_KNOWLEDGE_MODE: "self_hosted",
      HASNA_KNOWLEDGE_API_KEY: "hasna_knowledge_k",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.deprecatedAlias).toBe("self_hosted");
    expect(r.baseUrl).toBe("https://knowledge.hasna.xyz/v1");
    expect(r.apiUrlSource).toBe("default");
  });

  test("STORAGE_MODE=cloud (bare alias) is honored", () => {
    const r = resolveClientTransport("todos", {
      TODOS_STORAGE_MODE: "cloud",
      TODOS_API_URL: "https://todos.hasna.xyz",
      TODOS_API_KEY: "hasna_todos_z",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.modeSource).toBe("TODOS_STORAGE_MODE");
  });

  test("cloud requested but NO key => local + misconfigured (never silent wrong data)", () => {
    const r = resolveClientTransport("todos", { HASNA_TODOS_STORAGE_MODE: "cloud" });
    expect(r.transport).toBe("local");
    expect(r.misconfigured).toBe(true);
    expect(r.warning).toContain("HASNA_TODOS_API_KEY");
  });

  test("createClientTransport throws on misconfigured cloud", () => {
    expect(() => createClientTransport("todos", { HASNA_TODOS_STORAGE_MODE: "cloud" })).toThrow();
  });

  test("env-key spec + defaults", () => {
    const keys = clientTransportEnvKeys("agent-registry");
    expect(keys.modeKeys[0]).toBe("HASNA_AGENT_REGISTRY_STORAGE_MODE");
    expect(keys.apiUrlKeys[0]).toBe("HASNA_AGENT_REGISTRY_API_URL");
    expect(keys.apiKeyKeys[0]).toBe("HASNA_AGENT_REGISTRY_API_KEY");
    expect(defaultCloudBaseUrl("agent-registry")).toBe("https://agent-registry.hasna.xyz");
  });

  test("toV1BaseUrl is idempotent and strips trailing slash / existing /v1", () => {
    expect(toV1BaseUrl("https://todos.hasna.xyz")).toBe("https://todos.hasna.xyz/v1");
    expect(toV1BaseUrl("https://todos.hasna.xyz/")).toBe("https://todos.hasna.xyz/v1");
    expect(toV1BaseUrl("https://todos.hasna.xyz/v1")).toBe("https://todos.hasna.xyz/v1");
  });
});

// ---------------------------------------------------------------------------
// END-TO-END PROOF: a real loopback `/v1` server (the "cloud") + a demo app
// storage resolver that uses the shared contract to flip between a local file
// and the HTTP transport. Proves: flip on => reads/writes hit the cloud server
// (data lands in the server's store); flip off => reads/writes hit the local
// file. Same code path every real app will use.
// ---------------------------------------------------------------------------

interface Item {
  id: string;
  text: string;
}

describe("end-to-end data-source flip (real HTTP loopback)", () => {
  const EXPECTED_KEY = "hasna_demo_e2e_secret";
  const cloudStore = new Map<string, Item>();
  const seenAuth: string[] = [];
  let server: ReturnType<typeof Bun.serve>;
  let baseUrl: string;
  let localFile: string;
  let tmp: string;

  beforeAll(() => {
    server = Bun.serve({
      port: 0,
      async fetch(req) {
        const url = new URL(req.url);
        const key = req.headers.get("x-api-key") ?? "";
        const bearer = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
        seenAuth.push(key);
        if (key !== EXPECTED_KEY || bearer !== EXPECTED_KEY) {
          return Response.json({ error: "unauthorized" }, { status: 401 });
        }
        if (url.pathname === "/v1/items" && req.method === "GET") {
          return Response.json({ items: [...cloudStore.values()] });
        }
        if (url.pathname === "/v1/items" && req.method === "POST") {
          const body = (await req.json()) as Item;
          cloudStore.set(body.id, body);
          return Response.json({ ok: true, item: body }, { status: 201 });
        }
        return Response.json({ error: "not_found", path: url.pathname }, { status: 404 });
      },
    });
    baseUrl = `http://127.0.0.1:${server.port}`;
    tmp = mkdtempSync(join(tmpdir(), "hasna-flip-"));
    localFile = join(tmp, "db.json");
    writeFileSync(localFile, JSON.stringify({ items: [{ id: "local-1", text: "from local file" }] }));
  });

  afterAll(() => {
    server.stop(true);
    rmSync(tmp, { recursive: true, force: true });
  });

  // A demo app storage layer whose ONLY decision is `resolveClientTransport`.
  function makeStore(env: Record<string, string | undefined>) {
    const wired = createClientTransport("demo", env, {});
    return {
      wired,
      async list(): Promise<Item[]> {
        if (wired.transport === "cloud-http") {
          const res = await wired.client.get<{ items: Item[] }>("/items");
          return res.items;
        }
        return JSON.parse(readFileSync(localFile, "utf8")).items as Item[];
      },
      async add(item: Item): Promise<void> {
        if (wired.transport === "cloud-http") {
          await wired.client.post("/items", item);
          return;
        }
        const data = JSON.parse(readFileSync(localFile, "utf8"));
        data.items.push(item);
        writeFileSync(localFile, JSON.stringify(data));
      },
    };
  }

  const cloudEnv = {
    HASNA_DEMO_STORAGE_MODE: "self_hosted",
    HASNA_DEMO_API_URL: "", // filled in test (dynamic port)
    HASNA_DEMO_API_KEY: EXPECTED_KEY,
  };

  test("flip OFF (local): reads the local file, writes land locally", async () => {
    const store = makeStore({});
    expect(store.wired.transport).toBe("local");
    const before = await store.list();
    expect(before).toEqual([{ id: "local-1", text: "from local file" }]);
    await store.add({ id: "local-2", text: "local write" });
    const after = await store.list();
    expect(after.map((i) => i.id)).toEqual(["local-1", "local-2"]);
    // Nothing leaked to the cloud store.
    expect(cloudStore.size).toBe(0);
  });

  test("flip ON (cloud): read hits cloud, write LANDS in cloud DB, not local", async () => {
    // Seed cloud so a read is provably from the server, not the local file.
    cloudStore.set("cloud-1", { id: "cloud-1", text: "from cloud server" });
    const env = { ...cloudEnv, HASNA_DEMO_API_URL: baseUrl };
    const store = makeStore(env);
    expect(store.wired.transport).toBe("cloud-http");
    expect(store.wired.resolution.baseUrl).toBe(`${baseUrl}/v1`);

    const read = await store.list();
    expect(read).toEqual([{ id: "cloud-1", text: "from cloud server" }]); // NOT the local-file items

    await store.add({ id: "cloud-2", text: "cloud write" });
    // Write landed in the SERVER store...
    expect(cloudStore.has("cloud-2")).toBe(true);
    // ...and the local file is untouched (still just local-1 + local-2 from prior test).
    const localItems = JSON.parse(readFileSync(localFile, "utf8")).items as Item[];
    expect(localItems.map((i) => i.id)).toEqual(["local-1", "local-2"]);
    // The API key was actually sent on the wire.
    expect(seenAuth).toContain(EXPECTED_KEY);
  });

  test("flip BACK OFF (unset): instantly reverts to the untouched local original", async () => {
    const store = makeStore({});
    expect(store.wired.transport).toBe("local");
    const items = await store.list();
    // Exactly the local writes; zero cloud contamination.
    expect(items.map((i) => i.id)).toEqual(["local-1", "local-2"]);
  });

  test("wrong/absent key is rejected by the server (auth is enforced)", async () => {
    const bad = createHasnaHttpTransport({ name: "demo", baseUrl: `${baseUrl}/v1`, apiKey: "wrong" });
    await expect(bad.get("/items")).rejects.toThrow(/401/);
  });
});
