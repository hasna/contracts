import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  clientTransportEnvKeys,
  createClientTransport,
  createHasnaHttpTransport,
  defaultCloudBaseUrl,
  fleetApiDomain,
  HasnaHttpError,
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
      HASNA_TODOS_API_URL: "https://todos.your-deployment.example",
      HASNA_TODOS_API_KEY: "hasna_todos_x",
    });
    expect(r.transport).toBe("local");
  });

  test("cloud + url + key => cloud-http with /v1 base", () => {
    const r = resolveClientTransport("todos", {
      HASNA_TODOS_STORAGE_MODE: "cloud",
      HASNA_TODOS_API_URL: "https://todos.your-deployment.example",
      HASNA_TODOS_API_KEY: "hasna_todos_abc",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.baseUrl).toBe("https://todos.your-deployment.example/v1");
    expect(r.apiKeyPresent).toBe(true);
    // secret value is never surfaced
    expect(JSON.stringify(r)).not.toContain("hasna_todos_abc");
  });

  test("FLIP: url+key with NO mode env => inferred cloud-http (fleet-flip contract)", () => {
    const r = resolveClientTransport("todos", {
      HASNA_TODOS_API_URL: "https://todos.your-deployment.example",
      HASNA_TODOS_API_KEY: "hasna_todos_flip",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.mode).toBe("cloud");
    expect(r.baseUrl).toBe("https://todos.your-deployment.example/v1");
    expect(r.modeSource).toBe("HASNA_TODOS_API_URL+HASNA_TODOS_API_KEY");
    expect(JSON.stringify(r)).not.toContain("hasna_todos_flip");
  });

  test("FLIP revert: url present but key removed => back to local (not misconfigured)", () => {
    const r = resolveClientTransport("todos", {
      HASNA_TODOS_API_URL: "https://todos.your-deployment.example",
    });
    expect(r.transport).toBe("local");
    expect(r.mode).toBe("local");
    expect(r.misconfigured).toBe(false);
  });

  test("self_hosted alias normalizes to cloud and defaults the host", () => {
    const r = resolveClientTransport("knowledge", {
      HASNA_KNOWLEDGE_MODE: "self_hosted",
      HASNA_KNOWLEDGE_API_KEY: "hasna_knowledge_k",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.deprecatedAlias).toBe("self_hosted");
    expect(r.baseUrl).toBe("https://knowledge.your-deployment.example/v1");
    expect(r.apiUrlSource).toBe("default");
    expect(r.misconfigured).toBe(true);
    expect(r.warning).toContain("HASNA_FLEET_API_DOMAIN");
  });

  test("explicit per-app API URL wins over a malformed fleet domain", () => {
    const r = resolveClientTransport("todos", {
      HASNA_TODOS_STORAGE_MODE: "cloud",
      HASNA_TODOS_API_URL: "  https://api.customer.example/contracts/  ",
      HASNA_TODOS_API_KEY: "hasna_todos_custom",
      HASNA_FLEET_API_DOMAIN: "https://malformed.example/path",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.baseUrl).toBe("https://api.customer.example/contracts/v1");
    expect(r.apiUrlSource).toBe("HASNA_TODOS_API_URL");
    expect(r.misconfigured).toBe(false);
  });

  test("valid fleet domain is trimmed, normalized, and used only as fallback", () => {
    const r = resolveClientTransport("todos", {
      HASNA_TODOS_STORAGE_MODE: "cloud",
      HASNA_TODOS_API_KEY: "hasna_todos_fleet",
      HASNA_FLEET_API_DOMAIN: "  Fleet.Customer.Example  ",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.baseUrl).toBe("https://todos.fleet.customer.example/v1");
    expect(r.apiUrlSource).toBe("HASNA_FLEET_API_DOMAIN");
    expect(fleetApiDomain({ HASNA_FLEET_API_DOMAIN: "  Fleet.Customer.Example  " })).toBe(
      "fleet.customer.example",
    );
  });

  test("whitespace-only fleet domain uses the neutral non-resolving placeholder", () => {
    const env = { HASNA_FLEET_API_DOMAIN: " \t\n " };
    expect(fleetApiDomain(env)).toBe("your-deployment.example");
    expect(defaultCloudBaseUrl("todos", env)).toBe("https://todos.your-deployment.example");

    const r = resolveClientTransport("todos", {
      ...env,
      HASNA_TODOS_STORAGE_MODE: "cloud",
      HASNA_TODOS_API_KEY: "hasna_todos_placeholder",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.baseUrl).toBe("https://todos.your-deployment.example/v1");
    expect(r.apiUrlSource).toBe("HASNA_FLEET_API_DOMAIN");
    expect(r.misconfigured).toBe(true);
    expect(r.warning).toContain("HASNA_FLEET_API_DOMAIN");
  });

  test("malformed fleet domains deterministically use the neutral fallback and stay explicitly misconfigured", () => {
    for (const malformedDomain of [
      "https://fleet.customer.example/path",
      "fleet.customer.example/path",
      "fleet..customer.example",
      "-fleet.customer.example",
      "fleet.customer.example-",
      "fléet.customer.example",
      "xn--r8jz45g.customer.example",
      "\nfleet.customer.example",
    ]) {
      const env = { HASNA_FLEET_API_DOMAIN: malformedDomain };
      expect(fleetApiDomain(env)).toBe("your-deployment.example");
      expect(defaultCloudBaseUrl("todos", env)).toBe("https://todos.your-deployment.example");

      const r = resolveClientTransport("todos", {
        HASNA_TODOS_STORAGE_MODE: "cloud",
        HASNA_TODOS_API_KEY: "hasna_todos_invalid_domain",
        HASNA_FLEET_API_DOMAIN: malformedDomain,
      });
      expect(r.transport).toBe("cloud-http");
      expect(r.baseUrl).toBe("https://todos.your-deployment.example/v1");
      expect(r.apiUrlSource).toBe("HASNA_FLEET_API_DOMAIN");
      expect(r.misconfigured).toBe(true);
      expect(r.warning).toContain("HASNA_FLEET_API_DOMAIN");
    }
  });

  test("hostile fleet-domain authority text cannot reach an authenticated fetch", () => {
    const env = {
      HASNA_TODOS_STORAGE_MODE: "cloud",
      HASNA_TODOS_API_KEY: "x",
      HASNA_FLEET_API_DOMAIN: "fleet.customer.example\n@evil.example",
    };
    const r = resolveClientTransport("todos", env);
    expect(r.transport).toBe("cloud-http");
    expect(r.baseUrl).toBe("https://todos.your-deployment.example/v1");
    expect(r.apiUrlSource).toBe("HASNA_FLEET_API_DOMAIN");
    expect(r.misconfigured).toBe(true);

    let fetched = false;
    expect(() =>
      createClientTransport("todos", env, {
        fetchImpl: async () => {
          fetched = true;
          return Response.json({ ok: true });
        },
      }),
    ).toThrow(/HASNA_FLEET_API_DOMAIN/);
    expect(fetched).toBe(false);
  });

  test("unset fleet domain uses the app-specific neutral fallback and is explicitly misconfigured", () => {
    const r = resolveClientTransport("todos", {
      HASNA_TODOS_STORAGE_MODE: "cloud",
      HASNA_TODOS_API_KEY: "x",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.baseUrl).toBe("https://todos.your-deployment.example/v1");
    expect(r.apiUrlSource).toBe("default");
    expect(r.misconfigured).toBe(true);
    expect(r.warning).toContain("HASNA_FLEET_API_DOMAIN");
    expect(() =>
      createClientTransport("todos", {
        HASNA_TODOS_STORAGE_MODE: "cloud",
        HASNA_TODOS_API_KEY: "x",
      }),
    ).toThrow(/HASNA_FLEET_API_DOMAIN/);
  });

  test("explicit API URLs reject raw controls and userinfo before authority parsing", () => {
    const unsafe = [
      "https://api.customer.example\n@evil.example",
      "https://api.customer.example\r@evil.example",
      "https://api.customer.example\t@evil.example",
      "https://api.customer.example@evil.example",
      "https://evil.example@api.customer.example",
      "https://user:password@api.customer.example",
      "https://api.customer.example\\@evil.example",
      "https:\\\\evil.example\\contracts",
    ];

    for (const apiUrl of unsafe) {
      expect(() => toV1BaseUrl(apiUrl)).toThrow();
      const env = {
        HASNA_TODOS_STORAGE_MODE: "cloud",
        HASNA_TODOS_API_URL: apiUrl,
        HASNA_TODOS_API_KEY: "x",
      };
      const r = resolveClientTransport("todos", env);
      expect(r.transport).toBe("local");
      expect(r.baseUrl).toBeNull();
      expect(r.misconfigured).toBe(true);
      expect(() =>
        createHasnaHttpTransport({
          name: "todos",
          baseUrl: apiUrl,
          apiKey: "x",
        }),
      ).toThrow();

      let fetched = false;
      expect(() =>
        createClientTransport("todos", env, {
          fetchImpl: async () => {
            fetched = true;
            return Response.json({ ok: true });
          },
        }),
      ).toThrow();
      expect(fetched).toBe(false);
    }
  });

  test("explicit API URLs reject Unicode, percent-normalized, and punycode authorities", () => {
    for (const apiUrl of [
      "https://例え.customer.example",
      "https://éxample.customer.example",
      "https://xn--r8jz45g.customer.example",
      "https://%65xample.customer.example",
    ]) {
      expect(() => toV1BaseUrl(apiUrl)).toThrow();
    }
  });

  test("explicit API URLs reject parser-normalized noncanonical authorities", () => {
    for (const apiUrl of [
      "https://api_customer.example",
      "https://-bad.example",
      "https://foo..bar",
      "https://api.customer.example.",
      "https://2130706433",
      "https://127.1",
      "https://0x7f000001",
      "https://0177.0.0.1",
      "https://1.2.3.4.5",
    ]) {
      expect(() => toV1BaseUrl(apiUrl)).toThrow();
      expect(() =>
        createHasnaHttpTransport({
          name: "todos",
          baseUrl: apiUrl,
          apiKey: "x",
        }),
      ).toThrow();
    }
  });

  test("invalid raw authorities are rejected before WHATWG URL construction", () => {
    const OriginalURL = globalThis.URL;
    let constructorCalled = false;
    class TrackingURL extends OriginalURL {
      constructor(url: string | URL, base?: string | URL) {
        constructorCalled = true;
        super(url, base);
      }
    }

    Object.defineProperty(globalThis, "URL", {
      configurable: true,
      value: TrackingURL,
      writable: true,
    });
    try {
      expect(() => toV1BaseUrl("https://2130706433")).toThrow();
      expect(constructorCalled).toBe(false);
    } finally {
      Object.defineProperty(globalThis, "URL", {
        configurable: true,
        value: OriginalURL,
        writable: true,
      });
    }
  });

  test("explicit API URL policy preserves HTTPS paths and ports plus deliberate loopback HTTP", () => {
    expect(toV1BaseUrl("  https://x.test:8443/contracts/  ")).toBe(
      "https://x.test:8443/contracts/v1",
    );
    expect(toV1BaseUrl("https://203.0.113.10:8443/contracts/")).toBe(
      "https://203.0.113.10:8443/contracts/v1",
    );
    expect(toV1BaseUrl("https://[2001:db8::1]:8443/contracts/")).toBe(
      "https://[2001:db8::1]:8443/contracts/v1",
    );
    expect(toV1BaseUrl("http://127.0.0.1:43123")).toBe("http://127.0.0.1:43123/v1");
    expect(toV1BaseUrl("http://localhost:43123/contracts")).toBe(
      "http://localhost:43123/contracts/v1",
    );
    expect(toV1BaseUrl("http://[::1]:43123/contracts")).toBe(
      "http://[::1]:43123/contracts/v1",
    );
    expect(() => toV1BaseUrl("http://api.customer.example/contracts")).toThrow();
    expect(() => toV1BaseUrl("https://api.customer.example/contracts?tenant=one")).toThrow();
    expect(() => toV1BaseUrl("https://api.customer.example/contracts#fragment")).toThrow();
  });

  test("default host app slug is one canonical DNS label", () => {
    for (const valid of ["todos", "agent-registry", "app2", "2fa"]) {
      expect(defaultCloudBaseUrl(valid)).toBe(`https://${valid}.your-deployment.example`);
    }

    for (const invalid of [
      "",
      "Todos",
      " todos",
      "todos ",
      "todos/path",
      "todos.path",
      "todos.example",
      "-todos",
      "todos-",
      "tódos",
      "todos\npath",
    ]) {
      expect(() => defaultCloudBaseUrl(invalid)).toThrow();
    }

    const invalidResolution = resolveClientTransport("todos/path", {
      "HASNA_TODOS/PATH_STORAGE_MODE": "cloud",
      "HASNA_TODOS/PATH_API_KEY": "x",
    });
    expect(invalidResolution.transport).toBe("local");
    expect(invalidResolution.baseUrl).toBeNull();
    expect(invalidResolution.misconfigured).toBe(true);
    expect(invalidResolution.warning).toContain("one lowercase DNS label");
  });

  test("default host validates the composed app-prefix and fleet-domain length", () => {
    const maximumStandaloneDomain = [
      "a".repeat(63),
      "b".repeat(63),
      "c".repeat(63),
      "d".repeat(61),
    ].join(".");
    const env = { HASNA_FLEET_API_DOMAIN: maximumStandaloneDomain };
    expect(maximumStandaloneDomain).toHaveLength(253);
    expect(fleetApiDomain(env)).toBe(maximumStandaloneDomain);
    expect(defaultCloudBaseUrl("todos", env)).toBe(
      "https://todos.your-deployment.example",
    );

    const r = resolveClientTransport("todos", {
      ...env,
      HASNA_TODOS_STORAGE_MODE: "cloud",
      HASNA_TODOS_API_KEY: "x",
    });
    expect(r.transport).toBe("cloud-http");
    expect(r.baseUrl).toBe("https://todos.your-deployment.example/v1");
    expect(r.apiUrlSource).toBe("HASNA_FLEET_API_DOMAIN");
    expect(r.misconfigured).toBe(true);
    expect(r.warning).toMatch(/composed cloud hostname/i);

    let fetched = false;
    expect(() =>
      createClientTransport("todos", {
        ...env,
        HASNA_TODOS_STORAGE_MODE: "cloud",
        HASNA_TODOS_API_KEY: "x",
      }, {
        fetchImpl: async () => {
          fetched = true;
          return Response.json({ ok: true });
        },
      }),
    ).toThrow(/composed cloud hostname/i);
    expect(fetched).toBe(false);
  });

  test("STORAGE_MODE=cloud (bare alias) is honored", () => {
    const r = resolveClientTransport("todos", {
      TODOS_STORAGE_MODE: "cloud",
      TODOS_API_URL: "https://todos.your-deployment.example",
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
    expect(defaultCloudBaseUrl("agent-registry")).toBe("https://agent-registry.your-deployment.example");
  });

  test("toV1BaseUrl is idempotent and strips trailing slash / existing /v1", () => {
    expect(toV1BaseUrl("https://todos.your-deployment.example")).toBe("https://todos.your-deployment.example/v1");
    expect(toV1BaseUrl("https://todos.your-deployment.example/")).toBe("https://todos.your-deployment.example/v1");
    expect(toV1BaseUrl("https://todos.your-deployment.example/v1")).toBe("https://todos.your-deployment.example/v1");
  });
});

describe("authenticated redirect boundary", () => {
  const API_KEY = ["fixture", "redirect", "value"].join("-");

  test("301/302/303/307/308 never forward credentials or bodies to a redirected authority", async () => {
    const cases: Array<{
      status: 301 | 302 | 303 | 307 | 308;
      method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
      body?: { marker: string };
    }> = [
      { status: 301, method: "GET" },
      { status: 302, method: "POST", body: { marker: "post-body" } },
      { status: 303, method: "PATCH", body: { marker: "patch-body" } },
      { status: 307, method: "PUT", body: { marker: "put-body" } },
      { status: 308, method: "DELETE", body: { marker: "delete-body" } },
    ];

    for (const redirectCase of cases) {
      const targetRequests: Array<{
        method: string;
        apiKey: string | null;
        authorization: string | null;
        body: string;
      }> = [];
      const target = Bun.serve({
        hostname: "0.0.0.0",
        port: 0,
        async fetch(req) {
          targetRequests.push({
            method: req.method,
            apiKey: req.headers.get("x-api-key"),
            authorization: req.headers.get("authorization"),
            body: await req.text(),
          });
          return Response.json({ reached: true });
        },
      });
      const sourceRequests: Array<{
        apiKey: string | null;
        authorization: string | null;
      }> = [];
      const source = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(req) {
          sourceRequests.push({
            apiKey: req.headers.get("x-api-key"),
            authorization: req.headers.get("authorization"),
          });
          return new Response(null, {
            status: redirectCase.status,
            headers: { Location: `http://0.0.0.0:${target.port}/capture` },
          });
        },
      });

      try {
        const transport = createHasnaHttpTransport({
          name: "redirect-regression",
          baseUrl: `http://127.0.0.1:${source.port}`,
          apiKey: API_KEY,
          retry: false,
        });
        let thrown: unknown;
        try {
          await transport.request(
            redirectCase.method,
            `/redirect-${redirectCase.status}`,
            redirectCase.body,
            { headers: { "x-transport-marker": `status-${redirectCase.status}` } },
          );
        } catch (error) {
          thrown = error;
        }

        expect(thrown).toBeInstanceOf(HasnaHttpError);
        const httpError = thrown as HasnaHttpError;
        expect(httpError.status).toBe(redirectCase.status);
        expect(httpError.method).toBe(redirectCase.method);
        expect(httpError.path).toBe(`/redirect-${redirectCase.status}`);
        expect(httpError.message).toBe(
          `Hasna cloud request failed: ${redirectCase.method} /redirect-${redirectCase.status} -> ${redirectCase.status}`,
        );
        expect(sourceRequests).toEqual([
          { apiKey: API_KEY, authorization: `Bearer ${API_KEY}` },
        ]);
        expect(targetRequests).toEqual([]);
      } finally {
        source.stop(true);
        target.stop(true);
      }
    }
  });

  test("same-origin redirects and redirect loops fail after exactly one request", async () => {
    let sameOriginDestinationHits = 0;
    let loopHits = 0;
    let source: ReturnType<typeof Bun.serve>;
    source = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === "/v1/same-origin") {
          return new Response(null, {
            status: 307,
            headers: { Location: `http://127.0.0.1:${source.port}/v1/destination` },
          });
        }
        if (url.pathname === "/v1/destination") {
          sameOriginDestinationHits++;
          return Response.json({ reached: true });
        }
        if (url.pathname === "/v1/loop") {
          loopHits++;
          return new Response(null, {
            status: 308,
            headers: { Location: `http://127.0.0.1:${source.port}/v1/loop` },
          });
        }
        return Response.json({ error: "not_found" }, { status: 404 });
      },
    });

    try {
      const transport = createHasnaHttpTransport({
        name: "redirect-regression",
        baseUrl: `http://127.0.0.1:${source.port}`,
        apiKey: API_KEY,
        retry: false,
      });

      await expect(transport.get("/same-origin")).rejects.toMatchObject({
        status: 307,
        method: "GET",
        path: "/same-origin",
      });
      expect(sameOriginDestinationHits).toBe(0);

      await expect(transport.get("/loop")).rejects.toMatchObject({
        status: 308,
        method: "GET",
        path: "/loop",
      });
      expect(loopHits).toBe(1);
    } finally {
      source.stop(true);
    }
  });

  test("redirect destinations are never interpreted or followed by the authenticated fetch", async () => {
    for (const location of [
      "https://redirect.customer.example/v1",
      "http://api.customer.example/v1",
      "https://user:password@redirect.customer.example/v1",
      "file:///tmp/redirect-target",
      "data:application/json,%7B%22reached%22%3Atrue%7D",
    ]) {
      const calls: Array<{ url: string; redirect: RequestRedirect | undefined }> = [];
      const transport = createHasnaHttpTransport({
        name: "redirect-regression",
        baseUrl: "https://api.customer.example/v1",
        apiKey: API_KEY,
        retry: false,
        fetchImpl: async (url, init) => {
          calls.push({ url, redirect: init?.redirect });
          return new Response(null, {
            status: 307,
            headers: { Location: location },
          });
        },
      });

      await expect(transport.get("/items")).rejects.toMatchObject({
        status: 307,
        method: "GET",
        path: "/items",
      });
      expect(calls).toEqual([
        {
          url: "https://api.customer.example/v1/items",
          redirect: "manual",
        },
      ]);
    }
  });

  test("redirect responses are never retried even when a caller lists their status", async () => {
    let hits = 0;
    const transport = createHasnaHttpTransport({
      name: "redirect-regression",
      baseUrl: "https://api.customer.example/v1",
      apiKey: API_KEY,
      fetchImpl: async () => {
        hits++;
        return new Response(null, {
          status: 307,
          headers: { Location: "https://redirect.customer.example/v1" },
        });
      },
      sleepImpl: async () => {},
    });

    await expect(
      transport.get("/items", {
        retry: { retries: 3, retryStatuses: [307] },
      }),
    ).rejects.toMatchObject({ status: 307 });
    expect(hits).toBe(1);
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
