// LIVE conformance: drive the HTTP storage client against a REAL Hasna cloud app
// (`knowledge.your-deployment.example/v1`) end to end — create, get, list,
// update, delete —
// proving the client satisfies the app storage interface over the wire with a
// real API key.
//
// The key is pulled at runtime from Secrets Manager (`hasna/oss/<app>/api-key`)
// via the AWS CLI. If AWS creds / the CLI / network are unavailable, the test is
// SKIPPED (not failed) so offline CI stays green. Set
// HASNA_CONTRACTS_LIVE_CONFORMANCE=0 to force-skip.
//
// SAFETY: the key value is never printed. Everything the client creates is
// deleted at the end; the note is tagged so a stray row is identifiable.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { createHasnaStorageClient, type HasnaStorageClient } from "./storage.js";
import { createHasnaHttpTransport, defaultCloudBaseUrl, toV1BaseUrl } from "./transport.js";

const APP = "knowledge";
const RESOURCE = "notes";
// Real live runs should set the explicit per-app URL or a valid fleet domain.
// Absent both, this uses the same neutral, non-resolving placeholder as the
// package and fails fast instead of targeting a guessed real hostname.
const HOST = process.env.HASNA_KNOWLEDGE_API_URL?.trim() || defaultCloudBaseUrl(APP);

function fetchApiKey(app: string): string | null {
  if (process.env.HASNA_CONTRACTS_LIVE_CONFORMANCE === "0") return null;
  // Allow an already-exported key (CI secret) to avoid an AWS round-trip.
  const fromEnv = process.env[`HASNA_${app.toUpperCase()}_API_KEY`]?.trim();
  if (fromEnv) return fromEnv;
  try {
    const res = spawnSync(
      "aws",
      ["secretsmanager", "get-secret-value", "--secret-id", `hasna/oss/${app}/api-key`, "--query", "SecretString", "--output", "text", "--region", "us-east-1"],
      { encoding: "utf8", timeout: 20_000 },
    );
    if (res.status !== 0) return null;
    const key = res.stdout.trim();
    return key.length > 0 && !key.startsWith("None") ? key : null;
  } catch {
    return null;
  }
}

async function reachable(): Promise<boolean> {
  try {
    const r = await fetch(`${HOST}/health`, { signal: AbortSignal.timeout(8_000) });
    return r.ok;
  } catch {
    return false;
  }
}

describe("LIVE conformance: HTTP storage client vs a real cloud app", async () => {
  const apiKey = fetchApiKey(APP);
  const up = apiKey ? await reachable() : false;
  const run = Boolean(apiKey) && up;
  if (!run) {
    test.skip(`skipped: ${apiKey ? "app unreachable" : "no API key (AWS/env)"} — set HASNA_${APP.toUpperCase()}_API_KEY or ensure AWS creds`, () => {});
    return;
  }

  let store: HasnaStorageClient;
  const createdIds: string[] = [];

  beforeAll(() => {
    const transport = createHasnaHttpTransport({ name: APP, baseUrl: toV1BaseUrl(HOST), apiKey: apiKey!, timeoutMs: 20_000 });
    store = createHasnaStorageClient(APP, transport);
  });

  afterAll(async () => {
    for (const id of createdIds) {
      try {
        await store.delete(RESOURCE, id);
      } catch {
        /* best-effort cleanup */
      }
    }
  });

  test("create -> get -> list -> update -> delete round-trips on the live API", async () => {
    const marker = `contracts-live-conformance ${Date.now()}`;
    const created = await store.create<{ id: string; title: string; tags: string[] }>(RESOURCE, {
      title: marker,
      content: "created by @hasna/contracts live conformance test",
      tags: ["conformance", "contracts-client"],
    });
    expect(created.id).toBeTruthy();
    createdIds.push(created.id);

    const got = await store.get<{ id: string; title: string }>(RESOURCE, created.id);
    expect(got?.id).toBe(created.id);
    expect(got?.title).toBe(marker);

    const listed = await store.list<{ id: string }>(RESOURCE, { query: { limit: 5 } });
    expect(Array.isArray(listed.items)).toBe(true);
    expect(listed.total === null || typeof listed.total === "number").toBe(true);

    const updated = await store.update<{ id: string; tags: string[] }>(RESOURCE, created.id, { tags: ["conformance", "updated"] });
    expect(updated.id).toBe(created.id);

    await store.delete(RESOURCE, created.id);
    createdIds.pop();
    const afterDelete = await store.get(RESOURCE, created.id);
    expect(afterDelete).toBeNull();
  }, 40_000);

  test("get on a non-existent id returns null (404 => null)", async () => {
    const missing = await store.get(RESOURCE, "does-not-exist-00000000-0000-0000-0000-000000000000");
    expect(missing).toBeNull();
  }, 20_000);
});
