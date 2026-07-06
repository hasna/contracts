// Hasna Service Contract v1 helpers: load, validate, and derive the canonical
// env-key spec, secret refs, and sqlite path for a repo's `hasna.contract.json`.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { z } from "zod";
import {
  ServiceContractManifestSchema,
  SCHEMA_IDS,
  allowedBinsForName,
  databaseUrlSecretRefFor,
  defaultSqlitePathFor,
  type ServiceContractManifest
} from "./schemas";
import { storageEnvKeys, type StorageEnvKeys } from "./mode";

export const SERVICE_CONTRACT_MANIFEST_FILENAME = "hasna.contract.json";

/**
 * Draft-07 JSON Schema for `hasna.contract.json`. This is the source of truth
 * for external editor tooling; `src/hasna.contract.schema.json` is a shipped
 * copy kept identical by a conformance test. Runtime validation uses the Zod
 * schema (`ServiceContractManifestSchema`), which enforces the class rules.
 */
export const SERVICE_CONTRACT_JSON_SCHEMA = {
  $schema: "http://json-schema.org/draft-07/schema#",
  $id: "https://github.com/hasna/contracts/schema/hasna.service_contract.v1.json",
  title: "Hasna Service Contract v1",
  description:
    "Repo self-description (hasna.contract.json) for the Hasna Service Contract v1. Storage runtime enum is local|cloud ONLY per Amendment A1 (PURE REMOTE).",
  type: "object",
  additionalProperties: false,
  required: ["schema", "name", "class", "contractVersion", "kitVersion"],
  properties: {
    $schema: { type: "string", description: "Optional editor hint pointing at this JSON Schema." },
    schema: { const: SCHEMA_IDS.serviceContract },
    name: {
      type: "string",
      pattern: "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$",
      description: "Lowercase dashed app short-name, e.g. todos, mailery, loops."
    },
    class: { enum: ["library", "cli-with-store", "service", "saas"] },
    contractVersion: { const: "v1" },
    kitVersion: {
      type: "string",
      minLength: 1,
      description: "Version of @hasna/contracts (the contract kit) the repo tracks."
    },
    description: { type: "string", minLength: 1 },
    bins: {
      type: "array",
      items: { type: "string", minLength: 1 },
      description:
        "Declared bins. Allowlisted: <name>, <name>-cli, <name>-mcp, <name>-serve, <name>-worker, <name>-runner, <name>-daemon, <name>-migrate, <name>-doctor."
    },
    storage: {
      type: "object",
      additionalProperties: false,
      required: ["mode"],
      properties: {
        mode: {
          enum: ["local", "cloud"],
          description: "Runtime storage enum. local|cloud ONLY (Amendment A1: PURE REMOTE)."
        },
        envPrefix: {
          type: "string",
          pattern: "^HASNA_[A-Z][A-Z0-9]*_$",
          description: "Primary env prefix, e.g. HASNA_TODOS_."
        },
        aliasEnvPrefix: {
          type: "string",
          pattern: "^[A-Z][A-Z0-9]*_$",
          description: "Optional short alias env prefix, e.g. TODOS_."
        },
        databaseUrlSecretRef: {
          type: "string",
          pattern: "^hasna/oss/[a-z0-9-]+/database-url$",
          description: "Secret Manager ref for the cloud database URL."
        },
        sqlitePath: {
          type: "string",
          minLength: 1,
          description: "Local sqlite path (~/.hasna/<name>/<name>.db)."
        }
      }
    },
    metadata: { type: "object" }
  }
} as const;

/** Validate an object as a ServiceContractManifest, returning Zod issues. */
export function validateServiceContractManifest(
  value: unknown
): z.SafeParseReturnType<unknown, ServiceContractManifest> {
  return ServiceContractManifestSchema.safeParse(value);
}

export type LoadServiceContractResult =
  | { ok: true; manifest: ServiceContractManifest; path: string }
  | { ok: false; path: string; error: string; issues?: z.ZodIssue[] };

/** Read and validate `hasna.contract.json` from a repo root. */
export function loadServiceContractManifest(repoRoot: string): LoadServiceContractResult {
  const path = join(repoRoot, SERVICE_CONTRACT_MANIFEST_FILENAME);
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, path, error: `Could not read ${SERVICE_CONTRACT_MANIFEST_FILENAME}: ${message}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, path, error: `Invalid JSON in ${SERVICE_CONTRACT_MANIFEST_FILENAME}: ${message}` };
  }
  const result = validateServiceContractManifest(parsed);
  if (!result.success) {
    return { ok: false, path, error: "Service contract manifest failed validation", issues: result.error.issues };
  }
  return { ok: true, manifest: result.data, path };
}

/** Full canonical env-key + ref spec derived from an app name. */
export interface ServiceContractSpec {
  name: string;
  env: StorageEnvKeys;
  databaseUrlSecretRef: string;
  sqlitePath: string;
  allowedBins: string[];
}

export function serviceContractSpec(name: string): ServiceContractSpec {
  return {
    name,
    env: storageEnvKeys(name),
    databaseUrlSecretRef: databaseUrlSecretRefFor(name),
    sqlitePath: defaultSqlitePathFor(name),
    allowedBins: allowedBinsForName(name)
  };
}
