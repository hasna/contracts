// Hasna Service Contract v1 helpers: load, validate, and derive the canonical
// env-key spec, secret refs, and sqlite path for a repo's `hasna.contract.json`.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { z } from "zod";
import {
  ServiceContractManifestSchema,
  SCHEMA_IDS,
  STORAGE_WAIVER_REASON_MAX_LENGTH,
  STORAGE_WAIVER_REVIEWER_MAX_LENGTH,
  WAIVABLE_STORAGE_ENGINES,
  allowedBinsForName,
  databaseUrlSecretRefFor,
  defaultSqlitePathFor,
  type ServiceContractManifest
} from "./schemas";

import { storageEnvKeys, type StorageEnvKeys } from "./mode";

export const SERVICE_CONTRACT_MANIFEST_FILENAME = "hasna.contract.json";

/**
 * JSON-Schema mirror of the zod control-character rejection on waiver prose.
 * Kept as a constant so the two copies of the shipped schema cannot drift.
 */
const WAIVER_TEXT_JSON_SCHEMA_PATTERN = "^[^\\u0000-\\u001f\\u007f]*$";

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
    "Repo self-description (hasna.contract.json) for the Hasna Service Contract v1. Hosting story, product surfaces, and storage capabilities are separate declarations; the storage backend (sqlite | postgres) is the only runtime switch.",
  type: "object",
  additionalProperties: false,
  required: ["schema", "name", "class", "contractVersion", "kitVersion"],
  allOf: [
    {
      if: {
        required: ["class"],
        properties: {
          class: { const: "saas" }
        }
      },
      then: {
        required: ["storage"],
        properties: {
          storage: {
            required: ["mode", "envPrefix"],
            properties: {
              mode: { const: "postgres" }
            }
          }
        }
      }
    }
  ],
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
    hosting: {
      type: "array",
      items: { enum: ["user-hosted", "hasna-saas"] },
      minItems: 1,
      uniqueItems: true,
      description:
        "Customer-facing product stories. Public OSS cores include user-hosted; add hasna-saas only when a managed control plane exists."
    },
    serviceSurfaces: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "status", "authMode"],
        allOf: [
          {
            if: {
              required: ["status"],
              properties: {
                status: { const: "supported" },
                kind: { const: "api" }
              }
            },
            then: {
              required: ["bin", "health", "readiness", "version"]
            }
          }
        ],
        properties: {
          name: { type: "string", minLength: 1 },
          kind: { enum: ["api", "sdk", "mcp", "cli"] },
          status: { enum: ["supported", "deferred", "unsupported"] },
          bin: { type: "string", minLength: 1 },
          mcpBin: { type: "string", minLength: 1 },
          authMode: { enum: ["none", "local-only", "api-key", "session", "service-token", "custom"] },
          health: {
            type: "object",
            additionalProperties: false,
            required: ["method", "path"],
            properties: {
              method: { const: "GET" },
              path: { type: "string", pattern: "^/[A-Za-z0-9_./:*-]*$" },
              public: { type: "boolean" },
              description: { type: "string", minLength: 1 }
            }
          },
          readiness: {
            type: "object",
            additionalProperties: false,
            required: ["method", "path"],
            properties: {
              method: { const: "GET" },
              path: { type: "string", pattern: "^/[A-Za-z0-9_./:*-]*$" },
              public: { type: "boolean" },
              description: { type: "string", minLength: 1 }
            }
          },
          version: {
            type: "object",
            additionalProperties: false,
            required: ["method", "path"],
            properties: {
              method: { const: "GET" },
              path: { type: "string", pattern: "^/[A-Za-z0-9_./:*-]*$" },
              public: { type: "boolean" },
              description: { type: "string", minLength: 1 }
            }
          },
          apiBasePath: { type: "string", pattern: "^/v[0-9]+$" },
          openApiPath: { type: "string", pattern: "^/[A-Za-z0-9_./:-]*$" },
          exportSubpath: {
            type: "string",
            pattern: "^\\.(?:\\/[A-Za-z0-9_.-]+(?:\\/[A-Za-z0-9_.-]+)*)?$",
            description: "SDK package export key such as . or ./sdk."
          },
          generatedFrom: {
            type: "string",
            pattern: "^/[A-Za-z0-9_./:-]*$",
            description: "OpenAPI path used to generate the SDK."
          },
          clientClassName: {
            type: "string",
            pattern: "^[A-Za-z_$][A-Za-z0-9_$]*$"
          },
          deferReason: { type: "string", minLength: 1 },
          readinessGates: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["id", "kind"],
              properties: {
                id: { type: "string", minLength: 1 },
                kind: {
                  enum: ["auth", "storage", "secret-ref", "migration", "health", "readiness", "redaction", "smoke", "operator", "other"]
                },
                required: { type: "boolean" },
                command: { type: "string", minLength: 1 },
                evidenceRef: { type: "object" },
                status: { enum: ["pending", "passed", "failed", "blocked", "deferred"] },
                summary: { type: "string", minLength: 1 }
              }
            }
          }
        }
      },
      description:
        "Declared API, SDK, MCP, and CLI product surfaces. Legacy entries without kind remain parseable; new manifests declare kind explicitly."
    },
    storage: {
      type: "object",
      additionalProperties: false,
      required: ["mode"],
      properties: {
        mode: {
          enum: ["sqlite", "postgres"],
          description: "Active data backend. sqlite|postgres ONLY — the single runtime switch."
        },
        engines: {
          type: "array",
          items: { enum: ["sqlite", "json", "postgres"] },
          minItems: 1,
          uniqueItems: true,
          description: "Supported storage engines; capability metadata independent of the active backend."
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
          description: "Legacy/private-tier database secret ref. Public conformance rejects this field."
        },
        sqlitePath: {
          type: "string",
          pattern: "\\.db$",
          description: "Local sqlite path (~/.hasna/<name>/<name>.db)."
        },
        pgTestGate: {
          type: "object",
          additionalProperties: false,
          required: ["envVar", "command"],
          properties: {
            envVar: {
              type: "string",
              pattern: "^[A-Z][A-Z0-9_]*_TEST_DATABASE_URL$"
            },
            command: { type: "string", minLength: 1 }
          },
          description: "Environment-gated live PostgreSQL test command."
        }
      }
    },
    metadata: {
      type: "object",
      additionalProperties: true,
      properties: {
        conformance: {
          type: "object",
          additionalProperties: true,
          properties: {
            waiverProfile: {
              const: "non-node-monorepo",
              description:
                "Explicit surface-waiver eligibility for exceptional non-Node monorepos. Libraries are eligible for API/MCP waivers without this profile."
            },
            waivedSurfaces: {
              type: "array",
              uniqueItems: true,
              items: {
                type: "object",
                additionalProperties: false,
                required: ["kind", "reason"],
                properties: {
                  kind: { enum: ["api", "sdk", "mcp", "cli"] },
                  reason: { type: "string", minLength: 1 }
                }
              }
            },
            waivedStorageEngines: {
              type: "array",
              uniqueItems: true,
              // uniqueItems compares whole objects, so it cannot catch two
              // waivers for the same engine. With a single waivable engine the
              // item cap enforces "at most one waiver per engine" exactly.
              maxItems: WAIVABLE_STORAGE_ENGINES.length,
              items: {
                type: "object",
                additionalProperties: false,
                required: ["engine", "reason"],
                properties: {
                  engine: { enum: [...WAIVABLE_STORAGE_ENGINES] },
                  reason: {
                    type: "string",
                    minLength: 1,
                    maxLength: STORAGE_WAIVER_REASON_MAX_LENGTH,
                    allOf: [{ pattern: "\\S" }, { pattern: WAIVER_TEXT_JSON_SCHEMA_PATTERN }]
                  },
                  reviewedBy: {
                    type: "string",
                    minLength: 1,
                    maxLength: STORAGE_WAIVER_REVIEWER_MAX_LENGTH,
                    allOf: [{ pattern: "\\S" }, { pattern: WAIVER_TEXT_JSON_SCHEMA_PATTERN }]
                  },
                  expiresAt: { type: "string", format: "date-time" }
                }
              },
              description:
                "Explicit storage-engine exceptions, at most one per engine. Only a CLI-only cli-with-store repo (no <name>-serve bin, storage.mode sqlite, no hasna-saas story) may waive postgres; sqlite is never waivable, expiresAt is a UTC RFC 3339 timestamp, and conformance stops honouring a waiver once it has passed."
            }
          }
        }
      }
    }
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
  /** Legacy/private-tier helper; never persist this value in a public manifest. */
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
