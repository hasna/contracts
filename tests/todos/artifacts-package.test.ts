import { describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import {
  canonicalizeTodosValue,
  TODOS_CONTRACT_DESCRIPTOR,
  TODOS_CONTRACT_DIGEST,
  TODOS_CONTRACT_PROVENANCE,
  TODOS_GENERATED_ARTIFACT_ROOT,
  TODOS_GENERATOR_IDENTITY_DIGEST,
  TODOS_INVARIANT_REGISTRY,
  TODOS_INVARIANT_REGISTRY_DIGEST,
  TODOS_RUNTIME_VALIDATOR_BINDINGS,
  TODOS_OPERATION_MANIFEST_DIGEST,
  TODOS_OPERATION_MANIFEST,
  TODOS_PROVENANCE_DIGEST,
  TODOS_SOURCE_FREEZE,
  TaskToPrProjectionSchema,
  TodosCanonicalAuthorityHandshakeSchema,
  TodosIdentityContextSchema,
  TodosTransferBundleSchema,
  renderTodosArtifacts,
  buildTodosOpenApi,
  sha256TodosText,
  sha256TodosValue,
  validateTaskToPrProjectionTransition,
  validateTodosTransferBundle,
  verifyTodosContractDigests,
  verifyTodosRenderedArtifacts,
} from "../../src/todos";
import {
  TODOS_SCHEMA_BUNDLE_DIGEST,
} from "../../src/todos/schema-foundation";

const root = join(import.meta.dir, "..", "..");
const generatedRoot = join(root, TODOS_GENERATED_ARTIFACT_ROOT);

function listFiles(directory: string): string[] {
  const files: string[] = [];
  const walk = (current: string) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (entry.isFile()) {
        files.push(relative(directory, path));
      }
    }
  };
  walk(directory);
  return files.sort((left, right) => left.localeCompare(right));
}

function prettyJson(value: unknown): string {
  return `${JSON.stringify(canonicalizeTodosValue(value), null, 2)}\n`;
}

function recomputeArtifactChecksums(
  rendered: Record<string, string>,
): Record<string, string> {
  const next = { ...rendered };
  const files = Object.fromEntries(
    Object.entries(next)
      .filter(([path]) => path !== "checksums.json")
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([path, content]) => [path, sha256TodosText(content)]),
  );
  next["checksums.json"] = prettyJson({
    schema: "hasna.todos.artifact_checksums.v1",
    algorithm: "sha256",
    files,
    aggregateDigest: sha256TodosValue(files),
  });
  return next;
}

describe("Todos deterministic artifacts", () => {
  test("renders byte-identically and matches checked-in files", () => {
    const first = renderTodosArtifacts();
    const second = renderTodosArtifacts();
    expect(first).toEqual(second);
    expect(Object.keys(first).sort()).toEqual(listFiles(generatedRoot));
    for (const [path, content] of Object.entries(first)) {
      expect(readFileSync(join(generatedRoot, path), "utf8"), path).toBe(content);
    }
  });

  test("checksums cover every artifact except the checksum file itself", () => {
    const checksums = JSON.parse(readFileSync(join(generatedRoot, "checksums.json"), "utf8")) as {
      files: Record<string, string>;
    };
    const paths = listFiles(generatedRoot).filter((path) => path !== "checksums.json");
    expect(Object.keys(checksums.files).sort()).toEqual(paths);
    for (const path of paths) {
      expect(checksums.files[path], path).toBe(sha256TodosText(readFileSync(join(generatedRoot, path), "utf8")));
    }

    const contract = JSON.parse(readFileSync(join(generatedRoot, "contract.json"), "utf8")) as {
      descriptor: {
        manifestDigest: string;
        schemaBundleDigest: string;
        invariantRegistryDigest: string;
        provenanceDigest: string;
        generatorIdentityDigest: string;
      };
      digest: string;
    };
    expect(contract.digest).toBe(TODOS_CONTRACT_DIGEST);
    expect(contract.descriptor.manifestDigest).toBe(TODOS_OPERATION_MANIFEST_DIGEST);
    expect(contract.descriptor.schemaBundleDigest).toBe(TODOS_SCHEMA_BUNDLE_DIGEST);
    expect(contract.descriptor.invariantRegistryDigest).toBe(TODOS_INVARIANT_REGISTRY_DIGEST);
    expect(contract.descriptor.provenanceDigest).toBe(TODOS_PROVENANCE_DIGEST);
    expect(contract.descriptor.generatorIdentityDigest).toBe(TODOS_GENERATOR_IDENTITY_DIGEST);
    expect(verifyTodosContractDigests()).toBe(true);
    expect(verifyTodosRenderedArtifacts(renderTodosArtifacts())).toEqual({
      valid: true,
      issues: [],
    });
  });

  test("ships small valid and invalid lifecycle fixtures", () => {
    const fixture = (name: string) => JSON.parse(readFileSync(join(generatedRoot, "fixtures", name), "utf8"));
    expect(TodosCanonicalAuthorityHandshakeSchema.safeParse(fixture("authority.local.valid.json")).success).toBe(true);
    expect(TodosCanonicalAuthorityHandshakeSchema.safeParse(fixture("authority.cloud.valid.json")).success).toBe(true);
    expect(TodosIdentityContextSchema.safeParse(fixture("identity.valid.json")).success).toBe(true);
    expect(TodosIdentityContextSchema.safeParse(fixture("identity.invalid.json")).success).toBe(false);

    const transfer = TodosTransferBundleSchema.parse(fixture("transfer.valid.json"));
    expect(validateTodosTransferBundle(transfer).valid).toBe(true);
    expect(validateTodosTransferBundle(fixture("transfer.invalid.json")).valid).toBe(false);

    expect(TaskToPrProjectionSchema.safeParse(fixture("projection.valid.json")).success).toBe(true);
    const pair = fixture("projection-transition.invalid.json") as { previous: unknown; current: unknown };
    expect(validateTaskToPrProjectionTransition(pair.previous, pair.current).success).toBe(false);
  });

  test("generation check passes twice", () => {
    for (let index = 0; index < 2; index += 1) {
      const result = Bun.spawnSync(["bun", "scripts/generate-todos-contract.ts", "--check"], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    }
  });

  test("rejects checksum, manifest, provenance, invariant, and source-freeze tampering", () => {
    const checksumTamper = renderTodosArtifacts();
    checksumTamper["surface-map.json"] = `${checksumTamper["surface-map.json"]}\n`;
    expect(verifyTodosRenderedArtifacts(checksumTamper).valid).toBe(false);

    const manifestTamper = renderTodosArtifacts();
    const manifest = JSON.parse(manifestTamper["operation-manifest.json"]!) as {
      operations: Array<{ action: string }>;
    };
    manifest.operations[0]!.action = "tampered";
    manifestTamper["operation-manifest.json"] = prettyJson(manifest);
    expect(verifyTodosRenderedArtifacts(recomputeArtifactChecksums(manifestTamper)).issues)
      .toContain("Operation manifest digest is invalid");

    const provenanceTamper = renderTodosArtifacts();
    const provenance = JSON.parse(provenanceTamper["generator-provenance.json"]!) as {
      generatorVersion: string;
      identityDigest: string;
      outputContractDigest: string;
      [key: string]: unknown;
    };
    provenance.generatorVersion = "tampered";
    const {
      identityDigest: _identityDigest,
      outputContractDigest: _outputContractDigest,
      ...identity
    } = provenance;
    provenance.identityDigest = sha256TodosValue(identity);
    provenanceTamper["generator-provenance.json"] = prettyJson(provenance);
    expect(verifyTodosRenderedArtifacts(recomputeArtifactChecksums(provenanceTamper)).issues)
      .toContain("Generator provenance is invalid");

    const invariantTamper = renderTodosArtifacts();
    const invariants = JSON.parse(invariantTamper["invariant-registry.json"]!) as {
      invariants: Array<{ description: string }>;
    };
    invariants.invariants[0]!.description = "tampered";
    invariantTamper["invariant-registry.json"] = prettyJson(invariants);
    expect(verifyTodosRenderedArtifacts(recomputeArtifactChecksums(invariantTamper)).issues)
      .toContain("Invariant registry digest is invalid");

    const freezeTamper = renderTodosArtifacts();
    const sourceFreeze = JSON.parse(freezeTamper["source-freeze.json"]!) as {
      openTodos: { commitSha: string };
    };
    sourceFreeze.openTodos.commitSha = "0".repeat(40);
    freezeTamper["source-freeze.json"] = prettyJson(sourceFreeze);
    expect(verifyTodosRenderedArtifacts(recomputeArtifactChecksums(freezeTamper)).issues)
      .toContain("Source freeze is invalid");
  });

  test("rejects canonically different OpenAPI even after consistent checksum repair", () => {
    const openApiTamper = renderTodosArtifacts();
    const openapi = JSON.parse(openApiTamper["openapi.json"]!) as {
      info: { description: string };
    };
    openapi.info.description = "tampered but internally checksummed";
    openApiTamper["openapi.json"] = prettyJson(openapi);
    const rehashed = recomputeArtifactChecksums(openApiTamper);
    expect(verifyTodosRenderedArtifacts(rehashed).issues)
      .toContain("Canonical artifact mismatch: openapi.json");

    const checkRoot = mkdtempSync(join(tmpdir(), "todos-artifact-check-"));
    try {
      for (const [path, content] of Object.entries(rehashed)) {
        const absolutePath = join(checkRoot, path);
        mkdirSync(dirname(absolutePath), { recursive: true });
        writeFileSync(absolutePath, content, "utf8");
      }
      const result = Bun.spawnSync([
        "bun",
        "scripts/generate-todos-contract.ts",
        "--check",
        `--check-root=${checkRoot}`,
      ], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(result.exitCode).not.toBe(0);
      expect(new TextDecoder().decode(result.stderr)).toContain("openapi.json");
    } finally {
      rmSync(checkRoot, { recursive: true, force: true });
    }
  });

  test("mechanically maps every runtime validator into schemas and generated artifacts", () => {
    const schemaBundle = JSON.parse(readFileSync(join(generatedRoot, "schema-bundle.json"), "utf8")) as {
      runtimeValidationRequired: boolean;
      invariantRegistryDigest: string;
      invariants: typeof TODOS_INVARIANT_REGISTRY;
      schemas: Record<string, {
        "x-hasna-invariants"?: string[];
      }>;
    };
    const artifact = JSON.parse(readFileSync(join(generatedRoot, "invariant-registry.json"), "utf8"));
    expect(artifact).toEqual(TODOS_INVARIANT_REGISTRY);
    expect(schemaBundle.runtimeValidationRequired).toBe(true);
    expect(schemaBundle.invariantRegistryDigest).toBe(TODOS_INVARIANT_REGISTRY_DIGEST);
    expect(schemaBundle.invariants).toEqual(TODOS_INVARIANT_REGISTRY);

    const sourceFiles = listFiles(join(root, "src", "todos"))
      .filter((path) => path.endsWith(".ts"));
    const sourceByFile = new Map(
      sourceFiles.map((path) => [
        path,
        readFileSync(join(root, "src", "todos", path), "utf8"),
      ]),
    );
    const markerIds = [...sourceByFile.values()]
      .flatMap((source) => [
        ...source.matchAll(/@todos-runtime-validator ([a-z0-9_.-]+)/g),
      ].map((match) => match[1]!))
      .sort((left, right) => left.localeCompare(right));
    const bindingIds = TODOS_RUNTIME_VALIDATOR_BINDINGS
      .map((binding) => binding.id)
      .sort((left, right) => left.localeCompare(right));
    expect(markerIds).toEqual(bindingIds);
    expect(new Set(bindingIds).size).toBe(bindingIds.length);
    const superRefineCount = [...sourceByFile.values()]
      .reduce((count, source) => count + [...source.matchAll(/\.superRefine\(/g)].length, 0);
    expect(
      TODOS_RUNTIME_VALIDATOR_BINDINGS.filter((binding) => binding.kind === "refinement"),
    ).toHaveLength(superRefineCount);
    const exportedValidatorSymbols = [...sourceByFile.values()]
      .flatMap((source) => [
        ...source.matchAll(
          /^export function ((?:validate|verify|evaluate)[A-Za-z0-9_]*)/gm,
        ),
      ].map((match) => match[1]!))
      .sort((left, right) => left.localeCompare(right));
    const boundValidatorSymbols = TODOS_RUNTIME_VALIDATOR_BINDINGS
      .filter((binding) => binding.kind === "validator")
      .map((binding) => binding.symbol)
      .sort((left, right) => left.localeCompare(right));
    expect(exportedValidatorSymbols).toEqual(boundValidatorSymbols);

    for (const binding of TODOS_RUNTIME_VALIDATOR_BINDINGS) {
      const source = sourceByFile.get(binding.sourceFile);
      expect(source, binding.id).toBeDefined();
      expect(source, binding.id).toContain(binding.symbol);
      for (const schemaId of binding.schemaIds) {
        expect(schemaBundle.schemas[schemaId], `${binding.id}:${schemaId}`).toBeDefined();
      }
    }

    const registeredValidatorIds = [
      ...new Set(TODOS_INVARIANT_REGISTRY.invariants.flatMap(
        (invariant) => invariant.runtimeValidatorIds,
      )),
    ].sort((left, right) => left.localeCompare(right));
    expect(registeredValidatorIds).toEqual(bindingIds);
    const registeredInvariantIds = TODOS_INVARIANT_REGISTRY.invariants
      .map((invariant) => invariant.id)
      .sort((left, right) => left.localeCompare(right));
    const boundInvariantIds = [
      ...new Set(TODOS_RUNTIME_VALIDATOR_BINDINGS.flatMap(
        (binding) => binding.invariantIds,
      )),
    ].sort((left, right) => left.localeCompare(right));
    expect(registeredInvariantIds).toEqual(boundInvariantIds);

    for (const invariant of TODOS_INVARIANT_REGISTRY.invariants) {
      expect(invariant.runtimeValidatorIds.length, invariant.id).toBeGreaterThan(0);
      for (const schemaId of invariant.schemaIds) {
        expect(schemaBundle.schemas[schemaId], `${invariant.id}:${schemaId}`).toBeDefined();
      }
    }
    for (const [schemaId, schema] of Object.entries(schemaBundle.schemas)) {
      const expected = [
        ...new Set(TODOS_RUNTIME_VALIDATOR_BINDINGS
          .filter((binding) => binding.schemaIds.includes(schemaId))
          .flatMap((binding) => binding.invariantIds)),
      ].sort((left, right) => left.localeCompare(right));
      if (expected.length === 0) {
        expect(schema["x-hasna-invariants"], schemaId).toBeUndefined();
      } else {
        expect(schema["x-hasna-invariants"], schemaId).toEqual(expected);
      }
    }
  });

  test("OpenAPI binds the manifest-driven invocation context", () => {
    const openapi = buildTodosOpenApi() as {
      components: {
        schemas: Record<string, {
          properties?: Record<string, unknown>;
          required?: string[];
        }>;
      };
      paths: Record<string, Record<string, {
        operationId: string;
        parameters: Array<{
          name: string;
          in: string;
          required: boolean;
          schema?: Record<string, unknown>;
          content?: Record<string, unknown>;
        }>;
        security: Array<Record<string, string[]>>;
        "x-todos-required-scopes": string[];
        "x-todos-identity-context-schema": { $ref: string };
        "x-todos-invocation-context-schema": { $ref: string };
        "x-todos-invocation-bindings": {
          schema: { $ref: string };
          fields: Record<string, {
            source: { in: string; name?: string; mediaType?: string };
            target: string;
            required?: boolean;
            validated?: boolean;
          } | null>;
        };
      }>>;
    };
    for (const operation of TODOS_OPERATION_MANIFEST.operations) {
      const http = operation.surfaces.http;
      if (!http) continue;
      const document = openapi.paths[http.path]?.[http.method.toLowerCase()];
      expect(document, operation.id).toBeDefined();
      if (!document) continue;
      const headers = new Map(document.parameters.map((parameter) => [parameter.name, parameter]));
      for (const name of [
        "X-Todos-Mode",
        "X-Todos-Authority-Id",
        "X-Todos-Contract-Digest",
        "X-Todos-Manifest-Digest",
        "X-Todos-Operation-Id",
        "X-Todos-Request-Id",
      ]) {
        expect(headers.get(name)?.required, `${operation.id}:${name}`).toBe(true);
      }
      expect(headers.get("X-Todos-Contract-Digest")?.schema?.const).toBe(TODOS_CONTRACT_DIGEST);
      expect(headers.get("X-Todos-Manifest-Digest")?.schema?.const).toBe(TODOS_OPERATION_MANIFEST_DIGEST);
      expect(headers.get("X-Todos-Operation-Id")?.schema?.const).toBe(operation.id);
      expect(headers.get("Idempotency-Key")?.required ?? false).toBe(operation.idempotency === "required");
      expect(document.security).toEqual([{ bearerAuth: [] }]);
      expect(document["x-todos-required-scopes"]).toEqual(operation.requiredScopes);
      expect(document["x-todos-identity-context-schema"].$ref).toContain("identity_context");
      expect(document["x-todos-invocation-context-schema"].$ref).toContain("operation_invocation");
      const bindings = document["x-todos-invocation-bindings"];
      expect(bindings.schema.$ref).toContain("operation_invocation");
      expect(bindings.fields.mode?.source).toEqual({ in: "header", name: "X-Todos-Mode" });
      expect(bindings.fields.authorityId?.source).toEqual({ in: "header", name: "X-Todos-Authority-Id" });
      expect(bindings.fields.contractDigest?.source).toEqual({ in: "header", name: "X-Todos-Contract-Digest" });
      expect(bindings.fields.manifestDigest?.source).toEqual({ in: "header", name: "X-Todos-Manifest-Digest" });
      expect(bindings.fields.operationId?.source).toEqual({ in: "header", name: "X-Todos-Operation-Id" });
      expect(bindings.fields.identity).toMatchObject({
        source: { in: "security", name: "bearerAuth" },
        target: "identity",
        validated: true,
      });
      expect(bindings.fields.requestId).toMatchObject({ target: "identity.requestId" });
      if (operation.idempotency === "none") {
        expect(bindings.fields.idempotencyKey).toBeNull();
      } else {
        expect(bindings.fields.idempotencyKey).toMatchObject({
          source: { in: "header", name: "Idempotency-Key" },
          target: "identity.idempotencyKey",
          required: operation.idempotency === "required",
        });
      }
      expect(bindings.fields.request).toMatchObject({
        source: { in: http.method === "GET" ? "query" : "body" },
        target: "request",
      });

      const requestSchema = openapi.components.schemas[operation.requestSchemaId]!;
      const requestProperties = requestSchema.properties ?? {};
      const requiredFields = new Set(requestSchema.required ?? []);
      const pathFields = new Set(
        [...http.path.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((match) => match[1]!),
      );
      const pathParameters = document.parameters.filter((parameter) => parameter.in === "path");
      expect(pathParameters.map((parameter) => parameter.name).sort(), operation.id)
        .toEqual([...pathFields].sort());
      for (const parameter of pathParameters) {
        expect(parameter.required, `${operation.id}:${parameter.name}`).toBe(true);
        expect(parameter.schema?.$ref, `${operation.id}:${parameter.name}`)
          .toBe(`#/components/schemas/${operation.requestSchemaId}/properties/${parameter.name}`);
      }
      if (http.method === "GET") {
        const expectedQueries = Object.keys(requestProperties)
          .filter((field) => !pathFields.has(field))
          .sort();
        const queryParameters = document.parameters
          .filter((parameter) => parameter.in === "query");
        expect(queryParameters.map((parameter) => parameter.name).sort(), operation.id)
          .toEqual(expectedQueries);
        for (const parameter of queryParameters) {
          expect(parameter.required, `${operation.id}:${parameter.name}`)
            .toBe(requiredFields.has(parameter.name));
          expect(
            parameter.schema !== undefined || parameter.content !== undefined,
            `${operation.id}:${parameter.name}`,
          ).toBe(true);
        }
      } else {
        expect(document.parameters.some((parameter) => parameter.in === "query"), operation.id)
          .toBe(false);
      }
    }
  });

  test("ties all generated provenance surfaces to the canonical descriptor", () => {
    const surfaceMap = JSON.parse(readFileSync(join(generatedRoot, "surface-map.json"), "utf8")) as {
      provenance: unknown;
      provenanceDigest: string;
    };
    const sourceFreeze = JSON.parse(readFileSync(join(generatedRoot, "source-freeze.json"), "utf8"));
    expect(surfaceMap.provenance).toEqual(TODOS_CONTRACT_PROVENANCE);
    expect(surfaceMap.provenanceDigest).toBe(TODOS_PROVENANCE_DIGEST);
    expect(sourceFreeze).toEqual(TODOS_SOURCE_FREEZE);
    expect(TODOS_CONTRACT_DESCRIPTOR.provenance).toEqual(TODOS_CONTRACT_PROVENANCE);
  });
});

describe("Todos production boundary", () => {
  test("contains no forbidden mode, routing, or generic-helper dependencies", () => {
    const productionFiles = [
      ...listFiles(join(root, "src", "todos")).map((path) => join(root, "src", "todos", path)),
      ...listFiles(generatedRoot).map((path) => join(generatedRoot, path)),
    ];
    const forbidden = [
      /\bremote\b/i,
      /self_hosted/i,
      /self-hosted/i,
      /\bhybrid\b/i,
      /\bdeprecated\b/i,
      /\bcompatibility\b/i,
      /process\.env/,
      /Bun\.env/,
      /Deno\.env/,
      /\bSTORAGE_MODE\b/,
      /\bAPI_URL\b/,
      /\bAPI_KEY\b/,
      /fallback/i,
    ];
    for (const file of productionFiles) {
      const content = readFileSync(file, "utf8");
      for (const pattern of forbidden) {
        expect(pattern.test(content), `${relative(root, file)} matched ${pattern}`).toBe(false);
      }
      if (file.includes(`${join("src", "todos")}`)) {
        expect(content).not.toMatch(/from\s+["']\.\.\/(?:mode|service-contract|client|schemas)/);
      }
    }
    expect(readFileSync(join(root, "README.md"), "utf8")).not.toMatch(/fallback/i);
  });

  test("declares only the Todos subpath and artifact surfaces without a root re-export", () => {
    const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      version: string;
      exports: Record<string, unknown>;
      files: string[];
    };
    expect(packageJson.version).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
    expect(packageJson.exports["./todos"]).toBeDefined();
    expect(packageJson.exports["./todos/artifacts/*"]).toBe("./generated/todos/v1/*");
    expect(packageJson.files).toContain("generated/todos/v1");
    expect(readFileSync(join(root, "src", "index.ts"), "utf8")).not.toContain("./todos");
    expect(existsSync(join(root, "src", "todos", "index.ts"))).toBe(true);
  });
});
