import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version: string };
const { CONTRACTS_PACKAGE_VERSION } = await import("../dist/schemas.js");

type CommandResult = ReturnType<typeof Bun.spawnSync>;

function run(args: string[]): CommandResult {
  return Bun.spawnSync(["bun", "dist/cli/index.js", ...args], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe"
  });
}

function text(bytes: Uint8Array) {
  return new TextDecoder().decode(bytes);
}

function requireExit(result: CommandResult, expected: number, label: string) {
  if (result.exitCode !== expected) {
    throw new Error(`${label} exited ${result.exitCode}, expected ${expected}\nstdout:\n${text(result.stdout)}\nstderr:\n${text(result.stderr)}`);
  }
}

function parseJson(result: CommandResult, label: string) {
  try {
    return JSON.parse(text(result.stdout)) as Record<string, unknown>;
  } catch (error) {
    throw new Error(`${label} did not emit valid JSON: ${error instanceof Error ? error.message : String(error)}\n${text(result.stdout)}`);
  }
}

if (CONTRACTS_PACKAGE_VERSION !== packageJson.version) {
  throw new Error(`Version mismatch: package.json=${packageJson.version} dist=${CONTRACTS_PACKAGE_VERSION}`);
}

const version = run(["--version"]);
requireExit(version, 0, "version");
if (text(version.stdout).trim() !== packageJson.version) {
  throw new Error(`CLI version mismatch: ${text(version.stdout).trim()} !== ${packageJson.version}`);
}

const schemas = run(["schemas", "--json"]);
requireExit(schemas, 0, "schemas --json");
const schemaIds = parseJson(schemas, "schemas --json");
if (!Array.isArray(schemaIds) || !schemaIds.includes("hasna.proof_bundle.v1")) {
  throw new Error("schemas --json did not include hasna.proof_bundle.v1");
}

const explicitValidate = run(["validate", "--json", "--schema", "hasna.evidence_ref.v1", "examples/evidence-ref.valid.json"]);
requireExit(explicitValidate, 0, "explicit validate");
if (parseJson(explicitValidate, "explicit validate").ok !== true) {
  throw new Error("explicit validate did not return ok=true");
}

const invalidValidate = run(["validate", "--json", "examples/proof-bundle.invalid.json"]);
requireExit(invalidValidate, 1, "invalid validate");
const invalidPayload = parseJson(invalidValidate, "invalid validate");
if (invalidPayload.ok !== false || !Array.isArray(invalidPayload.issues)) {
  throw new Error("invalid validate did not return structured issues");
}

const conformance = run(["conformance", "--json", "examples"]);
requireExit(conformance, 0, "conformance");
const conformancePayload = parseJson(conformance, "conformance");
if (conformancePayload.ok !== true || conformancePayload.failed !== 0 || Number(conformancePayload.checked) <= 0) {
  throw new Error("conformance did not report a non-empty passing fixture set");
}

console.log("dist smoke passed");
