import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  version: string;
};
const core = await import("../dist/index.js");
const primitives = await import("../dist/primitives.js");

if (core.CONTRACTS_PACKAGE_VERSION !== packageJson.version) {
  throw new Error(`Version mismatch: ${core.CONTRACTS_PACKAGE_VERSION} !== ${packageJson.version}`);
}
if (Object.keys(primitives.CORE_SCHEMA_REGISTRY).length !== 10) {
  throw new Error("dist core schema registry is incomplete");
}

for (const fixture of ["n-minus-one.principal.valid.json", "n.principal.valid.json"]) {
  const value = JSON.parse(
    readFileSync(join(root, "fixtures", "compatibility", fixture), "utf8"),
  );
  if (!primitives.validateCoreContract(primitives.CORE_SCHEMA_IDS.principal, value).success) {
    throw new Error(`dist rejected compatibility fixture ${fixture}`);
  }
}

const files = readdirSync(join(root, "dist")).sort();
const expected = [
  "index.d.ts",
  "index.js",
  "primitives.d.ts",
  "primitives.js",
  "schemas.d.ts",
  "schemas.js",
  "validators.d.ts",
  "validators.js",
];
if (JSON.stringify(files) !== JSON.stringify(expected)) {
  throw new Error(`dist leaked a non-core surface: ${files.join(", ")}`);
}
for (const removed of [
  "scanNoCloudTarget",
  "createHasnaHttpTransport",
  "generateKit",
  "generateSdkFromOpenApi",
  "verifyApiKeyToken",
]) {
  if (removed in core) throw new Error(`runtime helper leaked through dist root: ${removed}`);
}

console.log("pure dist smoke passed");
