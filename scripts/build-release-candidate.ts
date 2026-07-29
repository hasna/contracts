import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative } from "node:path";
import { createHash } from "node:crypto";

const root = join(import.meta.dir, "..");
const version = "1.0.0-rc.1";
const check = process.argv.includes("--check");
const candidateDirectory = join(root, "release", version);
const archiveName = `hasna-contracts-${version}.tgz`;
const artifactNames = [
  archiveName,
  `${archiveName}.sha256`,
  `${archiveName}.spdx.json`,
  `${archiveName}.provenance.json`,
] as const;

function sha256(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function json(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function filesBelow(path: string): string[] {
  if (!existsSync(path)) return [];
  if (statSync(path).isFile()) return [path];
  return readdirSync(path, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))
    .flatMap((entry) => filesBelow(join(path, entry.name)));
}

function requireCommand(command: string[], cwd = root): void {
  const result = Bun.spawnSync(command, { cwd, stdout: "inherit", stderr: "inherit" });
  if (result.exitCode !== 0) {
    throw new Error(`${command.join(" ")} exited ${result.exitCode}`);
  }
}

function copyIntoPackage(source: string, packageRoot: string): void {
  const target = join(packageRoot, source);
  mkdirSync(dirname(target), { recursive: true });
  copyFileSync(join(root, source), target);
}

function inputFiles(): string[] {
  const fixed = [
    "package.json",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "hasna.contract.json",
    "src/hasna.contract.schema.json",
    "docs/CORE_RELEASE_CANDIDATE.md",
    "docs/release/reverse-dependencies.json",
  ];
  const directories = ["dist", "schemas/v1"];
  const fixtureFiles = filesBelow(join(root, "fixtures/compatibility"))
    .filter((file) => file.endsWith(".json"));
  return [
    ...fixed,
    ...directories.flatMap((directory) => filesBelow(join(root, directory)).map((file) => relative(root, file))),
    ...fixtureFiles.map((file) => relative(root, file)),
  ].sort();
}

function sourceDigest(files: string[]): string {
  const hash = createHash("sha256");
  for (const file of files) {
    hash.update(file);
    hash.update("\0");
    hash.update(readFileSync(join(root, file)));
    hash.update("\0");
  }
  return hash.digest("hex");
}

function spdxDocument(packageRoot: string, files: string[], digest: string): Record<string, unknown> {
  const spdxFiles = files.map((file) => {
    const checksum = sha256(readFileSync(join(packageRoot, file)));
    return {
      fileName: `./${file}`,
      SPDXID: `SPDXRef-File-${checksum.slice(0, 24)}`,
      checksums: [{ algorithm: "SHA256", checksumValue: checksum }],
      licenseConcluded: "NOASSERTION",
      copyrightText: "NOASSERTION",
    };
  });
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `@hasna/contracts-${version}`,
    documentNamespace: `https://github.com/hasna/contracts/releases/${version}/sbom-${digest}`,
    creationInfo: {
      created: "1970-01-01T00:00:00Z",
      creators: ["Tool: @hasna/contracts build-release-candidate.ts"],
    },
    packages: [
      {
        name: "@hasna/contracts",
        SPDXID: "SPDXRef-Package-contracts",
        versionInfo: version,
        downloadLocation: "NOASSERTION",
        filesAnalyzed: true,
        licenseConcluded: "Apache-2.0",
        licenseDeclared: "Apache-2.0",
        copyrightText: "NOASSERTION",
        externalRefs: [
          {
            referenceCategory: "PACKAGE-MANAGER",
            referenceType: "purl",
            referenceLocator: `pkg:npm/%40hasna/contracts@${version}`,
          },
        ],
      },
      {
        name: "zod",
        SPDXID: "SPDXRef-Package-zod",
        versionInfo: "3.25.76",
        downloadLocation: "https://registry.npmjs.org/zod/-/zod-3.25.76.tgz",
        filesAnalyzed: false,
        licenseConcluded: "MIT",
        licenseDeclared: "MIT",
        copyrightText: "NOASSERTION",
        externalRefs: [
          {
            referenceCategory: "PACKAGE-MANAGER",
            referenceType: "purl",
            referenceLocator: "pkg:npm/zod@3.25.76",
          },
        ],
      },
    ],
    files: spdxFiles,
    relationships: [
      { spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: "SPDXRef-Package-contracts" },
      { spdxElementId: "SPDXRef-Package-contracts", relationshipType: "DEPENDS_ON", relatedSpdxElement: "SPDXRef-Package-zod" },
      ...spdxFiles.map((file) => ({
        spdxElementId: "SPDXRef-Package-contracts",
        relationshipType: "CONTAINS",
        relatedSpdxElement: file.SPDXID,
      })),
    ],
  };
}

function provenance(archiveDigest: string, inputsDigest: string): Record<string, unknown> {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: archiveName, digest: { sha256: archiveDigest } }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://github.com/hasna/contracts/reproducible-tar/v1",
        externalParameters: {
          package: "@hasna/contracts",
          version,
          sourceDateEpoch: 0,
          tar: ["--sort=name", "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner", "--format=ustar"],
          gzip: ["-n", "-9"],
        },
        internalParameters: {},
        resolvedDependencies: [
          {
            uri: "git+https://github.com/hasna/contracts.git",
            digest: { sha256: inputsDigest },
          },
        ],
      },
      runDetails: {
        builder: { id: "https://github.com/hasna/contracts/scripts/build-release-candidate.ts" },
        metadata: { invocationId: `sha256:${inputsDigest}`, startedOn: "1970-01-01T00:00:00Z", finishedOn: "1970-01-01T00:00:00Z" },
        byproducts: [],
      },
    },
  };
}

function renderCandidate(outputDirectory: string): void {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "contracts-candidate-"));
  const packageRoot = join(temporaryRoot, "package");
  const uncompressed = join(temporaryRoot, `${archiveName}.tar`);
  try {
    mkdirSync(packageRoot, { recursive: true });
    const inputs = inputFiles();
    for (const file of inputs) copyIntoPackage(file, packageRoot);
    const inputsDigest = sourceDigest(inputs);
    const packagedFiles = filesBelow(packageRoot).map((file) => relative(packageRoot, file)).sort();
    const sbom = json(spdxDocument(packageRoot, packagedFiles, inputsDigest));
    writeFileSync(join(packageRoot, "SBOM.spdx.json"), sbom);

    requireCommand([
      "tar",
      "--sort=name",
      "--mtime=@0",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      "--format=ustar",
      "-cf",
      uncompressed,
      "-C",
      temporaryRoot,
      "package",
    ]);
    const compressed = Bun.spawnSync(["gzip", "-n", "-9", "-c", uncompressed], {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
    });
    if (compressed.exitCode !== 0) {
      throw new Error(`gzip exited ${compressed.exitCode}: ${new TextDecoder().decode(compressed.stderr)}`);
    }
    const archiveDigest = sha256(compressed.stdout);
    mkdirSync(outputDirectory, { recursive: true });
    writeFileSync(join(outputDirectory, archiveName), compressed.stdout);
    writeFileSync(join(outputDirectory, `${archiveName}.sha256`), `${archiveDigest}  ${archiveName}\n`);
    writeFileSync(join(outputDirectory, `${archiveName}.spdx.json`), sbom);
    writeFileSync(
      join(outputDirectory, `${archiveName}.provenance.json`),
      json(provenance(archiveDigest, inputsDigest)),
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

requireCommand(["bun", "run", "build"]);

if (!check) {
  renderCandidate(candidateDirectory);
  console.log(`Wrote reproducible candidate ${join("release", version, archiveName)}`);
} else {
  const checkDirectory = mkdtempSync(join(tmpdir(), "contracts-candidate-check-"));
  try {
    renderCandidate(checkDirectory);
    for (const artifact of artifactNames) {
      const expected = join(candidateDirectory, artifact);
      const actual = join(checkDirectory, artifact);
      if (!existsSync(expected)) throw new Error(`Missing checked-in candidate artifact: ${relative(root, expected)}`);
      if (sha256(readFileSync(expected)) !== sha256(readFileSync(actual))) {
        throw new Error(`Candidate artifact is not reproducible: ${basename(expected)}`);
      }
    }
    console.log(`Candidate ${version} is byte-for-byte reproducible`);
  } finally {
    rmSync(checkDirectory, { recursive: true, force: true });
  }
}
