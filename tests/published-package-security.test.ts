import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  appendFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { CONTRACTS_PACKAGE_VERSION } from "../src/schemas.js";

const root = join(import.meta.dir, "..");
const expectedUnreleasedVersion = "0.6.1";
const forbiddenInternalDomains = [["hasna", "xyz"].join(".")];

function commandText(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function run(command: string[], cwd = root): string {
  const result = Bun.spawnSync(command, {
    cwd,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(
      `${command.join(" ")} exited ${result.exitCode}\nstdout:\n${commandText(result.stdout)}\nstderr:\n${commandText(result.stderr)}`,
    );
  }
  return commandText(result.stdout).trim();
}

function collectFiles(target: string): string[] {
  const stat = lstatSync(target);
  if (stat.isSymbolicLink()) return [];
  if (stat.isFile()) return [target];
  if (!stat.isDirectory()) return [];
  return readdirSync(target, { withFileTypes: true }).flatMap((entry) =>
    collectFiles(join(target, entry.name)),
  );
}

function trackedFiles(): string[] {
  const result = Bun.spawnSync(["git", "ls-files", "-z"], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(`git ls-files failed: ${commandText(result.stderr)}`);
  }
  return commandText(result.stdout).split("\0").filter(Boolean);
}

function containsUtf16Domain(bytes: Uint8Array, domain: string, littleEndian: boolean): boolean {
  const required = domain.length * 2;
  for (let offset = 0; offset + required <= bytes.length; offset++) {
    let matches = true;
    for (let index = 0; index < domain.length; index++) {
      const expected = domain.charCodeAt(index);
      const character = bytes[offset + index * 2 + (littleEndian ? 0 : 1)]!;
      const zero = bytes[offset + index * 2 + (littleEndian ? 1 : 0)]!;
      const caseMatches =
        character === expected ||
        (expected >= 97 && expected <= 122 && character === expected - 32);
      if (!caseMatches || zero !== 0) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

function decodedCodePoint(encoded: string, radix: number): string | null {
  const value = Number.parseInt(encoded, radix);
  if (!Number.isFinite(value) || value < 0 || value > 0x10ffff) return null;
  return String.fromCodePoint(value);
}

function decodeTextEscapes(value: string): string {
  return value
    .replace(/%([0-9a-f]{2})/gi, (match, encoded: string) =>
      decodedCodePoint(encoded, 16) ?? match,
    )
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (match, encoded: string) =>
      decodedCodePoint(encoded, 16) ?? match,
    )
    .replace(/\\u([0-9a-f]{4})/gi, (match, encoded: string) =>
      decodedCodePoint(encoded, 16) ?? match,
    )
    .replace(/\\x([0-9a-f]{2})/gi, (match, encoded: string) =>
      decodedCodePoint(encoded, 16) ?? match,
    )
    .replace(/&#x([0-9a-f]+);?/gi, (match, encoded: string) =>
      decodedCodePoint(encoded, 16) ?? match,
    )
    .replace(/&#([0-9]+);?/g, (match, encoded: string) =>
      decodedCodePoint(encoded, 10) ?? match,
    );
}

function containsForbiddenInternalDomain(bytes: Uint8Array, decodeDepth = 0): boolean {
  for (const domain of forbiddenInternalDomains) {
    if (
      containsUtf16Domain(bytes, domain, true) ||
      containsUtf16Domain(bytes, domain, false)
    ) {
      return true;
    }
  }

  const text = new TextDecoder().decode(bytes);
  let decodedText = text;
  for (let round = 0; round < 3; round++) {
    const lowered = decodedText.toLowerCase();
    if (forbiddenInternalDomains.some((domain) => lowered.includes(domain))) {
      return true;
    }
    const next = decodeTextEscapes(decodedText);
    if (next === decodedText) break;
    decodedText = next;
  }

  if (decodeDepth >= 1) return false;

  const minimumHexLength = Math.min(
    ...forbiddenInternalDomains.map((domain) => domain.length * 2),
  );
  for (const match of text.matchAll(
    new RegExp(`[0-9a-f]{${minimumHexLength},}`, "gi"),
  )) {
    const token = match[0].length % 2 === 0 ? match[0] : match[0].slice(0, -1);
    if (
      token.length >= minimumHexLength &&
      containsForbiddenInternalDomain(Buffer.from(token, "hex"), decodeDepth + 1)
    ) {
      return true;
    }
  }

  const minimumBase64Length = Math.min(
    ...forbiddenInternalDomains.map((domain) =>
      Buffer.from(domain).toString("base64").replace(/=+$/, "").length
    ),
  );
  for (const match of text.matchAll(
    new RegExp(`[a-z0-9+/]{${minimumBase64Length},}={0,2}`, "gi"),
  )) {
    const token = match[0];
    if (
      token.length % 4 !== 1 &&
      containsForbiddenInternalDomain(Buffer.from(token, "base64"), decodeDepth + 1)
    ) {
      return true;
    }
  }

  return false;
}

function findForbiddenInternalDomains(scanRoot: string, targets: string[]): string[] {
  return targets
    .flatMap((target) => collectFiles(join(scanRoot, target)))
    .filter((file) => containsForbiddenInternalDomain(readFileSync(file)))
    .map((file) => relative(scanRoot, file))
    .sort();
}

interface RawTarMember {
  index: number;
  rawPath: string;
  path: string;
  rawLinkPath: string;
  linkPath: string;
  type: string;
  data: Uint8Array;
}

interface RawTarArchive {
  members: RawTarMember[];
  postEndBytes: Uint8Array;
}

interface TarFixtureEntry {
  path: string;
  type?: string;
  linkPath?: string;
  data?: Uint8Array;
}

function tarField(block: Uint8Array, offset: number, length: number, value: string): void {
  const encoded = new TextEncoder().encode(value);
  if (encoded.length > length) throw new Error(`Tar fixture field is too long: ${value}`);
  block.set(encoded, offset);
}

function tarOctalField(block: Uint8Array, offset: number, length: number, value: number): void {
  const encoded = value.toString(8).padStart(length - 1, "0");
  tarField(block, offset, length, `${encoded}\0`);
}

function tarFixtureHeader(entry: TarFixtureEntry): Uint8Array {
  const data = entry.data ?? new Uint8Array();
  const header = new Uint8Array(512);
  tarField(header, 0, 100, entry.path);
  tarOctalField(header, 100, 8, 0o644);
  tarOctalField(header, 108, 8, 0);
  tarOctalField(header, 116, 8, 0);
  tarOctalField(header, 124, 12, data.length);
  tarOctalField(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  tarField(header, 156, 1, entry.type ?? "0");
  tarField(header, 157, 100, entry.linkPath ?? "");
  tarField(header, 257, 6, "ustar\0");
  tarField(header, 263, 2, "00");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  tarField(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  return header;
}

function writeTarFixture(
  archivePath: string,
  entries: TarFixtureEntry[],
  trailer: Uint8Array = new Uint8Array(),
): void {
  const parts: Uint8Array[] = [];
  for (const entry of entries) {
    const data = entry.data ?? new Uint8Array();
    parts.push(tarFixtureHeader(entry), data);
    const padding = (512 - (data.length % 512)) % 512;
    if (padding > 0) parts.push(new Uint8Array(padding));
  }
  parts.push(new Uint8Array(1024), trailer);
  writeFileSync(archivePath, Buffer.concat(parts.map((part) => Buffer.from(part))));
}

function paxRecord(key: string, value: string): Uint8Array {
  const body = `${key}=${value}\n`;
  let length = body.length + 2;
  while (`${length} ${body}`.length !== length) {
    length = `${length} ${body}`.length;
  }
  return new TextEncoder().encode(`${length} ${body}`);
}

function tarString(block: Uint8Array, offset: number, length: number): string {
  const bytes = block.subarray(offset, offset + length);
  const end = bytes.indexOf(0);
  return new TextDecoder().decode(end === -1 ? bytes : bytes.subarray(0, end));
}

function tarNumber(block: Uint8Array, offset: number, length: number): number {
  const bytes = block.subarray(offset, offset + length);
  if ((bytes[0]! & 0x80) !== 0) {
    let value = BigInt(bytes[0]! & 0x7f);
    for (const byte of bytes.subarray(1)) value = (value << 8n) | BigInt(byte);
    return Number(value);
  }
  const encoded = new TextDecoder()
    .decode(bytes)
    .replace(/\0.*$/, "")
    .trim();
  return encoded ? Number.parseInt(encoded, 8) : 0;
}

function paxNames(data: Uint8Array): {
  path: string | null;
  linkPath: string | null;
} {
  const text = new TextDecoder().decode(data);
  let offset = 0;
  let path: string | null = null;
  let linkPath: string | null = null;
  while (offset < text.length) {
    const space = text.indexOf(" ", offset);
    if (space === -1) break;
    const length = Number.parseInt(text.slice(offset, space), 10);
    if (!Number.isFinite(length) || length <= 0) break;
    const record = text.slice(space + 1, offset + length - 1);
    const separator = record.indexOf("=");
    if (separator !== -1) {
      const key = record.slice(0, separator);
      const value = record.slice(separator + 1);
      if (key === "path") path = value;
      if (key === "linkpath") linkPath = value;
    }
    offset += length;
  }
  return { path, linkPath };
}

function readRawTarArchive(archivePath: string): RawTarArchive {
  const archive = readFileSync(archivePath);
  const bytes =
    archive[0] === 0x1f && archive[1] === 0x8b
      ? gunzipSync(archive)
      : archive;
  const members: RawTarMember[] = [];
  let offset = 0;
  let pendingLongPath: string | null = null;
  let pendingLongLinkPath: string | null = null;
  let pendingPaxPath: string | null = null;
  let pendingPaxLinkPath: string | null = null;
  let globalPaxPath: string | null = null;
  let globalPaxLinkPath: string | null = null;

  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      return { members, postEndBytes: bytes.subarray(offset) };
    }

    const name = tarString(header, 0, 100);
    const prefix = tarString(header, 345, 155);
    const headerPath = prefix ? `${prefix}/${name}` : name;
    const headerLinkPath = tarString(header, 157, 100);
    const size = tarNumber(header, 124, 12);
    const type = String.fromCharCode(header[156] || 0);
    const dataStart = offset + 512;
    if (!Number.isSafeInteger(size) || size < 0 || dataStart + size > bytes.length) {
      throw new Error("Tar archive contains an invalid or truncated member.");
    }
    const data = bytes.subarray(dataStart, dataStart + size);
    const isMetadataMember = type === "L" || type === "K" || type === "x" || type === "g";
    const path = isMetadataMember
      ? headerPath
      : pendingPaxPath ?? pendingLongPath ?? globalPaxPath ?? headerPath;
    const linkPath = isMetadataMember
      ? headerLinkPath
      : pendingPaxLinkPath ?? pendingLongLinkPath ?? globalPaxLinkPath ?? headerLinkPath;
    members.push({
      index: members.length + 1,
      rawPath: headerPath,
      path,
      rawLinkPath: headerLinkPath,
      linkPath,
      type,
      data,
    });

    if (type === "L") {
      pendingLongPath = new TextDecoder().decode(data).replace(/\0.*$/, "");
    } else if (type === "K") {
      pendingLongLinkPath = new TextDecoder().decode(data).replace(/\0.*$/, "");
    } else if (type === "x") {
      const names = paxNames(data);
      pendingPaxPath = names.path;
      pendingPaxLinkPath = names.linkPath;
    } else if (type === "g") {
      const names = paxNames(data);
      if (names.path !== null) globalPaxPath = names.path;
      if (names.linkPath !== null) globalPaxLinkPath = names.linkPath;
    } else {
      pendingLongPath = null;
      pendingLongLinkPath = null;
      pendingPaxPath = null;
      pendingPaxLinkPath = null;
    }

    offset = dataStart + Math.ceil(size / 512) * 512;
  }

  return { members, postEndBytes: bytes.subarray(offset) };
}

function readRawTarMembers(archivePath: string): RawTarMember[] {
  return readRawTarArchive(archivePath).members;
}

function findForbiddenRawTarMembers(archivePath: string): string[] {
  const archive = readRawTarArchive(archivePath);
  const findings = archive.members
    .filter((member) => {
      const rawPathBytes = new TextEncoder().encode(member.rawPath);
      const pathBytes = new TextEncoder().encode(member.path);
      const rawLinkPathBytes = new TextEncoder().encode(member.rawLinkPath);
      const linkPathBytes = new TextEncoder().encode(member.linkPath);
      return (
        containsForbiddenInternalDomain(rawPathBytes) ||
        containsForbiddenInternalDomain(pathBytes) ||
        containsForbiddenInternalDomain(rawLinkPathBytes) ||
        containsForbiddenInternalDomain(linkPathBytes) ||
        containsForbiddenInternalDomain(member.data)
      );
    })
    .map((member) => `#${member.index}:${member.path}`);
  if (containsForbiddenInternalDomain(archive.postEndBytes)) {
    findings.push("#trailer");
  }
  return findings;
}

function forbiddenEncodingFixtures(domain: string): Array<{
  name: string;
  bytes: Uint8Array;
}> {
  const characters = [...domain];
  const utf16Le = Buffer.from(domain, "utf16le");
  const utf16Be = Buffer.from(utf16Le);
  for (let index = 0; index < utf16Be.length; index += 2) {
    [utf16Be[index], utf16Be[index + 1]] = [utf16Be[index + 1]!, utf16Be[index]!];
  }

  return [
    { name: "case", bytes: Buffer.from(domain.toUpperCase()) },
    {
      name: "percent",
      bytes: Buffer.from(characters.map((character) =>
        `%${character.charCodeAt(0).toString(16).padStart(2, "0")}`
      ).join("")),
    },
    {
      name: "json-unicode",
      bytes: Buffer.from(characters.map((character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
      ).join("")),
    },
    {
      name: "javascript-hex",
      bytes: Buffer.from(characters.map((character) =>
        `\\x${character.charCodeAt(0).toString(16).padStart(2, "0")}`
      ).join("")),
    },
    {
      name: "html-decimal",
      bytes: Buffer.from(characters.map((character) =>
        `&#${character.charCodeAt(0)};`
      ).join("")),
    },
    {
      name: "html-hex",
      bytes: Buffer.from(characters.map((character) =>
        `&#x${character.charCodeAt(0).toString(16)};`
      ).join("")),
    },
    { name: "hex", bytes: Buffer.from(Buffer.from(domain).toString("hex")) },
    { name: "base64", bytes: Buffer.from(Buffer.from(domain).toString("base64")) },
    { name: "utf16-le", bytes: utf16Le },
    { name: "utf16-be", bytes: utf16Be },
  ];
}

describe("published package hostname and provenance boundary", () => {
  let temporaryRoot = "";
  let extractedPackageRoot = "";
  let packedArchivePath = "";

  beforeAll(() => {
    temporaryRoot = mkdtempSync(join(tmpdir(), "contracts-package-security-"));
    const extracted = join(temporaryRoot, "extracted");
    mkdirSync(extracted);

    run(["bun", "run", "build"]);
    const packedFilename = run([
      "bun",
      "pm",
      "pack",
      "--destination",
      temporaryRoot,
      "--ignore-scripts",
      "--quiet",
    ]);
    const archive = isAbsolute(packedFilename)
      ? packedFilename
      : join(temporaryRoot, packedFilename);
    packedArchivePath = archive;
    run(["tar", "-xzf", archive, "-C", extracted]);
    extractedPackageRoot = join(extracted, "package");
  }, 30_000);

  afterAll(() => {
    if (temporaryRoot) rmSync(temporaryRoot, { recursive: true, force: true });
  });

  test("scanner rejects a forbidden internal domain", () => {
    const fixtureRoot = join(temporaryRoot, "negative-control");
    mkdirSync(fixtureRoot);
    writeFileSync(join(fixtureRoot, "fixture.txt"), forbiddenInternalDomains[0]!.toUpperCase());
    expect(findForbiddenInternalDomains(fixtureRoot, ["."])).toEqual(["fixture.txt"]);
  });

  test("scanner rejects data-driven encoded forms of every forbidden domain", () => {
    for (const domain of forbiddenInternalDomains) {
      for (const fixture of forbiddenEncodingFixtures(domain)) {
        expect(
          containsForbiddenInternalDomain(fixture.bytes),
          `${domain} encoded as ${fixture.name}`,
        ).toBe(true);
      }
    }
  });

  test("all tracked source, docs, tests, and examples contain no forbidden internal domains", () => {
    const findings = findForbiddenInternalDomains(root, trackedFiles());
    expect(findings).toEqual([]);
  });

  test("generated build output contains no forbidden internal domains", () => {
    expect(findForbiddenInternalDomains(root, ["dist"])).toEqual([]);
  });

  test("actual packed archive contents contain no forbidden internal domains", () => {
    expect(findForbiddenInternalDomains(extractedPackageRoot, ["."])).toEqual([]);
    expect(findForbiddenRawTarMembers(packedArchivePath)).toEqual([]);

    const rawMembers = readRawTarMembers(packedArchivePath);
    expect(rawMembers.length).toBeGreaterThan(0);
    expect(
      rawMembers.filter((member) => member.path === "package/dist/cli/index.js").length,
    ).toBeGreaterThanOrEqual(1);
  });

  test("raw-member scan catches an encoded duplicate that extraction overwrites", () => {
    const fixtureRoot = join(temporaryRoot, "duplicate-member-negative-control");
    const first = join(fixtureRoot, "first", "package");
    const second = join(fixtureRoot, "second", "package");
    const extracted = join(fixtureRoot, "extracted");
    const archive = join(fixtureRoot, "duplicate.tar");
    mkdirSync(first, { recursive: true });
    mkdirSync(second, { recursive: true });
    mkdirSync(extracted);

    const encoded = Buffer.from(forbiddenInternalDomains[0]!).toString("base64");
    writeFileSync(join(first, "duplicate.txt"), encoded);
    writeFileSync(join(second, "duplicate.txt"), "clean replacement");
    run(["tar", "-cf", archive, "-C", join(fixtureRoot, "first"), "package/duplicate.txt"]);
    run(["tar", "-rf", archive, "-C", join(fixtureRoot, "second"), "package/duplicate.txt"]);
    run(["tar", "-xf", archive, "-C", extracted]);

    expect(findForbiddenInternalDomains(extracted, ["."])).toEqual([]);
    const duplicateMembers = readRawTarMembers(archive).filter(
      (member) => member.path === "package/duplicate.txt",
    );
    expect(duplicateMembers).toHaveLength(2);
    const findings = findForbiddenRawTarMembers(archive);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toContain("#1:package/duplicate.txt");
  });

  test("raw-member scan inspects encoded symlink targets", () => {
    const fixtureRoot = join(temporaryRoot, "symlink-target-negative-control");
    const packageRoot = join(fixtureRoot, "package");
    const archive = join(fixtureRoot, "symlink.tar");
    mkdirSync(packageRoot, { recursive: true });

    const encodedTarget = Buffer.from(forbiddenInternalDomains[0]!).toString("base64");
    symlinkSync(encodedTarget, join(packageRoot, "service-link"));
    run(["tar", "-cf", archive, "-C", fixtureRoot, "package/service-link"]);

    const findings = findForbiddenRawTarMembers(archive);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toContain("package/service-link");
  });

  test("raw-member scan inspects header paths hidden by PAX and GNU overrides", () => {
    const fixtureRoot = join(temporaryRoot, "overridden-header-negative-controls");
    mkdirSync(fixtureRoot, { recursive: true });
    const encoded = Buffer.from(forbiddenInternalDomains[0]!).toString("base64");

    const paxArchive = join(fixtureRoot, "pax.tar");
    writeTarFixture(paxArchive, [
      {
        path: "PaxHeaders.0/entry",
        type: "x",
        data: paxRecord("path", "package/clean-pax.txt"),
      },
      {
        path: `package/${encoded}`,
        data: Buffer.from("clean member bytes"),
      },
    ]);
    expect(readRawTarMembers(paxArchive)[1]?.path).toBe("package/clean-pax.txt");
    expect(findForbiddenRawTarMembers(paxArchive)).toHaveLength(1);

    const gnuArchive = join(fixtureRoot, "gnu.tar");
    writeTarFixture(gnuArchive, [
      {
        path: "././@LongLink",
        type: "L",
        data: Buffer.from("package/clean-gnu.txt\0"),
      },
      {
        path: `package/${encoded}`,
        data: Buffer.from("clean member bytes"),
      },
    ]);
    expect(readRawTarMembers(gnuArchive)[1]?.path).toBe("package/clean-gnu.txt");
    expect(findForbiddenRawTarMembers(gnuArchive)).toHaveLength(1);
  });

  test("raw-member scan inspects header linknames hidden by PAX overrides", () => {
    const fixtureRoot = join(temporaryRoot, "overridden-link-negative-control");
    mkdirSync(fixtureRoot, { recursive: true });
    const archive = join(fixtureRoot, "pax-link.tar");
    const encoded = Buffer.from(forbiddenInternalDomains[0]!).toString("base64");
    writeTarFixture(archive, [
      {
        path: "PaxHeaders.0/link",
        type: "x",
        data: paxRecord("linkpath", "package/clean-target"),
      },
      {
        path: "package/service-link",
        type: "2",
        linkPath: encoded,
      },
    ]);

    expect(readRawTarMembers(archive)[1]?.linkPath).toBe("package/clean-target");
    expect(findForbiddenRawTarMembers(archive)).toHaveLength(1);
  });

  test("raw-member scan permits benign post-zero bytes after scanning them", () => {
    const fixtureRoot = join(temporaryRoot, "trailing-tar-negative-control");
    const firstRoot = join(fixtureRoot, "first");
    const firstArchive = join(fixtureRoot, "first.tar");
    mkdirSync(firstRoot, { recursive: true });
    writeFileSync(join(firstRoot, "first.txt"), "first");
    run(["tar", "-cf", firstArchive, "-C", firstRoot, "first.txt"]);
    appendFileSync(firstArchive, "benign post-zero metadata");

    expect(findForbiddenRawTarMembers(firstArchive)).toEqual([]);
    expect(readRawTarMembers(firstArchive)).toHaveLength(1);
  });

  test("raw-member scan rejects encoded forbidden data in post-zero bytes", () => {
    const fixtureRoot = join(temporaryRoot, "hostile-trailing-tar-negative-control");
    const archive = join(fixtureRoot, "hostile-trailer.tar");
    mkdirSync(fixtureRoot, { recursive: true });
    writeTarFixture(
      archive,
      [{ path: "package/clean.txt", data: Buffer.from("clean") }],
      Buffer.from(Buffer.from(forbiddenInternalDomains[0]!).toString("base64")),
    );

    expect(findForbiddenRawTarMembers(archive)).toEqual(["#trailer"]);
  });

  test("source, generated output, and packed package use the fresh unreleased version", async () => {
    const sourcePackage = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      version: string;
    };
    const packedPackage = JSON.parse(
      readFileSync(join(extractedPackageRoot, "package.json"), "utf8"),
    ) as { version: string };
    const sourceContract = JSON.parse(
      readFileSync(join(root, "hasna.contract.json"), "utf8"),
    ) as { kitVersion: string };
    const packedContract = JSON.parse(
      readFileSync(join(extractedPackageRoot, "hasna.contract.json"), "utf8"),
    ) as { kitVersion: string };
    const generated = (await import(
      `${pathToFileURL(join(root, "dist/schemas.js")).href}?source=${Date.now()}`
    )) as { CONTRACTS_PACKAGE_VERSION: string };
    const packedGenerated = (await import(
      `${pathToFileURL(join(extractedPackageRoot, "dist/schemas.js")).href}?packed=${Date.now()}`
    )) as { CONTRACTS_PACKAGE_VERSION: string };

    expect(sourcePackage.version).toBe(expectedUnreleasedVersion);
    expect(CONTRACTS_PACKAGE_VERSION).toBe(expectedUnreleasedVersion);
    expect(generated.CONTRACTS_PACKAGE_VERSION).toBe(expectedUnreleasedVersion);
    expect(sourceContract.kitVersion).toBe(expectedUnreleasedVersion);
    expect(packedPackage.version).toBe(expectedUnreleasedVersion);
    expect(packedGenerated.CONTRACTS_PACKAGE_VERSION).toBe(expectedUnreleasedVersion);
    expect(packedContract.kitVersion).toBe(expectedUnreleasedVersion);
  });
});
