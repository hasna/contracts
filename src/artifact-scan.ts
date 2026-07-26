// Published-artifact guard: no vendor asset inventories in what ships.
//
// WHY THIS EXISTS, CONCRETELY. `@hasna/tenants@0.1.0` was published to the
// public registry with a complete 177-entry apex-domain portfolio compiled into
// `dist/index.js` and `dist/server/index.js`. The repo was private and
// `files: ["dist"]` meant only build output shipped, so the source file holding
// the list never left the machine while the list itself did. Every source-level
// review passed. `verify:release` ran typecheck, tests, and build, and inspected
// nothing that actually shipped.
//
// THE DETECTION IS STRUCTURAL, AND IT HAS TO BE. The obvious guard — a denylist
// of the assets we own — is the one guard we cannot ship, because the denylist
// IS the disclosure. So this scanner does not know or care WHICH assets are
// ours. It detects the SHAPE: a shipped file that carries a bulk inventory of
// registrable domains, hostnames, public IP addresses, or email addresses.
// That property survives renaming, reformatting, minification and bundling,
// and it is what an inventory looks like regardless of whose it is.
//
// WHAT THAT BUYS AND WHAT IT COSTS. It catches the incident class. It cannot
// decide whether a given list is ours, so a repo that legitimately ships public
// reference data (a public-suffix list, an ICANN TLD table) must declare a
// waiver naming the data — reviewed, and time-boxed, like every other waiver in
// this contract. Clause B states what a waiver may never cover: an inventory of
// assets the vendor owns is not eligible, at any threshold, in any encoding.
//
// FALSE POSITIVES ARE A REAL FAILURE MODE, NOT A NUISANCE. A mandatory gate that
// cries wolf gets switched off, and then it protects nothing — the same end
// state as a gate that cannot fail. So names that specifications reserve as
// non-real (RFC 2606 / RFC 6761 example and test names, RFC 5737 / 3849
// documentation IP ranges, private and loopback ranges) are excluded by rule
// rather than by a curated list, and the thresholds are set where an inventory
// begins rather than where a mention does.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { isRecognizedTld } from "./tlds";
import {
  commonArchiveRoot,
  isPackedArtifactPath,
  listArchiveEntries,
  normalizeArchiveEntry,
  readArchiveMemberBytes,
  MAX_SCANNED_MEMBER_BYTES,
} from "./packed-artifact";
// Type-only: the manifest schema declares the waiver shape, this module
// enforces it. Importing the type rather than the validator keeps the guard
// free of a zod runtime while still breaking the build if the two drift.
import type { AssetInventoryWaiver } from "./schemas";

/** Asset classes an inventory can be made of. */
export const ASSET_INVENTORY_KINDS = ["domain", "host", "ip", "email"] as const;
export type AssetInventoryKind = (typeof ASSET_INVENTORY_KINDS)[number];

/**
 * How many DISTINCT entries of one kind, in ONE shipped file, make an
 * inventory rather than a mention.
 *
 * These are the numbers where "this file lists our assets" starts being the
 * only plausible reading. A README naming a handful of hosts is documentation;
 * a bundle carrying 20 registrable domains is a portfolio. The incident's file
 * held 177. Set low enough to have caught it many times over, high enough that
 * ordinary code and docs do not trip it.
 */
export const DEFAULT_INVENTORY_THRESHOLDS: Readonly<Record<AssetInventoryKind, number>> = Object.freeze({
  domain: 20,
  host: 25,
  ip: 20,
  email: 15,
});

/**
 * Names specifications reserve as NOT REAL. Excluded by rule, not by taste:
 * RFC 2606 (`example.com|net|org`, `.test`, `.example`, `.invalid`,
 * `.localhost`) and RFC 6761. A doc full of `example.com` is documentation.
 */
const RESERVED_TLDS = new Set(["test", "example", "invalid", "localhost", "local", "internal", "onion", "arpa"]);
const RESERVED_DOMAINS = new Set(["example.com", "example.net", "example.org", "localhost"]);

/**
 * Registry-operated second-level labels, keyed by TLD: `a.co.uk` and `b.co.uk`
 * are two registrants, not one.
 *
 * Stored as labels rather than as dotted strings on purpose. Written the
 * obvious way (`"co.uk"`, `"com.au"`, …) this table IS a list of ~40 dotted
 * names, and the guard reading it flagged its own bundle as a domain
 * inventory — a satisfying proof that the detector works, and a bad reason to
 * need a waiver. Split by label it says what it actually means, and produces
 * no dotted literal in source or in `dist`.
 *
 * A pragmatic subset, not the public suffix list: shipping the full list would
 * be a genuine inventory, and missing an entry only makes the domain count
 * slightly over-eager on a file that is already an inventory.
 */
const REGISTRY_SECOND_LEVELS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  uk: ["co", "org", "ac", "gov", "me", "net", "sch"],
  au: ["com", "net", "org", "edu", "gov"],
  nz: ["co", "net", "org"],
  jp: ["co", "or", "ne", "ac", "go"],
  br: ["com", "net", "org"],
  in: ["co", "net", "org"],
  cn: ["com", "net", "org", "gov"],
  za: ["co", "org"],
  kr: ["co", "or"],
  mx: ["com"],
  ar: ["com"],
  tr: ["com"],
  sg: ["com"],
  hk: ["com"],
  tw: ["com"],
});

const MULTI_LABEL_SUFFIXES = new Set(
  Object.entries(REGISTRY_SECOND_LEVELS).flatMap(([tld, seconds]) => seconds.map((second) => [second, tld].join("."))),
);

/**
 * THE TWO SHAPES AN INVENTORY TAKES, AND WHY THERE ARE EXACTLY TWO.
 *
 * A candidate never counts because it merely appears somewhere. In a shipped
 * artifact `node.name`, `config.host`, `spec.info` and `exports.tr` are the
 * same characters as `brand.name`, `mail.host`, `acme.info` and `shop.tr`, so a
 * rule that counts any dotted lowercase run reports member access as a domain
 * portfolio. Measured, not assumed: over `node_modules` such a rule finds 139
 * distinct "domains" in TypeScript's own bundle and 25 in one of zod's locale
 * files, where the "TLDs" are `.name` and the ISO language codes. That is a
 * gate firing on every compliant repo, which is the gate getting switched off.
 *
 * So a candidate counts only where a LIST lives, and a list has two shapes:
 *
 *  1. A LITERAL INVENTORY. The candidate sits in a quoted string whose content
 *     is mostly assets — `["a-brand.com", …]`, `"a-brand.com,b-brand.com,…"
 *     .split(",")`, a newline-joined template literal. The ratio is what
 *     separates a list from a sentence, and it is also what keeps a `.map`
 *     file's `sourcesContent` — an entire source file inside one literal —
 *     from being read as an inventory of its own `x.name` expressions.
 *  2. A COLUMN INVENTORY. The candidate is the WHOLE of a delimited field, in
 *     the same column, on several consecutive lines: a `.csv`, a markdown
 *     table, a one-per-line list. A column is what a table is, and code does
 *     not accidentally produce one — the same corpus that yields 139 false
 *     domains under a token rule yields zero under this one.
 *
 * Both rules keep the requirements that always carried precision: the last
 * label must be a recognized TLD (`config.replace` is not a domain because
 * `replace` is not a TLD, `agents.list` because `list` is excluded
 * vocabulary), and every label must be lowercase `[a-z0-9-]`, which is what a
 * hostname is and what `connectionTimeoutMillis` is not.
 *
 * THE RESIDUAL, STATED: an inventory written as running prose — a bulleted
 * list, names inside sentences — is read but not counted. Clause B is a
 * prohibition, not a count.
 */
const QUOTED_LITERAL_PATTERN = /(?:"([^"\n]{3,})"|'([^'\n]{3,})'|`([^`]{3,})`)/g;
/** How a joined inventory separates its entries inside one literal. */
const LITERAL_SEPARATORS = /[\s,;|]+/;
/** How a row separates its fields: CSV commas, markdown pipes, TSV tabs. */
const FIELD_SEPARATORS = /[,|\t]/;
/** Consecutive rows that make a column a column rather than a coincidence. */
const MIN_COLUMN_RUN = 5;
const HOSTNAME_LITERAL = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
const EMAIL_LITERAL = /^[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
const IPV4_LITERAL = /^(?:\d{1,3}\.){3}\d{1,3}$/;
/** A bare IPv4 anywhere in the text; unlike a hostname it cannot be confused with code. */
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

/** Documentation, private, loopback, link-local, and multicast IPv4 space. */
function isReservedIpv4(value: string): boolean {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b, c] = parts as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127 || a >= 224) return true; // this-network, private, loopback, multicast+
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1 (RFC 5737)
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  return false;
}

function isReservedHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (RESERVED_DOMAINS.has(lower)) return true;
  const tld = lower.slice(lower.lastIndexOf(".") + 1);
  if (RESERVED_TLDS.has(tld)) return true;
  return [...RESERVED_DOMAINS].some((reserved) => lower.endsWith(`.${reserved}`));
}

/** `a.b.example.co.uk` -> `example.co.uk`; the unit a registrant actually owns. */
export function registrableDomain(hostname: string): string {
  const labels = hostname.toLowerCase().split(".");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return MULTI_LABEL_SUFFIXES.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

export interface AssetInventoryFinding {
  /** Member path inside the artifact. */
  path: string;
  kind: AssetInventoryKind;
  /** Number of distinct entries found. */
  count: number;
  /** The threshold that was exceeded. */
  threshold: number;
  /**
   * A small, redacted sample. Deliberately partial and masked: the report is
   * itself an artifact that gets pasted into tasks, channels, and CI logs, and
   * a guard that prints the inventory it just found has disclosed it again.
   */
  sample: string[];
}

/** A member the scan could not decode, and why it could not. */
export interface UnreadableMember {
  /** Member path inside the artifact. */
  path: string;
  reason: string;
}

export interface ArtifactScanOptions {
  /** Per-kind overrides. Merged over {@link DEFAULT_INVENTORY_THRESHOLDS}. */
  thresholds?: Partial<Record<AssetInventoryKind, number>>;
  /** Asset kinds a reviewed, unexpired waiver excuses. */
  waivedKinds?: readonly AssetInventoryKind[];
  /** Member paths to skip, as exact normalized paths. */
  ignorePaths?: readonly string[];
  /**
   * Ceiling on one member's decoded bytes; defaults to
   * {@link MAX_SCANNED_MEMBER_BYTES}. A member above it is reported as
   * unreadable, which fails the scan — the ceiling bounds memory, it does not
   * excuse a file from being read.
   */
  maxMemberBytes?: number;
}

export interface ArtifactScanReport {
  ok: boolean;
  /** The scanned target, as given. */
  target: string;
  /** `packed_artifact` when a tarball was read, `source_tree` for a directory. */
  scanMode: "packed_artifact" | "source_tree";
  /** Members that were read and searched. Non-empty on any real artifact. */
  membersScanned: number;
  /** Members skipped because they were binary — nothing to decode as text. */
  membersSkipped: number;
  findings: AssetInventoryFinding[];
  /** Findings suppressed by a declared waiver, kept for the audit trail. */
  waived: AssetInventoryFinding[];
  /**
   * Members that could not be decoded at all. NEVER a footnote: a member that
   * was not read cannot be cleared, so any entry here fails the scan.
   */
  unreadable: UnreadableMember[];
}

/** Mask an entry so the report names the SHAPE without republishing the value. */
function redact(entry: string): string {
  if (entry.includes("@")) {
    const [local, domain] = entry.split("@") as [string, string];
    return `${local.slice(0, 1)}***@${redact(domain)}`;
  }
  const labels = entry.split(".");
  const tld = labels.at(-1) ?? "";
  const head = labels.slice(0, -1).join(".");
  return `${head.slice(0, 2)}${"*".repeat(Math.max(head.length - 2, 1))}.${tld}`;
}

/**
 * Is this buffer text? A `.map`, a `.md` and a minified bundle all disclose
 * fine, so extension is not a useful filter; the presence of NUL bytes in the
 * first few KB is.
 */
function looksTextual(bytes: Buffer): boolean {
  const head = bytes.subarray(0, 8192);
  return !head.includes(0);
}

function distinct(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

/** Is this whole value a countable hostname — real TLD, not spec-reserved? */
function isCountableHostname(value: string): boolean {
  if (!HOSTNAME_LITERAL.test(value)) return false;
  if (isReservedHostname(value)) return false;
  return isRecognizedTld(value.slice(value.lastIndexOf(".") + 1));
}

/** Is this whole value a countable email address? */
function isCountableEmail(value: string): boolean {
  if (!EMAIL_LITERAL.test(value)) return false;
  const domain = value.slice(value.indexOf("@") + 1);
  if (isReservedHostname(domain)) return false;
  return isRecognizedTld(domain.slice(domain.lastIndexOf(".") + 1));
}

/** Shape 1: a quoted literal whose content is mostly assets. */
function collectLiteralInventories(text: string, hosts: Set<string>, emails: Set<string>): void {
  for (const match of text.matchAll(QUOTED_LITERAL_PATTERN)) {
    const literal = (match[1] ?? match[2] ?? match[3] ?? "").trim();
    if (!literal) continue;
    const pieces = literal.split(LITERAL_SEPARATORS).filter(Boolean);
    const assets = pieces.filter((piece) => isCountableHostname(piece) || isCountableEmail(piece));
    if (assets.length === 0) continue;
    // A literal that is MOSTLY assets is a list; one that names an asset in a
    // sentence is a mention, and the thresholds are set where an inventory
    // begins rather than where a mention does.
    if (assets.length * 2 < pieces.length) continue;
    for (const asset of assets) (isCountableEmail(asset) ? emails : hosts).add(asset);
  }
}

/** Shape 2: the same field position, an asset on several consecutive rows. */
function collectColumnInventories(text: string, hosts: Set<string>, emails: Set<string>): void {
  const runs = new Map<number, string[]>();
  const close = (column: number): void => {
    const values = runs.get(column);
    runs.delete(column);
    if (!values || values.length < MIN_COLUMN_RUN) return;
    for (const value of values) (isCountableEmail(value) ? emails : hosts).add(value);
  };

  for (const line of text.split(/\r?\n/)) {
    const fields = line.split(FIELD_SEPARATORS);
    // A row is either a row of COLUMNS, or a line that is nothing but the entry
    // itself. `    node.name,` is neither: one field with a comma hung off the
    // end of it is an argument list, and reading it as a table is how a guard
    // ends up reporting a bundle's member access as a portfolio.
    const populated = fields.filter((field) => field.trim() !== "").length;
    const trimmed = line.trim();
    const carried = new Set<number>();
    for (const [column, field] of fields.entries()) {
      const value = field.trim();
      if (!isCountableHostname(value) && !isCountableEmail(value)) continue;
      if (populated < 2 && trimmed !== value) continue;
      carried.add(column);
      const run = runs.get(column);
      if (run) run.push(value);
      else runs.set(column, [value]);
    }
    for (const column of [...runs.keys()]) if (!carried.has(column)) close(column);
  }
  for (const column of [...runs.keys()]) close(column);
}

/**
 * Count distinct assets of each kind in one member's text.
 *
 * Domains and emails are read from the two inventory shapes above, in whatever
 * encoding the file happens to use. IPv4 is read from anywhere, because a
 * dotted quad is not confusable with an identifier.
 */
export function inventoryCounts(text: string): Record<AssetInventoryKind, string[]> {
  const emails = new Set<string>();
  const hosts = new Set<string>();

  collectLiteralInventories(text, hosts, emails);
  collectColumnInventories(text, hosts, emails);

  // A hostname inside an email address is not independent evidence; counting it
  // twice would let one contact list trip two detectors.
  const emailHosts = new Set([...emails].map((email) => email.slice(email.indexOf("@") + 1)));
  const named = [...hosts].filter((host) => !emailHosts.has(host)).sort();
  const domains = distinct(named.map(registrableDomain));
  // A "host" is a MACHINE name under a domain — at least one label beyond the
  // registrable domain. Counting `a-brand.com` as both a domain and a host would
  // report one list twice and inflate every finding.
  const hostList = named.filter((host) => host !== registrableDomain(host));
  const ips = distinct(
    [...text.matchAll(IPV4_PATTERN)]
      .map((match) => match[0])
      .filter((ip) => IPV4_LITERAL.test(ip) && !isReservedIpv4(ip)),
  );

  return { domain: domains, host: hostList, ip: ips, email: [...emails].sort() };
}

/**
 * One member, either decoded or explained.
 *
 * Members are yielded one at a time rather than collected, because there is no
 * longer a small per-member cap to bound the total: holding the whole
 * uncompressed package in memory to scan it a file at a time would trade one
 * failure mode for another.
 */
type MemberRead = { path: string; bytes: Buffer } | { path: string; reason: string };

function readError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function* readDirectoryMembers(root: string, maxMemberBytes: number, dir: string = root): Generator<MemberRead> {
  const skipDirs = new Set([".git", "node_modules"]);
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!skipDirs.has(entry.name)) yield* readDirectoryMembers(root, maxMemberBytes, full);
      continue;
    }
    if (!entry.isFile()) continue;
    const path = relative(root, full).replaceAll("\\", "/");
    const size = statSync(full).size;
    if (size > maxMemberBytes) {
      yield { path, reason: `${size} bytes exceeds the ${maxMemberBytes}-byte scan ceiling` };
      continue;
    }
    try {
      yield { path, bytes: readFileSync(full) };
    } catch (error) {
      yield { path, reason: readError(error) };
    }
  }
}

function* readArchiveMembers(target: string, maxMemberBytes: number): Generator<MemberRead> {
  const entries = listArchiveEntries(target);
  const archiveRoot = commonArchiveRoot(entries);
  for (const entry of entries) {
    const path = normalizeArchiveEntry(entry, archiveRoot);
    if (!path) continue;
    try {
      yield { path, bytes: readArchiveMemberBytes(target, entry, maxMemberBytes) };
    } catch (error) {
      // A member that could not be decoded is reported as UNREADABLE and fails
      // the scan. The earlier draft counted it and carried on, which meant the
      // biggest file in the tarball — exactly where a compiled-in list ends
      // up — could go unread while the report still said `ok`. A clean verdict
      // over a file nobody read is worse than no scan at all.
      yield { path, reason: readError(error) };
    }
  }
}

/**
 * Scan a packed artifact (or, for local iteration, a directory) for bulk asset
 * inventories.
 *
 * Fails when the target yields zero readable members. A scanner that reports
 * `ok` after finding nothing to read is the vacuity trap this contract keeps
 * running into: it would pass on a broken path, a wrong filename, or an empty
 * tarball, and pass loudest exactly when it is protecting nothing. The same
 * rule applies one member at a time: a member the scan could not decode fails
 * it, because an unread file has not been cleared.
 */
export function scanPublishedArtifact(target: string, options: ArtifactScanOptions = {}): ArtifactScanReport {
  const stat = statSync(target);
  const scanMode: ArtifactScanReport["scanMode"] =
    stat.isDirectory() ? "source_tree" : isPackedArtifactPath(target) ? "packed_artifact" : "packed_artifact";
  if (!stat.isDirectory() && !isPackedArtifactPath(target)) {
    throw new Error("Artifact scan target must be a directory, .tgz, or .tar.gz file.");
  }

  const maxMemberBytes = options.maxMemberBytes ?? MAX_SCANNED_MEMBER_BYTES;
  const members = stat.isDirectory()
    ? readDirectoryMembers(target, maxMemberBytes)
    : readArchiveMembers(target, maxMemberBytes);

  const thresholds = { ...DEFAULT_INVENTORY_THRESHOLDS, ...options.thresholds };
  const waived = new Set(options.waivedKinds ?? []);
  const ignore = new Set(options.ignorePaths ?? []);

  const findings: AssetInventoryFinding[] = [];
  const waivedFindings: AssetInventoryFinding[] = [];
  const unreadable: UnreadableMember[] = [];
  let seen = 0;
  let scanned = 0;
  let skippedBinary = 0;

  for (const member of members) {
    seen += 1;
    if (ignore.has(member.path)) continue;
    if ("reason" in member) {
      unreadable.push({ path: member.path, reason: member.reason });
      continue;
    }
    if (!looksTextual(member.bytes)) {
      skippedBinary += 1;
      continue;
    }
    scanned += 1;
    const counts = inventoryCounts(member.bytes.toString("utf8"));
    for (const kind of ASSET_INVENTORY_KINDS) {
      const entries = counts[kind];
      const threshold = thresholds[kind];
      if (entries.length < threshold) continue;
      const finding: AssetInventoryFinding = {
        path: member.path,
        kind,
        count: entries.length,
        threshold,
        sample: entries.slice(0, 3).map(redact),
      };
      (waived.has(kind) ? waivedFindings : findings).push(finding);
    }
  }

  if (seen === 0) {
    throw new Error(
      `Artifact scan read zero members from ${basename(target)}. Refusing to report a clean verdict on nothing.`,
    );
  }

  return {
    ok: findings.length === 0 && unreadable.length === 0,
    target,
    scanMode,
    membersScanned: scanned,
    membersSkipped: skippedBinary,
    findings,
    waived: waivedFindings,
    unreadable,
  };
}

/** One-line-per-finding summary for CLI output and CI logs. */
export function formatArtifactScanReport(report: ArtifactScanReport): string {
  const lines = [
    `${report.ok ? "pass" : "FAIL"} artifact-scan ${basename(report.target)} (${report.scanMode}, ${report.membersScanned} members scanned, ${report.membersSkipped} binary skipped, ${report.unreadable.length} unreadable)`,
  ];
  for (const finding of report.findings) {
    lines.push(
      `  FAIL ${finding.path}: ${finding.count} distinct ${finding.kind} entries (threshold ${finding.threshold}) e.g. ${finding.sample.join(", ")}`,
    );
  }
  for (const member of report.unreadable) {
    lines.push(`  FAIL ${member.path}: could not be read, so it has not been cleared (${member.reason})`);
  }
  for (const finding of report.waived) {
    lines.push(`  waived ${finding.path}: ${finding.count} distinct ${finding.kind} entries`);
  }
  return lines.join("\n");
}

/**
 * Asset-inventory waivers a manifest declares, filtered to those still in force.
 *
 * The schema has carried `metadata.conformance.waivedAssetInventories` and
 * CONTRACT.md has documented it as the escape hatch for public reference data,
 * but until now nothing read it: a repo that declared the waiver exactly as the
 * contract instructed still failed the gate, and its only recourse was to
 * unwire the gate — the precise failure mode clause C exists to prevent.
 *
 * `expiresAt` is enforced here, so the time-boxing is a property rather than a
 * promise: an expired waiver stops applying on its own, without anyone
 * remembering to remove it. A waiver missing the accountability fields the
 * contract requires is not honoured either — a waiver nobody signed is not a
 * reviewed exception.
 */
export interface AssetInventoryWaiverResolution {
  /** Kinds a reviewed, unexpired waiver excuses. */
  kinds: AssetInventoryKind[];
  /** One audit line per declared waiver, applied or not. */
  notes: string[];
}

function isAssetInventoryKind(value: unknown): value is AssetInventoryKind {
  return typeof value === "string" && (ASSET_INVENTORY_KINDS as readonly string[]).includes(value);
}

/** A declared waiver, or the reason it cannot be honoured. */
function readDeclaredWaiver(value: unknown): AssetInventoryWaiver | string {
  if (typeof value !== "object" || value === null) return "waiver entry is not an object";
  const declared = value as Record<string, unknown>;
  const { kind, reason, reviewedBy, expiresAt } = declared;
  if (!isAssetInventoryKind(kind)) {
    return `waiver kind ${JSON.stringify(kind)} is not one of ${ASSET_INVENTORY_KINDS.join(", ")}`;
  }
  if (typeof reason !== "string" || reason.trim() === "") return `waiver for ${kind} names no reason`;
  if (typeof reviewedBy !== "string" || reviewedBy.trim() === "") return `waiver for ${kind} names no reviewer`;
  if (typeof expiresAt !== "string" || Number.isNaN(Date.parse(expiresAt))) return `waiver for ${kind} has no usable expiresAt`;
  return { kind, reason, reviewedBy, expiresAt };
}

export function resolveAssetInventoryWaivers(
  manifestPath: string,
  now: Date = new Date(),
): AssetInventoryWaiverResolution {
  if (!existsSync(manifestPath)) return { kinds: [], notes: [] };

  let manifest: unknown;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    throw new Error(`Could not read asset-inventory waivers from ${manifestPath}: ${readError(error)}`);
  }

  const conformance = (manifest as { metadata?: { conformance?: { waivedAssetInventories?: unknown } } })?.metadata
    ?.conformance;
  const declared = conformance?.waivedAssetInventories;
  if (declared === undefined) return { kinds: [], notes: [] };
  if (!Array.isArray(declared)) {
    return { kinds: [], notes: ["metadata.conformance.waivedAssetInventories is not an array; no waiver applied"] };
  }

  const kinds: AssetInventoryKind[] = [];
  const notes: string[] = [];
  for (const entry of declared) {
    const waiver = readDeclaredWaiver(entry);
    if (typeof waiver === "string") {
      notes.push(`${waiver}; not applied`);
      continue;
    }
    if (Date.parse(waiver.expiresAt) <= now.getTime()) {
      notes.push(`${waiver.kind} waiver expired at ${waiver.expiresAt}; not applied`);
      continue;
    }
    if (!kinds.includes(waiver.kind)) kinds.push(waiver.kind);
    notes.push(`${waiver.kind} waived until ${waiver.expiresAt} (reviewed by ${waiver.reviewedBy}): ${waiver.reason}`);
  }
  return { kinds, notes };
}
