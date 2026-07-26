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

import { readFileSync, readdirSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { isRecognizedTld } from "./tlds";
import {
  commonArchiveRoot,
  isPackedArtifactPath,
  listArchiveEntries,
  normalizeArchiveEntry,
  readArchiveMemberBytes,
  MAX_ARCHIVE_MEMBER_BYTES,
} from "./packed-artifact";

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
 * A candidate is only counted when it is the ENTIRE content of a quoted string
 * or a standalone token — never when it is `object.method` in an expression.
 *
 * An asset inventory in a shipped artifact is a list of literals. Member access
 * is not, and treating the two alike is what made the first draft of this guard
 * report `config.replace` as a domain. Labels must also be lowercase
 * `[a-z0-9-]`, which is what a hostname is and what `connectionTimeoutMillis`
 * is not.
 */
const QUOTED_TOKEN_PATTERN = /(?:"([^"\n]{3,253})"|'([^'\n]{3,253})'|`([^`\n]{3,253})`)/g;
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

export interface ArtifactScanOptions {
  /** Per-kind overrides. Merged over {@link DEFAULT_INVENTORY_THRESHOLDS}. */
  thresholds?: Partial<Record<AssetInventoryKind, number>>;
  /** Asset kinds a reviewed, unexpired waiver excuses. */
  waivedKinds?: readonly AssetInventoryKind[];
  /** Member paths to skip, as exact normalized paths. */
  ignorePaths?: readonly string[];
}

export interface ArtifactScanReport {
  ok: boolean;
  /** The scanned target, as given. */
  target: string;
  /** `packed_artifact` when a tarball was read, `source_tree` for a directory. */
  scanMode: "packed_artifact" | "source_tree";
  /** Members that were read and searched. Non-empty on any real artifact. */
  membersScanned: number;
  /** Members skipped because they were binary or oversized. */
  membersSkipped: number;
  findings: AssetInventoryFinding[];
  /** Findings suppressed by a declared waiver, kept for the audit trail. */
  waived: AssetInventoryFinding[];
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

/**
 * Count distinct assets of each kind in one member's text.
 *
 * Domains and emails are read only from complete quoted literals with a
 * recognized TLD. IPv4 is read from anywhere, because a dotted quad is not
 * confusable with an identifier.
 */
export function inventoryCounts(text: string): Record<AssetInventoryKind, string[]> {
  const emails = new Set<string>();
  const hosts = new Set<string>();

  for (const match of text.matchAll(QUOTED_TOKEN_PATTERN)) {
    const literal = (match[1] ?? match[2] ?? match[3] ?? "").trim();
    if (!literal) continue;
    const lowered = literal.toLowerCase();
    if (lowered !== literal) continue; // camelCase identifiers are not hostnames

    if (EMAIL_LITERAL.test(literal)) {
      const domain = literal.slice(literal.indexOf("@") + 1);
      if (!isReservedHostname(domain) && isRecognizedTld(domain.slice(domain.lastIndexOf(".") + 1))) {
        emails.add(literal);
      }
      continue;
    }
    if (!HOSTNAME_LITERAL.test(literal)) continue;
    if (isReservedHostname(literal)) continue;
    if (!isRecognizedTld(literal.slice(literal.lastIndexOf(".") + 1))) continue;
    hosts.add(literal);
    continue;
  }

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

interface ScannedMember {
  path: string;
  bytes: Buffer;
}

function collectDirectoryMembers(root: string): { members: ScannedMember[]; skipped: number } {
  const members: ScannedMember[] = [];
  let skipped = 0;
  const skipDirs = new Set([".git", "node_modules"]);

  function walk(dir: string): void {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (statSync(full).size > MAX_ARCHIVE_MEMBER_BYTES) {
        skipped += 1;
        continue;
      }
      members.push({ path: relative(root, full).replaceAll("\\", "/"), bytes: readFileSync(full) });
    }
  }

  walk(root);
  return { members, skipped };
}

function collectArchiveMembers(target: string): { members: ScannedMember[]; skipped: number } {
  const entries = listArchiveEntries(target);
  const archiveRoot = commonArchiveRoot(entries);
  const members: ScannedMember[] = [];
  let skipped = 0;
  for (const entry of entries) {
    const path = normalizeArchiveEntry(entry, archiveRoot);
    if (!path) continue;
    try {
      members.push({ path, bytes: readArchiveMemberBytes(target, entry) });
    } catch {
      // Oversized members are counted, never silently dropped: a scan that
      // quietly skipped the biggest file in the tarball would be worse than
      // no scan, because it would report a clean verdict.
      skipped += 1;
    }
  }
  return { members, skipped };
}

/**
 * Scan a packed artifact (or, for local iteration, a directory) for bulk asset
 * inventories.
 *
 * Fails when the target yields zero readable members. A scanner that reports
 * `ok` after finding nothing to read is the vacuity trap this contract keeps
 * running into: it would pass on a broken path, a wrong filename, or an empty
 * tarball, and pass loudest exactly when it is protecting nothing.
 */
export function scanPublishedArtifact(target: string, options: ArtifactScanOptions = {}): ArtifactScanReport {
  const stat = statSync(target);
  const scanMode: ArtifactScanReport["scanMode"] =
    stat.isDirectory() ? "source_tree" : isPackedArtifactPath(target) ? "packed_artifact" : "packed_artifact";
  if (!stat.isDirectory() && !isPackedArtifactPath(target)) {
    throw new Error("Artifact scan target must be a directory, .tgz, or .tar.gz file.");
  }

  const { members, skipped } = stat.isDirectory() ? collectDirectoryMembers(target) : collectArchiveMembers(target);
  if (members.length === 0) {
    throw new Error(
      `Artifact scan read zero members from ${basename(target)}. Refusing to report a clean verdict on nothing.`,
    );
  }

  const thresholds = { ...DEFAULT_INVENTORY_THRESHOLDS, ...options.thresholds };
  const waived = new Set(options.waivedKinds ?? []);
  const ignore = new Set(options.ignorePaths ?? []);

  const findings: AssetInventoryFinding[] = [];
  const waivedFindings: AssetInventoryFinding[] = [];
  let scanned = 0;
  let skippedBinary = skipped;

  for (const member of members) {
    if (ignore.has(member.path)) continue;
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

  return {
    ok: findings.length === 0,
    target,
    scanMode,
    membersScanned: scanned,
    membersSkipped: skippedBinary,
    findings,
    waived: waivedFindings,
  };
}

/** One-line-per-finding summary for CLI output and CI logs. */
export function formatArtifactScanReport(report: ArtifactScanReport): string {
  const lines = [
    `${report.ok ? "pass" : "FAIL"} artifact-scan ${basename(report.target)} (${report.scanMode}, ${report.membersScanned} members scanned, ${report.membersSkipped} skipped)`,
  ];
  for (const finding of report.findings) {
    lines.push(
      `  FAIL ${finding.path}: ${finding.count} distinct ${finding.kind} entries (threshold ${finding.threshold}) e.g. ${finding.sample.join(", ")}`,
    );
  }
  for (const finding of report.waived) {
    lines.push(`  waived ${finding.path}: ${finding.count} distinct ${finding.kind} entries`);
  }
  return lines.join("\n");
}
