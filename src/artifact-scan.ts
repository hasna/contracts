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

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { isRecognizedTld } from "./tlds";
import {
  commonArchiveRoot,
  isPackedArtifactPath,
  listArchiveEntries,
  normalizeArchiveEntry,
  extractArchive,
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
 *     is mostly assets — `"a-brand.com,b-brand.com,…".split(",")`, a
 *     newline-joined template literal — or in a RUN of sibling literals that
 *     between them form one list: `["a-brand.com", "b-brand.com", …]`, which is
 *     what an array of names looks like before and after minification. The
 *     ratio is what separates a list from a sentence, and it is also what keeps
 *     a `.map` file's `sourcesContent` — an entire source file inside one
 *     literal — from being read as an inventory of its own `x.name`
 *     expressions.
 *
 *     A LONE quoted asset is a MENTION, not a list, and this is not a nicety.
 *     `expect(isEmail("user@a-brand.com")).toBe(true)` is one literal with one
 *     piece; counting it made every scattered mention in a file aggregate into
 *     an "inventory", and a validator's fixture file — `zod@4.4.3` ships 23 and
 *     24 of them in its `string.test.ts`, `email-validator@2.0.4` 22 — failed a
 *     gate clause C makes mandatory and blocking. So a one-piece literal counts
 *     only where its neighbours are assets too, with nothing between them but
 *     the punctuation and keys a list is written with.
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
 * Both rules read a candidate through {@link hostComponent} first, because an
 * endpoint catalogue is not written as bare hostnames. `https://svc-1.a.com/v1`,
 * `//svc-1.a.com/v1` and `svc-1.a.com:443` are the forms an endpoint list
 * actually takes, and clause B names internal endpoint catalogues explicitly —
 * a rule that only saw the bare name let the whole category through.
 *
 * THE RESIDUALS, STATED: an inventory written as running prose — a bulleted
 * list, names inside sentences — is read but not counted, and neither is one
 * asset mentioned once per expression however many times a file does it.
 * Clause B is a prohibition, not a count.
 */
// Any quoted token, including 1- and 2-character ones. The `{3,}` floor meant a
// short key such as `"id"` was not matched at all, so its quote characters fell
// into the run glue — which excludes `"` — and broke the run at EVERY element.
// One two-character key anywhere in a keyed-object list took detection to zero.
// ESCAPE-AWARE. `"a \"b\" c"` is ONE literal, not three: a naive tokenizer
// pairs the inner quotes with the outer ones and every subsequent pairing is
// shifted by one, which silently mis-reads the rest of the file. A source map's
// `sourcesContent` is exactly that shape — the original source, quoted, with
// every quote escaped — and it is how a file excluded by `files` still ships.
const QUOTED_LITERAL_PATTERN = /"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\]|\\.)*)`/g;
/** How a joined inventory separates its entries inside one literal. */
const LITERAL_SEPARATORS = /[\s,;|]+/;
/** How a row separates its fields: CSV commas, markdown pipes, TSV tabs. */
const FIELD_SEPARATORS = /[,|\t]/;
/** Consecutive rows that make a column a column rather than a coincidence. */
const MIN_COLUMN_RUN = 5;
/** Sibling literals in a row that make an array a list rather than a mention. */
const MIN_LITERAL_RUN = 5;
/**
 * What may sit BETWEEN two quoted literals and still leave them siblings in one
 * list: the punctuation and keys that an array, an object, or a JSON document
 * puts between its elements — `,`, `:`, brackets, a number, an unquoted key.
 * A call breaks the run, and that is the whole point: `expect(isEmail(…))` and
 * `fetch(…)` around every entry are separate expressions that happen to mention
 * an asset, not a list that holds one.
 */
const LITERAL_RUN_GLUE = /^[\s,;:=|<>+\-\w$[\]{}]*$/;
/**
 * A key, not an entry: a JSON field name, an object key, a short description.
 * It carries no dot and no `@`, so it is not an asset that merely failed to
 * count, and `{"1und1": {"description": "…", "host": "…"}, …}` is still one
 * list of hosts. An entry that DOES look like an asset but is not countable —
 * a spec-reserved name, an unrecognized TLD — breaks the run instead, because a
 * list mostly made of those is a fixture table, not an inventory.
 */
const LABEL_LITERAL = /^[^.@\n]{1,80}$/;
/** `scheme://` or a scheme-relative `//`, the prefix that makes a piece a URL. */
const URL_AUTHORITY_PREFIX = /^(?:[a-z][a-z0-9+.-]*:)?\/\//;
/** Where a URL's authority ends. */
const URL_AUTHORITY_END = /[/?#]/;
/** A `:443` an endpoint list hangs off the end of a host. */
const HOST_PORT_SUFFIX = /:\d{1,5}$/;
const HOSTNAME_LITERAL = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
const EMAIL_LITERAL = /^[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
/**
 * Dotted-quad in PRESENTATION FORMAT: no leading zeros.
 *
 * `01.52.02.53` is not an address anyone writes; it is what random bytes look
 * like when a 135 MB `.node` binary is decoded as latin1. Accepting leading
 * zeros turned binary noise into findings — one native addon produced 153 IP
 * "entries", 147 of them zero-padded — and the exposure scaled with binary
 * size, so small artifacts looked clean and large ones failed inexplicably.
 * The comment claiming binary noise is harmless holds for domains, which need
 * a real TLD; it never held for IPs.
 */
const IPV4_LITERAL = /^(?:(?:0|[1-9]\d{0,2})\.){3}(?:0|[1-9]\d{0,2})$/;

/**
 * Object keys whose value is a VERSION, not an address.
 *
 * A dotted quad is numerically indistinguishable from a four-component version
 * string, so in code the only available signal is the key it sits under. This
 * is a DENYLIST rather than an address whitelist, and the difference is large:
 * an exact-match whitelist of address words silently dropped every compound
 * spelling — `ipAddress`, `public_ip`, `PublicIpAddress`, `ansible_host`,
 * `tailscale_ip`, `ips`, `addresses` — so a 40-record EC2 `describe-instances`
 * export keyed `PublicIpAddress` scanned clean, and a hostname->IP map scanned
 * clean on all four kinds.
 *
 * The denylist loses nothing measurable. Enumerating which keys actually hold
 * dotted quads in the two packages that produced the false positives:
 * `node-releases@2.0.19` `envs.json` -> `v8` only; `playwright@1.61.1`
 * `babelBundle.js` -> `v8` only, 315 occurrences. Suppressing those keys fixes
 * both without suppressing anything else.
 *
 * THE COST, stated accurately: a machine list keyed with a version word — say
 * `{"build": "51.15.0.10"}` — is not counted. That is the whole residual. It is
 * not, as an earlier comment here claimed, "a machine list keyed `node`": that
 * described the whitelist this replaced, which dropped every compound address
 * spelling and is why a 40-record EC2 export scanned clean.
 */
const VERSION_KEY =
  /(?:^|[_.-])(?:v8|node|chrome|chromium|electron|engine|firefox|safari|opera|edge|ie|deno|bun|npm|yarn|pnpm|python|ruby|java|dotnet|semver|ver|version|revision|build|sdk|runtime|target|min|max)(?:[_.-]|$)/i;

/**
 * Is this key one whose value is a version rather than an address?
 *
 * camelCase is split first (`engineVersion` -> `engine_version`), because the
 * word boundaries in a denylist are separators and camelCase has none.
 *
 * A key that is itself a HOSTNAME is never a version key, however it reads. In
 * a hostname->IP map the key is `node-7.fleet.example` and the value is the
 * address; matching `node` inside it suppressed the entire map.
 */
function isVersionKey(key: string): boolean {
  if (isCountableHostname(key.toLowerCase())) return false;
  const normalized = key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
  return VERSION_KEY.test(normalized);
}

/** The object key a quoted literal is the value of, if any. */
function enclosingKey(view: string, literalStart: number): string | null {
  const before = view.slice(Math.max(0, literalStart - 96), literalStart);
  const match = /(?:"([^"\n]{1,64})"|'([^'\n]{1,64})'|([A-Za-z_$][\w$-]{0,63}))\s*:\s*$/.exec(before);
  return match ? (match[1] ?? match[2] ?? match[3] ?? null) : null;
}
/** A bare IPv4 anywhere in the text; unlike a hostname it cannot be confused with code. */
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

/** Documentation, private, loopback, link-local, and multicast IPv4 space. */
/**
 * Addresses a text presents as values: whole quoted literals always, and bare
 * tokens only in non-code members. SVG path data, version quads and OIDs all
 * live inside code and none of them is a quoted address on its own.
 */
function addressCandidates(view: string, codeLike: boolean): string[] {
  const found: string[] = [];
  for (const match of view.matchAll(QUOTED_LITERAL_PATTERN)) {
    const literal = (match[1] ?? match[2] ?? match[3] ?? "").trim();
    if (!IPV4_LITERAL.test(literal)) continue;
    if (codeLike) {
      // In code, a quad that is the value of a NON-address key is a version
      // string. `{"v8":"11.0.244.1"}` × 30 counted as 30 addresses, and real
      // packages bundling browserslist or node-releases data (playwright: 44,
      // node-releases: 50) failed their own mandatory prepack gate with a
      // finding nobody could action. A bare array element has no key and still
      // counts, which is the shape a fleet list actually takes.
      const key = enclosingKey(view, match.index ?? 0);
      if (key !== null && isVersionKey(key)) continue;
    }
    found.push(literal);
  }
  if (!codeLike) {
    for (const match of view.matchAll(IPV4_PATTERN)) {
      if (IPV4_LITERAL.test(match[0])) found.push(match[0]);
    }
  }
  return found;
}

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

/**
 * Hard ceiling per asset kind: TWICE the default, no more.
 *
 * A caller may tighten a threshold as far as it likes. Loosening is capped
 * because clause C inspects the script graph and never the flags, so a repo
 * can bake a loosened threshold into its scan script and pass conformance
 * while suppressing findings. At the previous ceiling of 100 that was a 5x
 * loosening — up to 99 owned domains suppressed by a flag nothing checks. 2x
 * leaves room for a repo with a genuinely noisy artifact to tune, and leaves
 * none for switching the detector off.
 */
export const MAX_INVENTORY_THRESHOLDS: Readonly<Record<AssetInventoryKind, number>> = Object.freeze({
  domain: 40,
  host: 50,
  ip: 40,
  email: 30,
});

function clampThresholds(
  requested: Record<AssetInventoryKind, number>
): Record<AssetInventoryKind, number> {
  const clamped = { ...requested };
  for (const kind of ASSET_INVENTORY_KINDS) {
    const value = clamped[kind];
    if (!Number.isFinite(value) || value < 1) {
      throw new Error(`${kind} threshold must be a positive number.`);
    }
    if (value > MAX_INVENTORY_THRESHOLDS[kind]) {
      throw new Error(
        `${kind} threshold ${value} exceeds the ${MAX_INVENTORY_THRESHOLDS[kind]} ceiling. A threshold that high disables the detector, which is the gate being switched off through its own front door.`,
      );
    }
  }
  return clamped;
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
  /**
   * Findings raised only by the whole-artifact union, not by any single member.
   * Kept separate so a reader can tell "one file holds a list" from "the list is
   * spread across ten".
   */
  aggregateFindings?: AssetInventoryFinding[];
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

/**
 * Name a finding without republishing any part of it.
 *
 * Earlier versions emitted a prefix, the exact label length, and the full TLD
 * (`ha***.agency`). A portfolio is ONE brand across many TLDs, so three samples
 * of that form disclose two characters of the brand, its exact length, and
 * three registrations it holds — enough to name it and look the rest up. The
 * mask reconstructed the secret it existed to hide.
 *
 * Nothing identifying survives: no prefix, no length, no TLD. What remains is
 * the KIND and a short salted digest, which is stable within one report (so two
 * findings can be told apart) and useless outside it.
 */
function redact(entry: string, kind: AssetInventoryKind): string {
  // Labelled by the FINDING's kind, not by guessing from the value: a `domain`
  // finding printed `<host:…>`, which is merely confusing rather than unsafe,
  // but a report nobody trusts to say what it means gets skimmed.
  return `<${kind}:${reportDigest(entry)}>`;
}

/**
 * Per-report salt. Regenerated on every run, so a digest cannot be compared
 * against a rainbow table of candidate names, or across two reports.
 */
const REPORT_SALT = randomBytes(16);

function reportDigest(value: string): string {
  return createHash("sha256").update(REPORT_SALT).update(value, "utf8").digest("hex").slice(0, 8);
}
/** Lossless decoding for scanning: UTF-8 where valid, latin1 otherwise. */
function decodeMember(bytes: Buffer): string {
  const utf8 = bytes.toString("utf8");
  return utf8.includes("\ufffd") ? bytes.toString("latin1") : utf8;
}

function looksTextual(bytes: Buffer): boolean {
  const head = bytes.subarray(0, 8192);
  return !head.includes(0);
}

function distinct(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

/**
 * Decode the escape forms a disclosure can hide behind.
 *
 * Percent, `\uXXXX`, `\u{...}`, `\xXX`, HTML entities, and the JSON-escaped
 * quotes a source map's `sourcesContent` wraps original source in — which is
 * exactly how a file excluded by `files` still ships its contents.
 */
export function decodeEscapes(value: string): string {
  const codePoint = (encoded: string, radix: number): string | null => {
    const parsed = Number.parseInt(encoded, radix);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 0x10ffff) return null;
    return String.fromCodePoint(parsed);
  };

  // ONE alternation, not a chain of independent single-escape replaces.
  //
  // The distinction that matters is consuming each backslash exactly once: a
  // chain of separate `.replace()` calls cannot tell `\\n` (an escaped
  // backslash followed by the letter n) from `\n` (a newline), because the
  // second pass re-reads the backslash the first pass left behind. A single
  // alternating pattern has no such seam — and is ~5x faster than walking the
  // string character by character, which matters on a 16 MB bundle.
  //
  // `\n` is not optional here: every bundler emits `sourcesContent` as ONE
  // JSON string with the original file's newlines escaped, so the glue between
  // two entries is `,\n  ` — which contains a literal backslash, and
  // `LITERAL_RUN_GLUE` excludes backslash, so the run broke at every element.
  // A realistic `.map` carrying a full portfolio scanned clean because of it.
  const SIMPLE: Record<string, string> = {
    n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v", "0": "\0",
    '"': '"', "'": "'", "`": "`", "\\": "\\", "/": "/",
  };
  const decoded = value.replace(
    /\\u\{([0-9a-f]{1,6})\}|\\u([0-9a-f]{4})|\\x([0-9a-f]{2})|\\([\s\S])/gi,
    (match, braced?: string, fourHex?: string, twoHex?: string, single?: string) => {
      if (braced !== undefined) return codePoint(braced, 16) ?? match;
      if (fourHex !== undefined) return codePoint(fourHex, 16) ?? match;
      if (twoHex !== undefined) return codePoint(twoHex, 16) ?? match;
      // An escape this pass does not know keeps both characters verbatim.
      return single !== undefined ? SIMPLE[single] ?? match : match;
    },
  );

  // Percent- and entity-encoding are independent of backslash escaping.
  return decoded
    .replace(/%([0-9a-f]{2})/gi, (match, hex: string) => codePoint(hex, 16) ?? match)
    .replace(/&#x([0-9a-f]+);?/gi, (match, hex: string) => codePoint(hex, 16) ?? match)
    .replace(/&#([0-9]+);?/g, (match, dec: string) => codePoint(dec, 10) ?? match);
}

/**
 * The text, its escape-decoded form, and any base64/hex blob inside it decoded
 * one level.
 *
 * A decoded blob is DATA, not code, so it is also handed to the column
 * collector — an inventory shipped as one encoded string decodes to an
 * unquoted, comma-separated list, which no literal-shaped matcher would see.
 * One level only, and length-bounded: recursive decoding over a whole tarball
 * is unbounded work for diminishing returns.
 */
function decodedViews(text: string): string[] {
  const views = [text];
  const escaped = decodeEscapes(text);
  if (escaped !== text) views.push(escaped);

  const carriesAsset = /[a-z0-9]\.[a-z]/i;
  for (const match of text.matchAll(/[A-Za-z0-9+/]{64,}={0,2}/g)) {
    const token = match[0];
    if (token.length % 4 === 1) continue;
    const decoded = Buffer.from(token, "base64").toString("utf8");
    if (carriesAsset.test(decoded)) views.push(decoded);
  }
  for (const match of text.matchAll(/\b[0-9a-f]{64,}\b/gi)) {
    const token = match[0].length % 2 === 0 ? match[0] : match[0].slice(0, -1);
    const decoded = Buffer.from(token, "hex").toString("utf8");
    if (carriesAsset.test(decoded)) views.push(decoded);
  }
  return views;
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

/**
 * The host a piece names, whether it was written bare or as an endpoint.
 *
 * `https://user@svc-1.a-brand.com:8443/v1?x=1` and `svc-1.a-brand.com:443` are
 * the same machine as `svc-1.a-brand.com`, and an endpoint catalogue is written
 * in the first two forms far more often than the third. The path is stripped
 * only where a scheme (or a scheme-relative `//`) says the piece really is a
 * URL: without that marker `agents.list/get` is a member access, not a host.
 */
function hostComponent(piece: string): string {
  const prefix = URL_AUTHORITY_PREFIX.exec(piece);
  // A fully-qualified name ends in the root dot. `a-brand.com.` and
  // `a-brand.com` are the same name, and leaving the dot on made an entire
  // FQDN-formatted inventory invisible.
  if (!prefix) return piece.replace(HOST_PORT_SUFFIX, "").replace(/\.$/, "");
  let authority = piece.slice(prefix[0].length);
  const end = authority.search(URL_AUTHORITY_END);
  if (end >= 0) authority = authority.slice(0, end);
  const userinfo = authority.lastIndexOf("@");
  if (userinfo >= 0) authority = authority.slice(userinfo + 1);
  return authority.replace(HOST_PORT_SUFFIX, "").replace(/\.$/, "");
}

/**
 * The asset a piece carries — the email itself, or the host it names — or null.
 *
 * Lowercased first, because DNS is case-insensitive and the literal patterns are
 * not. Without this, `Portfolio-Brand.com` matched nothing: one capital letter
 * per entry defeated the entire guard, and a build step that upper-cases a
 * constant table would have done it by accident.
 */
function countableAsset(piece: string): string | null {
  const normalized = piece.toLowerCase();
  if (isCountableEmail(normalized)) return normalized;
  const host = hostComponent(normalized);
  return isCountableHostname(host) ? host : null;
}

function record(asset: string, hosts: Set<string>, emails: Set<string>): void {
  (isCountableEmail(asset) ? emails : hosts).add(asset);
}

/**
 * Shape 3: one asset per line, for a run of lines.
 *
 * A markdown bullet list, a one-column CSV, a hosts-style file and a plain
 * newline-separated dump all carry an inventory with no quotes and no field
 * separator, so neither the literal collector nor the column collector sees
 * them. The line IS the record in that shape.
 *
 * A run is required for the same reason it is required elsewhere: one asset
 * mentioned on one line is a mention, not a list. List markers (`-`, `*`, `+`,
 * `#`, a leading index, surrounding quotes/brackets) are stripped before the
 * line is judged, and a line that carries anything else substantial breaks the
 * run.
 */
/**
 * Is this run one receiver being dereferenced, rather than a list of names?
 *
 * `exports.vi`, `exports.ua`, `exports.tr` … — every ISO language code is a
 * delegated ccTLD, so a per-line rule reads a locale barrel file as a
 * ten-domain portfolio. The tell is that the FIRST label never varies while the
 * last one always does.
 *
 * A real portfolio has the SAME shape — one brand across many TLDs — so this
 * rule is only safe where property access is possible at all. It is applied to
 * code members only; `collectLineInventories` takes `codeLike` for exactly that
 * reason, and applying it to prose took markdown, numbered and YAML lists of
 * the real incident shape to zero detections.
 */
/**
 * Members read as CODE, where a bare `a.b` is a property access.
 *
 * Everything else — markdown, YAML, CSV, plain text, extensionless — is read as
 * data, where a bare `a.b` is a name. Getting this wrong is expensive in both
 * directions: applied to data it hides the real incident shape, and not applied
 * to code it reports every locale barrel as a portfolio.
 */
const CODE_EXTENSIONS = new Set([
  "js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "json", "map", "css", "scss", "html", "vue", "svelte",
]);

export function isCodeLikeMember(path: string): boolean {
  const name = path.slice(path.lastIndexOf("/") + 1);
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return false;
  return CODE_EXTENSIONS.has(name.slice(dot + 1).toLowerCase());
}

function isMemberAccessRun(run: readonly LineEntry[]): boolean {
  const twoLabel = run.filter((entry) => entry.asset.split(".").length === 2);
  if (twoLabel.length !== run.length) return false;
  const firstLabels = new Set(twoLabel.map((entry) => entry.asset.slice(0, entry.asset.indexOf("."))));
  if (firstLabels.size !== 1) return false;
  const tlds = new Set(twoLabel.map((entry) => entry.asset.slice(entry.asset.lastIndexOf(".") + 1)));
  return tlds.size === twoLabel.length;
}

interface LineEntry {
  asset: string;
}

export interface InventoryCountOptions {
  /**
   * Read this text as code. Defaults to true, which is the conservative choice
   * for a bare call: it only ever suppresses a finding in the one shape that is
   * genuinely ambiguous.
   */
  codeLike?: boolean;
}

function collectLineInventories(
  text: string,
  hosts: Set<string>,
  emails: Set<string>,
  codeLike: boolean
): void {
  let run: LineEntry[] = [];
  const closeRun = (): void => {
    // The member-access guard is a CODE rule. In prose and tabular data there
    // is no property access to confuse, and a run of one brand across many TLDs
    // is precisely what a portfolio looks like — the real disclosed artifact's
    // exact shape. Applying the guard there took markdown, numbered and YAML
    // lists of the real shape to zero.
    if (run.length >= MIN_LITERAL_RUN && !(codeLike && isMemberAccessRun(run))) {
      for (const entry of run) record(entry.asset, hosts, emails);
    }
    run = [];
  };
  for (const rawLine of text.split(/\r?\n/)) {
    const stripped = rawLine
      .trim()
      // List markers: `- x`, `* x`, `+ x`, `> x`, `1. x`, `1) x`, and the
      // `- name: x` / `name: x` forms a YAML sequence uses. Ordering matters:
      // the numeric marker must go before the key prefix, or `1. x` loses only
      // its digit.
      .replace(/^[-*+#>\s]+/, "")
      .replace(/^\d+[.):,]?\s*/, "")
      .replace(/^[A-Za-z0-9_-]{1,40}\s*:\s*/, "")
      .trim();
    if (!stripped) {
      // A blank line separates sections; it does not end a list.
      continue;
    }
    const line = stripped.replace(/^[\['"`(]+|[\]'"`),;]+$/g, "").trim();
    const asset = line ? countableAsset(line) : null;
    if (asset) {
      run.push({ asset });
      continue;
    }
    closeRun();
  }
  closeRun();
}

/**
 * Shape 4: a delimited run inside ONE piece of text, with no quoting at all.
 *
 * This is what a base64 or hex blob decodes to — `a.com,b.net,c.org` on a
 * single line — and what `"…".split(",")` holds before it is split. Only
 * applied to decoded views and to text with no line structure, so an ordinary
 * source file's punctuation cannot be read as a list.
 */
function collectDelimitedRun(text: string, hosts: Set<string>, emails: Set<string>): void {
  const pieces = text.split(LITERAL_SEPARATORS).filter(Boolean);
  if (pieces.length < MIN_LITERAL_RUN) return;
  const assets = pieces.map(countableAsset);
  const countable = assets.filter((asset): asset is string => asset !== null);
  // The run must be what the text mostly IS, not something it merely contains.
  if (countable.length < MIN_LITERAL_RUN) return;
  if (countable.length * 2 < pieces.length) return;
  for (const asset of countable) record(asset, hosts, emails);
}

/** Shape 1: a literal whose content is mostly assets, or a run of sibling ones. */
function collectLiteralInventories(
  text: string,
  hosts: Set<string>,
  emails: Set<string>,
  depth = 0
): void {
  // A one-piece literal is a mention on its own and an array element next to
  // its siblings, so it cannot be judged until the run it belongs to ends.
  let run: string[] = [];
  let previousEnd = -1;
  const closeRun = (): void => {
    if (run.length >= MIN_LITERAL_RUN) for (const asset of run) record(asset, hosts, emails);
    run = [];
  };

  for (const match of text.matchAll(QUOTED_LITERAL_PATTERN)) {
    const start = match.index ?? 0;
    const sibling = previousEnd >= 0 && LITERAL_RUN_GLUE.test(text.slice(previousEnd, start));
    previousEnd = start + match[0].length;

    const raw = match[1] ?? match[2] ?? match[3] ?? "";
    const literal = raw.replace(/\\(["'`\\])/g, "$1").trim();
    // A literal that itself contains quotes is a nested document — a source
    // map's `sourcesContent`, an embedded JSON blob, a serialized config. Read
    // it as one, rather than as a bag of fragments.
    if (depth < 2 && /["'`]/.test(literal)) {
      collectLiteralInventories(literal, hosts, emails, depth + 1);
    }
    const pieces = literal
      ? literal
          .split(LITERAL_SEPARATORS)
          .map((piece) => piece.replace(/^[\[\]{}()"'`]+|[\[\]{}()"'`;,]+$/g, ""))
          .filter(Boolean)
      : [];
    const assets = pieces.map(countableAsset).filter((asset): asset is string => asset !== null);
    const [first] = assets;

    if (!sibling) closeRun();

    if (first === undefined) {
      // An EMPTY or very short literal is neutral: neither an entry nor a
      // break. Matching only `{3,}` was the earlier bug — a 2-character key
      // such as `"id"` went unmatched, its quote characters fell into the run
      // glue (which excludes `"`), and the run broke at every element. Now
      // every quoted token is matched, so short ones must be explicitly
      // ignored rather than treated as list terminators.
      if (literal.length < 3) continue;
      // An address is a different asset KIND, counted by its own collector, so
      // it must not end a hostname run: in a hostname->IP map the two alternate,
      // and treating each address as a breaker took the map to zero on every
      // kind at once.
      if (IPV4_LITERAL.test(literal)) continue;
      // A key or a description leaves the list intact; a value shaped like an
      // asset that did not count ends it.
      if (!LABEL_LITERAL.test(literal)) closeRun();
      continue;
    }
    if (pieces.length === 1) {
      run.push(first);
      continue;
    }
    // A literal that is MOSTLY assets is a list in its own right, judged on its
    // own ratio: it does not need neighbours and it does not join a run.
    closeRun();
    if (assets.length * 2 >= pieces.length) for (const asset of assets) record(asset, hosts, emails);
  }
  closeRun();
}

/** Shape 2: the same field position, an asset on several consecutive rows. */
function collectColumnInventories(text: string, hosts: Set<string>, emails: Set<string>): void {
  const runs = new Map<number, string[]>();
  const close = (column: number): void => {
    const values = runs.get(column);
    runs.delete(column);
    if (!values || values.length < MIN_COLUMN_RUN) return;
    for (const value of values) record(value, hosts, emails);
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
      const asset = countableAsset(value);
      if (asset === null) continue;
      if (populated < 2 && trimmed !== value) continue;
      carried.add(column);
      const run = runs.get(column);
      if (run) run.push(asset);
      else runs.set(column, [asset]);
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
export function inventoryCounts(
  text: string,
  options: InventoryCountOptions = {}
): Record<AssetInventoryKind, string[]> {
  const codeLike = options.codeLike ?? true;
  const emails = new Set<string>();
  const hosts = new Set<string>();

  // Every decoded view, not just the literal bytes. An inventory that survives
  // a build step arrives percent-, `\uXXXX`- or entity-escaped, or packed into
  // a base64 blob, and a one-character change (`\u002e` for `.`) walked past
  // literal-only matching. `tests/published-package-security.test.ts` in this
  // same repository already decodes these forms before hunting a hostname; a
  // guard weaker than a test already in the tree is not a guard.
  const views = decodedViews(text);
  for (const [index, view] of views.entries()) {
    collectLiteralInventories(view, hosts, emails);
    collectColumnInventories(view, hosts, emails);
    collectLineInventories(view, hosts, emails, codeLike && index === 0);
    // Index 0 is the member as written; anything after it came out of an
    // escape or a blob, and a decoded blob is data with no code structure left
    // to confuse a bare list with an expression.
    if (index > 0) collectDelimitedRun(view, hosts, emails);
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
  // IPv4 is read only from places a value can stand alone. Scanning raw text
  // matched SVG path data in a minified bundle — `hasna-tables-0.1.0.tgz`
  // failed on 26 "addresses" that were coordinate pairs — so the comment
  // claiming a dotted quad "cannot be confused with code" was measurably false.
  // Every Hasna app shipping a bundled dashboard with icons would have hit it.
  const ips = distinct(
    views.flatMap((view) => addressCandidates(view, codeLike)).filter((ip) => !isReservedIpv4(ip)),
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
  // ONE decompression for the whole archive, then the ordinary directory walk.
  let extracted: string;
  try {
    extracted = extractArchive(target);
  } catch (error) {
    yield { path: basename(target), reason: `archive could not be extracted: ${readError(error)}` };
    return;
  }
  try {
    // npm packs everything under a single `package/` root; strip it so member
    // paths match what the manifest and the tarball listing call them.
    const root = existsSync(join(extracted, "package")) ? join(extracted, "package") : extracted;
    yield* readDirectoryMembers(root, maxMemberBytes);
  } finally {
    rmSync(extracted, { recursive: true, force: true });
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

  // A threshold high enough to disable a detector is the gate being switched
  // off through its own front door: `--domain-threshold 1000000` returned exit
  // 0 on the real leaked artifact while `published_artifact_gate` still passed,
  // because the gate inspects the script graph and never the flags.
  const thresholds = clampThresholds({ ...DEFAULT_INVENTORY_THRESHOLDS, ...options.thresholds });
  const waived = new Set(options.waivedKinds ?? []);
  const ignore = new Set(options.ignorePaths ?? []);

  const findings: AssetInventoryFinding[] = [];
  const waivedFindings: AssetInventoryFinding[] = [];
  const aggregateFindings: AssetInventoryFinding[] = [];
  const unreadable: UnreadableMember[] = [];
  // Union across members: ten files of eighteen beats any per-file threshold,
  // and the clause is about what the ARTIFACT discloses, not what one file does.
  const union: Record<AssetInventoryKind, Set<string>> = {
    domain: new Set(),
    host: new Set(),
    ip: new Set(),
    email: new Set(),
  };
  let seen = 0;
  let scanned = 0;
  let excludedByCaller = 0;

  for (const member of members) {
    seen += 1;
    if (ignore.has(member.path)) {
      excludedByCaller += 1;
      continue;
    }
    if ("reason" in member) {
      unreadable.push({ path: member.path, reason: member.reason });
      continue;
    }
    // Every member is decoded and scanned. Skipping "binary" members meant one
    // NUL byte in a leading comment removed a file from the scan and still
    // produced a clean verdict — a one-character evasion of the whole guard.
    // `latin1` never fails and never loses a byte, so a genuinely binary member
    // is decoded to noise instead of excluded; noise is harmless here, because a
    // finding needs many distinct names under real TLDs.
    scanned += 1;
    const counts = inventoryCounts(decodeMember(member.bytes), {
      codeLike: isCodeLikeMember(member.path),
    });
    for (const kind of ASSET_INVENTORY_KINDS) {
      const entries = counts[kind];
      for (const entry of entries) union[kind].add(entry);
      const threshold = thresholds[kind];
      if (entries.length < threshold) continue;
      const finding: AssetInventoryFinding = {
        path: member.path,
        kind,
        count: entries.length,
        threshold,
        sample: entries.slice(0, 3).map((entry) => redact(entry, kind)),
      };
      (waived.has(kind) ? waivedFindings : findings).push(finding);
    }
  }

  for (const kind of ASSET_INVENTORY_KINDS) {
    const entries = [...union[kind]].sort();
    const threshold = thresholds[kind];
    if (entries.length < threshold) continue;
    // Already reported against a single member; do not double-report.
    if (findings.some((finding) => finding.kind === kind)) continue;
    if (waivedFindings.some((finding) => finding.kind === kind)) continue;
    const finding: AssetInventoryFinding = {
      path: "<artifact>",
      kind,
      count: entries.length,
      threshold,
      sample: entries.slice(0, 3).map((entry) => redact(entry, kind)),
    };
    aggregateFindings.push(finding);
    (waived.has(kind) ? waivedFindings : findings).push(finding);
  }

  // `scanned`, not `seen`. Members that were merely ENUMERATED prove nothing:
  // `--ignore-paths '*'` produced `ok: true, membersScanned: 0` against a
  // 35-member artifact, which is the vacuous pass this check exists to stop.
  if (scanned === 0) {
    throw new Error(
      `Artifact scan read zero members from ${basename(target)} (${seen} seen, ${excludedByCaller} excluded). Refusing to report a clean verdict on nothing.`,
    );
  }

  return {
    ok: findings.length === 0 && unreadable.length === 0,
    target,
    scanMode,
    membersScanned: scanned,
    membersSkipped: excludedByCaller,
    findings,
    aggregateFindings,
    waived: waivedFindings,
    unreadable,
  };
}

/** One-line-per-finding summary for CLI output and CI logs. */
export function formatArtifactScanReport(report: ArtifactScanReport): string {
  const lines = [
    `${report.ok ? "pass" : "FAIL"} artifact-scan ${basename(report.target)} (${report.scanMode}, ${report.membersScanned} members scanned, ${report.membersSkipped} excluded, ${report.unreadable.length} unreadable)`,
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
