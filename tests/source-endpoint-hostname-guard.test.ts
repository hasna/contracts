// Every endpoint literal in this repository must name a place that does not exist.
//
// WHAT THIS GUARDS, AND WHY IT IS NOT ONE OF THE TWO GUARDS ALREADY IN THE TREE.
// Three internal hostnames sat in three client test fixtures across fourteen
// commits reachable from `main`. Two guards existed and neither closed the class:
//
//   * `tests/published-package-security.test.ts` scans every tracked file for an
//     ENUMERATED apex. It caught these three only once that apex was added to it,
//     which is remediation, not prevention: a hostname under any other apex still
//     passes. Enumerating more apexes is not the fix either — the enumeration
//     would itself be the asset inventory it exists to protect.
//   * `src/artifact-scan.ts` is a BULK guard: it reports an inventory (20 domains,
//     25 hosts) and deliberately treats a handful as a mention. Measured against
//     the real pre-fix trees of those three files, `inventoryCounts` returned
//     0 domains / 0 hosts for two of them and 1 host for the third, against 21
//     actual occurrences. It cannot see this shape and was never meant to.
//
// So the rule here is neither an apex list nor a count. It is a SHAPE at a
// threshold of ONE. In every tracked file, three things are read — a URL
// authority, a host followed by a path with no scheme in front of it, and an email
// address — and each must resolve to a name the specifications reserve as not-real
// (RFC 2606 `.example`, `.invalid`, `.test`, `example.com|net|org`; RFC 6761
// `.localhost`; RFC 5737 and RFC 3849 documentation addresses; loopback,
// link-local, unique-local, CGNAT and private ranges) or must appear EXACTLY — as
// a whole hostname, not as a registrable domain — in the allowlist below. Nothing
// in the rule names a Hasna domain, so this file adds no protected string to the
// repository, which the apex-enumeration approach cannot say of itself. For the
// same reason every positive control here assembles its fixture host from
// fragments at run time: a guard whose own source carries the shapes it hunts
// reports itself, and the obvious repair is to weaken the guard.
//
// MEASURED AGAINST THE INCIDENT, which is the only test of a rule like this that
// means anything. Restoring the three pre-fix fixture trees into a working tree
// takes this guard from 7 passing to 2 failing, with 18 findings on all three
// files (2 + 4 + 12 lines, 21 occurrences) resolving to ONE registrable domain.
// The first two rules were each needed for that: the authority rule alone reaches
// 16 findings and misses `src/client/conformance.live.test.ts` entirely, because
// its two occurrences are a schemeless `<app>.<apex>/v1` in a comment and a
// template literal whose apex is a literal behind an interpolated first label.
//
// A VIOLATION IS REPORTED AS A LOCATION, NEVER AS A VALUE. `file:line` plus the
// salted digest `src/artifact-scan.ts` already uses for its own findings. This
// repository is public and so are its CI logs: a guard whose failure output
// prints the hostname it just caught publishes the thing it was protecting, in
// the one place everybody looks. The location is enough to fix it locally.
//
// FAIL CLOSED, IN FIVE PLACES, because a scanner that reports clean for the wrong
// reason is worse than no scanner:
//   1. `git ls-files` exiting non-zero throws; it is not an empty scope.
//   2. The resolved scope is asserted to contain sentinel files, so a scope that
//      silently resolves to nothing cannot pass.
//   3. An unreadable member throws; it is never skipped.
//   4. An authority that looks like an address but cannot be parsed as one is
//      reported rather than left unjudged.
//   5. The whole tree is re-scanned with an EMPTY allowlist, which must produce
//      findings on exactly the allowlisted registrable domains, and the normal
//      scan must additionally WITNESS every allowlist entry at host granularity.
//      That pair is what makes the green result mean something: every run proves
//      the scan is still capable of firing on this tree, and that no allowlist
//      entry has gone dead and quietly become a blanket permission — including an
//      entry that shares an apex with a live sibling, which the registrable-domain
//      comparison alone cannot tell apart.
//
// RESIDUALS, STATED. A hostname assembled at run time from fragments is invisible
// here, as it is to the apex scan — which is the point of writing internal names
// that way, and this repository does so deliberately in `tests/conformance.test.ts`
// and `tests/published-package-security.test.ts`. A BARE dotted name in a string
// is not judged either: in this repository `src/artifact-scan.ts` and its test
// must carry dozens of fabricated `brand.com`-shaped strings to exercise the bulk
// detector, so a bare-name rule here would need an allowlist longer than the rule.
// An address in integer form (`2130706433`) carries no dot and is not judged, and
// a single-label authority names no registrable domain. Placeholder collapse is
// applied to the two host rules but not to the email rule, so an address whose
// LOCAL part is interpolated over a literal apex is not read — see `scanText`.
// Two more, measured by an adversarial pass over this guard rather than assumed:
// the schemeless rule requires the path's first character to be alphanumeric, so
// a schemeless host followed by a path that opens on punctuation is not read
// (the same endpoint written with a scheme still is, by the authority rule); and
// the only decoding applied here is `decodeEscapes`, so unlike the bulk guard's
// `decodedViews` this one does not decode a base64 or hex blob, and an endpoint
// packed into one is invisible. Neither shape occurs in this tree; both are
// recorded as decisions rather than left to be rediscovered.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import {
  decodeEscapes,
  isReservedHostname,
  isReservedIpv4,
  redact,
  registrableDomain,
} from "../src/artifact-scan.js";
import { PROGRAMMING_COLLISION_TLDS, isRecognizedTld } from "../src/tlds.js";

const root = join(import.meta.dir, "..");

/**
 * WHOLE HOSTNAMES a real endpoint literal in this repository may name.
 *
 * Every entry is either public infrastructure this project genuinely talks about
 * or a synthetic name a sibling guard's own controls require under a real TLD.
 * None is a Hasna asset — checked against the owned-domain registry, not by
 * eye — which is why this list can live in a public repository while an apex
 * denylist cannot.
 *
 * EXACT HOSTS, NOT REGISTRABLE DOMAINS, and the difference is the whole point of
 * this list. An entry at registrable-domain granularity permits every name under
 * it, so ONE entry for a hyperscaler's domain silently permits every account-,
 * region- and instance-bearing hostname that provider generates on our behalf —
 * which is the exact shape of a self-hosted deployment's own endpoints, and in
 * one common form embeds the account identifier itself. An adversarial pass
 * measured three such literals scoring zero findings under the registrable form.
 * Matching the whole host costs nothing here: the entries below ARE, one for one,
 * the complete set of hosts this tree names, so the registrable form was buying
 * breadth nothing in the repository ever used.
 *
 * ADDING AN ENTRY IS THE POINT. A new real hostname cannot enter this repository
 * without a line here, and that line is what a reviewer sees in the diff. A new
 * SUB-host of something already listed needs its own line too. The
 * empty-allowlist control below fails if an entry stops being used, so the list
 * cannot rot into a wildcard.
 */
const ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  // Public infrastructure this repository actually references.
  "www.apache.org", // the Apache-2.0 licence text and the FSL notice
  "github.com", // this repository, its issues, and example manifests
  "gitlab.com", // the fixture proving a repo URL need not be GitHub
  "data.iana.org", // provenance of the TLD snapshot in `src/tlds.ts`
  "json-schema.org", // the JSON Schema meta-schema every `$schema` declares
  "registry.npmjs.org", // the registry `publishConfig` publishes to
  // The one entry whose apex would have been the widest hole, which is why it is
  // pinned to the single host: the public CA bundle a generated app downloads to
  // verify a managed database's TLS certificate.
  "truststore.pki.rds.amazonaws.com",

  // Synthetic names the asset-inventory guard's own controls need under a REAL
  // TLD: a reserved name is not countable, so those controls could not tell the
  // rule under test from the plumbing. Fabricated, owned by nobody here.
  "svc-1.a.com",
  "svc-1.a-brand.com",
  "a-brand.com", // the mail-domain half of the same fixture family
  "agents.wiki",
  "config.wiki",
  "records.wiki",
  "schema.wiki",
  "session.wiki",
  "tenant.wiki",
]);

/**
 * The registrable domains those hosts sit under — what a FINDING names.
 *
 * A finding is reported as a registrable domain, never a full host, so that two
 * sub-hosts of one leaked apex read as one disclosure. This set is therefore
 * SMALLER than `ALLOWED_HOSTS` wherever two entries share an apex, which is why
 * the anti-rot control below witnesses entries at HOST granularity as well:
 * comparing only these would let a dead entry hide behind a live sibling.
 * Derived, never written down twice — a second hand-maintained list is a second
 * thing to forget.
 */
const ALLOWED_ASSETS: ReadonlySet<string> = new Set(
  [...ALLOWED_HOSTS].map((host) => registrableDomain(host)),
);

/**
 * Files whose presence proves the scope actually resolved.
 *
 * THIS FILE IS ONE OF THEM, and the reason is a measured mistake. While it was
 * still untracked, `git ls-files` did not list it, so the guard was not scanning
 * its own source and the claim that it cannot trip itself was untested. The first
 * run after committing reported this file, on a doc comment. A guard whose scope
 * silently excludes the newest file in the tree is a guard with a blind spot at
 * exactly the moment one matters.
 */
const SCOPE_SENTINELS = [
  "package.json",
  "src/artifact-scan.ts",
  "src/client/transport.test.ts",
  relative(root, import.meta.path),
];

/**
 * `scheme://authority`, or a scheme-relative `//authority`.
 *
 * Both forms, for the same reason `src/artifact-scan.ts` accepts both: an
 * endpoint hidden in a comment is still an endpoint. The authority ends at the
 * first delimiter a URL, or the code around it, can put after it.
 */
const URL_AUTHORITY = /(?:\b[a-z][a-z0-9+.-]*:)?\/\/(\[[^\]\s]+\]|[^\s"'`\\/?#<>()[\]{},;]+)/gi;
/**
 * A host and a path with NO scheme in front of them.
 *
 * Measured, not hypothesised: of the twenty-one occurrences the real incident put
 * into these three fixtures, the authority rule above catches nineteen. The other
 * two are in `src/client/conformance.live.test.ts`, and one of them is a prose
 * comment naming the endpoint as `<app>.<apex>/v1` with no scheme at all — the
 * line begins `//`, so there is no `//authority` for the rule above to find. This
 * shape adds no allowlist entry: run over the whole tree it produces nine hits,
 * eight of which are already allowlisted.
 *
 * The lookbehind is what keeps it off file paths and off the middle of tokens: it
 * must not start inside one, so `docs/architecture/factory-v1-contract-spec.md` is
 * a path and not a host under `.md`. Percent is in that set because without it the
 * tail of a percent-escape begins a name: a label whose fourth character had been
 * percent-escaped was read as a registrable domain invented out of the two hex
 * digits and whatever followed them. No example is written out here, deliberately —
 * the first draft of this comment spelled one, and the DECODED view of this very
 * file then reported it. See the header: the shapes this guard hunts cannot appear
 * in its own source, and that includes prose about them.
 */
const SCHEMELESS_HOST_PATH =
  /(?<![.\w/@%+~-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?::\d{1,5})?\/[a-z0-9]/gi;
/**
 * The placeholder spellings a host is assembled around.
 *
 * THE SHAPE THIS EXISTS FOR, from the real incident: the second of the two
 * occurrences the authority rule missed is a template literal whose FIRST label
 * is interpolated and whose apex is a literal — `${APP}.<apex>`. The apex is
 * fully written down, and a rule that gives up at `${` never sees it. Collapsing
 * every placeholder to one neutral label first turns that into `x.<apex>`, which
 * is an ordinary hostname the normal rules judge. It also stays quiet on the
 * inverse shape, `api.${domain}`, which collapses to `api.x` and names nothing.
 */
const PLACEHOLDER = /\$\{[^}\n]*\}|\{\{[^}\n]*\}\}|<[^<>\s]*>|\{[a-z0-9_]+\}|%[sdv]/gi;
/** An address as anyone writes it, and as `isReservedIpv4` expects it. */
const IPV4_LITERAL = /^(?:(?:0|[1-9]\d{0,2})\.){3}(?:0|[1-9]\d{0,2})$/;
/** A hostname's SHAPE. The lists it is judged against are imported, not copied. */
const HOSTNAME_LITERAL = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
const EMAIL_LITERAL = /[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}/gi;

/**
 * Is this label a delegated TLD — the FULL IANA namespace, not the subset the
 * bulk guard counts?
 *
 * `src/tlds.ts` withholds seventeen TLDs that collide with property names
 * (`.map`, `.tools`, `.email`, `.md`, …) because a bare `config.map` in a bundle
 * is member access, not a domain. In a URL authority that ambiguity does not
 * exist: an endpoint under `.tools` is an endpoint whatever else `.tools` reads
 * as. Judging authorities against the reduced set would leave seventeen TLDs
 * through, so the two exported halves are recombined here rather than a third
 * list being written.
 */
function isDelegatedTld(label: string): boolean {
  const lower = label.toLowerCase();
  return isRecognizedTld(lower) || PROGRAMMING_COLLISION_TLDS.has(lower);
}

/** The eight 16-bit groups of an IPv6 address, or null if it is not one. */
function ipv6Groups(value: string): number[] | null {
  let text = value.toLowerCase();
  const embedded = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
  if (embedded) {
    const octets = embedded[1]!.split(".").map(Number);
    if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
    const [a, b, c, d] = octets as [number, number, number, number];
    text = `${text.slice(0, embedded.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (head.length + tail.length > (halves.length === 1 ? 8 : 7)) return null;
  const groups =
    halves.length === 1
      ? head
      : [...head, ...new Array(8 - head.length - tail.length).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  const numbers = groups.map((group) =>
    /^[0-9a-f]{1,4}$/.test(group) ? Number.parseInt(group, 16) : Number.NaN,
  );
  return numbers.some(Number.isNaN) ? null : numbers;
}

/**
 * Is this IPv6 address one the specifications say is not a real place?
 *
 * An address this cannot PARSE is reported as NOT reserved, so an authority that
 * looks like an address but is not a valid one fails the guard rather than
 * slipping past it unjudged.
 */
function isReservedIpv6(value: string): boolean {
  const groups = ipv6Groups(value);
  if (groups === null) return false;
  const [first, second, , , , sixth, seventh, eighth] = groups as [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  if (groups.every((group) => group === 0)) return true; // ::            unspecified
  if (groups.slice(0, 7).every((group) => group === 0) && eighth === 1) return true; // ::1 loopback
  if (first === 0x2001 && second === 0x0db8) return true; // 2001:db8::/32 RFC 3849 documentation
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10    link-local
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7     unique-local
  if ((first & 0xff00) === 0xff00) return true; // ff00::/8     multicast
  // IPv4-mapped and IPv4-compatible forms carry an IPv4 address; judge that.
  if (groups.slice(0, 5).every((group) => group === 0) && (sixth === 0xffff || sixth === 0)) {
    return isReservedIpv4([seventh >> 8, seventh & 0xff, eighth >> 8, eighth & 0xff].join("."));
  }
  return false;
}

/**
 * The host an authority names, with userinfo, port and the FQDN root dot removed.
 *
 * THE PORT IS CUT AT THE COLON, not by matching `:\d{1,5}$`. A port is written
 * `:${server.port}` far more often than `:8443` in this repository, and an
 * interpolated or over-long one left the colon attached — which then read as an
 * IPv6 address, failed to parse, and reported eight loopback URLs as real
 * endpoints. Two or more colons DO mean an IPv6 address written without the
 * brackets a URL requires; that is judged rather than truncated, so a leak
 * spelled that way is still caught.
 */
function hostOfAuthority(authority: string): string {
  let text = authority.toLowerCase();
  const userinfo = text.lastIndexOf("@");
  if (userinfo >= 0) text = text.slice(userinfo + 1);
  if (text.startsWith("[")) {
    const close = text.indexOf("]");
    return close > 0 ? text.slice(1, close) : text.slice(1);
  }
  const colon = text.indexOf(":");
  if (colon >= 0 && text.indexOf(":", colon + 1) === -1) text = text.slice(0, colon);
  return text.replace(/\.$/, "");
}

type FindingKind = "host" | "ip" | "email";

interface Finding {
  path: string;
  line: number;
  kind: FindingKind;
  /** The registrable domain or address. Compared, digested — never printed. */
  asset: string;
}

/** A finding as it may be shown: where it is and what kind — never what it says. */
function describeFinding(finding: Finding): string {
  return `${finding.path}:${finding.line} ${redact(finding.asset, finding.kind)}`;
}

/**
 * The registrable domain a name resolves to, or null if it names nowhere real.
 *
 * Null covers all four ways a token can fail to be a place: it is not shaped like
 * a hostname, the specifications reserve it, its last label is not a delegated
 * TLD, or the WHOLE host is allowed here. The allowlist is consulted with the
 * full host and never with the registrable domain — see `ALLOWED_HOSTS` for why
 * that distinction is the difference between a list and a wildcard — while what
 * is REPORTED stays the registrable domain.
 */
function judgeHostname(
  host: string,
  allowed: ReadonlySet<string>,
  witnessed?: Set<string>,
): string | null {
  if (!HOSTNAME_LITERAL.test(host)) return null;
  if (isReservedHostname(host)) return null;
  if (!isDelegatedTld(host.slice(host.lastIndexOf(".") + 1))) return null;
  if (allowed.has(host)) {
    // Which entry did the work. The anti-rot control needs this at host
    // granularity; a registrable-domain comparison cannot distinguish an entry
    // that is still in use from a sibling under the same apex that is not.
    witnessed?.add(host);
    return null;
  }
  return registrableDomain(host);
}

/**
 * Scan one member's text for real endpoints, judged against `allowed`.
 *
 * FOUR VIEWS OF EVERY LINE, each earning its place against the real incident: as
 * written; escape-decoded, because a single `.` for `.` walked past
 * literal-only matching once already (the reason `decodeEscapes` exists in
 * `src/artifact-scan.ts`); and both of those with placeholders collapsed, which is
 * the only way the `${APP}.<apex>` occurrence is visible at all. A finding is
 * reported on the line that carried it, whichever view saw it.
 */
function scanText(
  path: string,
  text: string,
  allowed: ReadonlySet<string>,
  witnessed?: Set<string>,
): Finding[] {
  const findings: Finding[] = [];
  text.split("\n").forEach((rawLine, index) => {
    const line = index + 1;
    const decoded = decodeEscapes(rawLine);
    const written = [...new Set([rawLine, decoded])];
    // Placeholder collapse serves the HOSTNAME rules only. In a host it reveals an
    // apex that was fully written down (`${APP}.<apex>`); in an email's local part
    // it invents an address nobody wrote (`person${i}@…` becomes `personx@…`),
    // which turned three of the bulk guard's own generated fixtures into findings
    // and would have bought that noise with three allowlist entries.
    const views = [...new Set([...written, ...written.map((view) => view.replace(PLACEHOLDER, "x"))])];
    // One asset reported once per line, whatever spelling or view carried it: a
    // URL with userinfo is an authority AND an email address, and the escaped and
    // as-written views of the same line name the same place.
    const reported = new Set<string>();
    const report = (kind: FindingKind, asset: string): void => {
      if (reported.has(asset)) return;
      reported.add(asset);
      findings.push({ path, line, kind, asset });
    };
    for (const view of views) {
      for (const match of view.matchAll(URL_AUTHORITY)) {
        const host = hostOfAuthority(match[1]!);
        if (!host) continue;
        if (IPV4_LITERAL.test(host)) {
          if (!isReservedIpv4(host)) report("ip", host);
          continue;
        }
        if (host.includes(":")) {
          if (!isReservedIpv6(host)) report("ip", host);
          continue;
        }
        const registrable = judgeHostname(host, allowed, witnessed);
        if (registrable) report("host", registrable);
      }
      for (const match of view.matchAll(SCHEMELESS_HOST_PATH)) {
        const registrable = judgeHostname(match[1]!.toLowerCase(), allowed, witnessed);
        if (registrable) report("host", registrable);
      }
    }
    for (const view of written) {
      for (const match of view.matchAll(EMAIL_LITERAL)) {
        const address = match[0].toLowerCase();
        const registrable = judgeHostname(
          address.slice(address.indexOf("@") + 1),
          allowed,
          witnessed,
        );
        if (registrable) report("email", registrable);
      }
    }
  });
  return findings;
}

/**
 * Every tracked path. A `git ls-files` that fails throws: an empty scope is the
 * one failure a scanner must never be able to mistake for a clean result.
 */
function trackedFiles(): string[] {
  const result = Bun.spawnSync(["git", "-c", "color.ui=never", "ls-files", "-z"], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(
      `git ls-files exited ${result.exitCode}: ${new TextDecoder().decode(result.stderr)}`,
    );
  }
  const paths = new TextDecoder().decode(result.stdout).split("\0").filter(Boolean);
  if (paths.length === 0) throw new Error("git ls-files reported no tracked files; scope is unusable");
  return paths;
}

/** UTF-8 where the bytes are valid, latin1 otherwise — lossless either way. */
function readMember(path: string): string {
  const bytes = readFileSync(join(root, path));
  const utf8 = bytes.toString("utf8");
  return utf8.includes("�") ? bytes.toString("latin1") : utf8;
}

function scanTrackedTree(allowed: ReadonlySet<string>): {
  findings: Finding[];
  scanned: string[];
  /** Which allowlist entries actually suppressed something on this tree. */
  witnessed: Set<string>;
} {
  const scanned = trackedFiles();
  const witnessed = new Set<string>();
  const findings = scanned.flatMap((path) =>
    scanText(path, readMember(path), allowed, witnessed),
  );
  return { findings, scanned, witnessed };
}

/**
 * Fixture assets, assembled from fragments so this file carries none of the
 * shapes it hunts. `hasna/swarm`'s `scripts/no-cloud-artifact-scan.mjs` builds
 * its forbidden list the same way, for the same reason.
 */
const PROBE = {
  /** A fabricated apex under a real, countable TLD. */
  apex: ["fixture-probe", "wiki"].join("."),
  /** The same, under one of the TLDs the bulk guard withholds. */
  collisionApex: ["fixture-probe", "tools"].join("."),
  /** One octet outside RFC 5737 TEST-NET-3, so it is a real address. */
  address4: ["203", "0", "114", "7"].join("."),
  /** One hex digit outside the RFC 3849 documentation range. */
  address6: ["2001", "db9", "", "1"].join(":"),
  /** Address-shaped but not a valid address, so it must be reported unjudged. */
  malformedAddress6: ["2001", "db8", "", "", "1"].join(":"),
  /** A reserved counterpart for each, to prove the rule and not the plumbing. */
  reservedApex: ["fixture-probe", "example"].join("."),
  reservedAddress4: ["203", "0", "113", "10"].join("."),
  reservedAddress6: ["2001", "db8", "", "1"].join(":"),
};

/**
 * A host under a registrable domain that IS allowlisted, but which is not itself
 * an allowlisted host.
 *
 * Derived from the list at run time rather than written down, for the same reason
 * `PROBE` is assembled from fragments: spelling it out would put a reportable
 * name into this file, and the guard scans this file. Deriving it also means the
 * control keeps testing the real list instead of a copy of it that can drift.
 */
function siblingOfAllowedHost(): string {
  const [first] = [...ALLOWED_HOSTS];
  return ["not-a-real-sub", registrableDomain(first!)].join(".");
}

describe("source endpoint hostname guard", () => {
  test("the resolved scope is the tracked tree, not an empty set", () => {
    const scanned = trackedFiles();
    for (const sentinel of SCOPE_SENTINELS) expect(scanned).toContain(sentinel);
    expect(scanned.length).toBeGreaterThan(SCOPE_SENTINELS.length);
  });

  test("the allowlist cannot silently widen", () => {
    // A bare TLD (`"com"`) would permit an entire namespace and an upper-case or
    // port-bearing entry would never match, because the extractor hands over a
    // lower-cased, port-stripped host. Every entry must be a whole hostname,
    // under a delegated TLD, and not a name the specifications already reserve.
    for (const entry of ALLOWED_HOSTS) {
      expect(HOSTNAME_LITERAL.test(entry), `${entry} is not hostname-shaped`).toBe(true);
      expect(entry, `${entry} is not the lower-cased form the extractor compares`).toBe(
        entry.toLowerCase(),
      );
      expect(isReservedHostname(entry), `${entry} is spec-reserved and needs no entry`).toBe(false);
      expect(
        isDelegatedTld(entry.slice(entry.lastIndexOf(".") + 1)),
        `${entry} has no delegated TLD`,
      ).toBe(true);
      expect(
        registrableDomain(entry).split(".").length,
        `${entry} resolves to a bare TLD`,
      ).toBeGreaterThanOrEqual(2);
    }
  });

  test("the extractor fires on every kind it claims to catch", () => {
    const fires: Array<[string, string]> = [
      ["a plain endpoint", `const url = "https://console.${PROBE.apex}/v1";`],
      ["an endpoint in a comment", `// shape reference: //console.${PROBE.apex}/v1`],
      ["userinfo and a port", `const url = "https://operator@console.${PROBE.apex}:8443/v1?x=1";`],
      ["a deeper name under the same apex", `const url = "https://a.b.console.${PROBE.apex}/v1";`],
      ["a TLD the bulk guard withholds", `const url = "https://console.${PROBE.collisionApex}/v1";`],
      ["an address outside the documentation ranges", `const url = "https://${PROBE.address4}/v1";`],
      ["an IPv6 address outside the documentation range", `const url = "https://[${PROBE.address6}]/v1";`],
      ["an authority that only looks like an address", `const url = "https://[${PROBE.malformedAddress6}]/v1";`],
      ["an email address", `const contact = "ops@${PROBE.apex}";`],
      // The two shapes the real incident used that a scheme-only rule missed.
      ["a schemeless host and path in prose", `// endpoint: knowledge.${PROBE.apex}/v1 over the wire`],
      ["a literal apex with an interpolated label", `const HOST = \`https://\${APP}.${PROBE.apex}\`;`],
      ["a literal apex behind an angled placeholder", `const url = "https://<app>.${PROBE.apex}/v1";`],
      [
        "an endpoint hidden in an escape",
        `const url = "https://console.${PROBE.apex.replace("b", "%62")}/v1";`,
      ],
      // The regression control for the allowlist's granularity. Under a
      // registrable-domain allowlist this scored zero, which is how an
      // account-, region- or instance-bearing name generated under a listed
      // provider domain would have entered unreported.
      [
        "a new sub-host of an already-allowlisted host's domain",
        `const url = "https://${siblingOfAllowedHost()}/v1";`,
      ],
    ];
    for (const [label, source] of fires) {
      expect(scanText("fixture.ts", source, ALLOWED_HOSTS).length, label).toBe(1);
    }
  });

  test("the extractor does not fire on names the specifications reserve", () => {
    const quiet: Array<[string, string]> = [
      ["a documentation apex", `const url = "https://todos.${PROBE.reservedApex}/v1";`],
      ["RFC 2606 example.com", `const url = "https://api.example.com/v1";`],
      ["the .test TLD", `const url = "https://idp.example.test/v1";`],
      ["the .invalid TLD", `const url = "https://shared.invalid/v1";`],
      ["localhost", `const url = "http://localhost:8080/v1";`],
      ["loopback v4", `const url = "http://127.0.0.1:43123/v1";`],
      ["loopback v4 with an interpolated port", "const url = `http://127.0.0.1:${server.port}/v1`;"],
      ["a port with leading zeros", `const url = "https://${PROBE.reservedAddress4}:000443/v1";`],
      ["a connection string with userinfo", "// KIT_URL=postgres://user:<pw>@localhost:5432/db"],
      ["TEST-NET-3", `const url = "https://${PROBE.reservedAddress4}:8443/v1";`],
      ["TEST-NET-1", `const url = "https://192.0.2.1/v1";`],
      ["TEST-NET-2", `const url = "https://198.51.100.7/v1";`],
      ["a private range", `const url = "https://10.1.2.3/v1";`],
      ["loopback v6", `const url = "http://[::1]:8080/v1";`],
      ["the RFC 3849 range", `const url = "https://[${PROBE.reservedAddress6}]/v1";`],
      ["link-local v6", `const url = "https://[fe80::1]/v1";`],
      ["unique-local v6", `const url = "https://[fd00::1]/v1";`],
      ["a documentation email", `const contact = "ops@${PROBE.reservedApex}";`],
      ["a host built at run time", "const url = `https://${host}/v1`;"],
      ["an interpolated apex", "const url = `https://api.${domain}/v1`;"],
      ["an apex from an environment placeholder", `const url = "https://<app>.<FLEET_DOMAIN>/v1";`],
      ["a single-label authority", `const url = "https://svc/v1";`],
      ["member access", `const path = config.host.replace("a", "b");`],
      ["a source path", `const file = "src/client/transport.test.ts";`],
      ["a nested source path", `const doc = "docs/architecture/factory-v1-contract-spec.md";`],
      ["a scoped module path", `import { readFile } from "node:fs/promises";`],
      ["a versioned module path", `import * as z from "zod/v4";`],
      ["a config filename", `const spec = "tsconfig.build.json";`],
      // The allowlist still permits what it lists — the whole host, exactly.
      ["an allowlisted host", `const url = "https://${[...ALLOWED_HOSTS][0]}/v1";`],
      // The stated residual, asserted so it stays a decision rather than a bug.
      ["a bare dotted name", `const host = "console.${PROBE.apex}";`],
    ];
    for (const [label, source] of quiet) {
      expect(scanText("fixture.ts", source, ALLOWED_HOSTS).length, label).toBe(0);
    }
  });

  test("an unreadable member is an error, not a skipped file", () => {
    expect(() => readMember("this-path-is-not-in-the-tree.ts")).toThrow();
    expect(() => readMember("src")).toThrow();
  });

  test("no tracked file names a real endpoint outside the allowlist", () => {
    const { findings, scanned } = scanTrackedTree(ALLOWED_HOSTS);
    expect(scanned.length).toBeGreaterThan(SCOPE_SENTINELS.length);
    // Locations and kinds only. See the header: this repository's CI logs are public.
    expect(findings.map(describeFinding)).toEqual([]);
  }, 30_000);

  test("with an empty allowlist the same scan still fires, and every entry is still in use", () => {
    // THE CONTROL THAT MAKES THE GREEN RESULT MEAN SOMETHING. A guard that has
    // never produced a hit on the real tree cannot tell "nothing to find" from
    // "the extractor silently stopped working". With nothing allowed, this tree
    // must yield findings — and the distinct assets behind them must be exactly
    // the allowlist, so no entry can go dead and quietly become a wildcard.
    // Compared against `ALLOWED_ASSETS`, because a finding names a registrable
    // domain while an allowlist entry is a whole host.
    const { findings } = scanTrackedTree(new Set());
    expect(findings.length).toBeGreaterThan(0);
    const found = new Set(findings.map((finding) => finding.asset));
    // Allowlist entries are public by construction, so naming an unused one is safe.
    const unused = [...ALLOWED_ASSETS].filter((entry) => !found.has(entry)).sort();
    expect(unused).toEqual([]);
    // The other direction without printing a value: anything found here that is
    // NOT on the allowlist has already failed the test above.
    expect(found.size).toBe(ALLOWED_ASSETS.size);

    // AND EVERY ENTRY AT HOST GRANULARITY, which the comparison above cannot do
    // on its own: two entries may share one registrable domain, and then a dead
    // entry hides behind its live sibling. The normal scan records which entry
    // actually suppressed something, so an entry nothing matched is reported by
    // name — the diff a reviewer needs, and safe to print.
    const { witnessed } = scanTrackedTree(ALLOWED_HOSTS);
    expect([...ALLOWED_HOSTS].filter((host) => !witnessed.has(host)).sort()).toEqual([]);
    expect(witnessed.size).toBe(ALLOWED_HOSTS.size);
  }, 30_000);
});
