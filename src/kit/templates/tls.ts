// TLS resolution for the vendored Hasna storage kit.
//
// ONE correct TLS approach for the whole fleet. This replaces the three drifted
// variants that previously existed across repos, all of which hardcoded
// `{ rejectUnauthorized: false }` for any TLS connection — that silently
// disables certificate verification even when the caller asked for
// `verify-full`, which defeats the point of TLS against a cloud database.
//
// THE MODE TABLE — and as of this change it describes THE SOCKET, not just this
// function's return value:
//   - disable (explicit)        -> no TLS, stated explicitly (ssl: false), so an
//                                  ambient PGSSLMODE cannot override it.
//   - (no ssl param)            -> no explicit TLS policy (ssl: undefined); pg's
//                                  own PGSSLMODE fallback applies, as libpq
//                                  specifies. These two rows used to be one, and
//                                  collapsing them is what let PGSSLMODE
//                                  override an explicit operator disable.
//   - prefer / require          -> encrypt AND verify the server certificate
//                                  (rejectUnauthorized: true), pinning a CA
//                                  bundle when one is available.
//   - verify-ca / verify-full   -> encrypt AND verify against a CA bundle
//                                  (rejectUnauthorized: true, ca: <bundle>).
//                                  A CA bundle is REQUIRED; we throw if none is
//                                  available so verification can never silently
//                                  downgrade.
//   - sslmode present but EMPTY -> THROWS, exactly as any other unrecognised
//     (`?sslmode=`, `?sslmode=%20`)  value does, and exactly as libpq does. It is
//                                  NOT the "no ssl param" row above: the
//                                  parameter is present, so the DSN made a
//                                  statement, and an empty statement is not a
//                                  request for the default.
//
// `prefer` and `require` verify because THAT IS WHAT THEY HAVE ALWAYS DONE AT
// THE SOCKET (see the measurements below). This file used to claim they did not
// verify; the claim was wrong, and correcting the claim rather than the code is
// deliberate — see "WHY require VERIFIES" at the bottom.
//
// The CA bundle is loaded (in priority order) from:
//   1. an explicit `ca` string passed by the caller,
//   2. an explicit `caCertPath` passed by the caller,
//   3. `sslrootcert` in the connection string,
//   4. `PGSSLROOTCERT` (libpq's standard env var),
//   5. `NODE_EXTRA_CA_CERTS`.
// Download the Amazon RDS global bundle to one of those paths:
//   https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
//
// ── WHY THE DSN MUST BE STRIPPED, AND WHAT IT COST ──────────────────────────
//
// `pool.ts` hands pg BOTH a `connectionString` and this `ssl` object. pg
// re-parses the connection string and lets the parsed result WIN:
//
//   pg/lib/connection-parameters.js
//     config = Object.assign({}, config, parse(config.connectionString))
//   pg-connection-string/index.js
//     if (config.sslcert || config.sslkey || config.sslrootcert || config.sslmode) {
//       config.ssl = {}
//     }
//     if (config.sslnegotiation === 'direct' && config.ssl === undefined) {
//       config.ssl = true
//     }
//
// So while the DSN still carried an SSL query parameter, THIS FUNCTION'S RETURN
// VALUE WAS THROWN AWAY — including the `ca` bundle it had just loaded.
// `rejectUnauthorized` became undefined and Node's TLS default (`true`) applied.
//
// MEASURED BEFORE THIS CHANGE, against real TLS handshakes (a Postgres endpoint
// doing the real SSLRequest -> 'S' -> TLS upgrade), pg 8.22.0 AND pg 8.13.1,
// node 22.22.3:
//
//   DSN ?sslmode=require, no CA, self-signed server
//     kit returned {rejectUnauthorized:false}; pg computed {}
//     -> DEPTH_ZERO_SELF_SIGNED_CERT  "self-signed certificate"      IT VERIFIED
//   DSN ?sslmode=require, CA supplied, private-CA server
//     kit returned {rejectUnauthorized:false, ca}; pg computed {}
//     -> UNABLE_TO_VERIFY_LEAF_SIGNATURE                             CA DISCARDED
//   DSN ?sslmode=verify-full, CA supplied, private-CA server
//     kit returned {rejectUnauthorized:true, ca}; pg computed {}
//     -> UNABLE_TO_VERIFY_LEAF_SIGNATURE                             CA DISCARDED
//
// Controls, same run: `ssl:{rejectUnauthorized:false}` with NO sslmode in the
// DSN reached TLS; `ssl:{rejectUnauthorized:true, ca}` against the private-CA
// server connected. So the harness could produce both outcomes, and the
// failures above are verification, not a broken server.
//
// That third row is the operational defect: a CA supplied through `ca`,
// `caCertPath`, `PGSSLROOTCERT` or `NODE_EXTRA_CA_CERTS` never reached pg, so a
// private-CA server — AMAZON RDS INCLUDED, whose root is not in Node's trust
// store — failed with UNABLE_TO_VERIFY_LEAF_SIGNATURE while this header said
// verification was configured. That reads as a network fault and gets debugged
// in the wrong place.
//
// It was NOT a pg regression: 8.13.1 (this kit's declared floor, `pg: ^8.13.1`)
// and 8.22.0 computed identically. It had never worked.
//
// THE FIX: `connectionStringWithoutTlsParameters` removes every TLS query
// parameter after this module has resolved it, so pg has nothing to re-parse and
// the resolved object survives. `hasna/emails` reached the same fix
// independently and is measured working; this is a port of it.
//
// ── WHY require VERIFIES, AND WHY THAT IS NOT A SILENT CHANGE ───────────────
//
// Stripping the DSN makes this function's return value real. Had the old
// `require -> {rejectUnauthorized:false}` row survived the strip, `require`
// would have STOPPED verifying — a security regression delivered inside a bug
// fix. The rows for `prefer` and `require` therefore now say what the socket has
// always done. Nothing that connects today stops connecting; connections that
// were failing against a private CA start working.
//
// FORWARD HAZARD, and `tests/kit-tls-handshake.test.ts` pins it: pg-connection-
// string v3 / pg v9 adopt libpq semantics, under which `require` genuinely stops
// verifying. Because this kit no longer leaves `sslmode` in the DSN, that switch
// cannot silently weaken a kit-built pool — but the pinning test fails loudly if
// the resolved table ever drifts back toward non-verification.

import { readFileSync } from "node:fs";
import { ownProp, ownString } from "./own.js";

/**
 * Every query parameter pg's own connection-string parser inspects to build its
 * `ssl` object. Each one either resets `config.ssl` or feeds it, so ANY of them
 * left in the DSN discards what this module resolved.
 */
const PG_TLS_QUERY_PARAMETERS = new Set([
  "ssl",
  "sslmode",
  "sslrootcert",
  "sslcert",
  "sslkey",
  "sslpassword",
  "sslnegotiation",
  "uselibpqcompat",
]);

/**
 * The legacy boolean `ssl=` values, named so the two places that read them
 * cannot drift: `sslModeFromConnectionString` decides the MODE from the truthy
 * set, and `resolveTlsConfig` decides whether an operator explicitly asked for
 * TLS to be OFF from the falsey set.
 *
 * A value in NEITHER set (a typo such as `ssl=treu`) currently resolves to mode
 * `disable` but is not treated as an explicit off, so it falls through to pg's
 * PGSSLMODE fallback. `hasna/emails` throws on that input instead. That
 * divergence is left standing here deliberately — changing it would start
 * rejecting DSNs that connect today — and is recorded on the PR for row
 * c317d0bf rather than fixed inside it.
 */
const EXPLICIT_SSL_ON_VALUES = new Set(["1", "true", "yes", "on", "require"]);
const EXPLICIT_SSL_OFF_VALUES = new Set(["0", "false", "no", "off", "disable"]);

/**
 * Every `sslmode` libpq accepts, mapped to the mode this kit resolves it to.
 * `allow` maps to `prefer`; the rest map to themselves.
 *
 * THIS IS THE WHOLE RECOGNISED SET, IN ONE PLACE, AND THE THROW BELOW LISTS IT
 * FROM THESE KEYS. It replaces a `switch` whose `default: throw` was correct but
 * was reachable only for a value the caller had already proven truthy — so the
 * one input class that never reached the enumeration was the empty string. A
 * lookup cannot be short-circuited that way, and a set that prints itself cannot
 * drift out of step with the error message that documents it.
 *
 * A `Map` rather than an object literal for the same reason `own.ts` exists:
 * `SSLMODE_VALUES.get("constructor")` is a miss, where a bare object read is a
 * hit on the prototype.
 */
const SSLMODE_VALUES = new Map<string, SslMode>([
  ["disable", "disable"],
  ["allow", "prefer"],
  ["prefer", "prefer"],
  ["require", "require"],
  ["verify-ca", "verify-ca"],
  ["verify-full", "verify-full"],
]);

/** The `ssl` field shape accepted by `pg.Pool` / `pg.Client`. */
export type PgSslConfig =
  | boolean
  | {
      rejectUnauthorized: boolean;
      ca?: string;
      cert?: string;
      key?: string;
      passphrase?: string;
    };

export interface TlsResolveOptions {
  /** Inline CA bundle (PEM). Wins over every other CA source. */
  ca?: string;
  /** Path to a CA bundle PEM file, e.g. the Amazon RDS global bundle. */
  caCertPath?: string;
  /** Environment used to discover PGSSLROOTCERT / NODE_EXTRA_CA_CERTS. */
  env?: Record<string, string | undefined>;
}

export type SslMode = "disable" | "prefer" | "require" | "verify-ca" | "verify-full";

interface ConnectionStringParts {
  base: string;
  fragment: string;
  params: URLSearchParams;
}

function connectionStringParts(connectionString: string): ConnectionStringParts {
  const queryStart = connectionString.indexOf("?");
  if (queryStart === -1) {
    return { base: connectionString, fragment: "", params: new URLSearchParams() };
  }
  const base = connectionString.slice(0, queryStart);
  const queryAndFragment = connectionString.slice(queryStart + 1);
  const fragmentStart = queryAndFragment.indexOf("#");
  const query = fragmentStart === -1 ? queryAndFragment : queryAndFragment.slice(0, fragmentStart);
  const fragment = fragmentStart === -1 ? "" : queryAndFragment.slice(fragmentStart);
  return { base, fragment, params: new URLSearchParams(query) };
}

/** The TLS query parameters present in a DSN, keyed by lowercased name. */
function tlsQueryValues(connectionString: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const [key, value] of connectionStringParts(connectionString).params) {
    const normalized = key.toLowerCase();
    if (PG_TLS_QUERY_PARAMETERS.has(normalized)) values.set(normalized, value);
  }
  return values;
}

/**
 * Remove the TLS query parameters once this module has resolved them into an
 * explicit `ssl` option. pg re-parses `connectionString` AFTER merging pool
 * options and lets the parse win, so leaving `sslmode` (or `ssl`, `sslcert`,
 * `sslkey`, `sslrootcert`, `sslnegotiation`) in the URL replaces the resolved
 * SSL object with pg's own — discarding the CA bundle with it.
 *
 * Non-TLS parameters and any fragment are preserved exactly.
 */
export function connectionStringWithoutTlsParameters(connectionString: string): string {
  const { base, fragment, params } = connectionStringParts(connectionString);
  for (const key of [...params.keys()]) {
    if (PG_TLS_QUERY_PARAMETERS.has(key.toLowerCase())) params.delete(key);
  }
  const query = params.toString();
  return `${base}${query ? `?${query}` : ""}${fragment}`;
}

/**
 * The DSN's `sslmode` as written, normalized for comparison.
 *
 * `undefined` means THE PARAMETER IS ABSENT. It never means "present but
 * empty" — `?sslmode=` and `?sslmode=%20` both return `""`, which is a VALUE and
 * must be validated like any other. The two situations are different
 * instructions and this is the single place that decides so; both readers below
 * go through it, so neither can be fixed without the other.
 */
function rawSslMode(values: Map<string, string>): string | undefined {
  const raw = values.get("sslmode");
  return raw === undefined ? undefined : raw.trim().toLowerCase();
}

/**
 * Preserve pg's transport negotiation choice outside the stripped URL, so
 * `sslnegotiation=direct` survives as an explicit pool option instead of being
 * silently dropped.
 */
export function sslNegotiationFromConnectionString(
  connectionString: string,
): "postgres" | "direct" | undefined {
  const value = tlsQueryValues(connectionString).get("sslnegotiation")?.trim().toLowerCase();
  if (!value) return undefined;
  if (value === "postgres" || value === "direct") return value;
  throw new Error(`Unknown sslnegotiation '${value}' in connection string; expected postgres or direct.`);
}

/**
 * Extract the effective `sslmode` from a Postgres connection string. Honors the
 * `sslmode` query param, the legacy `ssl=true` boolean, and pg's rule that
 * `sslnegotiation=direct` implies TLS when no explicit SSL setting is present.
 * Returns `disable` when TLS is not requested.
 */
export function sslModeFromConnectionString(connectionString: string): SslMode {
  const values = tlsQueryValues(connectionString);

  // PRESENT-BUT-EMPTY IS A VALUE, NOT AN ABSENCE. This test used to be
  // `if (sslmode)`, and `"".trim()` is falsy, so `?sslmode=` and `?sslmode=%20`
  // skipped the enumeration entirely and fell through to the `disable` return —
  // byte-identical to a DSN carrying no ssl parameter at all, which then defers
  // to an ambient PGSSLMODE. Reachable through `?sslmode=${PGSSLMODE}` with the
  // variable unset, which is the commonest way a DSN is assembled: an operator
  // who meant `require` and whose interpolation came back empty got plaintext,
  // silently, with the DSN still reading as though it had said something.
  //
  // That is the shape row c317d0bf fixed one row over — an operator instruction
  // replaced by ambient state — and the answer is the same: the code was wrong.
  //
  // libpq agrees, and it is the reference this module names. Measured on psql
  // (PostgreSQL) 16.13, with an absent-parameter control that reaches the socket
  // and so proves these are parameter rejections rather than a generic failure:
  //   ?sslmode=       -> invalid sslmode value: ""
  //   ?sslmode=%20    -> invalid sslmode value: " "
  //   ?sslmode=bogus  -> invalid sslmode value: "bogus"
  //   (absent)        -> connection to server ... Connection refused
  // libpq rejects empty on exactly the same line, with exactly the same message,
  // as any other unrecognised value. Empty is not how libpq spells "unset".
  const sslmode = rawSslMode(values);
  if (sslmode !== undefined) {
    const resolved = SSLMODE_VALUES.get(sslmode);
    if (resolved) return resolved;
    throw new Error(
      `Unknown sslmode '${sslmode}' in connection string; expected one of ` +
        `${[...SSLMODE_VALUES.keys()].join(", ")}. Remove the parameter entirely to defer to ` +
        `PGSSLMODE — an empty value is not how that is spelled.`,
    );
  }

  if (values.has("ssl")) {
    const ssl = values.get("ssl")?.trim().toLowerCase();
    if (ssl && EXPLICIT_SSL_ON_VALUES.has(ssl)) return "require";
    return "disable";
  }

  const sslnegotiation = values.get("sslnegotiation")?.trim().toLowerCase();
  if (sslnegotiation === "direct") return "require";

  return "disable";
}

// Every read below is an OWN-property read (see `own.ts`). These options and env
// objects come from the caller, and a plain `options.ca` read walks the
// prototype chain — on a polluted process that injected a CA the caller never
// supplied, turning the fail-closed throw at the bottom of `resolveTlsConfig`
// into a silent success that trusts ONLY the attacker's trust anchor.
//
// `sslrootcert` is read from the DSN through URLSearchParams, whose `get` cannot
// return an inherited value, so it needs no `own.ts` guard.
function loadCaBundle(connectionString: string, options: TlsResolveOptions): string | null {
  const env = ownProp<Record<string, string | undefined>>(options, "env") ?? process.env;
  const ca = ownString(options, "ca");
  if (ca && ca.trim()) return ca;
  const sslRootCert = tlsQueryValues(connectionString).get("sslrootcert")?.trim();
  const path =
    ownString(options, "caCertPath") ??
    (sslRootCert ? sslRootCert : undefined) ??
    ownString(env, "PGSSLROOTCERT") ??
    ownString(env, "NODE_EXTRA_CA_CERTS");
  if (path && path.trim()) return readFileSync(path.trim(), "utf8");
  return null;
}

/**
 * Carry client-certificate material forward from the DSN. pg used to read these
 * itself; now that the parameters are stripped, this module must reproduce them
 * or `sslcert`/`sslkey` would be silently dropped.
 */
function loadClientCertificate(connectionString: string): {
  cert?: string;
  key?: string;
  passphrase?: string;
} {
  const values = tlsQueryValues(connectionString);
  const material: { cert?: string; key?: string; passphrase?: string } = {};
  const certPath = values.get("sslcert")?.trim();
  if (certPath) material.cert = readFileSync(certPath, "utf8");
  const keyPath = values.get("sslkey")?.trim();
  if (keyPath) material.key = readFileSync(keyPath, "utf8");
  const passphrase = values.get("sslpassword");
  if (passphrase) material.passphrase = passphrase;
  return material;
}

/**
 * Resolve the `pg` ssl config for a connection string. See the module header
 * for the full mode table.
 *
 * Returns `false` when TLS was explicitly switched off, and `undefined` when the
 * DSN expressed no TLS policy at all — those are different answers, and pg
 * treats them differently: only `undefined` lets `PGSSLMODE` decide.
 *
 * The caller MUST hand pg `connectionStringWithoutTlsParameters(connectionString)`
 * rather than the original DSN, or pg discards everything resolved here.
 */
export function resolveTlsConfig(
  connectionString: string,
  options: TlsResolveOptions = {},
): PgSslConfig | undefined {
  const mode = sslModeFromConnectionString(connectionString);

  if (mode === "disable") {
    // TWO DIFFERENT SITUATIONS REACH THIS BRANCH AND THEY MUST NOT RESOLVE THE
    // SAME WAY: an operator who wrote an explicit "off", and a DSN that simply
    // carries no ssl parameter. `sslModeFromConnectionString` collapses both to
    // `disable`, so the distinction has to be recovered here.
    //
    // Returning `undefined` sets no `config.ssl` key at all, and pg then reaches
    //   pg/lib/connection-parameters.js -> readSSLConfigFromEnvironment()
    // which reads `process.env.PGSSLMODE` DIRECTLY. `options.env` does not reach
    // that path — it isolates `loadCaBundle` in this module and nothing else.
    //
    // EXPLICIT OFF -> `false`. While the DSN still carried `?sslmode=disable`,
    // pg parsed it and set `config.ssl = false` itself, so the instruction was
    // delivered by accident of the parameter surviving. Now that
    // `connectionStringWithoutTlsParameters` strips it — which is the whole
    // point of that function — nothing says TLS was deliberately switched off,
    // and an ambient PGSSLMODE silently overrides the operator. Saying `false`
    // restores the instruction, and it is undiagnosable from the DSN otherwise.
    //
    // NO PARAMETER AT ALL -> `undefined`, deliberately kept. Such a DSN has
    // expressed no instruction, and deferring to PGSSLMODE is libpq's
    // documented behaviour. Widening this branch to a blanket `false` reads as
    // the tidier fix and is a CONFIDENTIALITY REGRESSION in the opposite
    // direction: an operator who sets PGSSLMODE=require to force TLS on bare
    // DSNs would be silently downgraded to plaintext. `tests/kit-tls-handshake`
    // pins both halves so neither can drift.
    // THE SECOND READER OF `sslmode`, AND IT GOES THROUGH THE SAME HELPER.
    // Behaviour here is unchanged: `sslModeFromConnectionString` above now
    // throws on a present-but-empty value, so this line can only ever see
    // `undefined` or a recognised mode. What changes is that it no longer keeps
    // its own copy of the normalization — the two readers used to carry
    // identical `?.trim().toLowerCase()` expressions, so a fix applied to one
    // was a half-fix, and nothing in the file said the other existed.
    const values = tlsQueryValues(connectionString);
    const sslmode = rawSslMode(values);
    const ssl = values.get("ssl")?.trim().toLowerCase();
    const explicitlyOff =
      sslmode === "disable" || (ssl !== undefined && EXPLICIT_SSL_OFF_VALUES.has(ssl));
    return explicitlyOff ? false : undefined;
  }

  const ca = loadCaBundle(connectionString, options);
  const clientCertificate = loadClientCertificate(connectionString);

  if (mode === "prefer" || mode === "require") {
    // Encrypt AND verify. This is what the socket has always done — pg treats
    // `prefer`, `require` and `verify-ca` as aliases for `verify-full` and says
    // so on stderr — so keeping it is preservation, not new strictness. A CA
    // bundle is pinned when available; without one, Node's trust store applies,
    // exactly as before.
    return { rejectUnauthorized: true, ...(ca ? { ca } : {}), ...clientCertificate };
  }

  // verify-ca / verify-full: verification is mandatory.
  if (!ca) {
    throw new Error(
      `sslmode=${mode} requires a CA bundle. Set PGSSLROOTCERT (or pass caCertPath/ca) to the ` +
        `Amazon RDS global bundle: https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`,
    );
  }
  return { rejectUnauthorized: true, ca, ...clientCertificate };
}
