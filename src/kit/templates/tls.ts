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
//   - disable / (no ssl param)  -> no TLS (ssl: undefined)
//   - prefer / require          -> encrypt AND verify the server certificate
//                                  (rejectUnauthorized: true), pinning a CA
//                                  bundle when one is available.
//   - verify-ca / verify-full   -> encrypt AND verify against a CA bundle
//                                  (rejectUnauthorized: true, ca: <bundle>).
//                                  A CA bundle is REQUIRED; we throw if none is
//                                  available so verification can never silently
//                                  downgrade.
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
 * `sslmode` query param and the legacy `ssl=true` boolean. Returns `disable`
 * when TLS is not requested.
 */
export function sslModeFromConnectionString(connectionString: string): SslMode {
  const values = tlsQueryValues(connectionString);

  const sslmode = values.get("sslmode")?.trim().toLowerCase();
  if (sslmode) {
    switch (sslmode) {
      case "disable":
      case "prefer":
      case "require":
      case "verify-ca":
      case "verify-full":
        return sslmode;
      case "allow":
        return "prefer";
      default:
        throw new Error(`Unknown sslmode '${sslmode}' in connection string.`);
    }
  }

  const ssl = values.get("ssl")?.trim().toLowerCase();
  if (ssl && ["1", "true", "yes", "on", "require"].includes(ssl)) return "require";

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
 * for the full mode table. Returns `undefined` when TLS should be off.
 *
 * The caller MUST hand pg `connectionStringWithoutTlsParameters(connectionString)`
 * rather than the original DSN, or pg discards everything resolved here.
 */
export function resolveTlsConfig(
  connectionString: string,
  options: TlsResolveOptions = {},
): PgSslConfig | undefined {
  const mode = sslModeFromConnectionString(connectionString);

  if (mode === "disable") return undefined;

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
