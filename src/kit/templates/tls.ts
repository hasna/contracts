// TLS resolution for the vendored Hasna storage kit.
//
// ONE correct TLS approach for the whole fleet. This replaces the three drifted
// variants that previously existed across repos, all of which hardcoded
// `{ rejectUnauthorized: false }` for any TLS connection — that silently
// disables certificate verification even when the caller asked for
// `verify-full`, which defeats the point of TLS against a cloud database.
//
// WHAT THIS FUNCTION RETURNS (its own contract, and all it can promise):
//   - disable / (no ssl param)  -> no TLS (ssl: undefined)
//   - prefer / require          -> encrypt, do NOT verify the server cert
//                                  (rejectUnauthorized: false) — this matches
//                                  what libpq `require` means and is the AWS
//                                  RDS default when no CA bundle is supplied.
//   - verify-ca / verify-full   -> encrypt AND verify against a CA bundle
//                                  (rejectUnauthorized: true, ca: <bundle>).
//                                  A CA bundle is REQUIRED; we throw if none is
//                                  available so verification can never silently
//                                  downgrade.
//
// ⚠ THAT TABLE DESCRIBES THIS FUNCTION'S RETURN VALUE, NOT THE CONNECTION.
//   `pg` DISCARDS IT whenever the DSN still carries an SSL query parameter, so
//   the table above is NOT what happens at the socket today. Read the next
//   block before relying on any row of it.
//
// ── MEASURED BEHAVIOUR AT THE SOCKET, 2026-08-08 ────────────────────────────
//
// `pool.ts` passes BOTH `connectionString` and this `ssl` object to `pg`. `pg`
// re-parses the connection string and lets the parsed result WIN:
//
//   pg/lib/connection-parameters.js
//     config = Object.assign({}, config, parse(config.connectionString))
//   pg-connection-string/index.js
//     if (config.sslcert || config.sslkey || config.sslrootcert || config.sslmode) {
//       config.ssl = {}
//     }
//
// So the moment the DSN contains `sslmode` (or `ssl`, `sslcert`, `sslkey`,
// `sslrootcert`), THIS FUNCTION'S RETURN VALUE IS THROWN AWAY — including the
// `ca` bundle it just loaded. `rejectUnauthorized` is then undefined, and Node's
// TLS default (`true`) applies.
//
// Measured against real TLS handshakes (fake Postgres endpoint doing the real
// SSLRequest -> 'S' -> TLS upgrade), pg 8.22.0 AND pg 8.13.1, node 22.22.3:
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
// pg says so itself, on stderr, verbatim:
//   "SECURITY WARNING: The SSL modes 'prefer', 'require', and 'verify-ca' are
//    treated as aliases for 'verify-full'."
//
// TWO CONSEQUENCES, in opposite directions:
//   1. `require` is SAFER than this file has been claiming — it verifies.
//   2. `verify-ca` / `verify-full` ARE BROKEN when the CA is supplied through
//      `ca` / `caCertPath` / `PGSSLROOTCERT` / `NODE_EXTRA_CA_CERTS`, because
//      that bundle never reaches pg. Against a private-CA server (Amazon RDS
//      included, whose root is not in Node's trust store) the connection fails
//      with UNABLE_TO_VERIFY_LEAF_SIGNATURE while this header says verification
//      is configured. That reads as a network fault and gets debugged in the
//      wrong place.
//
// This is NOT a pg regression: 8.13.1 (this kit's declared floor, `pg: ^8.13.1`)
// and 8.22.0 compute identically. It has never matched.
//
// FORWARD HAZARD: pg-connection-string v3 / pg v9 will adopt libpq semantics,
// at which point `require` really will stop verifying. The table at the top
// becomes accidentally true and every deployment's posture silently weakens.
//
// THE FIX IS A BEHAVIOUR CHANGE AND IS DELIBERATELY NOT IN THIS COMMIT: strip
// the TLS query parameters from the DSN in `pool.ts` after resolving them, so
// pg has nothing to re-parse. `hasna/emails` already does exactly this
// (`connectionStringWithoutTlsParameters` in its forked kit) and is measured
// working. Tracked on todos row 3dee42b0.
//
// The RDS CA bundle is loaded (in priority order) from:
//   1. an explicit `ca` string passed by the caller,
//   2. an explicit `caCertPath` passed by the caller,
//   3. `PGSSLROOTCERT` (libpq's standard env var),
//   4. `NODE_EXTRA_CA_CERTS`.
// Download the Amazon RDS global bundle to one of those paths:
//   https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem

import { readFileSync } from "node:fs";
import { ownProp, ownString } from "./own.js";

/** The `ssl` field shape accepted by `pg.Pool` / `pg.Client`. */
export type PgSslConfig = boolean | { rejectUnauthorized: boolean; ca?: string };

export interface TlsResolveOptions {
  /** Inline CA bundle (PEM). Wins over every other CA source. */
  ca?: string;
  /** Path to a CA bundle PEM file, e.g. the Amazon RDS global bundle. */
  caCertPath?: string;
  /** Environment used to discover PGSSLROOTCERT / NODE_EXTRA_CA_CERTS. */
  env?: Record<string, string | undefined>;
}

export type SslMode = "disable" | "prefer" | "require" | "verify-ca" | "verify-full";

/**
 * Extract the effective `sslmode` from a Postgres connection string. Honors the
 * `sslmode` query param and the legacy `ssl=true` boolean. Returns `disable`
 * when TLS is not requested.
 */
export function sslModeFromConnectionString(connectionString: string): SslMode {
  const queryStart = connectionString.indexOf("?");
  const params = new URLSearchParams(queryStart === -1 ? "" : connectionString.slice(queryStart + 1));

  const sslmode = params.get("sslmode")?.trim().toLowerCase();
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

  const ssl = params.get("ssl")?.trim().toLowerCase();
  if (ssl && ["1", "true", "yes", "on", "require"].includes(ssl)) return "require";

  return "disable";
}

// Every read below is an OWN-property read (see `own.ts`). These options and env
// objects come from the caller, and a plain `options.ca` read walks the
// prototype chain — on a polluted process that injected a CA the caller never
// supplied, turning the fail-closed throw at the bottom of `resolveTlsConfig`
// into a silent success that trusts ONLY the attacker's trust anchor.
function loadCaBundle(options: TlsResolveOptions): string | null {
  const env = ownProp<Record<string, string | undefined>>(options, "env") ?? process.env;
  const ca = ownString(options, "ca");
  if (ca && ca.trim()) return ca;
  const path =
    ownString(options, "caCertPath") ??
    ownString(env, "PGSSLROOTCERT") ??
    ownString(env, "NODE_EXTRA_CA_CERTS");
  if (path && path.trim()) return readFileSync(path.trim(), "utf8");
  return null;
}

/**
 * Resolve the `pg` ssl config for a connection string. See the module header
 * for the full mode table. Returns `undefined` when TLS should be off.
 */
export function resolveTlsConfig(
  connectionString: string,
  options: TlsResolveOptions = {},
): PgSslConfig | undefined {
  const mode = sslModeFromConnectionString(connectionString);

  if (mode === "disable" || mode === "prefer") {
    // `prefer` still lets pg negotiate TLS opportunistically without a config,
    // but we only force TLS at `require` and above. Treat both as no explicit
    // ssl config so a plain local Postgres keeps working.
    return undefined;
  }

  const ca = loadCaBundle(options);

  if (mode === "require") {
    // Encrypt but do not verify — libpq `require` semantics. If a CA bundle is
    // available we still pin it (strictly better) while keeping verification
    // relaxed so a rotated/regional RDS cert cannot hard-fail a `require` DSN.
    return ca ? { rejectUnauthorized: false, ca } : { rejectUnauthorized: false };
  }

  // verify-ca / verify-full: verification is mandatory.
  if (!ca) {
    throw new Error(
      `sslmode=${mode} requires a CA bundle. Set PGSSLROOTCERT (or pass caCertPath/ca) to the ` +
        `Amazon RDS global bundle: https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`,
    );
  }
  return { rejectUnauthorized: true, ca };
}
