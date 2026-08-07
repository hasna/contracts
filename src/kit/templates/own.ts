// Own-property reads for the vendored Hasna storage kit.
//
// Every options object and env object this kit reads is CALLER-SUPPLIED, and a
// plain `options.ca` read walks the prototype chain. In a process whose
// `Object.prototype` has been polluted, that read returns configuration the
// caller never set. This kit is STAMPED INTO CONSUMER REPOSITORIES, so it runs
// inside somebody else's process and the pollution sink belongs to them.
//
// What the unguarded reads did, measured:
//   - tls.ts    a prototype-supplied `ca`/`caCertPath` turned the fail-closed
//               `sslmode=verify-full requires a CA bundle` error into a silent
//               success: `{ rejectUnauthorized: true, ca: <attacker anchor> }`.
//               `rejectUnauthorized` stays TRUE, so the connection still
//               verifies — against a trust anchor the attacker supplied, and
//               every surface that would report a TLS problem reports success.
//   - pool.ts   copied a prototype-supplied `ca` into an OWN property before
//               calling `resolveTlsConfig`, so guarding tls.ts alone did not
//               close that path.
//   - backend.ts a prototype-supplied `HASNA_<APP>_DATABASE_URL` flipped the
//               backend to postgresql and redirected the connection.
//   - migrations.ts a prototype-supplied `ledgerTable` reached interpolated
//               DDL (SQL injection); a prototype-supplied `dryRun` turned an
//               apply into a no-op that still reported a plan.
//
// `Object.hasOwn` is the guard used throughout `@hasna/contracts` and it is
// TOKEN-INDEPENDENT: it closes `__proto__`, `constructor` and `prototype` at
// once, so there is no denylist of property names to keep current.
//
// `process.env` is prototype-pollutable too, so the default env path needs the
// same guard as a caller-supplied one.

// ONE TRAP, measured while writing this file: a guarded read whose result you
// store in a plain object literal is UNGUARDED AGAIN on read-back, because
// `result.ca` walks the same polluted chain. Where a guarded value is kept in a
// record before use, build that record with `Object.create(null)` — see
// `ownPoolOptions` in `pool.ts`.

/**
 * Read `key` from `source` only when `source` OWNS it.
 *
 * Returns `undefined` for an inherited property and for a null/undefined or
 * non-object source, so a guarded read is a drop-in for `source?.[key]` that
 * cannot be answered by the prototype chain.
 */
export function ownProp<T>(source: unknown, key: string): T | undefined {
  if (source === null || source === undefined) return undefined;
  const kind = typeof source;
  if (kind !== "object" && kind !== "function") return undefined;
  if (!Object.hasOwn(source as object, key)) return undefined;
  return (source as Record<string, unknown>)[key] as T | undefined;
}

/** `ownProp` narrowed to a string, so a polluted non-string cannot slip through. */
export function ownString(source: unknown, key: string): string | undefined {
  const value = ownProp<unknown>(source, key);
  return typeof value === "string" ? value : undefined;
}
