// The tenant identifier: the one narrow waist every Hasna auth seam agrees on.
//
// WHY THIS EXISTS. Repos independently grew a tenants concept and independently
// chose its storage type — `uuid` in one schema, `text` in another. Nothing
// reconciled them, so a token minted by one service could not name a tenant the
// next service could look up. The contract fixes the WIRE type once and lets
// each store keep whatever column it already has.
//
// THE DECISION.
//
//  1. On the wire a tenant id is ALWAYS a JSON string. Never a number, never an
//     object. A `uuid` column serializes to its canonical string form; a `text`
//     column passes through verbatim. Both sides then agree.
//
//  2. The grammar is deliberately permissive about SHAPE and strict about
//     CHARACTER SET. A UUID, a ULID, a slug (`acme-corp`) and a prefixed id
//     (`org_01HQ...`) are all legal, because all four are already in use. What
//     is NOT legal is anything that would be unsafe to put in a log line, an
//     HTTP header, or a URL path segment: whitespace, control characters, `/`,
//     `:` (reserved as the scope separator), `@`, quotes, or non-ASCII.
//
//  3. The value is OPAQUE and case-sensitive, with exactly one exception:
//     UUID-shaped values are compared in canonical lowercase form. This is not
//     cosmetic. PostgreSQL's `uuid` type round-trips every value to lowercase,
//     so a store with a `uuid` column and a store with a `text` column would
//     otherwise disagree about whether `A1B2...` and `a1b2...` are the same
//     tenant. Canonicalizing UUIDs — and only UUIDs — makes the two stores
//     agree without making unrelated identifiers case-insensitive.
//
//  4. Absence is NOT a wildcard. A claim set with no tenant id is untenanted,
//     which callers that require a tenant MUST reject. See `requireTenant` in
//     `verifyApiKeyToken`.

/**
 * Maximum tenant-id length. Chosen to hold a canonical UUID (36) or a prefixed
 * ULID (`org_` + 26 = 30) with headroom, while staying inside a comfortable
 * `varchar` and a single header value.
 */
export const MAX_TENANT_ID_LENGTH = 64;

/**
 * Tenant-id grammar: ASCII alphanumeric start, then alphanumerics plus `.`,
 * `_`, `-`. Anything a log parser, a header, or a URL segment would have to
 * escape is excluded by construction.
 */
export const TENANT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** Canonical RFC 4122 textual UUID, case-insensitive. */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Is `value` a syntactically valid tenant id? */
export function isValidTenantId(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_TENANT_ID_LENGTH && TENANT_ID_PATTERN.test(value);
}

/** Is `value` a textual UUID (either case)? */
export function isUuidTenantId(value: string): boolean {
  return UUID_PATTERN.test(value);
}

/**
 * Canonical comparison form. UUID-shaped ids fold to lowercase (matching what a
 * PostgreSQL `uuid` column returns); every other id is returned unchanged.
 * Does NOT validate — use {@link normalizeTenantId} when the input is untrusted.
 */
export function canonicalizeTenantId(value: string): string {
  return isUuidTenantId(value) ? value.toLowerCase() : value;
}

/**
 * Trim, validate, and canonicalize an untrusted tenant id. Throws a message
 * naming the grammar so a bad `--tid` is self-diagnosing at the CLI.
 */
export function normalizeTenantId(value: string): string {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (!isValidTenantId(trimmed)) {
    throw new Error(
      `Invalid tenant id '${value}'. Expected 1-${MAX_TENANT_ID_LENGTH} characters matching ${TENANT_ID_PATTERN} (a UUID, ULID, slug, or prefixed id).`
    );
  }
  return canonicalizeTenantId(trimmed);
}

/**
 * Compare two tenant ids under the canonical rule: exact match, except that
 * UUID-shaped ids ignore case. Invalid input never matches.
 */
export function tenantIdsEqual(left: string | null | undefined, right: string | null | undefined): boolean {
  if (!isValidTenantId(left) || !isValidTenantId(right)) return false;
  return canonicalizeTenantId(left) === canonicalizeTenantId(right);
}
