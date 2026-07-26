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
//  3. The value is OPAQUE and case-sensitive, with exactly ONE exception:
//     UUIDs. PostgreSQL's `uuid` type does not store what you gave it — it
//     PARSES and REWRITES it. `9D4B2A1C0E5F4A7B8C3D1E2F3A4B5C6D`,
//     `{9d4b2a1c-...}` and `9D4B2A1C-...` all come back as one canonical
//     lowercase hyphenated string. A `text` column does no such thing. That
//     asymmetry — not letter case in the abstract — is the mechanism behind the
//     `uuid`-here / `text`-there drift, so the contract folds exactly the forms
//     PostgreSQL folds and nothing else.
//
//     RESIDUAL, STATED DELIBERATELY. Two `text` rows that differ only in UUID
//     formatting or case are ONE tenant to this contract. If a store treats
//     them as two, that is a data-modelling bug this contract will not
//     accommodate — accommodating it would mean not closing the drift at all.
//
//     NOT FOLDED: everything else, including ULIDs. A ULID's canonical encoding
//     is uppercase Crockford base32 and issuers MUST emit that form; the
//     contract does not case-fold it, because unlike a UUID no database type
//     silently rewrites it, so folding would only create new ways for two
//     distinct opaque ids to collide.
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
 *
 * Built from {@link MAX_TENANT_ID_LENGTH} rather than written as a literal, so
 * the cap and the pattern cannot drift apart.
 */
export const TENANT_ID_PATTERN = new RegExp(
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,${MAX_TENANT_ID_LENGTH - 1}}$`
);

/**
 * The UUID spellings PostgreSQL's `uuid` input grammar accepts and rewrites:
 * hyphenated, hyphen-less, and either of those wrapped in braces, in any case.
 * These are exactly the forms that can enter a `uuid` column looking one way
 * and leave it looking another, so these are exactly the forms folded here.
 */
const UUID_HEX = "[0-9a-fA-F]";
const UUID_PATTERN = new RegExp(
  `^\\{?(?:${UUID_HEX}{8}-${UUID_HEX}{4}-${UUID_HEX}{4}-${UUID_HEX}{4}-${UUID_HEX}{12}|${UUID_HEX}{32})\\}?$`
);

/** Is `value` a syntactically valid tenant id? */
export function isValidTenantId(value: unknown): value is string {
  // The pattern's own quantifier enforces the cap; there is no second,
  // separately-maintained length check to fall out of sync with it.
  return typeof value === "string" && TENANT_ID_PATTERN.test(value);
}

/**
 * Is `value` a textual UUID in any spelling a PostgreSQL `uuid` column accepts?
 * Note that brace-wrapped forms are not valid tenant ids on their own (`{` is
 * outside the grammar) — they are recognized so {@link normalizeTenantId} can
 * turn operator input into a canonical id rather than rejecting it.
 */
export function isUuidTenantId(value: string): boolean {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

/**
 * Canonical comparison form: canonical lowercase hyphenated for every UUID
 * spelling, unchanged for everything else. Does NOT validate — use
 * {@link normalizeTenantId} when the input is untrusted.
 */
export function canonicalizeTenantId(value: string): string {
  if (!isUuidTenantId(value)) return value;
  const hex = value.replace(/[{}-]/g, "").toLowerCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Trim, validate, and canonicalize an untrusted tenant id. Throws a message
 * naming the grammar so a bad `--tid` is self-diagnosing at the CLI.
 */
export function normalizeTenantId(value: string): string {
  const trimmed = typeof value === "string" ? value.trim() : "";
  // A brace-wrapped UUID is legal INPUT even though `{` is outside the id
  // grammar: canonicalizing first means an operator pasting `{...}` from a
  // database client gets a valid id instead of a rejection.
  const canonical = canonicalizeTenantId(trimmed);
  if (!isValidTenantId(canonical)) {
    throw new Error(
      `Invalid tenant id '${value}'. Expected 1-${MAX_TENANT_ID_LENGTH} characters matching ${TENANT_ID_PATTERN} (a UUID, ULID, slug, or prefixed id).`
    );
  }
  return canonical;
}

/**
 * Compare two tenant ids under the canonical rule: exact match, except that
 * every UUID spelling folds to one value. Invalid input never matches.
 *
 * Both sides are trimmed first. Mint trims, so a comparison that did not would
 * reject an `expectedTid` read from a file or env var with a trailing newline —
 * fail-closed, but for a reason no operator could see.
 */
export function tenantIdsEqual(left: string | null | undefined, right: string | null | undefined): boolean {
  const canonical = (value: string | null | undefined): string | null => {
    if (typeof value !== "string") return null;
    const folded = canonicalizeTenantId(value.trim());
    return isValidTenantId(folded) ? folded : null;
  };
  const a = canonical(left);
  const b = canonical(right);
  return a !== null && b !== null && a === b;
}
