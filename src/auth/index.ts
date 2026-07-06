// Public surface of the Hasna API-key auth kit.
//
// Stateless, HMAC-signed, verifiable keys (prefix `hasna_<app>_`), a scope
// grammar (`<app>:<action>` + wildcards), TTL, a hashed-at-rest record store
// with a revocation list, a per-request audit hook, and an Express/Hono-agnostic
// `verifyApiKey()` middleware.

export * from "./scopes.js";
export * from "./keys.js";
export * from "./store.js";
export * from "./middleware.js";
