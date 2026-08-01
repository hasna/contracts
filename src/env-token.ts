// The app-name -> env-var token rule, in one place.
//
// `HASNA_<NAME>_*` is the contract's env-key convention (CONTRACT.md §3), and
// multiple modules need the `<NAME>` derivation: server backend config, client transport,
// and the identity seam. It lives in its own leaf module so `src/auth/*` can
// use it without importing `src/server-backend.ts` — which pulls in the Zod schema
// bundle, and would drag it into the dependency graph of every consumer that
// imports only `@hasna/contracts/auth`.

/** Minimal process-environment shape shared by backend and transport resolvers. */
export type Env = Record<string, string | undefined>;

/** Upper-snake env token for an app name, e.g. `open-mailery` -> `OPEN_MAILERY`. */
export function envToken(name: string): string {
  return name.toUpperCase().replace(/-/g, "_");
}
