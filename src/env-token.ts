// The app-name -> env-var token rule, in one place.
//
// `HASNA_<NAME>_*` is the contract's env-key convention (CONTRACT.md §3), and
// three modules need the `<NAME>` derivation: storage config, client transport,
// and the identity seam. It lives in its own leaf module so `src/auth/*` can
// use it without importing `src/mode.ts` — which pulls in the Zod schema
// bundle, and would drag it into the dependency graph of every consumer that
// imports only `@hasna/contracts/auth`.
//
// Re-exported from `./mode` for compatibility; that is still its public home.

/** Upper-snake env token for an app name, e.g. `open-mailery` -> `OPEN_MAILERY`. */
export function envToken(name: string): string {
  return name.toUpperCase().replace(/-/g, "_");
}
