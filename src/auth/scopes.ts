// Scope grammar for Hasna API keys.
//
// A scope is `<app>:<action>` where each side is either a concrete slug/action
// token or the wildcard `*`. The bare token `*` is a superuser grant that
// matches every scope. Required scopes are always concrete (`app:action`).
//
// Examples of GRANTED scopes:
//   "*"            -> superuser: satisfies any required scope
//   "todos:*"      -> every action on the todos app
//   "*:read"       -> the read action on any app
//   "todos:read"   -> exactly todos:read
//   "todos:tasks.create" -> namespaced action (dotted)
//
// Required scopes must be fully-qualified `app:action` (no wildcards).

/** A single scope token side: `*` or a slug/action (`[a-z][a-z0-9-.]*`). */
const SCOPE_PART = /^(?:\*|[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)*)$/;

/** Grant grammar: `*` OR `<part>:<part>`. */
export function isValidScope(scope: string): boolean {
  if (scope === "*") return true;
  const idx = scope.indexOf(":");
  if (idx <= 0 || idx === scope.length - 1) return false;
  const app = scope.slice(0, idx);
  const action = scope.slice(idx + 1);
  return SCOPE_PART.test(app) && SCOPE_PART.test(action);
}

/** Required scopes must be concrete `app:action` with no wildcards. */
export function isConcreteScope(scope: string): boolean {
  if (!isValidScope(scope) || scope === "*") return false;
  return !scope.includes("*");
}

/** Split `app:action` -> [app, action]; `*` -> ["*", "*"]. */
function parts(scope: string): [string, string] {
  if (scope === "*") return ["*", "*"];
  const idx = scope.indexOf(":");
  return [scope.slice(0, idx), scope.slice(idx + 1)];
}

/**
 * Does a single GRANTED scope satisfy a concrete REQUIRED scope?
 * Wildcards on the grant side match; the required side must be concrete.
 */
export function scopeMatches(granted: string, required: string): boolean {
  if (!isValidScope(granted) || !isConcreteScope(required)) return false;
  if (granted === "*") return true;
  const [gApp, gAction] = parts(granted);
  const [rApp, rAction] = parts(required);
  const appOk = gApp === "*" || gApp === rApp;
  const actionOk = gAction === "*" || gAction === rAction;
  return appOk && actionOk;
}

/** Does ANY granted scope satisfy the concrete required scope? */
export function hasScope(granted: readonly string[], required: string): boolean {
  return granted.some((g) => scopeMatches(g, required));
}

/** Do the granted scopes satisfy EVERY required scope? */
export function hasAllScopes(granted: readonly string[], required: readonly string[]): boolean {
  return required.every((r) => hasScope(granted, r));
}

/** Normalize + validate a list of granted scopes; throws on any invalid token. */
export function normalizeScopes(scopes: readonly string[]): string[] {
  const seen = new Set<string>();
  for (const raw of scopes) {
    const scope = raw.trim();
    if (!isValidScope(scope)) {
      throw new Error(`Invalid scope '${raw}'. Expected '*' or '<app>:<action>' (e.g. 'todos:read', 'todos:*').`);
    }
    seen.add(scope);
  }
  if (seen.size === 0) {
    throw new Error("At least one scope is required.");
  }
  return [...seen].sort();
}
