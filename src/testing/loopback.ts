// Bind-capability probes for the suites and release gates that need a real
// HTTP server.
//
// Two capabilities, probed SEPARATELY, because they fail independently: a
// sandbox that refuses the wildcard bind (0.0.0.0) normally still permits
// 127.0.0.1. Probing them together throws away the loopback-only coverage —
// the redirect-loop and Host-override boundaries — in exactly the environments
// where it would still have run.
//
// The policy is fail-closed. A suite or a gate that cannot bind never reports
// success: it fails. Skipping is an explicit, greppable operator decision
// (CONTRACTS_ALLOW_LOOPBACK_SKIP=1), it is never an accident of the
// environment, and the publish gate refuses it outright — see
// scripts/smoke-dist.ts.

export type LoopbackBindScope = "loopback" | "wildcard";

/**
 * Opt-in that downgrades a fail-closed loopback gate to an explicit skip.
 * `bun test` honours it (one named control test still fails, so the run can
 * never be green without the security suites). The publish gate does not.
 */
export const LOOPBACK_SKIP_ENV = "CONTRACTS_ALLOW_LOOPBACK_SKIP";

/**
 * Test seam: a comma-separated list of scopes whose probe is forced to report
 * "cannot bind", so the fail-closed paths stay reachable on a host that can in
 * fact bind. It can only ever DENY a capability — forcing a denial makes every
 * gate stricter, never laxer — so it cannot be used to walk an unverified
 * build past a release gate.
 */
export const LOOPBACK_PROBE_DENY_ENV = "CONTRACTS_LOOPBACK_PROBE_DENY";

export const loopbackBindHostnames: Record<LoopbackBindScope, string> = {
  loopback: "127.0.0.1",
  wildcard: "0.0.0.0",
};

type Environment = Record<string, string | undefined>;

function deniedScopes(env: Environment): Set<string> {
  return new Set(
    (env[LOOPBACK_PROBE_DENY_ENV] ?? "")
      .split(",")
      .map((scope) => scope.trim())
      .filter(Boolean),
  );
}

export function loopbackSkipAllowed(env: Environment = process.env): boolean {
  return env[LOOPBACK_SKIP_ENV] === "1";
}

const probeCache = new Map<LoopbackBindScope, boolean>();

/**
 * Probe one bind scope. The result of a real probe is cached — binding a port
 * per gated suite is wasteful — but the deny seam is re-read every call so a
 * test can flip it without poisoning the cache.
 */
export function canBind(scope: LoopbackBindScope, env: Environment = process.env): boolean {
  if (deniedScopes(env).has(scope)) return false;
  const cached = probeCache.get(scope);
  if (cached !== undefined) return cached;
  let server: ReturnType<typeof Bun.serve> | undefined;
  let available = false;
  try {
    server = Bun.serve({
      hostname: loopbackBindHostnames[scope],
      port: 0,
      fetch() {
        return new Response("ok");
      },
    });
    available = true;
  } catch {
    available = false;
  } finally {
    server?.stop(true);
  }
  probeCache.set(scope, available);
  return available;
}

export function canBindLoopback(env: Environment = process.env): boolean {
  return canBind("loopback", env);
}

export function canBindWildcard(env: Environment = process.env): boolean {
  return canBind("wildcard", env);
}

export type LoopbackDecision = "run" | "skip" | "fail";

export interface LoopbackRequirement {
  readonly requires: readonly LoopbackBindScope[];
  readonly missing: readonly LoopbackBindScope[];
  readonly decision: LoopbackDecision;
}

export interface ResolveLoopbackOptions {
  readonly probe?: (scope: LoopbackBindScope) => boolean;
  readonly skipAllowed?: boolean;
}

export function resolveLoopbackRequirement(
  requires: readonly LoopbackBindScope[],
  options: ResolveLoopbackOptions = {},
): LoopbackRequirement {
  const probe = options.probe ?? ((scope: LoopbackBindScope) => canBind(scope));
  const skipAllowed = options.skipAllowed ?? loopbackSkipAllowed();
  const missing = requires.filter((scope) => !probe(scope));
  const decision: LoopbackDecision = missing.length === 0
    ? "run"
    : skipAllowed
      ? "skip"
      : "fail";
  return { requires, missing, decision };
}

export function loopbackUnavailableMessage(
  label: string,
  missing: readonly LoopbackBindScope[],
): string {
  const detail = missing
    .map((scope) => `${scope} (${loopbackBindHostnames[scope]})`)
    .join(", ");
  return `${label} needs an HTTP bind this runtime refused: ${detail}. `
    + "This gate is fail-closed and will not report success without running. "
    + `Set ${LOOPBACK_SKIP_ENV}=1 to record an explicit, reviewed skip.`;
}

type SuiteBody = () => void;
type CaseBody = () => void | Promise<void>;

export interface LoopbackTestRunner {
  readonly describe: ((name: string, body: SuiteBody) => unknown) & {
    skip: (name: string, body: SuiteBody) => unknown;
  };
  readonly test: ((name: string, body: CaseBody) => unknown) & {
    skip: (name: string, body: CaseBody) => unknown;
  };
}

export interface LoopbackTestGate {
  readonly requirement: LoopbackRequirement;
  describe(name: string, body: SuiteBody): void;
  test(name: string, body: CaseBody): void;
}

/**
 * Gate a suite or a case on the bind scopes it actually uses.
 *
 * `run`  — the real runner, unchanged.
 * `skip` — the runner's skip, reachable only via LOOPBACK_SKIP_ENV.
 * `fail` — a single registered case that throws. The gated body is deliberately
 *          NOT executed (its setup binds the servers the runtime just refused),
 *          but the suite still reports a failure, so a runner that loses bind
 *          capability breaks the build instead of quietly shrinking the
 *          security suite to nothing.
 */
export function createLoopbackTestGate(
  requires: readonly LoopbackBindScope[],
  runner: LoopbackTestRunner,
  options: ResolveLoopbackOptions = {},
): LoopbackTestGate {
  const requirement = resolveLoopbackRequirement(requires, options);
  if (requirement.decision === "run") {
    return {
      requirement,
      describe: (name, body) => void runner.describe(name, body),
      test: (name, body) => void runner.test(name, body),
    };
  }
  if (requirement.decision === "skip") {
    return {
      requirement,
      describe: (name, body) => void runner.describe.skip(name, body),
      test: (name, body) => void runner.test.skip(name, body),
    };
  }
  const failClosed = (name: string) => {
    runner.test(name, () => {
      throw new Error(loopbackUnavailableMessage(name, requirement.missing));
    });
  };
  return {
    requirement,
    describe: (name) => void runner.describe(name, () => failClosed(name)),
    test: (name) => failClosed(name),
  };
}
