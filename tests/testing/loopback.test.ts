import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import {
  canBind,
  createLoopbackTestGate,
  LOOPBACK_PROBE_DENY_ENV,
  LOOPBACK_SKIP_ENV,
  loopbackSkipAllowed,
  loopbackUnavailableMessage,
  resolveLoopbackRequirement,
  type LoopbackBindScope,
  type LoopbackTestRunner,
} from "../../src/testing/loopback.js";

const root = join(import.meta.dir, "..", "..");

interface RegisteredCase {
  readonly kind: "test" | "test.skip";
  readonly name: string;
  readonly body: () => void | Promise<void>;
}

interface RegisteredSuite {
  readonly kind: "describe" | "describe.skip";
  readonly name: string;
  readonly body: () => void;
}

function recordingRunner() {
  const cases: RegisteredCase[] = [];
  const suites: RegisteredSuite[] = [];
  const describeFn = ((name: string, body: () => void) => {
    suites.push({ kind: "describe", name, body });
  }) as LoopbackTestRunner["describe"];
  Object.assign(describeFn, {
    skip: (name: string, body: () => void) => {
      suites.push({ kind: "describe.skip", name, body });
    },
  });
  const testFn = ((name: string, body: () => void | Promise<void>) => {
    cases.push({ kind: "test", name, body });
  }) as LoopbackTestRunner["test"];
  Object.assign(testFn, {
    skip: (name: string, body: () => void | Promise<void>) => {
      cases.push({ kind: "test.skip", name, body });
    },
  });
  return { runner: { describe: describeFn, test: testFn } as LoopbackTestRunner, cases, suites };
}

const denyAll = () => false;
const allowAll = () => true;

describe("resolveLoopbackRequirement — fail-closed bind policy", () => {
  test("an available bind runs", () => {
    const requirement = resolveLoopbackRequirement(["loopback", "wildcard"], {
      probe: allowAll,
      skipAllowed: false,
    });
    expect(requirement.decision).toBe("run");
    expect(requirement.missing).toEqual([]);
  });

  test("an unavailable bind FAILS rather than silently skipping", () => {
    const requirement = resolveLoopbackRequirement(["wildcard"], {
      probe: denyAll,
      skipAllowed: false,
    });
    expect(requirement.decision).toBe("fail");
    expect(requirement.missing).toEqual(["wildcard"]);
  });

  test("skipping requires the explicit opt-in", () => {
    const requirement = resolveLoopbackRequirement(["wildcard"], {
      probe: denyAll,
      skipAllowed: true,
    });
    expect(requirement.decision).toBe("skip");
  });

  test("capabilities are probed per requirement, not globally", () => {
    // The common sandbox restriction: the wildcard bind is denied while
    // 127.0.0.1 still works. A suite that only binds 127.0.0.1 must still run.
    const probe = (scope: LoopbackBindScope) => scope === "loopback";
    expect(resolveLoopbackRequirement(["loopback"], { probe, skipAllowed: false }).decision)
      .toBe("run");
    expect(resolveLoopbackRequirement(["wildcard"], { probe, skipAllowed: false }).decision)
      .toBe("fail");
    expect(
      resolveLoopbackRequirement(["loopback", "wildcard"], { probe, skipAllowed: false }).missing,
    ).toEqual(["wildcard"]);
  });

  test("the unavailable message names the scopes, the address, and the opt-in", () => {
    const message = loopbackUnavailableMessage("suite", ["wildcard"]);
    expect(message).toContain("wildcard (0.0.0.0)");
    expect(message).toContain("fail-closed");
    expect(message).toContain(LOOPBACK_SKIP_ENV);
  });
});

describe("createLoopbackTestGate", () => {
  test("registers a FAILING case, not a skip, when the bind is unavailable", async () => {
    const { runner, cases } = recordingRunner();
    const gate = createLoopbackTestGate(["wildcard"], runner, {
      probe: denyAll,
      skipAllowed: false,
    });
    gate.test("cross-authority redirect boundary", () => {
      throw new Error("gated body must not run");
    });

    expect(gate.requirement.decision).toBe("fail");
    expect(cases).toHaveLength(1);
    expect(cases[0]!.kind).toBe("test");
    await expect(Promise.resolve().then(() => cases[0]!.body())).rejects.toThrow(
      /needs an HTTP bind this runtime refused/,
    );
  });

  test("never executes the gated suite body when the bind is unavailable", () => {
    const { runner, suites } = recordingRunner();
    let bodyRan = false;
    const gate = createLoopbackTestGate(["wildcard"], runner, {
      probe: denyAll,
      skipAllowed: false,
    });
    gate.describe("end-to-end flip", () => {
      bodyRan = true;
    });

    expect(suites).toHaveLength(1);
    suites[0]!.body();
    expect(bodyRan).toBe(false);
  });

  test("uses the runner's skip only under the explicit opt-in", () => {
    const { runner, cases, suites } = recordingRunner();
    const gate = createLoopbackTestGate(["wildcard"], runner, {
      probe: denyAll,
      skipAllowed: true,
    });
    gate.test("case", () => {});
    gate.describe("suite", () => {});
    expect(cases[0]!.kind).toBe("test.skip");
    expect(suites[0]!.kind).toBe("describe.skip");
  });

  test("passes the real runner through when the bind is available", () => {
    const { runner, cases, suites } = recordingRunner();
    const gate = createLoopbackTestGate(["loopback"], runner, {
      probe: allowAll,
      skipAllowed: false,
    });
    gate.test("case", () => {});
    gate.describe("suite", () => {});
    expect(cases[0]!.kind).toBe("test");
    expect(suites[0]!.kind).toBe("describe");
  });
});

describe("the probe deny seam can only tighten a gate", () => {
  test("a denied scope reports unavailable without touching the cache", () => {
    expect(canBind("wildcard", { [LOOPBACK_PROBE_DENY_ENV]: "wildcard" })).toBe(false);
    expect(canBind("loopback", { [LOOPBACK_PROBE_DENY_ENV]: "wildcard" })).toBe(true);
    expect(canBind("wildcard", {})).toBe(true);
  });

  test("the skip opt-in is exact, not truthy", () => {
    expect(loopbackSkipAllowed({ [LOOPBACK_SKIP_ENV]: "1" })).toBe(true);
    expect(loopbackSkipAllowed({ [LOOPBACK_SKIP_ENV]: "true" })).toBe(false);
    expect(loopbackSkipAllowed({ [LOOPBACK_SKIP_ENV]: "" })).toBe(false);
    expect(loopbackSkipAllowed({})).toBe(false);
  });
});

// The publish gate (`smoke:dist`, run by `verify:release`, which is `prepack`
// and `prepublishOnly`) must never print "dist smoke passed" on a run that
// could not exercise the authenticated-redirect credential boundary. These
// cases drive the real script, so the guarantee is asserted on the artifact
// that actually gates npm rather than on a re-implementation of it.
describe("scripts/smoke-dist.ts publish gate", () => {
  function runSmokeDist(env: Record<string, string>) {
    const result = Bun.spawnSync(["bun", "scripts/smoke-dist.ts"], {
      cwd: root,
      env: { ...process.env, ...env },
      stdout: "pipe",
      stderr: "pipe",
    });
    return {
      exitCode: result.exitCode,
      stdout: new TextDecoder().decode(result.stdout),
      stderr: new TextDecoder().decode(result.stderr),
    };
  }

  test("refuses to run when a required bind is unavailable", () => {
    const result = runSmokeDist({
      [LOOPBACK_PROBE_DENY_ENV]: "wildcard",
      [LOOPBACK_SKIP_ENV]: "",
    });
    expect(result.stdout).not.toContain("dist smoke passed");
    expect(result.exitCode).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain(
      "needs an HTTP bind this runtime refused",
    );
  });

  test("refuses the skip opt-in and reports UNVERIFIED instead of passing", () => {
    const result = runSmokeDist({
      [LOOPBACK_PROBE_DENY_ENV]: "wildcard",
      [LOOPBACK_SKIP_ENV]: "1",
    });
    expect(result.stdout).not.toContain("dist smoke passed");
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("dist smoke UNVERIFIED");
  });
});
