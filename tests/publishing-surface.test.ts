// Regression suite for the optional `publishing` manifest surface.
//
// The surface exists because npm is retiring 2FA-bypass granular tokens: from
// phase 2 those tokens can only read and stage, so every package that ships
// needs a declared release path (trusted publishing or staged publishing).
// Nothing in the manifest modelled how a package SHIPS — only what it exposes.
//
// Two properties are load-bearing and each has a test below:
//
//   1. ADDITIVE — every manifest that validated before still validates, and
//      `publishing` is absent from `required`.
//   2. ORTHOGONAL AXES — mechanism, credential, flow and provenance are
//      separate fields rather than one enum, because the most advanced
//      pipeline in the fleet (hasna/accounts: CI + trusted publisher + staged
//      + provenance, driven by a bespoke script) cannot be expressed by a
//      single value without losing three of its four properties.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  SCHEMA_IDS,
  SERVICE_CONTRACT_VERSION,
  SERVICE_CONTRACT_JSON_SCHEMA,
  PUBLISH_STATUSES,
  PUBLISH_MECHANISMS,
  PUBLISH_CREDENTIALS,
  PUBLISH_FLOWS,
  PROVENANCE_MODES,
  PUBLISH_WORKFLOW_PROVIDERS,
  validateServiceContractManifest,
} from "../src";

const repoRoot = join(import.meta.dir, "..");

const baseManifest = {
  schema: SCHEMA_IDS.serviceContract,
  name: "todos",
  class: "cli-with-store",
  contractVersion: SERVICE_CONTRACT_VERSION,
  kitVersion: "0.9.0",
  bins: ["todos", "todos-mcp"],
  storage: {
    backend: "sqlite",
    sqlitePath: "~/.hasna/todos/todos.db",
  },
} as const;

const withPublishing = (publishing: unknown) => ({ ...baseManifest, publishing });

const ciTarget = {
  package: "@hasna/todos",
  registry: "registry.npmjs.org",
  mechanism: "ci",
  credential: "trusted-publisher",
  workflow: {
    provider: "github-actions",
    repository: "hasna/todos",
    file: "publish.yml",
    environment: "release",
  },
} as const;

describe("publishing is additive and optional", () => {
  test("positive control: the base manifest with no publishing is valid", () => {
    expect(validateServiceContractManifest(baseManifest).success).toBe(true);
  });

  test("publishing is not a required top-level property", () => {
    expect(SERVICE_CONTRACT_JSON_SCHEMA.required).not.toContain("publishing");
  });

  test("omitting publishing leaves the parsed manifest without the key", () => {
    const result = validateServiceContractManifest(baseManifest);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.publishing).toBeUndefined();
    }
  });

  test("a manifest declaring publishing is valid", () => {
    expect(
      validateServiceContractManifest(
        withPublishing({ status: "published", targets: [ciTarget] }),
      ).success,
    ).toBe(true);
  });
});

describe("status is a positive statement, not an absence", () => {
  test("unpublished is declarable and distinct from omitting publishing", () => {
    const result = validateServiceContractManifest(
      withPublishing({ status: "unpublished" }),
    );
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.publishing?.status).toBe("unpublished");
    }
  });

  test("published with no targets is refused", () => {
    const result = validateServiceContractManifest(
      withPublishing({ status: "published", targets: [] }),
    );
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(JSON.stringify(result.error.issues)).toContain("at least one target");
    }
  });

  test("unpublished carrying targets is refused", () => {
    const result = validateServiceContractManifest(
      withPublishing({ status: "unpublished", targets: [ciTarget] }),
    );
    expect(result.success).toBe(false);
  });

  test("there is no unknown status; the survey's uncertainty is not the repo's", () => {
    expect(PUBLISH_STATUSES).toEqual(["published", "unpublished"]);
    expect(
      validateServiceContractManifest(withPublishing({ status: "unknown" })).success,
    ).toBe(false);
  });
});

describe("mechanism and credential are separate axes", () => {
  test("manual publishing is representable — it is the fleet's dominant state", () => {
    const result = validateServiceContractManifest(
      withPublishing({
        status: "published",
        targets: [
          {
            package: "@hasna/todos",
            registry: "registry.npmjs.org",
            mechanism: "manual",
            credential: "token",
          },
        ],
      }),
    );
    expect(result.success).toBe(true);
  });

  test("mechanism=ci requires the workflow triple", () => {
    const result = validateServiceContractManifest(
      withPublishing({
        status: "published",
        targets: [
          {
            package: "@hasna/todos",
            registry: "registry.npmjs.org",
            mechanism: "ci",
            credential: "token",
          },
        ],
      }),
    );
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(JSON.stringify(result.error.issues)).toContain("mechanism=ci requires workflow");
    }
  });

  test("mechanism=manual must not carry a workflow", () => {
    const result = validateServiceContractManifest(
      withPublishing({
        status: "published",
        targets: [{ ...ciTarget, mechanism: "manual", credential: "token" }],
      }),
    );
    expect(result.success).toBe(false);
  });

  test("trusted-publisher is refused outside CI — workload identity needs a job", () => {
    const result = validateServiceContractManifest(
      withPublishing({
        status: "published",
        targets: [
          {
            package: "@hasna/todos",
            registry: "registry.npmjs.org",
            mechanism: "manual",
            credential: "trusted-publisher",
          },
        ],
      }),
    );
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(JSON.stringify(result.error.issues)).toContain("trusted-publisher requires mechanism=ci");
    }
  });

  test("flow and provenance default without being declared", () => {
    const result = validateServiceContractManifest(
      withPublishing({ status: "published", targets: [ciTarget] }),
    );
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.publishing?.targets[0]?.flow).toBe("direct");
      expect(result.data.publishing?.targets[0]?.provenance).toBe("none");
    }
  });

  test("the four axes are independent vocabularies", () => {
    expect(PUBLISH_MECHANISMS).toEqual(["ci", "manual"]);
    expect(PUBLISH_CREDENTIALS).toEqual(["trusted-publisher", "token"]);
    expect(PUBLISH_FLOWS).toEqual(["direct", "staged"]);
    expect(PROVENANCE_MODES).toEqual(["required", "best-effort", "none"]);
  });
});

describe("registry is declared, never assumed", () => {
  test("a registry other than npm is accepted", () => {
    expect(
      validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [{ ...ciTarget, registry: "npm.pkg.github.com" }],
        }),
      ).success,
    ).toBe(true);
  });

  test("a registry with a port and path is accepted", () => {
    expect(
      validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [{ ...ciTarget, registry: "registry.example.test:8443/npm" }],
        }),
      ).success,
    ).toBe(true);
  });

  test("a scheme is refused so the field cannot carry a URL", () => {
    expect(
      validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [{ ...ciTarget, registry: "https://registry.npmjs.org" }],
        }),
      ).success,
    ).toBe(false);
  });

  test("embedded credentials are structurally impossible in registry", () => {
    // This repo is public. A registry URL with userinfo would put a live
    // credential in a world-readable manifest, so the shape forbids it rather
    // than relying on review to notice.
    for (const hostile of [
      "user:hunter2@registry.npmjs.org",
      "https://user:hunter2@registry.npmjs.org",
      "token@registry.npmjs.org",
    ]) {
      const result = validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [{ ...ciTarget, registry: hostile }],
        }),
      );
      expect(result.success, `registry ${hostile} must be refused`).toBe(false);
    }
  });
});

describe("workflow names the registration triple exactly", () => {
  test("environment is optional and its absence means no gate", () => {
    const { environment, ...noEnv } = ciTarget.workflow;
    const result = validateServiceContractManifest(
      withPublishing({
        status: "published",
        targets: [{ ...ciTarget, workflow: noEnv }],
      }),
    );
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.publishing?.targets[0]?.workflow?.environment).toBeUndefined();
    }
  });

  test("a workflow path is refused; registries key on the bare filename", () => {
    const result = validateServiceContractManifest(
      withPublishing({
        status: "published",
        targets: [
          { ...ciTarget, workflow: { ...ciTarget.workflow, file: ".github/workflows/publish.yml" } },
        ],
      }),
    );
    expect(result.success).toBe(false);
  });

  test(".yaml is accepted alongside .yml", () => {
    expect(
      validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [{ ...ciTarget, workflow: { ...ciTarget.workflow, file: "release.yaml" } }],
        }),
      ).success,
    ).toBe(true);
  });

  test("the CI provider is declared rather than assumed to be GitHub", () => {
    expect(PUBLISH_WORKFLOW_PROVIDERS).toEqual(["github-actions", "gitlab-ci"]);
    expect(
      validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [
            { ...ciTarget, workflow: { ...ciTarget.workflow, provider: "gitlab-ci" } },
          ],
        }),
      ).success,
    ).toBe(true);
  });

  test("a repository that is not owner/repo is refused", () => {
    expect(
      validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [{ ...ciTarget, workflow: { ...ciTarget.workflow, repository: "todos" } }],
        }),
      ).success,
    ).toBe(false);
  });
});

describe("the surface fits the release paths actually in use", () => {
  // The six distinct (workflow file, environment) pairs measured across the 26
  // repos that publish from CI today. An empty string in the survey means the
  // workflow declares no environment, which is expressed here by omitting it.
  const observed: ReadonlyArray<readonly [string, string | undefined]> = [
    ["rust-release.yml", undefined],
    ["publish.yml", undefined],
    ["publish-package.yml", "publish"],
    ["release.yml", undefined],
    ["publish.yml", "release"],
    ["publish-package.yml", undefined],
  ];

  for (const [file, environment] of observed) {
    test(`observed combination ${file} / ${environment ?? "(no environment)"} is expressible`, () => {
      const workflow = {
        provider: "github-actions",
        repository: "hasna/example",
        file,
        ...(environment ? { environment } : {}),
      };
      const result = validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [{ ...ciTarget, workflow }],
        }),
      );
      expect(result.success).toBe(true);
    });
  }

  test("the hasna/accounts pipeline survives without losing any of its four properties", () => {
    // accounts publishes via `bun run scripts/release-provenance.ts
    // publish-staged`, so a detector that greps run-steps for `npm publish`
    // records it as having no publish job. It is in fact the most advanced
    // pipeline in the fleet, and every one of its properties must survive a
    // round trip through the schema.
    const result = validateServiceContractManifest(
      withPublishing({
        status: "published",
        targets: [
          {
            package: "@hasna/accounts",
            registry: "registry.npmjs.org",
            access: "public",
            mechanism: "ci",
            credential: "trusted-publisher",
            flow: "staged",
            provenance: "required",
            workflow: {
              provider: "github-actions",
              repository: "hasna/accounts",
              file: "release.yml",
              environment: "npm-release",
            },
          },
        ],
      }),
    );
    expect(result.success).toBe(true);
    if (result.success) {
      const target = result.data.publishing?.targets[0];
      expect(target?.mechanism).toBe("ci");
      expect(target?.credential).toBe("trusted-publisher");
      expect(target?.flow).toBe("staged");
      expect(target?.provenance).toBe("required");
    }
  });

  test("a repo publishing several packages declares one target each", () => {
    const result = validateServiceContractManifest(
      withPublishing({
        status: "published",
        targets: [
          { ...ciTarget, package: "@hasna/todos" },
          { ...ciTarget, package: "@hasna/todos-sdk" },
        ],
      }),
    );
    expect(result.success).toBe(true);
  });

  test("the same package at two registries is allowed; a duplicate pair is not", () => {
    expect(
      validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [
            { ...ciTarget, registry: "registry.npmjs.org" },
            { ...ciTarget, registry: "npm.pkg.github.com" },
          ],
        }),
      ).success,
    ).toBe(true);

    const duplicate = validateServiceContractManifest(
      withPublishing({ status: "published", targets: [ciTarget, ciTarget] }),
    );
    expect(duplicate.success).toBe(false);
    if (!duplicate.success) {
      expect(JSON.stringify(duplicate.error.issues)).toContain("Duplicate publish target");
    }
  });
});

describe("the surface stays closed", () => {
  test("an unknown key inside publishing is refused, not ignored", () => {
    expect(
      validateServiceContractManifest(
        withPublishing({ status: "published", targets: [ciTarget], cadence: "weekly" }),
      ).success,
    ).toBe(false);
  });

  test("an unknown key inside a target is refused", () => {
    expect(
      validateServiceContractManifest(
        withPublishing({
          status: "published",
          targets: [{ ...ciTarget, tokenName: "NPM_TOKEN" }],
        }),
      ).success,
    ).toBe(false);
  });

  test("both JSON Schema copies carry publishing and keep it closed", () => {
    const shipped = JSON.parse(
      readFileSync(join(repoRoot, "src", "hasna.contract.schema.json"), "utf8"),
    );
    for (const [label, schema] of [
      ["exported constant", SERVICE_CONTRACT_JSON_SCHEMA],
      ["shipped file", shipped],
    ] as const) {
      const publishing = (schema as any).properties?.publishing;
      expect(publishing, `${label} declares publishing`).toBeDefined();
      expect(publishing.additionalProperties, `${label} publishing is closed`).toBe(false);
      expect(publishing.properties.targets.items.additionalProperties).toBe(false);
      expect(publishing.properties.targets.items.properties.workflow.additionalProperties).toBe(
        false,
      );
      expect((schema as any).required).not.toContain("publishing");
    }
  });
});
