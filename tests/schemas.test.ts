import { describe, expect, test } from "bun:test";
import {
  ActorRefSchema,
  AppCloudManifestSchema,
  ContractSchemaRegistry,
  type EvidenceRef,
  EvidenceRefSchema,
  IntegrationRefSchema,
  NoCloudEvidencePackSchema,
  parseEmbeddedContract,
  parseContract,
  ProviderLiveModeStandardSchema,
  ProjectManifestSchema,
  ProjectPanelSchema,
  ProjectSnapshotSchema,
  ProofBundleSchema,
  RenderManifestSchema,
  ScaffoldInstallRecordSchema,
  ScaffoldManifestSchema,
  SCHEMA_IDS,
  validateEmbeddedContract,
  validateContract,
  WorkRunSchema
} from "../src";
import providerLiveModeStandard from "../examples/provider-live-mode-standard.valid.json";

const createdAt = "2026-06-27T10:00:00.000Z";

const actor = {
  id: "actor_codewith_004",
  kind: "agent",
  name: "Codewith account004"
} as const;

const taskRef = {
  id: "task_123",
  kind: "task",
  externalId: "task_123",
  sourcePackage: "@hasna/todos"
} as const;

const evidence = {
  id: "ev_123",
  kind: "command_output",
  uri: "artifact://runs/run_123/test-output.txt",
  redaction: "none",
  producer: actor,
  resourceRefs: [taskRef]
} as const;

const evidencePointer = {
  id: evidence.id,
  kind: evidence.kind,
  uri: evidence.uri,
  summary: "typecheck output"
} as const;

describe("core schemas", () => {
  test("registry contains only concrete schemas", () => {
    for (const [schemaId, schema] of Object.entries(ContractSchemaRegistry)) {
      const parsed = schema.safeParse({ schema: schemaId, id: "x", createdAt });
      if (schemaId === SCHEMA_IDS.actorRef) {
        expect(parsed.success).toBe(false);
      }
    }
  });

  test("validates actor and evidence refs", () => {
    expect(ActorRefSchema.parse({ ...actor, schema: SCHEMA_IDS.actorRef, createdAt }).id).toBe("actor_codewith_004");
    expect(EvidenceRefSchema.parse({ ...evidence, schema: SCHEMA_IDS.evidenceRef, createdAt }).resourceRefs).toHaveLength(1);
  });

  test("validator helpers return schema-specific types", () => {
    const value = { ...evidence, schema: SCHEMA_IDS.evidenceRef, createdAt };
    const parsed: EvidenceRef = parseContract(SCHEMA_IDS.evidenceRef, value);
    expect(parsed.uri).toBe(evidence.uri);

    const result = validateContract(SCHEMA_IDS.evidenceRef, value);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.uri).toBe(evidence.uri);
    }
  });

  test("embedded helpers dispatch by schema field", () => {
    const value = { ...evidence, schema: SCHEMA_IDS.evidenceRef, createdAt };
    const result = validateEmbeddedContract(value);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.schemaId).toBe(SCHEMA_IDS.evidenceRef);
      expect((result.data as EvidenceRef).id).toBe(evidence.id);
    }

    expect((parseEmbeddedContract(value) as EvidenceRef).id).toBe(evidence.id);
    expect(validateEmbeddedContract({ schema: "hasna.missing.v1", id: "x" }).success).toBe(false);
  });

  test("rejects unknown top-level fields under the same schema id", () => {
    const result = validateContract(SCHEMA_IDS.actorRef, {
      ...actor,
      schema: SCHEMA_IDS.actorRef,
      createdAt,
      futureField: "requires a coordinated schema rollout"
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((issue) => issue.code === "unrecognized_keys" && issue.keys.includes("futureField"))).toBe(true);
    }
  });

  test("rejects contradictory cost estimates", () => {
    const result = validateContract(SCHEMA_IDS.costEstimate, {
      schema: SCHEMA_IDS.costEstimate,
      id: "cost_bad",
      createdAt,
      currency: "usd",
      amountMicros: 1,
      promptTokens: 10,
      completionTokens: 20,
      totalTokens: 999
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      const paths = result.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("currency");
      expect(paths).toContain("totalTokens");
    }
  });

  test("allows compact local resource pointers but validates portable resource refs", () => {
    const localPointer = validateContract(SCHEMA_IDS.workRun, {
      schema: SCHEMA_IDS.workRun,
      id: "run_local_pointer",
      createdAt,
      objective: "Use compact local pointer",
      status: "succeeded",
      actor,
      finishedAt: createdAt,
      resourceRefs: [{ kind: "task", id: "task_local" }],
      evidenceRefs: [evidencePointer]
    });
    expect(localPointer.success).toBe(true);

    const brokenRef = validateContract(SCHEMA_IDS.resourceRef, {
      schema: SCHEMA_IDS.resourceRef,
      id: "task_bad",
      createdAt,
      kind: "task",
      sourcePackage: "@hasna/todos"
    });
    expect(brokenRef.success).toBe(false);
  });

  test("allows compact local evidence pointers while evidence refs stay dereferenceable", () => {
    const compactEvidencePointer = validateContract(SCHEMA_IDS.workRun, {
      schema: SCHEMA_IDS.workRun,
      id: "run_compact_evidence",
      createdAt,
      objective: "Use compact evidence pointer",
      status: "succeeded",
      actor,
      finishedAt: createdAt,
      evidenceRefs: [{ id: "ev_tests" }]
    });
    expect(compactEvidencePointer.success).toBe(true);

    const missingEvidenceUri = validateContract(SCHEMA_IDS.evidenceRef, {
      schema: SCHEMA_IDS.evidenceRef,
      id: "ev_missing_uri",
      createdAt,
      kind: "command_output"
    });
    expect(missingEvidenceUri.success).toBe(false);
  });

  test("rejects whitespace and unsupported evidence URIs", () => {
    for (const uri of ["   ", "ftp://example.test/evidence.txt"]) {
      const result = validateContract(SCHEMA_IDS.evidenceRef, {
        ...evidence,
        schema: SCHEMA_IDS.evidenceRef,
        createdAt,
        uri
      });
      expect(result.success).toBe(false);
    }
  });

  test("rejects contradictory decisions", () => {
    const selectedWithoutResource = validateContract(SCHEMA_IDS.decisionEnvelope, {
      schema: SCHEMA_IDS.decisionEnvelope,
      id: "decision_bad",
      createdAt,
      decisionType: "model_route",
      status: "selected",
      reason: "No selected target."
    });
    expect(selectedWithoutResource.success).toBe(false);

    const deniedWithSelected = validateContract(SCHEMA_IDS.decisionEnvelope, {
      schema: SCHEMA_IDS.decisionEnvelope,
      id: "decision_denied_bad",
      createdAt,
      decisionType: "policy",
      status: "denied",
      selected: [taskRef],
      reason: "Denied while still selecting a target.",
      policyBundleId: "policy_default"
    });
    expect(deniedWithSelected.success).toBe(false);
  });

  test("validates provider live-mode standard first targets", () => {
    const parsed = ProviderLiveModeStandardSchema.parse(providerLiveModeStandard);
    expect(parsed.modes).toEqual(["mock", "fixture", "sandbox", "read_only_live", "live_mutating"]);
    expect(parsed.credentialPolicy.rawSecretInputsAllowed).toBe(false);
    expect(parsed.credentialPolicy.missingCredentialBehavior).toBe("fail_closed");
    expect(parsed.firstAdoptionTargets.map((target) => target.appId).sort()).toEqual([
      "open-feedback",
      "open-mailery",
      "open-telephony"
    ]);
  });

  test("rejects live provider mutation without approval, idempotency, sandbox evidence, and rollback", () => {
    const result = ProviderLiveModeStandardSchema.safeParse({
      ...providerLiveModeStandard,
      operationCards: [
        {
          providerId: "twilio",
          appId: "open-telephony",
          adapterId: "telephony-twilio",
          ownerPackage: "@hasna/telephony",
          modes: ["fixture", "live_mutating"],
          defaultMode: "fixture",
          credentialRequirements: [],
          operations: [
            {
              operation: "send_sms",
              supportedModes: ["live_mutating"],
              sideEffectClass: "read_only",
              requiresApproval: false,
              requiresIdempotencyKey: false,
              requiresSandboxEvidence: false,
              requiresRollbackOrRevocation: false
            }
          ],
          rateLimitPosture: "none"
        }
      ],
      firstAdoptionTargets: [
        {
          appId: "open-telephony",
          repo: "/home/hasna/workspace/hasna/opensource/open-telephony",
          priority: "p0",
          requiredEvidence: ["webhook fixture"],
          firstOperations: ["send_sms"]
        }
      ]
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      const issuePaths = result.error.issues.map((issue) => issue.path.join("."));
      expect(issuePaths).toContain("operationCards.0.operations.0.sideEffectClass");
      expect(issuePaths).toContain("operationCards.0.operations.0.requiresApproval");
      expect(issuePaths).toContain("operationCards.0.operations.0.requiresIdempotencyKey");
      expect(issuePaths).toContain("operationCards.0.operations.0.requiresSandboxEvidence");
      expect(issuePaths).toContain("operationCards.0.operations.0.rollbackOrRevocation");
      expect(issuePaths).toContain("operationCards.0.operations.0.reconciliation");
      expect(issuePaths).toContain("operationCards.0.credentialRequirements");
    }
  });

  test("validates a work run with nested evidence", () => {
    const workRun = WorkRunSchema.parse({
      schema: SCHEMA_IDS.workRun,
      id: "run_123",
      createdAt,
      objective: "Implement shared contracts",
      status: "succeeded",
      actor,
      finishedAt: createdAt,
      resourceRefs: [taskRef],
      evidenceRefs: [evidencePointer]
    });

    expect(workRun.evidenceRefs[0]?.id).toBe("ev_123");
  });

  test("rejects terminal work runs without evidence or valid chronology", () => {
    const noEvidence = validateContract(SCHEMA_IDS.workRun, {
      schema: SCHEMA_IDS.workRun,
      id: "run_no_evidence",
      createdAt,
      objective: "Claim success without evidence",
      status: "succeeded",
      actor,
      finishedAt: createdAt
    });
    expect(noEvidence.success).toBe(false);

    const backwards = validateContract(SCHEMA_IDS.workRun, {
      schema: SCHEMA_IDS.workRun,
      id: "run_backwards",
      createdAt,
      objective: "Finish before start",
      status: "failed",
      actor,
      startedAt: "2026-06-27T10:05:00.000Z",
      finishedAt: "2026-06-27T10:00:00.000Z",
      evidenceRefs: [evidencePointer]
    });
    expect(backwards.success).toBe(false);
  });

  test("validates proof bundles", () => {
    const proof = ProofBundleSchema.parse({
      schema: SCHEMA_IDS.proofBundle,
      id: "proof_123",
      createdAt,
      subject: taskRef,
      status: "succeeded",
      verdict: "passed",
      checks: [
        {
          checkId: "typecheck",
          status: "succeeded",
          evidenceRefs: [evidencePointer]
        }
      ],
      verifier: actor
    });

    expect(proof.checks[0]?.status).toBe("succeeded");
  });

  test("validates project manifests with standardized layout and integration refs", () => {
    const integration = IntegrationRefSchema.parse({
      schema: SCHEMA_IDS.integrationRef,
      id: "integration_todos_swiss_bank_account",
      createdAt,
      kind: "todos",
      name: "Project todos",
      projectId: "swiss-bank-account",
      sourcePackage: "@hasna/todos",
      externalId: "swiss-bank-account"
    });

    const manifest = ProjectManifestSchema.parse({
      schema: SCHEMA_IDS.projectManifest,
      id: "project_swiss_bank_account",
      createdAt,
      projectId: "swiss-bank-account",
      slug: "swiss-bank-account",
      name: "Swiss Bank Account",
      classification: "sensitive",
      integrations: [integration]
    });

    expect(manifest.layout.schemaRoot).toBe(".hasna/project");
    expect(manifest.integrations[0]?.kind).toBe("todos");
  });

  test("rejects unsafe project paths and manifest integration mismatches", () => {
    const unsafePath = validateContract(SCHEMA_IDS.projectManifest, {
      schema: SCHEMA_IDS.projectManifest,
      id: "project_unsafe_path",
      createdAt,
      projectId: "swiss-bank-account",
      slug: "swiss-bank-account",
      name: "Swiss Bank Account",
      layout: {
        dashboardManifest: "../dashboard.json"
      }
    });
    expect(unsafePath.success).toBe(false);
    if (!unsafePath.success) {
      expect(unsafePath.error.issues.map((issue) => issue.path.join("."))).toContain("layout.dashboardManifest");
    }

    const mismatch = validateContract(SCHEMA_IDS.projectManifest, {
      schema: SCHEMA_IDS.projectManifest,
      id: "project_mismatch",
      createdAt,
      projectId: "swiss-bank-account",
      slug: "swiss-bank-account",
      name: "Swiss Bank Account",
      integrations: [
        {
          schema: SCHEMA_IDS.integrationRef,
          id: "integration_wrong_project",
          createdAt,
          kind: "todos",
          name: "Wrong project",
          projectId: "other-project",
          sourcePackage: "@hasna/todos",
          externalId: "other-project"
        }
      ]
    });
    expect(mismatch.success).toBe(false);
    if (!mismatch.success) {
      expect(mismatch.error.issues.map((issue) => issue.path.join("."))).toContain("integrations.0.projectId");
    }

    const duplicateAndWrongRenderKind = validateContract(SCHEMA_IDS.projectManifest, {
      schema: SCHEMA_IDS.projectManifest,
      id: "project_bad_refs",
      createdAt,
      projectId: "swiss-bank-account",
      slug: "swiss-bank-account",
      name: "Swiss Bank Account",
      integrations: [
        {
          schema: SCHEMA_IDS.integrationRef,
          id: "integration_duplicate",
          createdAt,
          kind: "todos",
          name: "Todos",
          sourcePackage: "@hasna/todos",
          externalId: "swiss-bank-account"
        },
        {
          schema: SCHEMA_IDS.integrationRef,
          id: "integration_duplicate",
          createdAt,
          kind: "files",
          name: "Files",
          sourcePackage: "@hasna/files",
          externalId: "swiss-bank-account"
        }
      ],
      renderManifests: [{ kind: "file", id: "render_dashboard", uri: "render://projects/swiss-bank-account/dashboard" }]
    });
    expect(duplicateAndWrongRenderKind.success).toBe(false);
    if (!duplicateAndWrongRenderKind.success) {
      const paths = duplicateAndWrongRenderKind.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("integrations.1.id");
      expect(paths).toContain("renderManifests.0.kind");
    }
  });

  test("validates project panels and requires explanations for unavailable provider states", () => {
    const readyPanel = ProjectPanelSchema.parse({
      schema: SCHEMA_IDS.projectPanel,
      id: "panel_tasks",
      createdAt,
      projectId: "swiss-bank-account",
      provider: { kind: "todos", id: "integration_todos" },
      kind: "tasks",
      title: "Tasks",
      generatedAt: createdAt,
      metrics: [{ id: "open_tasks", label: "Open tasks", value: 3 }]
    });
    expect(readyPanel.metrics[0]?.status).toBe("unknown");

    const emptyPanel = ProjectPanelSchema.parse({
      schema: SCHEMA_IDS.projectPanel,
      id: "panel_empty",
      createdAt,
      projectId: "swiss-bank-account",
      provider: { kind: "files", id: "integration_files" },
      kind: "files",
      title: "Files",
      state: "empty",
      generatedAt: createdAt
    });
    expect(emptyPanel.state).toBe("empty");

    const missingReason = validateContract(SCHEMA_IDS.projectPanel, {
      schema: SCHEMA_IDS.projectPanel,
      id: "panel_auth",
      createdAt,
      projectId: "swiss-bank-account",
      provider: { kind: "mailery", id: "integration_mailery" },
      kind: "mailery",
      title: "Email",
      state: "auth_required",
      generatedAt: createdAt
    });
    expect(missingReason.success).toBe(false);
    if (!missingReason.success) {
      expect(missingReason.error.issues.map((issue) => issue.path.join("."))).toContain("stateReason");
    }

    const duplicateMetricsAndWrongAction = validateContract(SCHEMA_IDS.projectPanel, {
      schema: SCHEMA_IDS.projectPanel,
      id: "panel_duplicate_metrics",
      createdAt,
      projectId: "swiss-bank-account",
      provider: { kind: "actions", id: "integration_actions" },
      kind: "actions",
      title: "Actions",
      generatedAt: createdAt,
      metrics: [
        { id: "available_actions", label: "Available actions", value: 2 },
        { id: "available_actions", label: "Duplicate actions", value: 2 }
      ],
      actions: [{ kind: "tool", id: "action_open_contract", uri: "integration://actions/open-contract" }]
    });
    expect(duplicateMetricsAndWrongAction.success).toBe(false);
    if (!duplicateMetricsAndWrongAction.success) {
      const paths = duplicateMetricsAndWrongAction.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("metrics.1.id");
      expect(paths).toContain("actions.0.kind");
    }
  });

  test("validates render manifests and import boundaries", () => {
    const manifest = RenderManifestSchema.parse({
      schema: SCHEMA_IDS.renderManifest,
      id: "render_dashboard",
      createdAt,
      projectId: "swiss-bank-account",
      name: "Dashboard",
      version: "0.1.0",
      views: [{ id: "dashboard", title: "Dashboard", kind: "canvas", default: true }]
    });
    expect(manifest.manifestPath).toBe(".hasna/project/dashboard.render.json");

    const duplicateDefaults = validateContract(SCHEMA_IDS.renderManifest, {
      ...manifest,
      id: "render_duplicate_defaults",
      views: [
        { id: "dashboard", title: "Dashboard", kind: "canvas", default: true },
        { id: "documents", title: "Documents", kind: "document", default: true }
      ]
    });
    expect(duplicateDefaults.success).toBe(false);

    const missingImportPath = validateContract(SCHEMA_IDS.renderManifest, {
      ...manifest,
      id: "render_missing_import_path",
      imports: [{ id: "theme", kind: "local", specifier: "theme" }]
    });
    expect(missingImportPath.success).toBe(false);
    if (!missingImportPath.success) {
      expect(missingImportPath.error.issues.map((issue) => issue.path.join("."))).toContain("imports.0.path");
    }

    const duplicateIdsAndWrongPanelRef = validateContract(SCHEMA_IDS.renderManifest, {
      ...manifest,
      id: "render_duplicate_ids",
      imports: [
        { id: "theme", kind: "local", specifier: "theme", path: ".hasna/project/theme.json" },
        { id: "theme", kind: "local", specifier: "theme-copy", path: ".hasna/project/theme-copy.json" }
      ],
      views: [
        {
          id: "dashboard",
          title: "Dashboard",
          kind: "canvas",
          panelRefs: [{ kind: "file", id: "panel_tasks", uri: "dashboard://swiss-bank-account/panels/tasks" }],
          imports: [
            { id: "snapshot", kind: "provider", specifier: "project-snapshot", provider: "todos" },
            { id: "snapshot", kind: "provider", specifier: "project-snapshot-copy", provider: "files" }
          ]
        },
        { id: "dashboard", title: "Duplicate Dashboard", kind: "canvas" }
      ]
    });
    expect(duplicateIdsAndWrongPanelRef.success).toBe(false);
    if (!duplicateIdsAndWrongPanelRef.success) {
      const paths = duplicateIdsAndWrongPanelRef.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("imports.1.id");
      expect(paths).toContain("views.1.id");
      expect(paths).toContain("views.0.imports.1.id");
      expect(paths).toContain("views.0.panelRefs.0.kind");
    }
  });

  test("validates project snapshots and rejects mismatched panel ownership", () => {
    const panel = ProjectPanelSchema.parse({
      schema: SCHEMA_IDS.projectPanel,
      id: "panel_tasks",
      createdAt,
      projectId: "swiss-bank-account",
      provider: { kind: "todos", id: "integration_todos" },
      kind: "tasks",
      title: "Tasks",
      generatedAt: createdAt,
      metrics: [{ id: "open_tasks", label: "Open tasks", value: 3 }]
    });

    const snapshot = ProjectSnapshotSchema.parse({
      schema: SCHEMA_IDS.projectSnapshot,
      id: "snapshot_swiss_bank_account",
      createdAt,
      projectId: "swiss-bank-account",
      generatedAt: createdAt,
      manifestRef: { kind: "project", id: "swiss-bank-account", uri: "project://swiss-bank-account" },
      panels: [panel]
    });
    expect(snapshot.panels).toHaveLength(1);

    const mismatch = validateContract(SCHEMA_IDS.projectSnapshot, {
      ...snapshot,
      id: "snapshot_mismatch",
      panels: [{ ...panel, id: "panel_other", projectId: "other-project" }]
    });
    expect(mismatch.success).toBe(false);
    if (!mismatch.success) {
      expect(mismatch.error.issues.map((issue) => issue.path.join("."))).toContain("panels.0.projectId");
    }

    const badRefs = validateContract(SCHEMA_IDS.projectSnapshot, {
      ...snapshot,
      id: "snapshot_bad_refs",
      manifestRef: { kind: "file", id: "swiss-bank-account", uri: "project://swiss-bank-account" },
      renderManifestRef: { kind: "file", id: "render_dashboard", uri: "render://projects/swiss-bank-account/dashboard" },
      proofBundleRefs: [{ kind: "report", id: "proof_dashboard", uri: "artifact://proof/dashboard.json" }]
    });
    expect(badRefs.success).toBe(false);
    if (!badRefs.success) {
      const paths = badRefs.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("manifestRef.kind");
      expect(paths).toContain("renderManifestRef.kind");
      expect(paths).toContain("proofBundleRefs.0.kind");
    }
  });

  test("validates app-owned cloud manifests without allowing shared cloud runtimes", () => {
    const manifest = AppCloudManifestSchema.parse({
      schema: SCHEMA_IDS.appCloudManifest,
      id: "cloud_manifest_open_todos",
      createdAt,
      packageName: "@hasna/todos",
      appId: "open-todos",
      storageMode: "app_owned_cloud",
      cloudBoundary: "app_owned",
      cloudResources: [
        {
          id: "todos-postgres-primary",
          provider: "aws",
          kind: "database",
          ownerPackage: "@hasna/todos"
        }
      ],
      dependencies: ["@hasna/events"]
    });
    expect(manifest.forbiddenSharedRuntimes).toEqual(["@hasna/cloud", "open-cloud"]);

    const legacyAppId = AppCloudManifestSchema.parse({
      ...manifest,
      id: "cloud_manifest_legacy_app_ref",
      appId: "Open Todos Legacy"
    });
    expect(legacyAppId.appId).toBe("Open Todos Legacy");

    const extendedForbiddenRuntimes = AppCloudManifestSchema.safeParse({
      ...manifest,
      id: "cloud_manifest_extended_forbidden",
      forbiddenSharedRuntimes: ["@hasna/cloud", "open-cloud", "cloud-mcp", "legacy-cloud"]
    });
    expect(extendedForbiddenRuntimes.success).toBe(true);

    const forbiddenByManifest = validateContract(SCHEMA_IDS.appCloudManifest, {
      ...manifest,
      id: "cloud_manifest_forbidden_by_manifest",
      forbiddenSharedRuntimes: ["@hasna/cloud", "open-cloud", "cloud-mcp"],
      dependencies: ["cloud-mcp"]
    });
    expect(forbiddenByManifest.success).toBe(false);
    if (!forbiddenByManifest.success) {
      expect(forbiddenByManifest.error.issues.map((issue) => issue.path.join("."))).toContain("dependencies");
    }

    const invalid = validateContract(SCHEMA_IDS.appCloudManifest, {
      ...manifest,
      id: "cloud_manifest_invalid",
      packageName: "@hasna/cloud",
      dependencies: ["@hasna/cloud"]
    });
    expect(invalid.success).toBe(false);
    if (!invalid.success) {
      const paths = invalid.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("packageName");
      expect(paths).toContain("dependencies");
      expect(paths).toContain("cloudResources.0.ownerPackage");
    }

    const invalidModes = [
      { ...manifest, id: "cloud_manifest_local_bad", storageMode: "local_only", cloudBoundary: "app_owned" },
      { ...manifest, id: "cloud_manifest_external_bad", storageMode: "external_service", cloudBoundary: "external_service" },
      { ...manifest, id: "cloud_manifest_hybrid_bad", storageMode: "hybrid_local_cache", cloudBoundary: "local_cache" }
    ];
    for (const invalidMode of invalidModes) {
      expect(validateContract(SCHEMA_IDS.appCloudManifest, invalidMode).success).toBe(false);
    }
  });

  test("no-cloud evidence packs cannot pass with blocking findings", () => {
    const invalid = NoCloudEvidencePackSchema.safeParse({
      schema: SCHEMA_IDS.noCloudEvidencePack,
      id: "no_cloud_invalid",
      createdAt,
      subject: {
        kind: "repo",
        id: "open-cloud",
        uri: "git+https://github.com/hasna/cloud.git"
      },
      scanMode: "ci",
      status: "succeeded",
      verdict: "passed",
      checks: [
        {
          id: "package_manifest",
          kind: "package_manifest",
          status: "failed",
          target: "package.json"
        }
      ],
      findings: [
        {
          id: "finding_cloud",
          kind: "package_manifest",
          severity: "critical",
          path: "package.json",
          pattern: "@hasna/cloud",
          message: "Forbidden shared cloud runtime dependency in dependencies"
        }
      ]
    });

    expect(invalid.success).toBe(false);
    if (!invalid.success) {
      const paths = invalid.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("findings");
      expect(paths).toContain("checks");
    }
  });

  test("no-cloud evidence packs aggregate nested check findings", () => {
    const invalid = NoCloudEvidencePackSchema.safeParse({
      schema: SCHEMA_IDS.noCloudEvidencePack,
      id: "no_cloud_nested_invalid",
      createdAt,
      subject: {
        kind: "repo",
        id: "open-todos",
        uri: "repo://open-todos"
      },
      scanMode: "ci",
      status: "succeeded",
      verdict: "passed",
      checks: [
        {
          id: "source_runtime",
          kind: "source_import",
          status: "succeeded",
          target: "repo://open-todos#source_runtime",
          findings: [
            {
              id: "finding_nested_cloud",
              kind: "source_import",
              severity: "critical",
              path: "index.js",
              pattern: "open-cloud",
              message: "Forbidden runtime reference"
            }
          ]
        }
      ]
    });

    expect(invalid.success).toBe(false);
    if (!invalid.success) {
      const paths = invalid.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("findings");
      expect(paths).toContain("checks.0.findings");
    }
  });

  test("no-cloud evidence packs cannot pass with incomplete checks", () => {
    const invalid = NoCloudEvidencePackSchema.safeParse({
      schema: SCHEMA_IDS.noCloudEvidencePack,
      id: "no_cloud_incomplete_invalid",
      createdAt,
      subject: {
        kind: "repo",
        id: "open-todos",
        uri: "repo://open-todos"
      },
      scanMode: "ci",
      status: "succeeded",
      verdict: "passed",
      checks: [
        {
          id: "source_runtime",
          kind: "source_import",
          status: "skipped",
          target: "repo://open-todos#source_runtime"
        }
      ]
    });

    expect(invalid.success).toBe(false);
    if (!invalid.success) {
      expect(invalid.error.issues.map((issue) => issue.path.join("."))).toContain("checks");
    }
  });

  test("rejects passed proof bundles without evidence", () => {
    expect(() =>
      ProofBundleSchema.parse({
        schema: SCHEMA_IDS.proofBundle,
        id: "proof_empty",
        createdAt,
        subject: taskRef,
        status: "succeeded",
        verdict: "passed",
        checks: [{ checkId: "typecheck", status: "succeeded" }],
        verifier: actor
      })
    ).toThrow();
  });

  test("rejects passed proof bundles with failed checks", () => {
    const result = validateContract(SCHEMA_IDS.proofBundle, {
      schema: SCHEMA_IDS.proofBundle,
      id: "proof_failed_check",
      createdAt,
      subject: taskRef,
      status: "succeeded",
      verdict: "passed",
      checks: [{ checkId: "typecheck", status: "failed", evidenceRefs: [evidencePointer] }],
      verifier: actor
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((issue) => issue.path.join(".") === "checks.0.status")).toBe(true);
    }
  });

  test("validates active scaffold manifests with portable output and checks", () => {
    const manifest = ScaffoldManifestSchema.parse({
      schema: SCHEMA_IDS.scaffoldManifest,
      id: "scaffold-open-source",
      createdAt,
      name: "scaffold-open-source",
      version: "1.0.0",
      summary: "Open-source CLI/MCP package scaffold.",
      type: "open_source",
      status: "active",
      capabilities: ["cli", "mcp", "library", "tests"],
      output: {
        packageManager: "bun",
        languages: ["TypeScript"],
        requiredFiles: ["package.json"],
        requiredDirectories: ["src"]
      },
      env: [
        {
          key: "HASNA_HOME",
          description: "Optional Hasna state directory override."
        }
      ],
      scripts: [
        {
          name: "test",
          command: "bun test",
          required: true
        }
      ],
      validationChecks: [
        {
          id: "tests",
          kind: "test",
          command: "bun test"
        }
      ]
    });

    expect(manifest.capabilities).toContain("mcp");
    expect(manifest.env[0]?.secret).toBe(false);
  });

  test("rejects active scaffold manifests without output requirements or checks", () => {
    const result = validateContract(SCHEMA_IDS.scaffoldManifest, {
      schema: SCHEMA_IDS.scaffoldManifest,
      id: "scaffold-empty",
      createdAt,
      name: "scaffold-empty",
      version: "1.0.0",
      summary: "Invalid active scaffold.",
      type: "open_source",
      status: "active",
      output: {}
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      const paths = result.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("validationChecks");
      expect(paths).toContain("output");
    }
  });

  test("rejects scaffold manifests that expose secret defaults or local source paths", () => {
    const secretDefault = validateContract(SCHEMA_IDS.scaffoldManifest, {
      schema: SCHEMA_IDS.scaffoldManifest,
      id: "scaffold-secret-default",
      createdAt,
      name: "scaffold-secret-default",
      version: "1.0.0",
      summary: "Invalid scaffold with secret default.",
      type: "open_source",
      status: "active",
      output: {
        requiredFiles: ["package.json"]
      },
      env: [
        {
          key: "API_KEY",
          description: "Provider key.",
          secret: true,
          default: "not-public"
        }
      ],
      validationChecks: [
        {
          id: "tests",
          kind: "test",
          command: "bun test"
        }
      ]
    });
    expect(secretDefault.success).toBe(false);
    if (!secretDefault.success) {
      expect(secretDefault.error.issues.map((issue) => issue.path.join("."))).toContain("env.0.default");
    }

    const localSource = validateContract(SCHEMA_IDS.scaffoldManifest, {
      schema: SCHEMA_IDS.scaffoldManifest,
      id: "scaffold-local-source",
      createdAt,
      name: "scaffold-local-source",
      version: "1.0.0",
      summary: "Invalid scaffold with local source URI.",
      type: "open_source",
      status: "active",
      source: {
        kind: "repo",
        id: "local-template",
        uri: "file:///local/private/template"
      },
      output: {
        requiredFiles: ["package.json"]
      },
      validationChecks: [
        {
          id: "tests",
          kind: "test",
          command: "bun test"
        }
      ]
    });
    expect(localSource.success).toBe(false);
    if (!localSource.success) {
      expect(localSource.error.issues.map((issue) => issue.path.join("."))).toContain("source.uri");
    }
  });

  test("validates scaffold install records and requires evidence for installed records", () => {
    const installRecord = ScaffoldInstallRecordSchema.parse({
      schema: SCHEMA_IDS.scaffoldInstallRecord,
      id: "install_scaffold_open_source_001",
      createdAt,
      scaffoldId: "scaffold-open-source",
      scaffoldVersion: "1.0.0",
      target: {
        kind: "repo",
        id: "open-example",
        uri: "git+https://github.com/hasna/open-example.git"
      },
      status: "installed",
      installedAt: createdAt,
      generatedFiles: [
        {
          kind: "file",
          id: "package_json",
          uri: "repo://open-example/package.json"
        }
      ]
    });
    expect(installRecord.scaffoldId).toBe("scaffold-open-source");

    const missingEvidence = validateContract(SCHEMA_IDS.scaffoldInstallRecord, {
      schema: SCHEMA_IDS.scaffoldInstallRecord,
      id: "install_missing_evidence",
      createdAt,
      scaffoldId: "scaffold-open-source",
      target: {
        kind: "repo",
        id: "open-example",
        uri: "git+https://github.com/hasna/open-example.git"
      },
      status: "installed",
      installedAt: createdAt
    });
    expect(missingEvidence.success).toBe(false);
  });
});

describe("distribution schemas", () => {
  const validApp = {
    schema: SCHEMA_IDS.app,
    id: "app_open_todos",
    createdAt,
    appId: "open-todos",
    npmName: "@hasna/todos",
    repoFolder: "open-todos",
    githubUrl: "https://github.com/hasna/todos",
    projectSlug: "open-todos",
    surfaces: {
      bins: ["todos", "todos-mcp"],
      mcp: { transport: "http", bin: "todos-mcp" },
      http: { healthPath: "/health", port: 4310 }
    },
    lifecycle: "active",
    releaseChannel: "stable"
  } as const;

  const validRelease = {
    schema: SCHEMA_IDS.release,
    id: "release_open_todos_0_11_63",
    createdAt,
    appId: "open-todos",
    package: "@hasna/todos",
    version: "0.11.63",
    gitSha: "9fceb02d0ae598e95dc970b74767f19372d61af8",
    publishedAt: createdAt,
    publishPath: "skill",
    evidenceRefs: [evidencePointer]
  } as const;

  const validRollout = {
    schema: SCHEMA_IDS.rolloutRecord,
    id: "rollout_open_todos_spark01",
    createdAt,
    appId: "open-todos",
    package: "@hasna/todos",
    version: "0.11.63",
    machine: "spark01",
    action: "update",
    result: "succeeded",
    verifiedBy: { cliVersion: "0.11.63", mcpHealth: "ok" },
    at: createdAt
  } as const;

  test("validates canonical app identity and applies defaults", () => {
    const app = parseContract(SCHEMA_IDS.app, validApp);
    expect(app.appId).toBe("open-todos");
    expect(app.surfaces.bins).toEqual(["todos", "todos-mcp"]);
    expect(app.tags).toEqual([]);

    const minimal = parseContract(SCHEMA_IDS.app, {
      schema: SCHEMA_IDS.app,
      id: "app_open_uptime",
      createdAt,
      appId: "open-uptime",
      npmName: "@hasna/uptime",
      repoFolder: "open-uptime",
      githubUrl: "git+https://github.com/hasna/uptime.git",
      projectSlug: "open-uptime",
      lifecycle: "stub"
    });
    expect(minimal.releaseChannel).toBe("stable");
    expect(minimal.surfaces).toEqual({ bins: [] });
  });

  test("rejects apps with bad slugs, non-github urls, or duplicate bins", () => {
    expect(validateContract(SCHEMA_IDS.app, { ...validApp, appId: "Open Todos" }).success).toBe(false);
    expect(validateContract(SCHEMA_IDS.app, { ...validApp, githubUrl: "https://gitlab.com/hasna/todos" }).success).toBe(false);
    expect(validateContract(SCHEMA_IDS.app, { ...validApp, lifecycle: "retired" }).success).toBe(false);

    const duplicateBins = validateContract(SCHEMA_IDS.app, {
      ...validApp,
      surfaces: { bins: ["todos", "todos"] }
    });
    expect(duplicateBins.success).toBe(false);
    if (!duplicateBins.success) {
      expect(duplicateBins.error.issues.map((issue) => issue.path.join("."))).toContain("surfaces.bins.1");
    }
  });

  test("validates releases and allows deferred changelog refs", () => {
    const release = parseContract(SCHEMA_IDS.release, validRelease);
    expect(release.changelogRef).toBeUndefined();
    expect(release.publishPath).toBe("skill");

    const withChangelog = parseContract(SCHEMA_IDS.release, {
      ...validRelease,
      changelogRef: { kind: "document", id: "changelog_open_todos_0_11_63", uri: "https://github.com/hasna/todos/blob/main/CHANGELOG.md" }
    });
    expect(withChangelog.changelogRef?.id).toBe("changelog_open_todos_0_11_63");
  });

  test("requires publish evidence unless the release is backfilled", () => {
    const missingEvidence = validateContract(SCHEMA_IDS.release, { ...validRelease, evidenceRefs: [] });
    expect(missingEvidence.success).toBe(false);
    if (!missingEvidence.success) {
      expect(missingEvidence.error.issues.map((issue) => issue.path.join("."))).toContain("evidenceRefs");
    }

    const backfilled = validateContract(SCHEMA_IDS.release, {
      ...validRelease,
      publishPath: "backfilled",
      evidenceRefs: []
    });
    expect(backfilled.success).toBe(true);

    expect(validateContract(SCHEMA_IDS.release, { ...validRelease, gitSha: "not-a-sha" }).success).toBe(false);
    expect(validateContract(SCHEMA_IDS.release, { ...validRelease, version: "v1.2" }).success).toBe(false);
  });

  test("validates rollout records and enforces action/result coupling", () => {
    const rollout = parseContract(SCHEMA_IDS.rolloutRecord, validRollout);
    expect(rollout.verifiedBy?.mcpHealth).toBe("ok");

    const freezeBlockedOk = validateContract(SCHEMA_IDS.rolloutRecord, {
      ...validRollout,
      id: "rollout_freeze_blocked",
      action: "freeze-blocked",
      result: "blocked",
      verifiedBy: undefined
    });
    expect(freezeBlockedOk.success).toBe(true);

    const freezeBlockedBad = validateContract(SCHEMA_IDS.rolloutRecord, {
      ...validRollout,
      action: "freeze-blocked",
      result: "succeeded"
    });
    expect(freezeBlockedBad.success).toBe(false);
    if (!freezeBlockedBad.success) {
      expect(freezeBlockedBad.error.issues.map((issue) => issue.path.join("."))).toContain("result");
    }

    const unverifiedSuccess = validateContract(SCHEMA_IDS.rolloutRecord, {
      ...validRollout,
      verifiedBy: undefined
    });
    expect(unverifiedSuccess.success).toBe(false);
    if (!unverifiedSuccess.success) {
      expect(unverifiedSuccess.error.issues.map((issue) => issue.path.join("."))).toContain("verifiedBy");
    }

    const emptyVerificationSuccess = validateContract(SCHEMA_IDS.rolloutRecord, {
      ...validRollout,
      verifiedBy: {}
    });
    expect(emptyVerificationSuccess.success).toBe(false);
    if (!emptyVerificationSuccess.success) {
      expect(emptyVerificationSuccess.error.issues.map((issue) => issue.path.join("."))).toContain("verifiedBy");
    }

    const notCheckedOnlySuccess = validateContract(SCHEMA_IDS.rolloutRecord, {
      ...validRollout,
      verifiedBy: { mcpHealth: "not_checked" }
    });
    expect(notCheckedOnlySuccess.success).toBe(false);
    if (!notCheckedOnlySuccess.success) {
      expect(notCheckedOnlySuccess.error.issues.map((issue) => issue.path.join("."))).toContain("verifiedBy");
    }

    const notCheckedWithCliVersion = validateContract(SCHEMA_IDS.rolloutRecord, {
      ...validRollout,
      verifiedBy: { cliVersion: "0.11.63", mcpHealth: "not_checked" }
    });
    expect(notCheckedWithCliVersion.success).toBe(true);
  });

  test("validates announcements with per-channel delivery status", () => {
    const announcement = parseContract(SCHEMA_IDS.announcement, {
      schema: SCHEMA_IDS.announcement,
      id: "announcement_open_todos_0_11_63",
      createdAt,
      campaignId: "campaign_open_todos_0_11_63",
      appId: "open-todos",
      releaseRef: { kind: "release", id: "release_open_todos_0_11_63" },
      channels: [
        { channel: "email", status: "sent", deliveredAt: createdAt },
        { channel: "telegram", status: "failed", detail: "bot token expired" }
      ],
      audienceRef: { kind: "audience", id: "audience_oss_operators" },
      sentAt: createdAt
    });
    expect(announcement.channels).toHaveLength(2);
  });

  test("rejects announcements with wrong ref kinds or incomplete channel states", () => {
    const base = {
      schema: SCHEMA_IDS.announcement,
      id: "announcement_bad",
      createdAt,
      campaignId: "campaign_bad",
      channels: [{ channel: "email", status: "sent", deliveredAt: createdAt }],
      audienceRef: { kind: "audience", id: "audience_oss_operators" },
      sentAt: createdAt
    } as const;

    expect(validateContract(SCHEMA_IDS.announcement, { ...base, audienceRef: { kind: "task", id: "x" } }).success).toBe(false);
    expect(validateContract(SCHEMA_IDS.announcement, { ...base, releaseRef: { kind: "task", id: "x" } }).success).toBe(false);
    expect(validateContract(SCHEMA_IDS.announcement, { ...base, channels: [] }).success).toBe(false);
    expect(
      validateContract(SCHEMA_IDS.announcement, { ...base, channels: [{ channel: "email", status: "sent" }] }).success
    ).toBe(false);
    expect(
      validateContract(SCHEMA_IDS.announcement, { ...base, channels: [{ channel: "telegram", status: "failed" }] }).success
    ).toBe(false);
  });

  test("validates audiences with tag/attribute/group predicates and consent policy", () => {
    const audience = parseContract(SCHEMA_IDS.audience, {
      schema: SCHEMA_IDS.audience,
      id: "audience_oss_operators",
      createdAt,
      audienceId: "oss-operators",
      name: "OSS fleet operators",
      definition: {
        predicates: [
          { kind: "tag", value: "fleet-operator" },
          { kind: "attribute", key: "machine", op: "in", values: ["spark01", "spark02"] },
          { kind: "group", op: "exists", value: "oss" }
        ]
      },
      consentPolicy: "opt_in",
      suppressionSyncedAt: null
    });
    expect(audience.definition.match).toBe("all");
    expect(audience.definition.predicates[0]?.op).toBe("eq");
  });

  test("rejects audiences with malformed predicates", () => {
    const base = {
      schema: SCHEMA_IDS.audience,
      id: "audience_bad",
      createdAt,
      audienceId: "oss-operators",
      name: "OSS fleet operators",
      consentPolicy: "opt_in"
    } as const;

    const missingKey = validateContract(SCHEMA_IDS.audience, {
      ...base,
      definition: { predicates: [{ kind: "attribute", op: "eq", value: "spark01" }] }
    });
    expect(missingKey.success).toBe(false);
    if (!missingKey.success) {
      expect(missingKey.error.issues.map((issue) => issue.path.join("."))).toContain("definition.predicates.0.key");
    }

    expect(
      validateContract(SCHEMA_IDS.audience, {
        ...base,
        definition: { predicates: [{ kind: "tag", op: "in", values: [] }] }
      }).success
    ).toBe(false);
    expect(validateContract(SCHEMA_IDS.audience, { ...base, definition: { predicates: [] } }).success).toBe(false);
  });

  test("app cloud manifests preserve v1 appId compatibility while app identity stays strict", () => {
    const manifest = {
      schema: SCHEMA_IDS.appCloudManifest,
      id: "cloud_manifest_open_todos",
      createdAt,
      packageName: "@hasna/todos",
      appId: "open-todos",
      storageMode: "local_only",
      cloudBoundary: "none"
    } as const;
    expect(validateContract(SCHEMA_IDS.appCloudManifest, manifest).success).toBe(true);
    expect(validateContract(SCHEMA_IDS.appCloudManifest, { ...manifest, appId: "Open Todos!" }).success).toBe(true);
    expect(validateContract(SCHEMA_IDS.app, { ...validApp, appId: "Open Todos!" }).success).toBe(false);
  });
});
