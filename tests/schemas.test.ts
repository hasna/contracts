import { describe, expect, test } from "bun:test";
import {
  ActorRefSchema,
  ContractSchemaRegistry,
  type EvidenceRef,
  EvidenceRefSchema,
  parseEmbeddedContract,
  parseContract,
  ProofBundleSchema,
  SCHEMA_IDS,
  validateEmbeddedContract,
  validateContract,
  WorkRunSchema
} from "../src";

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
      expect(result.data.id).toBe(evidence.id);
    }

    expect(parseEmbeddedContract(value).id).toBe(evidence.id);
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
});
