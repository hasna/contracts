import { describe, expect, test } from "bun:test";
import { CONTRACTS_PACKAGE_NAME, ContractSchemaRegistry, SCHEMA_IDS, validateContract } from "../src";

describe("@hasna/contracts scaffold", () => {
  test("exports package metadata and initial schema registry", () => {
    expect(CONTRACTS_PACKAGE_NAME).toBe("@hasna/contracts");
    expect(Object.keys(ContractSchemaRegistry)).toContain(SCHEMA_IDS.evidenceRef);
  });

  test("registry schemas reject mismatched schema ids", () => {
    const value = {
      schema: SCHEMA_IDS.actorRef,
      id: "agent_codewith",
      createdAt: "2026-06-27T10:00:00.000Z",
      kind: "agent"
    };

    expect(validateContract(SCHEMA_IDS.evidenceRef, value).success).toBe(false);
    expect(validateContract(SCHEMA_IDS.actorRef, value).success).toBe(true);
  });
});
