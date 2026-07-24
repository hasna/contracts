import { describe, expect, test } from "bun:test";
import {
  DEFAULT_SECURE_LOCAL_STORE_POLICY,
  SCHEMA_IDS,
  secureLocalStorePolicy,
  validateContract
} from "../src";

describe("secure local-store declarative contract", () => {
  test("default policy validates and inventories required stores", () => {
    const result = validateContract(
      SCHEMA_IDS.secureLocalStorePolicy,
      DEFAULT_SECURE_LOCAL_STORE_POLICY
    );
    expect(result.success).toBe(true);

    const storeIds = new Set(
      DEFAULT_SECURE_LOCAL_STORE_POLICY.stores.map((store) => store.storeId)
    );
    for (const id of [
      "codewith",
      "todos",
      "conversations",
      "mementos",
      "knowledge",
      "projects",
      "browser",
      "terminal",
      "logs",
      "loops"
    ]) {
      expect(storeIds.has(id)).toBe(true);
    }
  });

  test("filters the policy by exact store id and rejects unknown ids", () => {
    expect(
      secureLocalStorePolicy(["todos"]).stores.map((store) => store.storeId)
    ).toEqual(["todos"]);
    expect(() => secureLocalStorePolicy(["missing-store"])).toThrow(
      /Unknown secure local store id/
    );
  });

  test("policy metadata is JSON-portable and carries no executable values", () => {
    const policy = secureLocalStorePolicy();
    const roundTrip = JSON.parse(JSON.stringify(policy));
    expect(
      validateContract(SCHEMA_IDS.secureLocalStorePolicy, roundTrip).success
    ).toBe(true);

    const visit = (value: unknown): void => {
      expect(typeof value).not.toBe("function");
      if (Array.isArray(value)) {
        for (const item of value) visit(item);
      } else if (value && typeof value === "object") {
        for (const item of Object.values(value)) visit(item);
      }
    };
    visit(policy);
  });

  test("lifecycle and SQLite operations are declarations for owning packages", () => {
    const todos = secureLocalStorePolicy(["todos"]).stores[0];
    expect(todos?.packageName).toBe("@hasna/todos");
    expect(todos?.directoryMode).toBe("0700");
    expect(todos?.fileMode).toBe("0600");
    expect(todos?.retentionAdapters[0]?.activeRecordExclusions.length).toBeGreaterThan(0);
    expect(todos?.retentionAdapters[0]?.sqliteMaintenance).toEqual({
      safeWhen: "exclusive_access",
      operations: ["wal_checkpoint_truncate", "optimize"]
    });
    expect(
      DEFAULT_SECURE_LOCAL_STORE_POLICY.warnings.some((warning) =>
        warning.includes("never executed by @hasna/contracts")
      )
    ).toBe(true);
  });
});
