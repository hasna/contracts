import { describe, expect, test } from "bun:test";
import { sha256TodosValue } from "../../src/todos/common";
import {
  TODOS_INVARIANT_REGISTRY,
  TODOS_INVARIANT_REGISTRY_DIGEST,
  TODOS_INVARIANT_REGISTRY_SCHEMA_ID,
  TODOS_RUNTIME_INVARIANTS,
  todosInvariantIdsForSchema,
} from "../../src/todos/invariants";

describe("Todos invariants", () => {
  test("publishes a unique frozen registry with a deterministic digest", () => {
    const invariantIds = TODOS_RUNTIME_INVARIANTS.map((invariant) => invariant.id);

    expect(TODOS_INVARIANT_REGISTRY).toEqual({
      schema: TODOS_INVARIANT_REGISTRY_SCHEMA_ID,
      version: "1",
      runtimeValidationRequired: true,
      invariants: TODOS_RUNTIME_INVARIANTS,
    });
    expect(new Set(invariantIds).size).toBe(invariantIds.length);
    expect(Object.isFrozen(TODOS_INVARIANT_REGISTRY)).toBe(true);
    expect(Object.isFrozen(TODOS_RUNTIME_INVARIANTS)).toBe(true);
    expect(TODOS_RUNTIME_INVARIANTS.every(Object.isFrozen)).toBe(true);
    expect(TODOS_INVARIANT_REGISTRY_DIGEST).toBe(sha256TodosValue(TODOS_INVARIANT_REGISTRY));
  });

  test("returns sorted invariant ids for a schema without leaking mutable registry state", () => {
    const expected = [
      "todos.identity.authorization_binding",
      "todos.identity.context_semantics",
    ];
    const first = todosInvariantIdsForSchema("hasna.todos.identity_context.v1");

    expect(first).toEqual(expected);
    first.push("todos.injected");
    expect(todosInvariantIdsForSchema("hasna.todos.identity_context.v1")).toEqual(expected);
  });

  test("returns an empty list for empty and unknown schema ids", () => {
    expect(todosInvariantIdsForSchema("")).toEqual([]);
    expect(todosInvariantIdsForSchema("hasna.todos.unknown.v1")).toEqual([]);
  });
});
