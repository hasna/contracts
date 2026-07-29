import { describe, expect, test } from "bun:test";
import {
  TODOS_DOMAIN_FIELD_CLASSIFICATION,
  TODOS_DOMAIN_SCHEMA_IDS,
  TODOS_DOMAIN_SCHEMAS,
  TODOS_TASK_STATUS_TRANSITIONS,
  TODOS_TERMINAL_TASK_STATUSES,
  TodosAgentSchema,
  TodosDependencySchema,
  TodosGitObjectIdSchema,
  TodosTaskSchema,
  isTodosTerminalTaskStatus,
  validateTodosTaskStatusTransition,
} from "../../src/todos/domain";

const timestamp = "2026-07-29T12:00:00.000Z";

function entity(id: string) {
  return {
    id,
    owner: "tenant-a",
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function task() {
  return {
    ...entity("task-1"),
    shortId: null,
    title: "Add direct domain coverage",
    description: null,
    status: "ready" as const,
    priority: "high" as const,
    projectId: null,
    taskListId: null,
    planId: null,
    parentTaskId: null,
    assignedAgentId: null,
    fingerprint: null,
    tags: ["contracts"],
    acceptanceCriteria: [],
    dueAt: null,
    completedAt: null,
    externalOwnerRefs: [],
  };
}

describe("Todos domain lifecycle", () => {
  test("identifies every terminal status without treating active statuses as terminal", () => {
    expect(TODOS_TERMINAL_TASK_STATUSES).toEqual(["completed", "failed", "cancelled"]);
    for (const status of TODOS_TERMINAL_TASK_STATUSES) {
      expect(isTodosTerminalTaskStatus(status), status).toBe(true);
    }
    for (const status of ["pending", "ready", "in_progress", "blocked"] as const) {
      expect(isTodosTerminalTaskStatus(status), status).toBe(false);
    }
  });

  test("accepts allowed transitions and reports whether they reach a terminal state", () => {
    expect(validateTodosTaskStatusTransition("pending", "ready")).toEqual({
      success: true,
      replayed: false,
      terminal: false,
    });
    expect(validateTodosTaskStatusTransition("in_progress", "completed")).toEqual({
      success: true,
      replayed: false,
      terminal: true,
    });
  });

  test("accepts idempotent replays for active and terminal states", () => {
    expect(validateTodosTaskStatusTransition("blocked", "blocked")).toEqual({
      success: true,
      replayed: true,
      terminal: false,
    });
    expect(validateTodosTaskStatusTransition("failed", "failed")).toEqual({
      success: true,
      replayed: true,
      terminal: true,
    });
  });

  test("rejects invalid, terminal, and disallowed transitions with useful targets", () => {
    expect(validateTodosTaskStatusTransition(undefined, "ready")).toEqual({
      success: false,
      reason: "invalid_status",
      allowedTargets: [],
    });
    expect(validateTodosTaskStatusTransition("ready", "unknown")).toEqual({
      success: false,
      reason: "invalid_status",
      allowedTargets: [],
    });
    expect(validateTodosTaskStatusTransition("completed", "ready")).toEqual({
      success: false,
      reason: "terminal_status",
      allowedTargets: [],
    });
    expect(validateTodosTaskStatusTransition("pending", "completed")).toEqual({
      success: false,
      reason: "transition_not_allowed",
      allowedTargets: TODOS_TASK_STATUS_TRANSITIONS.pending,
    });
  });
});

describe("Todos domain schemas", () => {
  test("accepts a valid task and guards completion and tag uniqueness", () => {
    const valid = task();
    expect(TodosTaskSchema.safeParse(valid).success).toBe(true);
    expect(TodosTaskSchema.safeParse({ ...valid, tags: ["contracts", "contracts"] }).success)
      .toBe(false);
    expect(TodosTaskSchema.safeParse({ ...valid, status: "completed", completedAt: null }).success)
      .toBe(false);
    expect(TodosTaskSchema.safeParse({
      ...valid,
      status: "completed",
      completedAt: timestamp,
    }).success).toBe(true);
  });

  test("guards duplicate agent roles and self-referencing dependencies", () => {
    const agent = {
      ...entity("agent-1"),
      displayName: "Contract agent",
      status: "active",
      roles: ["customer_member"],
      activeProjectId: null,
      activeTaskListId: null,
      lastHeartbeatAt: timestamp,
      releasedAt: null,
    };
    expect(TodosAgentSchema.safeParse(agent).success).toBe(true);
    expect(TodosAgentSchema.safeParse({
      ...agent,
      roles: ["customer_member", "customer_member"],
    }).success).toBe(false);

    const dependency = {
      ...entity("dependency-1"),
      sourceTaskId: "task-1",
      targetTaskId: "task-2",
      kind: "requires",
    };
    expect(TodosDependencySchema.safeParse(dependency).success).toBe(true);
    expect(TodosDependencySchema.safeParse({
      ...dependency,
      targetTaskId: dependency.sourceTaskId,
    }).success).toBe(false);
  });

  test("enforces Git object algorithms and their exact digest lengths", () => {
    expect(TodosGitObjectIdSchema.safeParse({ algorithm: "sha1", value: "a".repeat(40) }).success)
      .toBe(true);
    expect(TodosGitObjectIdSchema.safeParse({ algorithm: "sha256", value: "b".repeat(64) }).success)
      .toBe(true);
    expect(TodosGitObjectIdSchema.safeParse({ algorithm: "sha1", value: "a".repeat(39) }).success)
      .toBe(false);
    expect(TodosGitObjectIdSchema.safeParse({ algorithm: "sha256", value: "g".repeat(64) }).success)
      .toBe(false);
  });

  test("keeps every exported domain schema and transfer classification keyed by its id", () => {
    const ids = Object.values(TODOS_DOMAIN_SCHEMA_IDS).sort();
    expect(Object.keys(TODOS_DOMAIN_SCHEMAS).sort()).toEqual(ids);
    expect(Object.keys(TODOS_DOMAIN_FIELD_CLASSIFICATION).sort()).toEqual(ids);
    expect(Object.isFrozen(TODOS_DOMAIN_SCHEMAS)).toBe(true);
    expect(Object.isFrozen(TODOS_DOMAIN_FIELD_CLASSIFICATION)).toBe(true);

    for (const schemaId of ids) {
      expect(TODOS_DOMAIN_SCHEMAS[schemaId]!.safeParse(undefined).success, schemaId).toBe(false);
      const classifications = TODOS_DOMAIN_FIELD_CLASSIFICATION[schemaId]!;
      expect(Object.isFrozen(classifications), schemaId).toBe(true);
      expect(Object.keys(classifications).length, schemaId).toBeGreaterThan(0);
      expect(Object.values(classifications).every((classification) =>
        ["portable", "reference_only", "excluded"].includes(classification)
      ), schemaId).toBe(true);
    }
  });
});
