import { describe, expect, test } from "bun:test";
import {
  resolveServerDataBackend,
  serverDataBackendEnvKeys,
  envToken,
  SERVER_DATA_BACKENDS,
} from "../src";

describe("server data backend", () => {
  test("enum is sqlite|postgresql only", () => {
    expect(SERVER_DATA_BACKENDS).toEqual(["sqlite", "postgresql"]);
  });

  test("derives canonical and alias database URL keys", () => {
    expect(envToken("todos")).toBe("TODOS");
    expect(envToken("open-mailery")).toBe("OPEN_MAILERY");
    expect(serverDataBackendEnvKeys("todos")).toEqual({
      databaseUrlKeys: ["HASNA_TODOS_DATABASE_URL", "TODOS_DATABASE_URL"],
    });
  });

  test("defaults to sqlite with no database URL", () => {
    expect(resolveServerDataBackend("todos", {})).toEqual({
      backend: "sqlite",
      source: "default",
      databaseUrlPresent: false,
      databaseUrlSource: null,
    });
  });

  test("canonical or alias database URL selects postgresql without exposing it", () => {
    const canonical = resolveServerDataBackend("todos", {
      HASNA_TODOS_DATABASE_URL: "postgres://fixture.invalid/todos",
    });
    expect(canonical).toEqual({
      backend: "postgresql",
      source: "HASNA_TODOS_DATABASE_URL",
      databaseUrlPresent: true,
      databaseUrlSource: "HASNA_TODOS_DATABASE_URL",
    });
    expect(JSON.stringify(canonical)).not.toContain("fixture.invalid");

    expect(
      resolveServerDataBackend("todos", {
        TODOS_DATABASE_URL: "postgres://fixture.invalid/todos",
      }),
    ).toMatchObject({
      backend: "postgresql",
      source: "TODOS_DATABASE_URL",
      databaseUrlSource: "TODOS_DATABASE_URL",
    });
  });

  test("every legacy mode variable fails with database URL guidance", () => {
    for (const key of [
      "HASNA_TODOS_STORAGE_MODE",
      "HASNA_TODOS_MODE",
      "TODOS_STORAGE_MODE",
      "TODOS_MODE",
    ]) {
      for (const value of ["cloud", "", "   "]) {
        expect(
          () => resolveServerDataBackend("todos", { [key]: value }),
          `${key}=${JSON.stringify(value)} must throw`,
        ).toThrow(/removed.*HASNA_TODOS_DATABASE_URL/i);
      }
    }
  });
});
