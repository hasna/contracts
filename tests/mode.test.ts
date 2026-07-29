import { describe, expect, test } from "bun:test";
import {
  normalizeStorageMode,
  resolveStorageMode,
  storageEnvKeys
} from "../src/mode";
import { envToken } from "../src/env-token";
import { STORAGE_MODES } from "../src/schemas";

describe("storage backend normalizer", () => {
  test("enum is sqlite|postgres only", () => {
    expect(STORAGE_MODES).toEqual(["sqlite", "postgres"]);
  });

  test("normalizes canonical values", () => {
    expect(normalizeStorageMode("sqlite")).toEqual({ mode: "sqlite" });
    expect(normalizeStorageMode("postgres")).toEqual({ mode: "postgres" });
    expect(normalizeStorageMode("  POSTGRES  ")).toEqual({ mode: "postgres" });
    expect(normalizeStorageMode("postgresql")).toEqual({ mode: "postgres" });
  });

  test("removed placement words throw with a migration hint", () => {
    for (const word of ["local", "cloud", "remote", "hybrid", "self_hosted", "self-hosted"]) {
      expect(() => normalizeStorageMode(word), `${word} must throw`).toThrow(
        /runtime-placement axis was removed/
      );
    }
  });

  test("rejects unknown modes", () => {
    expect(() => normalizeStorageMode("sync")).toThrow(/Unknown storage mode/);
    expect(() => normalizeStorageMode("cache")).toThrow(/Unknown storage mode/);
  });
});

describe("env spec", () => {
  test("derives canonical and alias keys", () => {
    expect(envToken("todos")).toBe("TODOS");
    expect(envToken("open-mailery")).toBe("OPEN_MAILERY");
    expect(storageEnvKeys("todos")).toEqual({
      modeKeys: ["HASNA_TODOS_STORAGE_MODE", "TODOS_STORAGE_MODE"],
      databaseUrlKeys: ["HASNA_TODOS_DATABASE_URL", "TODOS_DATABASE_URL"]
    });
  });

  test("defaults to sqlite with no env", () => {
    const r = resolveStorageMode("todos", {});
    expect(r.mode).toBe("sqlite");
    expect(r.source).toBe("default");
    expect(r.databaseUrlPresent).toBe(false);
    expect(r.warning).toBeNull();
  });

  test("a bare DATABASE_URL selects postgres", () => {
    const r = resolveStorageMode("todos", { HASNA_TODOS_DATABASE_URL: "postgres://u:p@host/db" });
    expect(r.mode).toBe("postgres");
    expect(r.source).toBe("HASNA_TODOS_DATABASE_URL");
    expect(r.databaseUrlPresent).toBe(true);
  });

  test("reads canonical mode key and db url presence without leaking value", () => {
    const r = resolveStorageMode("todos", {
      HASNA_TODOS_STORAGE_MODE: "postgres",
      HASNA_TODOS_DATABASE_URL: "postgres://u:p@host/db"
    });
    expect(r.mode).toBe("postgres");
    expect(r.source).toBe("HASNA_TODOS_STORAGE_MODE");
    expect(r.databaseUrlPresent).toBe(true);
    expect(r.databaseUrlSource).toBe("HASNA_TODOS_DATABASE_URL");
    expect(r.warning).toBeNull();
  });

  test("warns when postgres has no database url", () => {
    const r = resolveStorageMode("todos", { HASNA_TODOS_STORAGE_MODE: "postgres" });
    expect(r.mode).toBe("postgres");
    expect(r.databaseUrlPresent).toBe(false);
    expect(r.warning).toContain("postgres storage needs HASNA_TODOS_DATABASE_URL");
  });

  test("removed placement words in the env throw, and alias env keys warn", () => {
    expect(() =>
      resolveStorageMode("todos", { HASNA_TODOS_STORAGE_MODE: "self_hosted", HASNA_TODOS_DATABASE_URL: "x" })
    ).toThrow(/runtime-placement axis was removed/);

    const aliasKey = resolveStorageMode("todos", { TODOS_STORAGE_MODE: "sqlite" });
    expect(aliasKey.mode).toBe("sqlite");
    expect(aliasKey.source).toBe("TODOS_STORAGE_MODE");
    expect(aliasKey.warning).toContain("canonical key is HASNA_TODOS_STORAGE_MODE");
  });
});
