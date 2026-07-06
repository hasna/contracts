import { describe, expect, test } from "bun:test";
import {
  normalizeStorageMode,
  resolveStorageMode,
  storageEnvKeys,
  envToken,
  STORAGE_MODES,
  DEPRECATED_STORAGE_MODE_ALIASES
} from "../src";

describe("storage mode normalizer", () => {
  test("enum is local|cloud only", () => {
    expect(STORAGE_MODES).toEqual(["local", "cloud"]);
  });

  test("normalizes canonical values", () => {
    expect(normalizeStorageMode("local")).toEqual({ mode: "local", deprecatedAlias: null });
    expect(normalizeStorageMode("cloud")).toEqual({ mode: "cloud", deprecatedAlias: null });
    expect(normalizeStorageMode("  CLOUD  ")).toEqual({ mode: "cloud", deprecatedAlias: null });
  });

  test("maps deprecated aliases to cloud", () => {
    for (const alias of DEPRECATED_STORAGE_MODE_ALIASES) {
      expect(normalizeStorageMode(alias)).toEqual({ mode: "cloud", deprecatedAlias: alias });
    }
    // dash form normalizes to snake alias
    expect(normalizeStorageMode("self-hosted")).toEqual({ mode: "cloud", deprecatedAlias: "self_hosted" });
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

  test("defaults to local with no env", () => {
    const r = resolveStorageMode("todos", {});
    expect(r.mode).toBe("local");
    expect(r.source).toBe("default");
    expect(r.databaseUrlPresent).toBe(false);
    expect(r.warning).toBeNull();
  });

  test("reads canonical mode key and db url presence without leaking value", () => {
    const r = resolveStorageMode("todos", {
      HASNA_TODOS_STORAGE_MODE: "cloud",
      HASNA_TODOS_DATABASE_URL: "postgres://u:p@host/db"
    });
    expect(r.mode).toBe("cloud");
    expect(r.source).toBe("HASNA_TODOS_STORAGE_MODE");
    expect(r.databaseUrlPresent).toBe(true);
    expect(r.databaseUrlSource).toBe("HASNA_TODOS_DATABASE_URL");
    expect(r.warning).toBeNull();
  });

  test("warns when cloud has no database url", () => {
    const r = resolveStorageMode("todos", { HASNA_TODOS_STORAGE_MODE: "cloud" });
    expect(r.mode).toBe("cloud");
    expect(r.databaseUrlPresent).toBe(false);
    expect(r.warning).toContain("cloud mode needs HASNA_TODOS_DATABASE_URL");
  });

  test("warns on deprecated alias and on alias env key", () => {
    const alias = resolveStorageMode("todos", { HASNA_TODOS_STORAGE_MODE: "self_hosted", HASNA_TODOS_DATABASE_URL: "x" });
    expect(alias.mode).toBe("cloud");
    expect(alias.deprecatedAlias).toBe("self_hosted");
    expect(alias.warning).toContain("Deprecated storage mode 'self_hosted'");

    const aliasKey = resolveStorageMode("todos", { TODOS_STORAGE_MODE: "local" });
    expect(aliasKey.mode).toBe("local");
    expect(aliasKey.source).toBe("TODOS_STORAGE_MODE");
    expect(aliasKey.warning).toContain("canonical key is HASNA_TODOS_STORAGE_MODE");
  });
});
