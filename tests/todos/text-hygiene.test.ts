import { describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  findTodosTextHygieneIssues,
} from "../../scripts/check-todos-text-hygiene";

const root = join(import.meta.dir, "..", "..");

describe("Todos owned text hygiene", () => {
  test("checks tracked and untracked owned files from the filesystem", () => {
    expect(findTodosTextHygieneIssues(root)).toEqual([]);

    const fixtureRoot = mkdtempSync(join(tmpdir(), "todos-text-hygiene-"));
    try {
      const sourceRoot = join(fixtureRoot, "src", "todos");
      mkdirSync(sourceRoot, { recursive: true });
      writeFileSync(
        join(sourceRoot, "new-untracked-file.ts"),
        "export const value = true;  \n\n",
        "utf8",
      );
      expect(findTodosTextHygieneIssues(fixtureRoot)).toEqual([
        {
          path: join("src", "todos", "new-untracked-file.ts"),
          line: 1,
          kind: "trailing_whitespace",
        },
        {
          path: join("src", "todos", "new-untracked-file.ts"),
          line: 2,
          kind: "trailing_blank_line",
        },
      ]);
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });
});
