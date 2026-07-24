import {
  existsSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import {
  extname,
  join,
  relative,
} from "node:path";

export interface TodosTextHygieneIssue {
  path: string;
  line: number;
  kind:
    | "carriage_return"
    | "trailing_whitespace"
    | "missing_final_newline"
    | "trailing_blank_line";
}

const OWNED_DIRECTORIES = [
  "src/todos",
  "tests/todos",
  "scripts",
  "generated/todos/v1",
] as const;
const OWNED_ROOT_FILES = ["README.md", "package.json"] as const;
const TEXT_EXTENSIONS = new Set([".ts", ".json", ".md", ".yaml", ".yml"]);

function listTextFiles(repositoryRoot: string): string[] {
  const files: string[] = [];
  const walk = (directory: string): void => {
    if (!existsSync(directory)) return;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (entry.isFile() && TEXT_EXTENSIONS.has(extname(entry.name))) {
        files.push(path);
      }
    }
  };
  for (const directory of OWNED_DIRECTORIES) {
    walk(join(repositoryRoot, directory));
  }
  for (const file of OWNED_ROOT_FILES) {
    const path = join(repositoryRoot, file);
    if (existsSync(path)) files.push(path);
  }
  return [...new Set(files)].sort((left, right) => left.localeCompare(right));
}

export function findTodosTextHygieneIssues(
  repositoryRoot: string,
): TodosTextHygieneIssue[] {
  const issues: TodosTextHygieneIssue[] = [];
  for (const absolutePath of listTextFiles(repositoryRoot)) {
    const path = relative(repositoryRoot, absolutePath);
    const content = readFileSync(absolutePath, "utf8");
    const lines = content.split("\n");
    for (const [index, line] of lines.entries()) {
      if (line.includes("\r")) {
        issues.push({ path, line: index + 1, kind: "carriage_return" });
      }
      if (/[ \t]+$/.test(line)) {
        issues.push({ path, line: index + 1, kind: "trailing_whitespace" });
      }
    }
    if (!content.endsWith("\n")) {
      issues.push({
        path,
        line: Math.max(1, lines.length),
        kind: "missing_final_newline",
      });
    } else if (content.endsWith("\n\n")) {
      issues.push({
        path,
        line: Math.max(1, lines.length - 1),
        kind: "trailing_blank_line",
      });
    }
  }
  return issues;
}

if (import.meta.main) {
  const rootArgument = process.argv.find((argument) => argument.startsWith("--root="));
  const repositoryRoot = rootArgument
    ? rootArgument.slice("--root=".length)
    : join(import.meta.dir, "..");
  const issues = findTodosTextHygieneIssues(repositoryRoot);
  if (issues.length > 0) {
    for (const issue of issues) {
      console.error(`${issue.path}:${issue.line}: ${issue.kind}`);
    }
    process.exitCode = 1;
  } else {
    console.log("Todos owned text hygiene is clean.");
  }
}
