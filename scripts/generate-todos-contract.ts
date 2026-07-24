import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";
import {
  TODOS_GENERATED_ARTIFACT_ROOT,
  renderTodosArtifacts,
} from "../src/todos/artifacts";

const repositoryRoot = join(import.meta.dir, "..");
const checkOnly = process.argv.includes("--check");
const checkRootArgument = process.argv.find((argument) => argument.startsWith("--check-root="));
const outputRoot = checkRootArgument
  ? checkRootArgument.slice("--check-root=".length)
  : join(repositoryRoot, TODOS_GENERATED_ARTIFACT_ROOT);

if (checkRootArgument && !checkOnly) {
  throw new Error("--check-root requires --check");
}

function listFiles(root: string): string[] {
  if (!existsSync(root)) {
    return [];
  }
  const files: string[] = [];
  const walk = (directory: string) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (entry.isFile()) {
        files.push(relative(root, path));
      }
    }
  };
  walk(root);
  return files.sort((left, right) => left.localeCompare(right));
}

const rendered = renderTodosArtifacts();
const expectedPaths = Object.keys(rendered).sort((left, right) => left.localeCompare(right));

if (checkOnly) {
  const actualPaths = listFiles(outputRoot);
  const drift = new Set<string>();
  for (const path of new Set([...expectedPaths, ...actualPaths])) {
    const expected = rendered[path];
    const absolutePath = join(outputRoot, path);
    if (expected === undefined || !existsSync(absolutePath)) {
      drift.add(path);
      continue;
    }
    if (readFileSync(absolutePath, "utf8") !== expected) {
      drift.add(path);
    }
  }
  if (drift.size > 0) {
    console.error(`Todos generated artifacts are stale: ${[...drift].sort().join(", ")}`);
    process.exitCode = 1;
  } else {
    console.log(`Todos generated artifacts are current (${expectedPaths.length} files).`);
  }
} else {
  rmSync(outputRoot, { recursive: true, force: true });
  for (const [path, content] of Object.entries(rendered)) {
    const absolutePath = join(outputRoot, path);
    mkdirSync(dirname(absolutePath), { recursive: true });
    writeFileSync(absolutePath, content, "utf8");
  }
  console.log(`Wrote ${expectedPaths.length} Todos artifacts to ${TODOS_GENERATED_ARTIFACT_ROOT}.`);
}
