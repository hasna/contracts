import { join } from "node:path";

const root = join(import.meta.dir, "..");
const builds = [
  ["bun", "run", "build"],
  ["bun", "run", "--filter", "@hasna/contracts-auth", "build"],
  ["bun", "run", "--filter", "@hasna/contracts-client", "build"],
  ["bun", "run", "--filter", "@hasna/contracts-sdk-generator", "build"],
  ["bun", "run", "--filter", "@hasna/contracts-vendor-kit", "build"],
  ["tsc", "-p", "fixtures/compatibility/tsconfig.matrix.json"],
] as const;

for (const command of builds) {
  const result = Bun.spawnSync([...command], { cwd: root, stdout: "inherit", stderr: "inherit" });
  if (result.exitCode !== 0) process.exit(result.exitCode ?? 1);
}

console.log("N, N-1, and split-package consumer compile matrix passed");
