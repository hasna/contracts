// Pack this repo the way `npm publish` would, then scan what actually shipped.
//
// This is the repo's own clause-C gate, and it dogfoods the check the contract
// asks every publishing repo to wire (R5). It packs to a temp directory with
// `--ignore-scripts` — without that, packing from inside `prepack` would
// re-enter `prepack` forever.
//
// It scans the TARBALL, never `src/`. The disclosure this exists to prevent was
// invisible from the repo: the file holding the inventory was excluded by
// `files`, while the built output carrying the same data was not.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import {
  formatArtifactScanReport,
  resolveAssetInventoryWaivers,
  scanPublishedArtifact,
} from "../src/artifact-scan";

function run(command: string[], cwd: string): string {
  const result = Bun.spawnSync(command, { cwd, stdout: "pipe", stderr: "pipe" });
  const stdout = new TextDecoder().decode(result.stdout).trim();
  if (result.exitCode !== 0) {
    const stderr = new TextDecoder().decode(result.stderr).trim();
    throw new Error(`${command.join(" ")} exited ${result.exitCode}\n${stdout}\n${stderr}`);
  }
  return stdout;
}

const repoRoot = join(import.meta.dir, "..");
const workspace = mkdtempSync(join(tmpdir(), "contracts-artifact-scan-"));

try {
  const packed = run(["bun", "pm", "pack", "--destination", workspace, "--ignore-scripts", "--quiet"], repoRoot);
  const archive = isAbsolute(packed) ? packed : join(workspace, packed);
  // The manifest is where a reviewed, time-boxed waiver is declared, so the
  // gate has to read it. A waiver the enforcement never loads is not an escape
  // hatch; it is a documented dead end that leaves a legitimate repo no way to
  // publish except to unwire the gate.
  const waivers = resolveAssetInventoryWaivers(join(repoRoot, "hasna.contract.json"));
  for (const note of waivers.notes) console.log(`waiver: ${note}`);
  const report = scanPublishedArtifact(archive, { waivedKinds: waivers.kinds });
  console.log(formatArtifactScanReport(report));
  if (!report.ok) {
    console.error(
      "\nA published artifact must not carry a bulk asset inventory. See CONTRACT.md clause B.",
    );
    process.exit(1);
  }
} finally {
  rmSync(workspace, { recursive: true, force: true });
}
