// Shared command handlers for the storage-kit generator, used by both the
// `contracts vendor-kit` subcommand and the standalone `contracts-kit` bin.

import { checkKit, generateKit } from "../kit/generate";

export interface VendorKitCliOptions {
  json?: boolean;
  check?: boolean;
  kitVersion?: string;
  contract?: boolean;
}

export function runVendorKit(targetRepo: string, options: VendorKitCliOptions): void {
  if (options.check) {
    runCheckKit(targetRepo, options);
    return;
  }
  const result = generateKit({
    targetRepo,
    ...(options.kitVersion !== undefined ? { version: options.kitVersion } : {}),
    writeContract: options.contract !== false,
  });
  if (options.json) {
    console.log(JSON.stringify({ ok: true, action: "vendor", ...result }, null, 2));
  } else {
    console.log(`ok vendored storage-kit v${result.version} -> ${result.targetDir}`);
    console.log(`  files: ${result.written.join(", ")}`);
    console.log(`  hasna.contract.json kitVersion ${result.contractUpdated ? "updated" : "unchanged"}`);
  }
}

export function runCheckKit(targetRepo: string, options: VendorKitCliOptions): void {
  const result = checkKit({
    targetRepo,
    ...(options.kitVersion !== undefined ? { version: options.kitVersion } : {}),
    writeContract: options.contract !== false,
  });
  if (options.json) {
    console.log(JSON.stringify({ action: "check", ...result }, null, 2));
  } else {
    console.log(`${result.ok ? "ok" : "fail"} storage-kit check (expected v${result.version}) ${result.targetDir}`);
    for (const file of result.files) {
      if (file.status !== "ok") console.log(`  ${file.status} ${file.file}`);
    }
    for (const extra of result.extras) {
      console.log(`  unexpected ${extra}`);
    }
    if (result.manifest !== "ok") {
      console.log(`  ${result.manifest} ${".storage-kit-manifest.json"}`);
    }
    for (const issue of result.manifestIssues) {
      console.log(`    manifest: ${issue}`);
    }
    if (result.staleVersion) {
      console.log(`  stale: on-disk kit is v${result.staleVersion}, regenerate to v${result.version}`);
    }
    if (result.contractMissing) {
      console.log("  missing hasna.contract.json kitVersion stamp");
    } else if (result.contractStaleVersion !== null) {
      console.log(
        `  stale: hasna.contract.json kitVersion is ${result.contractStaleVersion ?? "<missing>"}, regenerate to v${result.version}`,
      );
    }
    for (const issue of result.contractIssues) {
      console.log(`    hasna.contract.json: ${issue}`);
    }
    if (!result.ok) {
      console.log("  run: bunx @hasna/contracts vendor-kit   (regenerate the kit)");
    }
  }
  if (!result.ok) process.exitCode = 1;
}
