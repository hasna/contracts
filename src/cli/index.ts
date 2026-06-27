#!/usr/bin/env bun

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { Command, CommanderError } from "commander";
import {
  CONTRACTS_PACKAGE_VERSION,
  ContractSchemaRegistry,
  type KnownSchemaId
} from "../schemas";
import { getEmbeddedSchemaId, validateContract } from "../validators";

function collectJsonFiles(root: string): string[] {
  const stat = statSync(root);
  if (stat.isFile()) {
    return root.endsWith(".json") ? [root] : [];
  }
  const files: string[] = [];
  for (const entry of readdirSync(root).sort()) {
    files.push(...collectJsonFiles(join(root, entry)));
  }
  return files;
}

function readJsonFile(file: string): { ok: true; value: unknown } | { ok: false; error: string } {
  try {
    return { ok: true, value: JSON.parse(readFileSync(file, "utf8")) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, error: message };
  }
}

function reportCliError(options: { json?: boolean }, error: string, details: Record<string, unknown> = {}) {
  if (options.json) {
    console.log(JSON.stringify({ ok: false, error, ...details }, null, 2));
  } else {
    console.error(error);
  }
  process.exitCode = 2;
}

function argvRequestsJson(argv: string[]) {
  return argv.includes("--json") || argv.includes("-j");
}

function reportParserJsonError(code: string, error: string) {
  console.log(JSON.stringify({ ok: false, code, error }, null, 2));
  process.exitCode = 1;
  return true;
}

function preflightJsonUsageErrors(argv: string[]) {
  if (!argvRequestsJson(argv)) {
    return false;
  }

  const args = argv.slice(2);
  const command = args[0];
  if (!command) {
    return false;
  }

  if (!["schemas", "validate", "conformance"].includes(command)) {
    return reportParserJsonError("commander.unknownCommand", `unknown command '${command}'`);
  }

  const allowedOptionsByCommand: Record<string, Set<string>> = {
    schemas: new Set(["--json", "-j"]),
    validate: new Set(["--json", "-j", "--schema"]),
    conformance: new Set(["--json", "-j"])
  };
  const allowedOptions = allowedOptionsByCommand[command] ?? new Set<string>();
  const positionals: string[] = [];

  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) {
      continue;
    }
    if (arg.startsWith("--schema=")) {
      if (arg.slice("--schema=".length).length === 0) {
        return reportParserJsonError("commander.optionMissingArgument", "option '--schema <id>' argument missing");
      }
      continue;
    }
    if (arg === "--schema") {
      const schemaValue = args[index + 1];
      if (!schemaValue || schemaValue.startsWith("-")) {
        return reportParserJsonError("commander.optionMissingArgument", "option '--schema <id>' argument missing");
      }
      index += 1;
      continue;
    }
    if (arg.startsWith("-")) {
      if (!allowedOptions.has(arg)) {
        return reportParserJsonError("commander.unknownOption", `unknown option '${arg}'`);
      }
      continue;
    }
    positionals.push(arg);
  }

  if (command === "validate" && positionals.length === 0) {
    return reportParserJsonError("commander.missingArgument", "missing required argument 'file'");
  }

  return false;
}

export function createContractsProgram() {
  const program = new Command();

  program
    .name("contracts")
    .description("Validate Hasna shared contract JSON files")
    .version(CONTRACTS_PACKAGE_VERSION);

  program
    .command("schemas")
    .description("List known contract schema ids")
    .option("-j, --json", "Output JSON")
    .action((options: { json?: boolean }) => {
      const schemas = Object.keys(ContractSchemaRegistry);
      if (options.json) {
        console.log(JSON.stringify(schemas, null, 2));
        return;
      }
      for (const schema of schemas) {
        console.log(schema);
      }
    });

  program
    .command("validate")
    .description("Validate a JSON file against a contract schema")
    .argument("<file>", "JSON file path")
    .option("--schema <id>", "Contract schema id. Defaults to the file's embedded schema field")
    .option("-j, --json", "Output JSON")
    .action((file: string, options: { schema?: string; json?: boolean }) => {
      const loaded = readJsonFile(file);
      if (!loaded.ok) {
        reportCliError(options, `Could not read or parse ${file}: ${loaded.error}`, { file, code: "read_or_parse_error" });
        return;
      }

      const schemaId = options.schema ? (options.schema as KnownSchemaId) : getEmbeddedSchemaId(loaded.value);
      if (!schemaId || !(schemaId in ContractSchemaRegistry)) {
        const error = options.schema
          ? `Unknown schema: ${options.schema}`
          : "No schema provided and file does not include a known embedded schema field";
        reportCliError(options, error, { file, schema: options.schema ?? null, code: "unknown_schema" });
        return;
      }

      const result = validateContract(schemaId, loaded.value);
      if (result.success) {
        if (options.json) {
          console.log(JSON.stringify({ ok: true, schema: schemaId, file }, null, 2));
        } else {
          console.log(`ok ${schemaId} ${file}`);
        }
        return;
      }

      if (options.json) {
        console.log(JSON.stringify({ ok: false, schema: schemaId, file, issues: result.error.issues }, null, 2));
      } else {
        console.error(`invalid ${schemaId} ${file}`);
        for (const issue of result.error.issues) {
          console.error(`- ${issue.path.join(".") || "<root>"}: ${issue.message}`);
        }
      }
      process.exitCode = 1;
    });

  program
    .command("conformance")
    .description("Validate example fixtures. *.valid.json must pass; *.invalid.json must fail")
    .argument("[path]", "Examples path", "examples")
    .option("-j, --json", "Output JSON")
    .action((root: string, options: { json?: boolean }) => {
      let files: string[];
      try {
        files = collectJsonFiles(root).filter((file) => file.endsWith(".valid.json") || file.endsWith(".invalid.json"));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        reportCliError(options, `Could not read examples path ${root}: ${message}`, { path: root, code: "examples_path_error" });
        return;
      }

      if (files.length === 0) {
        reportCliError(options, `No conformance fixtures found in ${root}`, { path: root, checked: 0, code: "no_fixtures" });
        return;
      }

      const results = files.map((file) => {
        const expectedValid = file.endsWith(".valid.json");
        const loaded = readJsonFile(file);
        if (!loaded.ok) {
          return { file, expectedValid, ok: false, schema: null, error: loaded.error };
        }
        const schemaId = getEmbeddedSchemaId(loaded.value);
        if (!schemaId) {
          return { file, expectedValid, ok: false, schema: null, error: "missing or unknown embedded schema" };
        }
        const result = validateContract(schemaId, loaded.value);
        const valid = result.success;
        return {
          file,
          expectedValid,
          ok: expectedValid ? valid : !valid,
          schema: schemaId,
          error: result.success ? null : result.error.issues.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`).join("; ")
        };
      });

      const failed = results.filter((result) => !result.ok);
      if (options.json) {
        console.log(JSON.stringify({ ok: failed.length === 0, checked: results.length, failed: failed.length, results }, null, 2));
      } else {
        for (const result of results) {
          console.log(`${result.ok ? "ok" : "fail"} ${result.expectedValid ? "valid" : "invalid"} ${result.schema ?? "unknown"} ${result.file}`);
          if (!result.ok && result.error) {
            console.log(`  ${result.error}`);
          }
        }
      }
      if (failed.length > 0) {
        process.exitCode = 1;
      }
    });

  return program;
}

export function main(argv = process.argv) {
  if (preflightJsonUsageErrors(argv)) {
    return;
  }
  const program = createContractsProgram();
  const wantsJson = argvRequestsJson(argv);
  if (wantsJson) {
    program.configureOutput({
      writeErr: () => {}
    });
  }
  program.exitOverride();
  try {
    program.parse(argv);
  } catch (error) {
    const commanderError = error as Partial<CommanderError> & { message?: string };
    if (error instanceof CommanderError || typeof commanderError.code === "string" || typeof commanderError.exitCode === "number") {
      const exitCode = commanderError.exitCode ?? 2;
      if (exitCode === 0) {
        process.exitCode = 0;
        return;
      }
      const code = commanderError.code || "commander_error";
      const message = commanderError.message || "Command failed";
      if (wantsJson) {
        console.log(JSON.stringify({ ok: false, code, error: message }, null, 2));
      } else {
        console.error(message);
      }
      process.exitCode = exitCode;
      return;
    }
    throw error;
  }
}

if (import.meta.main) {
  main();
}
