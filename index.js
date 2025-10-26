#!/usr/bin/env node

// const fs = require("fs");
const path = require("path");
const chalk = require("chalk");
const yargs = require("yargs/yargs");

// Parsers
const { parseOpenAPI } = require("./lib/parsers/openapi");
const { parsePostman } = require("./lib/parsers/postman");

// Normalizers & Scanners
const { normalizeSpec, scanSpec } = require("./lib/normalizer");

function detectFileType(filePath) {
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".postman_collection.json")) return "postman";
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return "yaml";
  if (lower.startsWith("http://") || lower.startsWith("https://")) return "url";
  return "unknown";
}

async function main() {
  const { hideBin } = require("yargs/helpers");

  const argv = yargs(hideBin(process.argv))
    .command(
      "scan <file>",
      "Scan an OpenAPI/Swagger spec for security issues",
      (yargs) => {
        yargs.positional("file", {
          describe: "Path to OpenAPI/Swagger YAML or JSON file",
          type: "string",
        });
      }
    )
    .option("verbose", {
      alias: "v",
      type: "boolean",
      description: "Show detailed output",
      default: false,
    })
    .demandCommand(1, "You must provide a command")
    .help()
    .version("0.1.0").argv;

  const input = argv.file;
  let spec, normalized;

  try {
    const type = detectFileType(input);

    if (type === "postman") {
      console.log(chalk.blue("📦 Detected Postman Collection"));
      spec = parsePostman(input);
      normalized = require("./lib/parsers/postman").normalizePostman(spec);
    } else if (type === "json" || type === "yaml") {
      console.log(chalk.blue("📄 Detected OpenAPI/Swagger spec"));
      spec = parseOpenAPI(input);
      normalized = normalizeSpec(spec);
    } else {
      console.error(chalk.red("Unsupported input type"));
      process.exit(1);
    }

    const issues = scanSpec(normalized);

    if (issues.length === 0) {
      console.log(chalk.green("✅ No high-risk issues found!"));
    } else {
      issues.forEach((issue) => {
        console.log(chalk.red(`⚠️  ${issue.message}`));
        console.log(chalk.gray(`   ${issue.detail}`));
        console.log(chalk.yellow(`   💡 ${issue.fix}\n`));
      });
      process.exit(1);
    }
  } catch (e) {
    console.error(chalk.red("❌ Error:"), e.message);
    process.exit(1);
  }
}

main();
