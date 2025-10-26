#!/usr/bin/env node

const path = require("path");
const chalk = require("chalk");
const { hideBin } = require("yargs/helpers");
const yargs = require("yargs");

// Parsers
const { parseOpenAPI } = require("./lib/parsers/openapi");
const { parsePostman, normalizePostman } = require("./lib/parsers/postman");
const { parseHAR, normalizeHAR } = require("./lib/parsers/har");

// Normalizers & Scanners
const { normalizeSpec, scanSpec } = require("./lib/normalizer");

function detectFileType(filePath) {
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".postman_collection.json")) return "postman";
  if (lower.endsWith(".har")) return "har";
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return "yaml";
  if (lower.startsWith("http://") || lower.startsWith("https://")) return "url";
  return "unknown";
}

async function main() {
  const argv = yargs(hideBin(process.argv))
    .command(
      "scan <file>",
      "Scan API spec, Postman collection, HAR file, or URL for security issues",
      (yargs) => {
        yargs.positional("file", {
          describe: "Path to spec file or URL",
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
    .version("0.4.0").argv; // 👈 Update to match your release

  const input = argv.file;

  try {
    const type = detectFileType(input);

    let normalized;

    switch (type) {
      case "postman": {
        console.log(chalk.blue("📦 Detected Postman Collection"));
        const collection = parsePostman(input);
        normalized = normalizePostman(collection);
        break;
      }

      case "har": {
        console.log(chalk.blue("🌐 Detected HAR file"));
        const harData = parseHAR(input);
        normalized = normalizeHAR(harData);
        break;
      }

      case "json":
      case "yaml": {
        console.log(chalk.blue("📄 Detected OpenAPI/Swagger spec"));
        const spec = parseOpenAPI(input);
        normalized = normalizeSpec(spec);
        break;
      }

      case "url": {
        console.error(
          chalk.red("❌ Live URL scanning not supported in v0.4.0")
        );
        console.log(
          chalk.gray("Tip: Export your API as OpenAPI, Postman, or HAR first.")
        );
        process.exit(1);
      }

      default: {
        console.error(
          chalk.red(`❌ Unsupported file type: ${path.extname(input)}`)
        );
        console.log(
          chalk.gray(
            "Supported: .yaml, .yml, .json, .postman_collection.json, .har"
          )
        );
        process.exit(1);
      }
    }

    const issues = scanSpec(normalized);

    if (issues.length === 0) {
      console.log(chalk.green("✅ No high-risk issues found!"));
    } else {
      console.log(chalk.red(`⚠️  Found ${issues.length} security issue(s):\n`));
      issues.forEach((issue) => {
        console.log(chalk.red(`• ${issue.message}`));
        console.log(chalk.gray(`  → ${issue.detail}`));
        console.log(chalk.yellow(`  💡 ${issue.fix}\n`));
      });
      process.exit(1);
    }
  } catch (e) {
    console.error(chalk.red("❌ Error:"), e.message);
    if (argv.verbose) {
      console.error(chalk.gray(e.stack));
    }
    process.exit(1);
  }
}

main();
