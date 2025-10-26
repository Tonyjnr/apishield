#!/usr/bin/env node

const { loadConfig } = require("./lib/config");
const fs = require("fs"); // Required for file existence checks
const path = require("path");
const chalk = require("chalk");
const { hideBin } = require("yargs/helpers");
const yargs = require("yargs");

// Parsers
const { parseOpenAPI } = require("./lib/parsers/openapi");
const { parsePostman, normalizePostman } = require("./lib/parsers/postman");
const { parseHAR, normalizeHAR } = require("./lib/parsers/har");
const { scanLiveURL, normalizeProbedResults } = require("./lib/parsers/live");

// Normalizers & Scanners
const { normalizeSpec, scanSpec } = require("./lib/normalizer");

/**
 * Detects input type with URL priority
 */
function detectInputType(input) {
  // URLs always take precedence
  if (input.startsWith("http://") || input.startsWith("https://")) {
    return "url";
  }

  const lower = input.toLowerCase();
  if (lower.endsWith(".postman_collection.json")) return "postman";
  if (lower.endsWith(".har")) return "har";
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return "yaml";
  return "unknown";
}

async function main() {
  const argv = yargs(hideBin(process.argv))
    .command(
      "scan [file]",
      "Scan API spec, Postman collection, HAR file, or URL for security issues",
      (yargs) => {
        yargs.positional("file", {
          describe: "Path to spec file or URL",
          type: "string",
        });
      }
    )
    .option("file", {
      alias: "f",
      type: "string",
      description: "Local spec file (alternative to positional arg)",
    })
    .option("url", {
      alias: "u",
      type: "string",
      description: "Remote URL to scan",
    })
    .option("verbose", {
      alias: "v",
      type: "boolean",
      description: "Show detailed output",
      default: false,
    })
    .check((argv) => {
      const inputFile = argv.file || argv.url || argv.file;
      if (!inputFile) {
        throw new Error("Please provide a file path or URL");
      }
      if (argv.file && argv.url) {
        throw new Error("Use either --file or --url, not both");
      }
      return true;
    })
    .demandCommand(1, "You must provide a command")
    .help()
    .version("0.5.0").argv;

  // Resolve input source
  const input = argv.url || argv.file || argv._[1];

  try {
    const type = detectInputType(input);
    let normalized;

    switch (type) {
      case "postman": {
        const filePath = path.resolve(input);
        if (!fs.existsSync(filePath)) {
          console.error(chalk.red(`File not found: ${filePath}`));
          process.exit(1);
        }
        console.log(chalk.blue("📦 Detected Postman Collection"));
        const collection = parsePostman(filePath);
        normalized = normalizePostman(collection);
        break;
      }

      case "har": {
        const filePath = path.resolve(input);
        if (!fs.existsSync(filePath)) {
          console.error(chalk.red(`File not found: ${filePath}`));
          process.exit(1);
        }
        console.log(chalk.blue("🌐 Detected HAR file"));
        const harData = parseHAR(filePath);
        normalized = normalizeHAR(harData);
        break;
      }

      case "json":
      case "yaml": {
        const filePath = path.resolve(input);
        if (!fs.existsSync(filePath)) {
          console.error(chalk.red(`File not found: ${filePath}`));
          process.exit(1);
        }
        console.log(chalk.blue("📄 Detected OpenAPI/Swagger spec"));
        const spec = parseOpenAPI(filePath);
        normalized = normalizeSpec(spec);
        break;
      }

      case "url": {
        console.log(chalk.blue(`🌐 Scanning live API: ${input}`));
        const liveResult = await scanLiveURL(input);
        if (liveResult.type === "openapi") {
          normalized = normalizeSpec(liveResult.data);
        } else {
          normalized = normalizeProbedResults(liveResult.data);
        }
        break;
      }

      default: {
        console.error(chalk.red(`❌ Unsupported input: ${input}`));
        console.log(
          chalk.gray(
            "Supported: .yaml, .yml, .json, .postman_collection.json, .har, or https:// URLs"
          )
        );
        process.exit(1);
      }
    }

    const config = loadConfig();
    const issues = scanSpec(normalized, config);

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
