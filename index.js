#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");
const chalk = require("chalk");

// List of sensitive field names (case-insensitive)
const SENSITIVE_FIELDS = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "apikey",
  "ssn",
  "socialsecurity",
  "creditcard",
  "ccv",
  "cvv",
  "dob",
  "birthdate",
];

function isSensitiveField(fieldName) {
  return SENSITIVE_FIELDS.some((s) => fieldName.toLowerCase().includes(s));
}

function scanOpenAPI(spec) {
  const issues = [];
  const paths = spec.paths || {};

  for (const [pathStr, pathObj] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(pathObj)) {
      if (typeof op !== "object") continue;

      const opId = `${method.toUpperCase()} ${pathStr}`;

      // 🔒 Check 1: Missing authentication
      const hasSecurity =
        (op.security && op.security.length > 0) ||
        (spec.security && spec.security.length > 0);

      if (!hasSecurity) {
        const isLikelyPublic =
          pathStr.includes("login") ||
          pathStr.includes("register") ||
          pathStr.includes("public") ||
          pathStr.includes("auth");

        if (!isLikelyPublic) {
          issues.push({
            severity: "high",
            message: `Missing authentication`,
            detail: `Endpoint ${opId} has no security scheme defined.`,
            fix: `Add a 'security' block to the operation or global spec.`,
          });
        }
      }

      // 👁️ Check 2: Sensitive data in responses
      const responses = op.responses || {};
      for (const [status, res] of Object.entries(responses)) {
        if (status.startsWith("2") && res.content) {
          for (const [mimeType, mediaType] of Object.entries(res.content)) {
            if (!mediaType.schema) continue;

            const findSensitiveFields = (obj, prefix = "") => {
              let fields = [];
              if (obj && typeof obj === "object" && !Array.isArray(obj)) {
                for (const [key, value] of Object.entries(obj)) {
                  const fullName = prefix ? `${prefix}.${key}` : key;
                  if (isSensitiveField(key)) {
                    fields.push(fullName);
                  }
                  if (value && typeof value === "object") {
                    fields = fields.concat(
                      findSensitiveFields(value, fullName)
                    );
                  }
                }
              }
              return fields;
            };

            const sensitiveFields = findSensitiveFields(mediaType.schema);
            if (sensitiveFields.length > 0) {
              issues.push({
                severity: "high",
                message: `Sensitive data exposed in response`,
                detail: `${opId} returns: ${sensitiveFields.join(", ")}`,
                fix: `Remove or mask sensitive fields from the response schema.`,
              });
            }
          }
        }
      }
    }
  }

  return issues;
}

// Parse CLI args
const yargs = require("yargs/yargs");
const { hideBin } = require("yargs/helpers");

const argv = yargs(hideBin(process.argv))
  .command(
    "scan <file>",
    "Scan an OpenAPI spec for security issues",
    (yargs) => {
      yargs.positional("file", {
        describe: "Path to OpenAPI YAML or JSON file",
        type: "string",
      });
    }
  )
  .demandCommand(1, "You must provide a command")
  .help().argv;

// Main
(async () => {
  try {
    const filePath = path.resolve(argv.file);
    if (!fs.existsSync(filePath)) {
      console.error(chalk.red(`File not found: ${filePath}`));
      process.exit(1);
    }

    const fileContent = fs.readFileSync(filePath, "utf8");
    let spec;
    if (filePath.endsWith(".yaml") || filePath.endsWith(".yml")) {
      spec = yaml.load(fileContent);
    } else {
      spec = JSON.parse(fileContent);
    }

    console.log(chalk.blue(`🔍 Scanning ${argv.file}...\n`));

    const issues = scanOpenAPI(spec);

    if (issues.length === 0) {
      console.log(chalk.green("✅ No high-risk issues found!"));
    } else {
      issues.forEach((issue) => {
        console.log(chalk.red(`⚠️  ${issue.message}`));
        console.log(chalk.gray(`   ${issue.detail}`));
        console.log(chalk.yellow(`   💡 ${issue.fix}\n`));
      });
      console.log(chalk.red(`${issues.length} issue(s) detected.`));
      process.exit(1); // fail CI
    }
  } catch (e) {
    console.error(chalk.red("❌ Error:"), e.message);
    process.exit(1);
  }
})();
