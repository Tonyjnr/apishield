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
  "api_key",
  "ssn",
  "socialsecurity",
  "creditcard",
  "ccv",
  "cvv",
  "dob",
  "birthdate",
  "privatekey",
  "private_key",
];

function isSensitiveField(fieldName) {
  return SENSITIVE_FIELDS.some((s) => fieldName.toLowerCase().includes(s));
}

/**
 * Normalize Swagger 2.0 specs to OpenAPI 3-like structure
 */
function normalizeSpec(spec) {
  // Detect Swagger 2.0
  if (spec.swagger && spec.swagger.startsWith("2.")) {
    console.log(
      chalk.yellow(
        "⚠️  Detected Swagger 2.0 — converting to OpenAPI-like structure...\n"
      )
    );

    const normalized = {
      openapi: "3.0.0", // Mark as normalized
      info: spec.info || {},
      paths: {},
      security: spec.security || [], // global security
      _isSwagger2: true,
    };

    // Check if security is defined
    const hasSecurityDefs =
      spec.securityDefinitions &&
      Object.keys(spec.securityDefinitions).length > 0;

    // Convert paths
    for (const [pathStr, methods] of Object.entries(spec.paths || {})) {
      normalized.paths[pathStr] = {};

      for (const [method, op] of Object.entries(methods)) {
        // Skip non-operation keys like 'parameters', 'summary', etc.
        if (["parameters", "$ref", "summary", "description"].includes(method)) {
          continue;
        }

        const normMethod = method.toLowerCase();
        normalized.paths[pathStr][normMethod] = {
          ...op,
          // Keep operation-level security or inherit global
          security:
            op.security !== undefined ? op.security : normalized.security,
        };
      }
    }

    // Store security definitions for reference
    if (hasSecurityDefs) {
      normalized._securityDefinitions = spec.securityDefinitions;
    }

    return normalized;
  }

  // Already OpenAPI 3.x
  return spec;
}

/**
 * Main security scanning logic
 */
function scanSpec(spec) {
  const issues = [];
  const paths = spec.paths || {};
  const isSwagger2 = spec._isSwagger2 || false;

  for (const [pathStr, pathObj] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(pathObj)) {
      if (typeof op !== "object") continue;

      const opId = `${method.toUpperCase()} ${pathStr}`;

      // 🔒 Check 1: Missing authentication
      const hasSecurity =
        (Array.isArray(op.security) && op.security.length > 0) ||
        (Array.isArray(spec.security) && spec.security.length > 0);

      const isLikelyPublic =
        /login|register|signup|auth|public|health|status|webhook/i.test(
          pathStr
        );

      if (!hasSecurity && !isLikelyPublic) {
        issues.push({
          severity: "high",
          message: `Missing authentication`,
          detail: `Endpoint ${opId} has no security scheme defined.`,
          fix: `Add a 'security' block to the operation or global spec.`,
        });
      }

      // 👁️ Check 2: Sensitive data in responses
      const responses = op.responses || {};

      for (const [status, res] of Object.entries(responses)) {
        if (!status.startsWith("2")) continue;

        let schema = null;

        // OpenAPI 3: res.content['application/json'].schema
        if (res.content && res.content["application/json"]) {
          schema = res.content["application/json"].schema;
        }
        // Swagger 2: res.schema
        else if (res.schema) {
          schema = res.schema;
        }

        if (!schema) continue;

        // Recursively find sensitive fields in schema
        const findSensitiveFields = (obj, prefix = "") => {
          let fields = [];

          if (!obj || typeof obj !== "object") return fields;

          // Handle 'properties' in schema
          const props = obj.properties || obj;

          for (const [key, value] of Object.entries(props)) {
            const fullName = prefix ? `${prefix}.${key}` : key;

            if (isSensitiveField(key)) {
              fields.push(fullName);
            }

            // Recurse into nested objects
            if (value && typeof value === "object") {
              if (value.properties) {
                fields = fields.concat(findSensitiveFields(value, fullName));
              } else if (value.items && value.items.properties) {
                // Handle arrays of objects
                fields = fields.concat(
                  findSensitiveFields(value.items, fullName)
                );
              }
            }
          }

          return fields;
        };

        const sensitiveFields = findSensitiveFields(schema);

        if (sensitiveFields.length > 0) {
          issues.push({
            severity: "high",
            message: `Sensitive data exposed in response`,
            detail: `${opId} returns: ${sensitiveFields.join(", ")}`,
            fix: `Remove or mask sensitive fields from the response schema.`,
          });
        }
      }

      // 🔓 Check 3: Excessive data exposure (too many fields)
      if (method.toLowerCase() === "get") {
        const successResponse = responses["200"] || responses["201"];
        if (successResponse) {
          let schema = null;

          if (
            successResponse.content &&
            successResponse.content["application/json"]
          ) {
            schema = successResponse.content["application/json"].schema;
          } else if (successResponse.schema) {
            schema = successResponse.schema;
          }

          if (schema && schema.properties) {
            const fieldCount = Object.keys(schema.properties).length;
            if (fieldCount > 20) {
              issues.push({
                severity: "medium",
                message: `Possible excessive data exposure`,
                detail: `${opId} returns ${fieldCount} fields. Consider pagination or field filtering.`,
                fix: `Implement field selection (e.g., ?fields=id,name) or pagination.`,
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

// Main execution
(async () => {
  try {
    const filePath = path.resolve(argv.file);

    if (!fs.existsSync(filePath)) {
      console.error(chalk.red(`❌ File not found: ${filePath}`));
      process.exit(1);
    }

    const fileContent = fs.readFileSync(filePath, "utf8");
    let spec;

    // Parse based on file extension
    if (filePath.endsWith(".json")) {
      spec = JSON.parse(fileContent);
    } else if (filePath.endsWith(".yaml") || filePath.endsWith(".yml")) {
      spec = yaml.load(fileContent);
    } else {
      console.error(
        chalk.red("❌ Unsupported file type. Use .json, .yaml, or .yml")
      );
      process.exit(1);
    }

    // Detect spec version
    const specVersion = spec.openapi || spec.swagger || "unknown";
    console.log(
      chalk.blue(
        `🔍 Scanning ${path.basename(argv.file)} (${specVersion})...\n`
      )
    );

    // Normalize Swagger 2.0 to OpenAPI 3-like structure
    const normalizedSpec = normalizeSpec(spec);

    if (argv.verbose) {
      console.log(
        chalk.gray(
          `📊 Found ${Object.keys(normalizedSpec.paths || {}).length} paths\n`
        )
      );
    }

    // Run security scan
    const issues = scanSpec(normalizedSpec);

    // Report results
    if (issues.length === 0) {
      console.log(chalk.green("✅ No security issues found!"));
      console.log(
        chalk.gray("Your API spec looks secure. Keep up the good work!\n")
      );
    } else {
      // Group by severity
      const highIssues = issues.filter((i) => i.severity === "high");
      const mediumIssues = issues.filter((i) => i.severity === "medium");

      if (highIssues.length > 0) {
        console.log(
          chalk.red.bold(`🚨 High Severity Issues (${highIssues.length}):\n`)
        );
        highIssues.forEach((issue, idx) => {
          console.log(chalk.red(`${idx + 1}. ${issue.message}`));
          console.log(chalk.gray(`   ${issue.detail}`));
          console.log(chalk.yellow(`   💡 ${issue.fix}\n`));
        });
      }

      if (mediumIssues.length > 0) {
        console.log(
          chalk.yellow.bold(
            `⚠️  Medium Severity Issues (${mediumIssues.length}):\n`
          )
        );
        mediumIssues.forEach((issue, idx) => {
          console.log(chalk.yellow(`${idx + 1}. ${issue.message}`));
          console.log(chalk.gray(`   ${issue.detail}`));
          console.log(chalk.cyan(`   💡 ${issue.fix}\n`));
        });
      }

      console.log(
        chalk.red(`\n📊 Summary: ${issues.length} issue(s) detected`)
      );
      console.log(
        chalk.gray(
          `   High: ${highIssues.length} | Medium: ${mediumIssues.length}\n`
        )
      );

      process.exit(1); // Fail CI on issues
    }
  } catch (e) {
    console.error(chalk.red("❌ Error:"), e.message);
    if (argv.verbose) {
      console.error(chalk.gray(e.stack));
    }
    process.exit(1);
  }
})();
