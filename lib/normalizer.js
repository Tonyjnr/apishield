// lib/normalizer.js

// This file handles normalization, scanning, and sensitive-field classification for OpenAPI/Swagger specs.
import chalk from "chalk";

// Sensitive field patterns (shared across scanners)
const SENSITIVE_FIELDS = {
  // 🔑 1. Authentication & Credentials
  credentials: {
    fields: [
      "password",
      "passwd",
      "pwd",
      "secret",
      "token",
      "access_token",
      "refresh_token",
      "auth",
      "authorization",
      "bearer",
      "session",
      "sessionid",
      "session_id",
      "login",
      "userpass",
      "credentials",
      "api_key",
      "apikey",
      "client_secret",
      "client_id",
      "app_secret",
      "app_key",
    ],
    regulations: ["SOX", "PCI-DSS"],
  },

  // 🔐 2. Encryption & Cryptographic Keys
  encryptionKeys: {
    fields: [
      "encryptionkey",
      "encryption_key",
      "privatekey",
      "private_key",
      "publickey",
      "public_key",
      "ssh_key",
      "rsa_key",
      "gpg_key",
      "pem",
      "cert",
      "certificate",
      "keystore",
      "salt",
      "iv",
      "crypto_key",
      "signing_key",
      "keypair",
    ],
    regulations: ["SOX", "FISMA"],
  },

  // 💳 3. Financial & Payment Data
  financial: {
    fields: [
      "creditcard",
      "credit_card",
      "card_number",
      "cc_number",
      "cvv",
      "cvc",
      "ccv",
      "expiration",
      "expiry_date",
      "billing_address",
      "iban",
      "swift",
      "routing_number",
      "account_number",
      "account_no",
      "bank_account",
      "bank_name",
      "transaction_id",
      "payment_info",
      "card_info",
      "upi_id",
      "wallet_id",
    ],
    regulations: ["PCI-DSS", "SOX", "CCPA"],
  },

  // 🧍 4. Personal Identifiers (PII)
  pii: {
    fields: [
      "ssn",
      "social_security",
      "socialsecurity",
      "national_id",
      "nid",
      "passport",
      "passport_number",
      "driver_license",
      "license_number",
      "employee_id",
      "student_id",
      "tax_id",
      "tin",
      "voter_id",
      "citizen_id",
    ],
    regulations: ["GDPR", "CCPA", "PIPEDA", "LGPD"],
  },

  // 🏠 5. Personal Information (General)
  personalInfo: {
    fields: [
      "dob",
      "date_of_birth",
      "birthdate",
      "firstname",
      "lastname",
      "fullname",
      "name",
      "email",
      "phone",
      "phonenumber",
      "mobile",
      "address",
      "home_address",
      "zipcode",
      "zip",
      "postalcode",
      "state",
      "country",
      "city",
      "gender",
      "age",
    ],
    regulations: ["GDPR", "CCPA", "PIPEDA", "LGPD"],
  },

  // 🧬 6. Health & Biometric Information
  health: {
    fields: [
      "fingerprint",
      "retina",
      "iris",
      "dna",
      "medical_record",
      "health_id",
      "insurance_number",
      "insuranceid",
      "patient_id",
      "diagnosis",
      "treatment",
      "blood_type",
      "disability_status",
      "medication",
    ],
    regulations: ["HIPAA", "GDPR", "CCPA"],
  },

  // 🧩 7. System / App Tokens
  systemTokens: {
    fields: [
      "csrf_token",
      "xsrf_token",
      "otp",
      "2fa",
      "mfa",
      "recovery_code",
      "reset_token",
      "invite_code",
      "activation_key",
      "magic_link",
      "verification_code",
      "reset_code",
      "webauthn",
      "sso_token",
      "oidc_token",
      "fido2_key",
      "refresh_secret",
    ],
    regulations: ["SOX"],
  },

  // ☁️ 8. Cloud & DevOps Secrets
  cloudSecrets: {
    fields: [
      "aws_secret_access_key",
      "aws_access_key_id",
      "azure_key",
      "gcp_key",
      "service_account",
      "firebase_key",
      "webhook_secret",
      "slack_webhook",
      "discord_token",
      "github_token",
      "gitlab_token",
      "npm_token",
      "docker_token",
      "heroku_api_key",
      "vercel_token",
      "netlify_token",
      "digitalocean_key",
      "ssh_config",
      "ci_secret",
      "ci_token",
    ],
    regulations: ["SOX", "FISMA"],
  },

  // 🌐 9. Network / Device Identifiers
  network: {
    fields: [
      "ip",
      "ip_address",
      "mac",
      "mac_address",
      "hostname",
      "device_id",
      "device_token",
      "location",
      "geo",
      "latitude",
      "longitude",
      "tracking_id",
      "session_cookie",
      "cookie",
      "browser_fingerprint",
    ],
    regulations: ["GDPR", "CCPA", "PIPEDA"],
  },

  // 🧱 10. Configuration / Internal System Data
  systemConfig: {
    fields: [
      "debug",
      "stacktrace",
      "error_trace",
      "internal_note",
      "admin_comment",
      "system_path",
      "config_path",
      "logfile",
      "log_path",
      "env",
      "environment",
      "debug_mode",
      "debug_token",
      "stack",
      "traceback",
      "error_message",
      "error_details",
      "trace_id",
      "build_config",
    ],
    regulations: ["SOX"],
  },

  // 🤖 11. AI / ML Integrations (modern API risk surface)
  aiIntegrations: {
    fields: [
      "openai_key",
      "openai_api_key",
      "anthropic_key",
      "huggingface_token",
      "replicate_api_token",
      "cohere_api_key",
      "stability_key",
      "palm_api_key",
      "vertex_ai_key",
      "azure_openai_key",
    ],
    regulations: ["SOX"],
  },
};

// 👇 Flattened array for quick scanning
const ALL_SENSITIVE_FIELDS = Object.values(SENSITIVE_FIELDS).flatMap(
  (category) => category.fields
);

// Updated: accept custom fields
function isSensitiveField(fieldName, customFields = []) {
  const allPatterns = [...ALL_SENSITIVE_FIELDS, ...customFields];
  const lowerName = fieldName.toLowerCase();
  return allPatterns.some((pattern) =>
    lowerName.includes(pattern.toLowerCase())
  );
}

// New: Get regulatory context for sensitive fields
function getRegulatoryContext(fieldName) {
  const lowerName = fieldName.toLowerCase();
  const regulations = new Set();

  for (const [categoryName, category] of Object.entries(SENSITIVE_FIELDS)) {
    if (
      category.fields.some((field) => lowerName.includes(field.toLowerCase()))
    ) {
      category.regulations.forEach((reg) => regulations.add(reg));
    }
  }

  return Array.from(regulations);
}

/**
 * Normalize Swagger 2.0 specs to OpenAPI 3-like structure
 */
function normalizeSpec(spec) {
  if (spec.swagger && spec.swagger.startsWith("2.")) {
    console.log(
      chalk.yellow(
        "⚠️  Detected Swagger 2.0 — converting to OpenAPI-like structure...\n"
      )
    );

    const normalized = {
      openapi: "3.0.0",
      info: spec.info || {},
      paths: {},
      security: spec.security || [],
      _isSwagger2: true,
    };

    const hasSecurityDefs =
      spec.securityDefinitions &&
      Object.keys(spec.securityDefinitions).length > 0;

    for (const [pathStr, methods] of Object.entries(spec.paths || {})) {
      normalized.paths[pathStr] = {};

      for (const [method, op] of Object.entries(methods)) {
        // Skip non-operation keys
        if (
          [
            "parameters",
            "$ref",
            "summary",
            "description",
            "consumes",
            "produces",
          ].includes(method)
        ) {
          continue;
        }

        const normMethod = method.toLowerCase();
        normalized.paths[pathStr][normMethod] = {
          ...op,
          security:
            op.security !== undefined ? op.security : normalized.security,
        };
      }
    }

    if (hasSecurityDefs) {
      normalized._securityDefinitions = spec.securityDefinitions;
    }

    return normalized;
  }

  return spec; // Assume OpenAPI 3.x
}

// Helper: check if path matches ignore pattern (supports *)
function shouldIgnorePath(pathStr, ignorePaths) {
  return ignorePaths.some((ignore) => {
    if (ignore.includes("*")) {
      // Convert glob-like pattern to regex
      const regexStr = "^" + ignore.replace(/\*/g, ".*") + "$";
      return new RegExp(regexStr).test(pathStr);
    }
    return pathStr.includes(ignore);
  });
}

/**
 * Scan a normalized spec for security issues
 */
function scanSpec(
  normalizedSpec,
  config = { ignorePaths: [], customSensitiveFields: [] }
) {
  const issues = [];
  const paths = normalizedSpec.paths || {};

  for (const [pathStr, pathObj] of Object.entries(paths)) {
    // ✅ Skip ignored paths
    if (shouldIgnorePath(pathStr, config.ignorePaths)) {
      continue;
    }

    for (const [method, op] of Object.entries(pathObj)) {
      if (typeof op !== "object") continue;

      const opId = `${method.toUpperCase()} ${pathStr}`;

      // 🔒 Check: Missing authentication
      const hasSecurity =
        (Array.isArray(op.security) && op.security.length > 0) ||
        (Array.isArray(normalizedSpec.security) &&
          normalizedSpec.security.length > 0);

      const isLikelyPublic =
        /login|register|signup|auth|public|health|status|metrics|healthz|readiness|version|openapi\.json|swagger\.json/i.test(
          pathStr
        );

      if (!hasSecurity && !isLikelyPublic) {
        issues.push({
          severity: "high",
          message: "Missing authentication",
          detail: `Endpoint ${opId} has no security scheme defined.`,
          fix: "Add a 'security' block to the operation or global spec.",
        });
      }

      // 👁️ Check: Sensitive data in responses
      const responses = op.responses || {};
      for (const [status, res] of Object.entries(responses)) {
        if (!status.startsWith("2")) continue;

        let schema = null;
        // OpenAPI 3.x
        if (res.content && res.content["application/json"]) {
          schema = res.content["application/json"].schema;
        }
        // Swagger 2.0
        else if (res.schema) {
          schema = res.schema;
        }

        if (!schema) continue;

        const findSensitiveFields = (
          obj,
          prefix = "",
          customFields = config.customSensitiveFields
        ) => {
          let fields = [];
          if (obj && typeof obj === "object" && !Array.isArray(obj)) {
            for (const [key, value] of Object.entries(obj)) {
              const fullName = prefix ? `${prefix}.${key}` : key;
              if (isSensitiveField(key, customFields)) {
                fields.push(fullName);
              }
              if (value && typeof value === "object") {
                fields = fields.concat(
                  findSensitiveFields(value, fullName, customFields)
                );
              }
            }
          }
          return fields;
        };

        const sensitiveFields = findSensitiveFields(schema);
        if (sensitiveFields.length > 0) {
          // Check if compliance mode is enabled
          if (config.compliance) {
            const complianceRegulations = new Set();
            const complianceFields = [];

            // Get regulatory context for each sensitive field
            for (const field of sensitiveFields) {
              const fieldName = field.split(".").pop(); // Get the actual field name
              const regulations = getRegulatoryContext(fieldName);

              // Filter by compliance mode (e.g., 'gdpr' only shows GDPR-regulated fields)
              if (
                config.compliance === "gdpr" &&
                regulations.includes("GDPR")
              ) {
                complianceRegulations.add("GDPR");
                complianceFields.push(field);
              } else if (
                config.compliance === "ccpa" &&
                regulations.includes("CCPA")
              ) {
                complianceRegulations.add("CCPA");
                complianceFields.push(field);
              } else if (
                config.compliance === "hipaa" &&
                regulations.includes("HIPAA")
              ) {
                complianceRegulations.add("HIPAA");
                complianceFields.push(field);
              } else if (
                config.compliance === "pci" &&
                regulations.includes("PCI-DSS")
              ) {
                complianceRegulations.add("PCI-DSS");
                complianceFields.push(field);
              }
            }

            // Only report if there are compliance-relevant fields
            if (complianceFields.length > 0) {
              issues.push({
                severity: "high",
                message: `${config.compliance.toUpperCase()} compliance violation`,
                detail: `${opId} exposes ${config.compliance.toUpperCase()}-regulated data: ${complianceFields.join(
                  ", "
                )}`,
                fix: `Remove or mask ${config.compliance.toUpperCase()}-regulated fields from the response schema.`,
                regulations: Array.from(complianceRegulations),
              });
            }
          } else {
            // Standard mode - report all sensitive fields
            issues.push({
              severity: "high",
              message: "Sensitive data exposed in response",
              detail: `${opId} returns: ${sensitiveFields.join(", ")}`,
              fix: "Remove or mask sensitive fields from the response schema.",
            });
          }
        }

        // 📊 Check: Excessive data exposure (>20 fields)
        if (schema?.properties) {
          const fieldCount = Object.keys(schema.properties).length;
          if (fieldCount > 20) {
            issues.push({
              severity: "medium",
              message: "Excessive data exposure",
              detail: `${opId} returns ${fieldCount} fields in response`,
              fix: "Reduce response fields or implement field filtering (e.g., ?fields=id,name)",
            });
          }
        }
      }

      // Handle probed endpoints (from HAR/live scan)
      if (op._probed && op._sensitiveFields && op._sensitiveFields.length > 0) {
        // Check if compliance mode is enabled for probed endpoints
        if (config.compliance) {
          const complianceRegulations = new Set();
          const complianceFields = [];

          // Get regulatory context for each sensitive field
          for (const field of op._sensitiveFields) {
            const fieldName = field.split(".").pop(); // Get the actual field name
            const regulations = getRegulatoryContext(fieldName);

            // Filter by compliance mode
            if (config.compliance === "gdpr" && regulations.includes("GDPR")) {
              complianceRegulations.add("GDPR");
              complianceFields.push(field);
            } else if (
              config.compliance === "ccpa" &&
              regulations.includes("CCPA")
            ) {
              complianceRegulations.add("CCPA");
              complianceFields.push(field);
            } else if (
              config.compliance === "hipaa" &&
              regulations.includes("HIPAA")
            ) {
              complianceRegulations.add("HIPAA");
              complianceFields.push(field);
            } else if (
              config.compliance === "pci" &&
              regulations.includes("PCI-DSS")
            ) {
              complianceRegulations.add("PCI-DSS");
              complianceFields.push(field);
            }
          }

          // Only report if there are compliance-relevant fields
          if (complianceFields.length > 0) {
            issues.push({
              severity: "high",
              message: `${config.compliance.toUpperCase()} compliance violation`,
              detail: `${opId} exposes ${config.compliance.toUpperCase()}-regulated data: ${complianceFields.join(
                ", "
              )}`,
              fix: `Remove or mask ${config.compliance.toUpperCase()}-regulated fields from the response.`,
              regulations: Array.from(complianceRegulations),
            });
          }
        } else {
          // Standard mode - report all sensitive fields
          issues.push({
            severity: "high",
            message: "Sensitive data exposed in response",
            detail: `${opId} returns: ${op._sensitiveFields.join(", ")}`,
            fix: "Remove or mask sensitive fields from the response.",
          });
        }
      }
    }
  }

  return issues;
}

export {
  normalizeSpec,
  scanSpec,
  isSensitiveField,
  getRegulatoryContext,
  SENSITIVE_FIELDS,
};
