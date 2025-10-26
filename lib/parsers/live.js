// lib/parsers/live.js
const fetch = require("node-fetch");
const chalk = require("chalk");

// Common paths to probe if no OpenAPI spec is found
const COMMON_PATHS = [
  "/api/users",
  "/api/user",
  "/users",
  "/user",
  "/api/admin",
  "/admin",
  "/api/profile",
  "/profile",
  "/api/me",
  "/me",
  "/health",
  "/status",
  "/.env", // Should 404 or 403
  "/config.json", // Should not be public
  "/swagger.json",
  "/openapi.json",
];

// Paths that are likely public (won't flag missing auth)
const PUBLIC_PATHS = [
  "login",
  "register",
  "signup",
  "auth",
  "public",
  "health",
  "status",
  "metrics",
  "version",
];

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isLikelyPublic(path) {
  return PUBLIC_PATHS.some((p) => path.toLowerCase().includes(p));
}

function extractSensitiveFields(obj, prefix = "") {
  const SENSITIVE_PATTERNS = [
    "password",
    "token",
    "secret",
    "key",
    "ssn",
    "credit",
    "cvv",
    "dob",
    "private",
    "aws_",
    "firebase",
    "api_",
    "client_id",
    "client_secret",
  ];

  let fields = [];
  if (obj && typeof obj === "object" && !Array.isArray(obj)) {
    for (const [key, value] of Object.entries(obj)) {
      const fullName = prefix ? `${prefix}.${key}` : key;
      if (SENSITIVE_PATTERNS.some((p) => key.toLowerCase().includes(p))) {
        fields.push(fullName);
      }
      if (value && typeof value === "object") {
        fields = fields.concat(extractSensitiveFields(value, fullName));
      }
    }
  }
  return fields;
}

async function probeEndpoint(baseURL, path, delayMs = 1000) {
  const url = new URL(path, baseURL).href;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent":
          "APIShield/0.5.0 (security scanner; contact: onuzulikeanthony432@gmail.com)",
        Accept: "application/json, */*",
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // Respect robots.txt (basic check)
    if (response.status === 403 && path === "/robots.txt") {
      return null;
    }

    let authDetected = false;
    let sensitiveFields = [];

    // Check for auth challenges
    if (response.headers.get("www-authenticate")) {
      authDetected = true;
    }

    // Check response body for sensitive data (if JSON)
    let responseBody = null;
    const contentType = response.headers.get("content-type") || "";
    if (response.ok && contentType.includes("application/json")) {
      try {
        responseBody = await response.json();
        sensitiveFields = extractSensitiveFields(responseBody);
      } catch (e) {
        // Ignore parse errors
      }
    }

    await sleep(delayMs); // Be kind

    return {
      path,
      method: "GET",
      status: response.status,
      authDetected,
      sensitiveFields,
      hasJsonBody: !!responseBody,
    };
  } catch (error) {
    if (error.name === "AbortError") {
      console.warn(chalk.yellow(`⚠️  Timeout on ${path}`));
    }
    return null;
  }
}

async function scanLiveURL(baseURL) {
  console.log(chalk.blue(`🌐 Scanning live API at ${baseURL}...\n`));

  // Step 1: Try to find OpenAPI spec
  const specPaths = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/api/swagger.json",
  ];

  for (const specPath of specPaths) {
    try {
      const specUrl = new URL(specPath, baseURL).href;
      const response = await fetch(specUrl, { timeout: 5000 });

      if (
        response.ok &&
        response.headers.get("content-type")?.includes("json")
      ) {
        const spec = await response.json();
        if (spec.openapi || spec.swagger) {
          console.log(chalk.green(`✅ Found OpenAPI spec at ${specPath}`));
          return {
            type: "openapi",
            data: spec,
            source: specUrl,
          };
        }
      }
    } catch {}
  }

  // Step 2: Fallback to probing
  console.log(
    chalk.yellow("⚠️  No OpenAPI spec found. Probing common endpoints...\n")
  );

  const results = [];
  for (const path of COMMON_PATHS) {
    const result = await probeEndpoint(baseURL, path, 800); // 800ms delay
    if (result) results.push(result);
  }

  return {
    type: "probed",
    data: results,
    source: baseURL,
  };
}

// Normalize probed results to internal format
function normalizeProbedResults(probedData) {
  const normalized = { paths: {}, _source: "live-probe" };

  for (const result of probedData) {
    if (result.status >= 200 && result.status < 300) {
      const method = "get";
      normalized.paths[result.path] = normalized.paths[result.path] || {};

      // Build response schema from actual data (if available)
      let schema = null;
      if (result.hasJsonBody && result.sensitiveFields.length > 0) {
        // We don't have full schema, but we know sensitive fields exist
        // We'll let the scanner flag based on response content
        schema = { properties: {} };
        result.sensitiveFields.forEach((field) => {
          const parts = field.split(".");
          let current = schema.properties;
          for (let i = 0; i < parts.length - 1; i++) {
            current[parts[i]] = current[parts[i]] || { properties: {} };
            current = current[parts[i]].properties;
          }
          current[parts[parts.length - 1]] = { type: "string" };
        });
      }

      normalized.paths[result.path][method] = {
        security: result.authDetected ? ["probed-auth"] : [],
        responses: schema
          ? {
              [result.status]: { schema },
            }
          : {},
        _probed: true,
        _sensitiveFields: result.sensitiveFields,
      };
    }
  }

  return normalized;
}

module.exports = { scanLiveURL, normalizeProbedResults };
