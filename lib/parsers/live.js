// lib/parsers/live.js
const fetch = require("node-fetch");
const chalk = require("chalk");
const yaml = require("js-yaml"); // For YAML spec support

// Common paths to probe if no OpenAPI spec is found (relative to base URL)
const SPEC_PATHS_TO_PROBE = [
  "/openapi.json",
  "/openapi.yaml",
  "/swagger.json",
  "/swagger.yaml",
  "/api-docs",
  "/v2/api-docs",
  "/api/swagger.json",
  "/api/v3/openapi.json", // common in newer APIs
];

// Common paths to probe for endpoints (if no spec found)
const COMMON_ENDPOINT_PATHS = [
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
  "/.env",
  "/config.json",
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

// Helper: Is this URL likely a direct spec?
function isDirectSpecUrl(url) {
  const lower = url.toLowerCase();
  return (
    lower.endsWith("/openapi.json") ||
    lower.endsWith("/openapi.yaml") ||
    lower.endsWith("/swagger.json") ||
    lower.endsWith("/swagger.yaml") ||
    lower.includes("/openapi") ||
    lower.includes("/swagger")
  );
}

// Helper: Try to parse response as OpenAPI/Swagger spec
async function parseSpecResponse(response, url) {
  const contentType = (
    response.headers.get("content-type") || ""
  ).toLowerCase();
  let text, spec;

  try {
    text = await response.text();

    if (contentType.includes("application/json") || url.endsWith(".json")) {
      spec = JSON.parse(text);
    } else if (
      contentType.includes("yaml") ||
      url.endsWith(".yaml") ||
      url.endsWith(".yml")
    ) {
      spec = yaml.load(text);
    } else {
      // Fallback: try JSON first, then YAML
      try {
        spec = JSON.parse(text);
      } catch {
        spec = yaml.load(text);
      }
    }

    // Validate it's actually a spec
    if (spec && (spec.openapi || spec.swagger)) {
      return spec;
    }
  } catch (e) {
    // Parse error — not a valid spec
  }
  return null;
}

async function probeEndpoint(baseURL, path, delayMs = 800) {
  const url = new URL(path, baseURL).href;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

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
    await sleep(delayMs);

    if (!response.ok) return null;

    let authDetected = !!response.headers.get("www-authenticate");
    let sensitiveFields = [];
    let hasJsonBody = false;

    const contentType = (
      response.headers.get("content-type") || ""
    ).toLowerCase();
    if (contentType.includes("application/json")) {
      try {
        const body = await response.json();
        sensitiveFields = extractSensitiveFields(body);
        hasJsonBody = true;
      } catch {}
    }

    return {
      path,
      method: "GET",
      status: response.status,
      authDetected,
      sensitiveFields,
      hasJsonBody,
    };
  } catch {
    return null;
  }
}

async function scanLiveURL(inputUrl) {
  // ✅ STEP 1: Check if input is a DIRECT SPEC URL
  if (isDirectSpecUrl(inputUrl)) {
    try {
      const response = await fetch(inputUrl, { timeout: 5000 });
      if (response.ok) {
        const spec = await parseSpecResponse(response, inputUrl);
        if (spec) {
          console.log(
            chalk.green(`✅ Valid OpenAPI/Swagger spec loaded from ${inputUrl}`)
          );
          return { type: "openapi", data: spec, source: inputUrl };
        }
      }
    } catch (e) {
      console.warn(
        chalk.yellow(`⚠️  Could not load spec from ${inputUrl}: ${e.message}`)
      );
    }
  }

  // ✅ STEP 2: Treat as BASE URL and probe for specs
  const baseUrl = inputUrl.endsWith("/") ? inputUrl : inputUrl + "/";

  for (const specPath of SPEC_PATHS_TO_PROBE) {
    try {
      const specUrl = new URL(specPath, baseUrl).href;
      const response = await fetch(specUrl, { timeout: 5000 });

      if (response.ok) {
        const spec = await parseSpecResponse(response, specUrl);
        if (spec) {
          console.log(chalk.green(`✅ Found OpenAPI spec at ${specUrl}`));
          return { type: "openapi", data: spec, source: specUrl };
        }
      }
    } catch {}
  }

  // ✅ STEP 3: Fallback to endpoint probing
  console.log(
    chalk.yellow("⚠️  No OpenAPI spec found. Probing common endpoints...\n")
  );

  const results = [];
  for (const path of COMMON_ENDPOINT_PATHS) {
    const result = await probeEndpoint(baseUrl, path);
    if (result) results.push(result);
  }

  return {
    type: "probed",
    data: results,
    source: baseUrl,
  };
}

function normalizeProbedResults(probedData) {
  const normalized = { paths: {}, _source: "live-probe" };

  for (const result of probedData) {
    if (result.status >= 200 && result.status < 300) {
      const method = "get";
      normalized.paths[result.path] = normalized.paths[result.path] || {};

      let schema = null;
      if (result.hasJsonBody && result.sensitiveFields.length > 0) {
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
        responses: schema ? { [result.status]: { schema } } : {},
        _probed: true,
        _sensitiveFields: result.sensitiveFields,
      };
    }
  }

  return normalized;
}

module.exports = { scanLiveURL, normalizeProbedResults };
