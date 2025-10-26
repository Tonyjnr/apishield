import fs from "fs";

function parseHAR(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  return JSON.parse(content);
}

function inferSchema(obj) {
  if (obj === null) return { type: "null" };
  if (typeof obj !== "object") return { type: typeof obj };
  if (Array.isArray(obj)) {
    return {
      type: "array",
      items: obj.length > 0 ? inferSchema(obj[0]) : {},
    };
  }
  const properties = {};
  for (const [key, value] of Object.entries(obj)) {
    properties[key] = inferSchema(value);
  }
  return { type: "object", properties };
}

function normalizeHAR(harData) {
  const normalized = { paths: {}, _source: "har" };

  const entries = harData.log?.entries || [];

  for (const entry of entries) {
    const request = entry.request;
    const response = entry.response;

    if (!request || !response) continue;

    // Skip non-HTTP(S)
    if (!request.url.startsWith("http")) continue;

    const url = new URL(request.url);
    const path = url.pathname || "/";
    const method = request.method.toLowerCase();

    // Check auth in request
    const hasAuthHeader = request.headers?.some(
      (h) =>
        h.name.toLowerCase() === "authorization" ||
        h.name.toLowerCase() === "x-api-key"
    );

    // Parse response body if JSON
    let responseSchema = null;
    if (
      response.content?.mimeType === "application/json" &&
      response.content.text
    ) {
      try {
        const body = JSON.parse(response.content.text);
        responseSchema = inferSchema(body);
      } catch {}
    }

    normalized.paths[path] = normalized.paths[path] || {};
    normalized.paths[path][method] = {
      security: hasAuthHeader ? ["har-auth"] : [],
      responses: responseSchema
        ? {
            [response.status]: {
              schema: responseSchema,
            },
          }
        : {},
      _source: "har",
    };
  }

  return normalized;
}

export { parseHAR, normalizeHAR };
