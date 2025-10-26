import fs from "fs";

function parsePostman(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  return JSON.parse(content);
}

function normalizePostman(collection) {
  const normalized = { paths: {}, security: [] };

  function processItems(items, basePath = "") {
    for (const item of items) {
      if (item.item) {
        // Folder — recurse
        processItems(item.item, basePath);
      } else if (item.request) {
        const method = (item.request.method || "GET").toLowerCase();

        // Handle URL (string or object)
        let rawUrl = "";
        if (typeof item.request.url === "string") {
          rawUrl = item.request.url;
        } else if (item.request.url && item.request.url.raw) {
          rawUrl = item.request.url.raw;
        }

        // Extract path (remove protocol/host)
        let path = "/";
        try {
          const url = new URL(
            rawUrl.startsWith("http") ? rawUrl : `http://localhost${rawUrl}`
          );
          path = url.pathname || "/";
        } catch {
          // Fallback: assume it's a relative path
          path = rawUrl.startsWith("/") ? rawUrl : `/${rawUrl}`;
        }

        // Check auth
        const hasAuth = !!(
          item.request.auth ||
          (item.request.header &&
            item.request.header.some(
              (h) => h.key === "Authorization" || h.key === "X-API-Key"
            ))
        );

        normalized.paths[path] = normalized.paths[path] || {};
        normalized.paths[path][method] = {
          security: hasAuth ? ["postman-auth"] : [],
          responses: {}, // Postman rarely has response schemas
          _source: "postman",
        };
      }
    }
  }

  if (collection.item) {
    processItems(collection.item);
  }

  return normalized;
}

export { parsePostman, normalizePostman };
