const fs = require("fs");
const yaml = require("js-yaml");

function parseOpenAPI(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  if (filePath.endsWith(".json")) {
    return JSON.parse(content);
  } else {
    return yaml.load(content);
  }
}

module.exports = { parseOpenAPI };
