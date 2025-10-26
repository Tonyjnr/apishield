import fs from "fs";
import yaml from "js-yaml";

function parseOpenAPI(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  if (filePath.endsWith(".json")) {
    return JSON.parse(content);
  } else {
    return yaml.load(content);
  }
}

export { parseOpenAPI };
