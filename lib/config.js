// lib/config.js
import fs from "fs";
import path from "path";
import chalk from "chalk";

const DEFAULT_CONFIG = {
  ignorePaths: [],
  customSensitiveFields: [],
  rules: {
    missingAuth: "error",
    sensitiveData: "error",
  },
};

function loadConfig(cwd = process.cwd()) {
  const configPath = path.join(cwd, "config.apishield.json");

  if (fs.existsSync(configPath)) {
    try {
      const userConfig = JSON.parse(fs.readFileSync(configPath, "utf8"));
      const merged = { ...DEFAULT_CONFIG, ...userConfig };

      // Merge arrays properly
      if (userConfig.ignorePaths) {
        merged.ignorePaths = [
          ...new Set([
            ...DEFAULT_CONFIG.ignorePaths,
            ...userConfig.ignorePaths,
          ]),
        ];
      }
      if (userConfig.customSensitiveFields) {
        merged.customSensitiveFields = [
          ...new Set([
            ...DEFAULT_CONFIG.customSensitiveFields,
            ...userConfig.customSensitiveFields,
          ]),
        ];
      }

      console.log(chalk.gray("📝 Using config from .apishield.json"));
      return merged;
    } catch (e) {
      console.warn(
        chalk.yellow("⚠️  Invalid .apishield.json — using defaults")
      );
    }
  }

  return DEFAULT_CONFIG;
}

export { loadConfig, DEFAULT_CONFIG };
