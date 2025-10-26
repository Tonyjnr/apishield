// lib/reporters/threatModel.js
import chalk from "chalk";

/**
 * Maps APIShield issues to STRIDE threat model
 */
const THREAT_MAP = {
  "Missing authentication": {
    stride: "Spoofing",
    impact:
      "An attacker can access or modify resources without authentication.",
    owasp: "API1:2023 - Broken Object Level Authorization",
    severity: "high",
  },
  "Sensitive data exposed in response": {
    stride: "Information Disclosure",
    impact:
      "PII, secrets, or internal data may be leaked to unauthorized parties.",
    owasp: "API3:2023 - Excessive Data Exposure",
    severity: "high",
  },
  "Excessive data exposure": {
    stride: "Information Disclosure",
    impact:
      "Large responses increase attack surface and risk of accidental data leaks.",
    owasp: "API3:2023 - Excessive Data Exposure",
    severity: "medium",
  },
  // Compliance violations
  "GDPR compliance violation": {
    stride: "Information Disclosure",
    impact:
      "Personal data exposure violates European data protection regulations.",
    owasp: "API3:2023 - Excessive Data Exposure",
    severity: "high",
  },
  "CCPA compliance violation": {
    stride: "Information Disclosure",
    impact: "Personal data exposure violates California privacy rights.",
    owasp: "API3:2023 - Excessive Data Exposure",
    severity: "high",
  },
  "HIPAA compliance violation": {
    stride: "Information Disclosure",
    impact:
      "Health information exposure violates healthcare data protection laws.",
    owasp: "API3:2023 - Excessive Data Exposure",
    severity: "high",
  },
  "PCI-DSS compliance violation": {
    stride: "Information Disclosure",
    impact: "Payment data exposure violates card industry security standards.",
    owasp: "API3:2023 - Excessive Data Exposure",
    severity: "high",
  },
};

/**
 * Generate a STRIDE-based threat model report
 */
function generateThreatModel(issues) {
  console.log(chalk.bold.blue("\n🛡️  APIShield Threat Model Report\n"));

  if (issues.length === 0) {
    console.log(chalk.green("✅ No security threats identified!"));
    console.log(
      chalk.gray("Your API appears to follow security best practices.\n")
    );
    return;
  }

  // Group issues by STRIDE category
  const strideGroups = {
    Spoofing: [],
    "Information Disclosure": [],
    Tampering: [],
    Repudiation: [],
    "Denial of Service": [],
    "Elevation of Privilege": [],
    Unknown: [],
  };

  // Categorize issues
  issues.forEach((issue) => {
    const threat = THREAT_MAP[issue.message] || {
      stride: "Unknown",
      impact: "Unknown threat type",
      owasp: "Unknown",
      severity: issue.severity || "unknown",
    };

    if (!strideGroups[threat.stride]) {
      strideGroups[threat.stride] = [];
    }

    strideGroups[threat.stride].push({
      ...issue,
      threat,
    });
  });

  // Display threats by STRIDE category
  Object.entries(strideGroups).forEach(([strideCategory, threats]) => {
    if (threats.length === 0) return;

    console.log(chalk.bold.cyan(`\n📋 ${strideCategory.toUpperCase()}`));
    console.log(chalk.gray(`${threats.length} threat(s) identified\n`));

    threats.forEach((issue, index) => {
      const severityColor =
        issue.threat.severity === "high" ? chalk.red : chalk.yellow;

      console.log(severityColor(`${index + 1}. ${issue.message}`));
      console.log(chalk.gray(`   → ${issue.detail}`));
      console.log(chalk.gray(`   Impact: ${issue.threat.impact}`));
      console.log(chalk.gray(`   OWASP: ${issue.threat.owasp}`));
      console.log(chalk.yellow(`   🔧 Fix: ${issue.fix}`));

      if (issue.regulations) {
        console.log(
          chalk.gray(`   Regulations: ${issue.regulations.join(", ")}`)
        );
      }

      console.log(); // Empty line for readability
    });
  });

  // Summary
  console.log(chalk.bold.blue("\n📊 Threat Summary"));
  console.log(chalk.gray(`Total threats: ${issues.length}`));

  const severityCounts = issues.reduce((acc, issue) => {
    const threat = THREAT_MAP[issue.message];
    const severity = threat?.severity || issue.severity || "unknown";
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});

  Object.entries(severityCounts).forEach(([severity, count]) => {
    const color =
      severity === "high"
        ? chalk.red
        : severity === "medium"
        ? chalk.yellow
        : chalk.gray;
    console.log(
      color(
        `   ${severity.charAt(0).toUpperCase() + severity.slice(1)}: ${count}`
      )
    );
  });

  console.log(chalk.gray("\n💡 Learn more about STRIDE threat modeling:"));
  console.log(chalk.gray("   https://owasp.org/www-community/Threat_Modeling"));
}

/**
 * Generate a JSON threat model report
 */
function generateThreatModelJSON(issues) {
  const threats = issues.map((issue) => {
    const threat = THREAT_MAP[issue.message] || {
      stride: "Unknown",
      impact: "Unknown threat type",
      owasp: "Unknown",
      severity: issue.severity || "unknown",
    };

    return {
      message: issue.message,
      detail: issue.detail,
      fix: issue.fix,
      severity: issue.severity,
      stride: threat.stride,
      impact: threat.impact,
      owasp: threat.owasp,
      regulations: issue.regulations || null,
    };
  });

  return {
    timestamp: new Date().toISOString(),
    totalThreats: issues.length,
    threats,
  };
}

export { generateThreatModel, generateThreatModelJSON, THREAT_MAP };
