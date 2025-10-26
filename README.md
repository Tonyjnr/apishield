# 🛡️ APIShield

**Fast, lightweight API security scanner for indie developers.**

APIShield analyzes your OpenAPI/Swagger specs and catches common security issues before they reach production. Perfect for CI/CD pipelines, pre-commit hooks, and local development.

[![npm version](https://img.shields.io/npm/v/@tonyjnr/apishield.svg)](https://www.npmjs.com/package/@tonyjnr/apishield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

- 🔍 **Multi-format support**: OpenAPI 3.x, Swagger 2.0, YAML & JSON
- 🚨 **Security checks**: Missing auth, sensitive data exposure, excessive data leakage
- ⚡ **Lightning fast**: Scans in milliseconds, perfect for CI/CD
- 🎯 **Zero config**: Just point it at your spec file
- 🎨 **Beautiful output**: Color-coded issues with actionable fixes
- 🔧 **CI-friendly**: Exits with error code on issues

---

## 🚀 Quick Start

### Installation

```bash
# Global installation (recommended)
npm install -g @tonyjnr/apishield

# Or use with npx (no install needed)
npx @tonyjnr/apishield scan openapi.yaml
```

### Usage

```bash
# Scan an OpenAPI 3 file
apishield scan openapi.yaml

# Scan a Swagger 2.0 file
apishield scan swagger.json

# Verbose mode
apishield scan api-spec.yaml --verbose
```

---

## 📋 What It Checks

### 🔒 Missing Authentication

Detects endpoints without security schemes (excludes common public paths like `/login`, `/register`, `/public/*`, `/health`)

```yaml
# ❌ Will flag this
/admin/users:
  get:
    responses: ...
    # No security defined!

# ✅ This is good
/admin/users:
  get:
    security:
      - bearerAuth: []
    responses: ...
```

### 👁️ Sensitive Data Exposure

Scans response schemas for fields that shouldn't be exposed:

- Passwords (`password`, `passwd`, `pwd`)
- Tokens (`token`, `apiKey`, `secret`)
- Personal data (`ssn`, `creditCard`, `cvv`, `dob`)
- Private keys (`privateKey`, `private_key`)

```yaml
# ❌ Will flag this
/users/{id}:
  get:
    responses:
      '200':
        content:
          application/json:
            schema:
              properties:
                username: string
                password: string  # 🚨 EXPOSED!
```

### 📊 Excessive Data Exposure

Warns when GET endpoints return too many fields (>20), suggesting pagination or field filtering.

---

## 🎯 Real-World Example

**Input** (`api.yaml`):

```yaml
openapi: 3.0.0
paths:
  /users/{id}:
    get:
      responses:
        '200':
          content:
            application/json:
              schema:
                properties:
                  id: string
                  username: string
                  password: string
```

**Output**:

```🔍 Scanning api.yaml (3.0.0)...

🚨 High Severity Issues (2):

1. Missing authentication
   Endpoint GET /users/{id} has no security scheme defined.
   💡 Add a 'security' block to the operation or global spec.

2. Sensitive data exposed in response
   GET /users/{id} returns: password
   💡 Remove or mask sensitive fields from the response schema.

📊 Summary: 2 issue(s) detected
   High: 2 | Medium: 0
```

---

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
name: API Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npx @tonyjnr/apishield scan openapi.yaml
```

### Pre-commit Hook

```bash
# .husky/pre-commit
npx @tonyjnr/apishield scan openapi.yaml
```

### GitLab CI

```yaml
api_security:
  script:
    - npx @tonyjnr/apishield scan openapi.yaml
```

---

## 🗺️ Roadmap

### Phase 1 (Current - v0.1.x)

- ✅ OpenAPI 3.x support
- ✅ Swagger 2.0 support
- ✅ JSON & YAML parsing
- ✅ Basic security checks

### Phase 2 (v0.2.x) - Coming Soon

- 🔜 Postman Collection support
- 🔜 HAR file analysis
- 🔜 Live URL scanning
- 🔜 Custom rule configuration

### Phase 3 (v0.3.x)

- 🔮 GraphQL schema support
- 🔮 AI-powered test generation
- 🔮 Web dashboard
- 🔮 Team collaboration features

---

## 🤝 Contributing

Found a bug? Have an idea? Contributions welcome!

```bash
# Clone the repo
git clone https://github.com/tonyjnr/apishield.git
cd apishield

# Install dependencies
npm install

# Test locally
node index.js scan test-files/swagger2-test.json
```

---

## 📖 Supported Formats

| Format | Extension | Status |
|--------|-----------|--------|
| OpenAPI 3.0 | `.yaml`, `.yml`, `.json` | ✅ Full support |
| OpenAPI 3.1 | `.yaml`, `.yml`, `.json` | ✅ Full support |
| Swagger 2.0 | `.json`, `.yaml` | ✅ Full support |
| Postman Collection | `.postman_collection.json` | 🔜 Phase 2 |
| HAR Files | `.har` | 🔜 Phase 2 |
| GraphQL | `.graphql` | 🔜 Phase 3 |

---

## 💡 Why APIShield?

Most API security tools are:

- 🏢 Enterprise-focused (expensive, complex)
- 🐌 Slow (require full environment setup)
- 🔌 Runtime-only (catch issues too late)

**APIShield is different:**

- 🆓 Free and open source
- ⚡ Instant feedback (static analysis)
- 🎯 Built for indie devs & small teams
- 🔄 CI/CD native

---

## 📝 License

MIT © Onuzulike Anthony Ifechukwu

---

## 🙏 Acknowledgments

Inspired by the OWASP API Security Top 10 and built for the indie dev community.

**Made with ❤️ for developers who ship fast but secure.**

---

## 📬 Support

- 🐛 [Report a bug](https://github.com/tonyjnr/apishield/issues)
- 💡 [Request a feature](https://github.com/tonyjnr/apishield/issues)
- 📧 Email: <onuzulikeanthony432@gmail.com>

---

**Star ⭐ this repo if APIShield helps secure your APIs!**
