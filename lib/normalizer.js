// lib/normalizer.js
const chalk = require('chalk');

// Sensitive field patterns (shared across scanners)
const SENSITIVE_FIELDS = {
  // 🔑 1. Authentication & Credentials
  credentials: [
    'password', 'passwd', 'pwd', 'secret', 'token', 'access_token', 'refresh_token',
    'auth', 'authorization', 'bearer', 'session', 'sessionid', 'session_id',
    'login', 'userpass', 'credentials', 'api_key', 'apikey', 'client_secret',
    'client_id', 'app_secret', 'app_key'
  ],

  // 🔐 2. Encryption & Cryptographic Keys
  encryptionKeys: [
    'encryptionkey', 'encryption_key', 'privatekey', 'private_key', 'publickey',
    'public_key', 'ssh_key', 'rsa_key', 'gpg_key', 'pem', 'cert', 'certificate',
    'keystore', 'salt', 'iv', 'crypto_key', 'signing_key', 'keypair'
  ],

  // 💳 3. Financial & Payment Data
  financial: [
    'creditcard', 'credit_card', 'card_number', 'cc_number', 'cvv', 'cvc', 'ccv',
    'expiration', 'expiry_date', 'billing_address', 'iban', 'swift', 'routing_number',
    'account_number', 'account_no', 'bank_account', 'bank_name', 'transaction_id',
    'payment_info', 'card_info', 'upi_id', 'wallet_id'
  ],

  // 🧍 4. Personal Identifiers (PII)
  pii: [
    'ssn', 'social_security', 'socialsecurity', 'national_id', 'nid', 'passport',
    'passport_number', 'driver_license', 'license_number', 'employee_id', 'student_id',
    'tax_id', 'tin', 'voter_id', 'citizen_id'
  ],

  // 🏠 5. Personal Information (General)
  personalInfo: [
    'dob', 'date_of_birth', 'birthdate', 'firstname', 'lastname', 'fullname', 'name',
    'email', 'phone', 'phonenumber', 'mobile', 'address', 'home_address', 'zipcode',
    'zip', 'postalcode', 'state', 'country', 'city', 'gender', 'age'
  ],

  // 🧬 6. Health & Biometric Information
  health: [
    'fingerprint', 'retina', 'iris', 'dna', 'medical_record', 'health_id',
    'insurance_number', 'insuranceid', 'patient_id', 'diagnosis', 'treatment',
    'blood_type', 'disability_status', 'medication'
  ],

  // 🧩 7. System / App Tokens
  systemTokens: [
    'csrf_token', 'xsrf_token', 'otp', '2fa', 'mfa', 'recovery_code', 'reset_token',
    'invite_code', 'activation_key', 'magic_link', 'verification_code', 'reset_code'
  ],

  // ☁️ 8. Cloud & DevOps Secrets
  cloudSecrets: [
    'aws_secret_access_key', 'aws_access_key_id', 'azure_key', 'gcp_key',
    'service_account', 'firebase_key', 'webhook_secret', 'slack_webhook',
    'discord_token', 'github_token', 'gitlab_token', 'npm_token', 'docker_token',
    'heroku_api_key', 'vercel_token', 'netlify_token', 'digitalocean_key',
    'ssh_config', 'ci_secret', 'ci_token'
  ],

  // 🌐 9. Network / Device Identifiers
  network: [
    'ip', 'ip_address', 'mac', 'mac_address', 'hostname', 'device_id', 'device_token',
    'location', 'geo', 'latitude', 'longitude', 'tracking_id', 'session_cookie',
    'cookie', 'browser_fingerprint'
  ],

  // 🧱 10. Configuration / Internal System Data
  systemConfig: [
    'debug', 'stacktrace', 'error_trace', 'internal_note', 'admin_comment',
    'system_path', 'config_path', 'logfile', 'log_path'
  ]
};

// 👇 Flattened array for quick scanning
const ALL_SENSITIVE_FIELDS = Object.values(SENSITIVE_FIELDS_CATEGORIES).flat();

function isSensitiveField(fieldName) {
  const lowerName = fieldName.toLowerCase();
  return ALL_SENSITIVE_FIELDS.some(pattern => 
    lowerName.includes(pattern.toLowerCase())
  );
}

/**
 * Normalize Swagger 2.0 specs to OpenAPI 3-like structure
 */
function normalizeSpec(spec) {
  if (spec.swagger && spec.swagger.startsWith('2.')) {
    console.log(
      chalk.yellow(
        '⚠️  Detected Swagger 2.0 — converting to OpenAPI-like structure...\n'
      )
    );

    const normalized = {
      openapi: '3.0.0',
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
        if (['parameters', '$ref', 'summary', 'description', 'consumes', 'produces'].includes(method)) {
          continue;
        }

        const normMethod = method.toLowerCase();
        normalized.paths[pathStr][normMethod] = {
          ...op,
          security: op.security !== undefined ? op.security : normalized.security,
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

/**
 * Scan a normalized spec for security issues
 */
function scanSpec(normalizedSpec) {
  const issues = [];
  const paths = normalizedSpec.paths || {};

  for (const [pathStr, pathObj] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(pathObj)) {
      if (typeof op !== 'object') continue;

      const opId = `${method.toUpperCase()} ${pathStr}`;

      // 🔒 Check: Missing authentication
      const hasSecurity = 
        (Array.isArray(op.security) && op.security.length > 0) || 
        (Array.isArray(normalizedSpec.security) && normalizedSpec.security.length > 0);

      const isLikelyPublic = /login|register|signup|auth|public|health|status|metrics/i.test(pathStr);
      
      if (!hasSecurity && !isLikelyPublic) {
        issues.push({
          severity: 'high',
          message: 'Missing authentication',
          detail: `Endpoint ${opId} has no security scheme defined.`,
          fix: "Add a 'security' block to the operation or global spec."
        });
      }

      // 👁️ Check: Sensitive data in responses
      const responses = op.responses || {};
      for (const [status, res] of Object.entries(responses)) {
        if (!status.startsWith('2')) continue;

        let schema = null;
        // OpenAPI 3.x
        if (res.content && res.content['application/json']) {
          schema = res.content['application/json'].schema;
        } 
        // Swagger 2.0
        else if (res.schema) {
          schema = res.schema;
        }

        if (!schema) continue;

        const findSensitiveFields = (obj, prefix = '') => {
          let fields = [];
          if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
            for (const [key, value] of Object.entries(obj)) {
              const fullName = prefix ? `${prefix}.${key}` : key;
              if (isSensitiveField(key)) {
                fields.push(fullName);
              }
              if (value && typeof value === 'object') {
                fields = fields.concat(findSensitiveFields(value, fullName));
              }
            }
          }
          return fields;
        };

        const sensitiveFields = findSensitiveFields(schema);
        if (sensitiveFields.length > 0) {
          issues.push({
            severity: 'high',
            message: 'Sensitive data exposed in response',
            detail: `${opId} returns: ${sensitiveFields.join(', ')}`,
            fix: 'Remove or mask sensitive fields from the response schema.'
          });
        }
      }
    }
  }

  return issues;
}

module.exports = {
  normalizeSpec,
  scanSpec,
  isSensitiveField, // useful for HAR/Postman later
  SENSITIVE_FIELDS
};