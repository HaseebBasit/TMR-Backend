/**
 * Phase 7B.6.2 — Production Secret Hardening & Validation Module
 * 
 * Enforces production security invariants for cryptographic tokens:
 * 1. Fails fast if JWT_SECRET or JWT_REFRESH_SECRET is missing in production.
 * 2. Fails fast if secrets match known development or default fallback strings.
 * 3. Fails fast if secrets are under 32 characters (256 bits of entropy minimum).
 * 4. Fails fast if access-token and refresh-token secrets are identical.
 * 5. Provides safe fallbacks in development/test mode without compromising production.
 */

const KNOWN_INSECURE_SECRETS = [
  'rekhta_access_secret_2026_super_secure',
  'rekhta_refresh_secret_2026_super_secure',
  'rekhta_super_secret_jwt_key_2026',
  'rekhta_refresh_super_secret_2026',
  'secret',
  'jwt_secret',
  'jwt_refresh_secret',
  'password',
  'super_secret',
  '12345678',
  'changeme',
];

const MIN_SECRET_LENGTH = 32;

/**
 * Validate JWT secret configuration against production safety invariants.
 * @param {Object} env Environment variables object (defaults to process.env)
 * @returns {Object} Object containing validated accessSecret and refreshSecret
 */
function validateProductionSecrets(env = process.env) {
  const isProduction = env.NODE_ENV === 'production';
  const accessSecret = env.JWT_SECRET;
  const refreshSecret = env.JWT_REFRESH_SECRET;

  if (!isProduction) {
    return {
      valid: true,
      mode: 'development_fallback',
      accessSecret: accessSecret || 'rekhta_access_secret_2026_super_secure',
      refreshSecret: refreshSecret || 'rekhta_refresh_secret_2026_super_secure',
    };
  }

  // 1. Missing secret validation
  if (!accessSecret || typeof accessSecret !== 'string' || accessSecret.trim() === '') {
    throw new Error('[FATAL SECURITY EXCEPTION]: Production JWT_SECRET is missing or empty.');
  }
  if (!refreshSecret || typeof refreshSecret !== 'string' || refreshSecret.trim() === '') {
    throw new Error('[FATAL SECURITY EXCEPTION]: Production JWT_REFRESH_SECRET is missing or empty.');
  }

  const trimmedAccess = accessSecret.trim();
  const trimmedRefresh = refreshSecret.trim();

  // 2. Known default / development secret rejection
  if (KNOWN_INSECURE_SECRETS.includes(trimmedAccess)) {
    throw new Error('[FATAL SECURITY EXCEPTION]: Production JWT_SECRET matches a known insecure/development default value.');
  }
  if (KNOWN_INSECURE_SECRETS.includes(trimmedRefresh)) {
    throw new Error('[FATAL SECURITY EXCEPTION]: Production JWT_REFRESH_SECRET matches a known insecure/development default value.');
  }

  // 3. Minimum length & entropy enforcement (>= 32 characters / 256 bits)
  if (trimmedAccess.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `[FATAL SECURITY EXCEPTION]: Production JWT_SECRET is insufficiently long (${trimmedAccess.length} chars). Minimum ${MIN_SECRET_LENGTH} characters required.`
    );
  }
  if (trimmedRefresh.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `[FATAL SECURITY EXCEPTION]: Production JWT_REFRESH_SECRET is insufficiently long (${trimmedRefresh.length} chars). Minimum ${MIN_SECRET_LENGTH} characters required.`
    );
  }

  // 4. Distinct secrets requirement (Access and Refresh keys must never be identical)
  if (trimmedAccess === trimmedRefresh) {
    throw new Error(
      '[FATAL SECURITY EXCEPTION]: Production JWT_SECRET and JWT_REFRESH_SECRET must be distinct, independently generated secrets.'
    );
  }

  return {
    valid: true,
    mode: 'production_hardened',
    accessSecret: trimmedAccess,
    refreshSecret: trimmedRefresh,
  };
}

module.exports = {
  validateProductionSecrets,
  KNOWN_INSECURE_SECRETS,
  MIN_SECRET_LENGTH,
};
