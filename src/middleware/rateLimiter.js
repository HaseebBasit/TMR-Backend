/**
 * Phase 7B.6.2 — Authentication Rate Limiting Middleware
 * 
 * IP-based in-memory rate limiting for publicly accessible authentication endpoints:
 * - Stricter limits on login attempts to mitigate credential brute-forcing.
 * - Abuse prevention limits on password-reset requests.
 * - Consistent HTTP 429 responses with standard RateLimit headers.
 * - Zero disclosure of account existence in error payloads.
 * - Central configuration with automatic in-memory cache sweep.
 * 
 * Note: This implementation provides process-level in-memory rate limiting.
 * For horizontally scaled, multi-instance deployments across multiple Node processes,
 * a distributed shared store (e.g. Redis) is required.
 */

// Central in-memory storage for active rate-limiting windows
const rateLimitStores = new Map();

/**
 * Periodically purge expired IP records to prevent memory leaks.
 */
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStores.entries()) {
    if (now >= record.resetTime) {
      rateLimitStores.delete(key);
    }
  }
}, CLEANUP_INTERVAL_MS);

// Ensure cleanup interval does not block Node process termination
if (cleanupTimer.unref) {
  cleanupTimer.unref();
}

/**
 * Extract client IP address accurately, supporting reverse proxies.
 */
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded && typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || '127.0.0.1';
}

/**
 * Factory function to create centralized rate limiting middleware.
 */
function createRateLimiter(options) {
  const {
    name,
    windowMs = 15 * 60 * 1000, // 15 minutes default
    max = 10,                   // 10 requests default
    message = 'Too many requests from this IP address. Please try again later.',
  } = options;

  return function rateLimiter(req, res, next) {
    // In test environment, pass through unless TEST_ENABLE_RATE_LIMIT is explicitly set
    if (process.env.NODE_ENV === 'test' && process.env.TEST_ENABLE_RATE_LIMIT !== 'true') {
      return next();
    }

    const ip = getClientIp(req);
    const key = `${name}:${ip}`;
    const now = Date.now();

    let record = rateLimitStores.get(key);

    if (!record || now >= record.resetTime) {
      record = {
        count: 1,
        resetTime: now + windowMs,
      };
      rateLimitStores.set(key, record);
    } else {
      record.count += 1;
    }

    const effectiveMax = typeof options.getMax === 'function' ? options.getMax() : max;
    const remaining = Math.max(0, effectiveMax - record.count);
    const resetTimeSeconds = Math.ceil(record.resetTime / 1000);
    const retryAfterSeconds = Math.max(1, Math.ceil((record.resetTime - now) / 1000));

    // Standard IETF RateLimit Headers
    res.setHeader('RateLimit-Limit', effectiveMax);
    res.setHeader('RateLimit-Remaining', remaining);
    res.setHeader('RateLimit-Reset', resetTimeSeconds);

    if (record.count > effectiveMax) {
      res.setHeader('Retry-After', retryAfterSeconds);
      return res.status(429).json({
        success: false,
        error: message,
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: retryAfterSeconds,
      });
    }

    next();
  };
}

/**
 * Login Rate Limiter:
 * 10 attempts per 15-minute window in production.
 * Stricter threshold to mitigate brute-force password guessing.
 */
const loginRateLimiter = createRateLimiter({
  name: 'auth_login',
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  getMax: () => {
    if (process.env.RATE_LIMIT_LOGIN_MAX) {
      return parseInt(process.env.RATE_LIMIT_LOGIN_MAX, 10);
    }
    return 10;
  },
  message: 'Too many login attempts from this IP address. Please try again after 15 minutes.',
});

/**
 * Password Reset Rate Limiter:
 * 5 requests per 15-minute window in production.
 * Prevents email enumeration and SMTP spam.
 */
const passwordResetRateLimiter = createRateLimiter({
  name: 'auth_forgot_password',
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  getMax: () => {
    if (process.env.RATE_LIMIT_RESET_MAX) {
      return parseInt(process.env.RATE_LIMIT_RESET_MAX, 10);
    }
    return 5;
  },
  message: 'Too many password reset requests from this IP address. Please try again after 15 minutes.',
});

/**
 * Emergency Access Rate Limiter:
 * 20 requests per 15-minute window in production.
 * Prevents key brute-forcing on emergency interface while allowing multi-step verification.
 */
const emergencyAccessRateLimiter = createRateLimiter({
  name: 'emergency_access',
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  getMax: () => {
    if (process.env.RATE_LIMIT_EMERGENCY_MAX) {
      return parseInt(process.env.RATE_LIMIT_EMERGENCY_MAX, 10);
    }
    return 20;
  },
  message: 'Too many emergency access attempts from this IP address. Please try again after 15 minutes.',
});

/**
 * Reset helper for testing isolation.
 */
function clearAllRateLimitStores() {
  rateLimitStores.clear();
}

function clearRateLimitStore(name, ip) {
  if (name && ip) {
    rateLimitStores.delete(`${name}:${ip}`);
  } else if (name) {
    for (const key of rateLimitStores.keys()) {
      if (key.startsWith(`${name}:`)) {
        rateLimitStores.delete(key);
      }
    }
  } else {
    rateLimitStores.clear();
  }
}

module.exports = {
  createRateLimiter,
  loginRateLimiter,
  passwordResetRateLimiter,
  emergencyAccessRateLimiter,
  clearAllRateLimitStores,
  clearRateLimitStore,
  getClientIp,
};
