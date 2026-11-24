/**
 * Ta'meer-e-Rekhta CSRF Protection Middleware
 * Defends cookie-authenticated state-changing requests against Cross-Site Request Forgery.
 */

const ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://tameererekhta.org',
  'https://www.tameererekhta.org',
  'https://tameer-e-rekhta.vercel.app',
];

if (process.env.FRONTEND_URL) {
  const customFrontend = process.env.FRONTEND_URL.replace(/\/$/, '');
  if (!ALLOWED_ORIGINS.includes(customFrontend)) {
    ALLOWED_ORIGINS.push(customFrontend);
  }
}

if (process.env.ALLOWED_ORIGINS) {
  process.env.ALLOWED_ORIGINS.split(',').forEach((orig) => {
    const trimmed = orig.trim().replace(/\/$/, '');
    if (trimmed && !ALLOWED_ORIGINS.includes(trimmed)) {
      ALLOWED_ORIGINS.push(trimmed);
    }
  });
}

const isOriginAllowed = (origin) => {
  if (!origin) return false;
  return ALLOWED_ORIGINS.some(
    (allowed) => origin === allowed || (origin.endsWith('.vercel.app') && origin.includes('tameer'))
  );
};

const csrfProtection = (req, res, next) => {
  // Safe read-only HTTP methods are exempt
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const origin = req.headers.origin;
  const referer = req.headers.referer;

  // 1. Strict Origin verification when Origin header is supplied
  if (origin) {
    if (!isOriginAllowed(origin)) {
      return res.status(403).json({
        success: false,
        error: `CSRF Protection: Request origin '${origin}' is not authorized.`,
        code: 'CSRF_ORIGIN_REJECTED',
      });
    }
    return next();
  }

  // 2. Fallback to Referer validation when Origin header is omitted
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const refererOrigin = refererUrl.origin;
      if (!isOriginAllowed(refererOrigin)) {
        return res.status(403).json({
          success: false,
          error: `CSRF Protection: Referer origin '${refererOrigin}' is not authorized.`,
          code: 'CSRF_REFERER_REJECTED',
        });
      }
      return next();
    } catch {
      return res.status(403).json({
        success: false,
        error: 'CSRF Protection: Malformed referer header.',
        code: 'CSRF_MALFORMED_REFERER',
      });
    }
  }

  // 3. For Cookie-Authenticated State-Changing Requests:
  // If Origin/Referer is completely missing from a request carrying auth cookies,
  // require a custom verification header (cross-site HTML forms cannot attach custom headers)
  const hasAuthCookie = req.cookies?.rekhta_access_token || req.cookies?.rekhta_refresh_token;
  if (hasAuthCookie) {
    const customHeader =
      req.headers['x-requested-with'] ||
      req.headers['x-rekhta-portal'] ||
      req.headers['x-client-type'];

    if (!customHeader) {
      return res.status(403).json({
        success: false,
        error: 'CSRF Protection: Missing origin and verification header for cookie-authenticated request.',
        code: 'CSRF_HEADER_MISSING',
      });
    }
  }

  next();
};

module.exports = { csrfProtection, ALLOWED_ORIGINS, isOriginAllowed };
