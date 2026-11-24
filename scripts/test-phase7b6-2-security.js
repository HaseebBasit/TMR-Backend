/**
 * Phase 7B.6.2 — Production Secret Hardening & Authentication Rate Limiting Test Suite
 * Mode: Strictly Offline Mock Isolation — Zero Database Writes
 * 
 * Verifies:
 * 1. Cryptographic Secret Validation Invariants (missing, weak, known-default, identical rejection)
 * 2. Cryptographic Secret Generator Utility (256-bit entropy, distinct pairs)
 * 3. In-Memory IP Rate Limiter (headers, threshold enforcement, 429 payload, reset helpers)
 * 4. Integration with POST /api/auth/login (10/15min threshold, no account leakage)
 * 5. Integration with POST /api/auth/forgot-password (5/15min threshold, bucket isolation)
 */

process.env.NODE_ENV = 'test';
// Ensure rate limiting is enabled for this test suite
process.env.TEST_ENABLE_RATE_LIMIT = 'true';

const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const app = require('../src/server');
const {
  validateProductionSecrets,
  KNOWN_INSECURE_SECRETS,
  MIN_SECRET_LENGTH,
} = require('../src/config/secrets');
const {
  createRateLimiter,
  loginRateLimiter,
  passwordResetRateLimiter,
  clearAllRateLimitStores,
} = require('../src/middleware/rateLimiter');
const { generateSecureSecret } = require('./generate-secrets');
const { setMemoryUser } = require('../src/middleware/auth');

let passedTests = 0;
let failedTests = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passedTests++;
  } else {
    console.error(`  [FAIL] ${testName} ${details ? '- ' + details : ''}`);
    failedTests++;
  }
}

let server;
let serverPort;

function makeRequest({ method = 'GET', path, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const reqHeaders = { ...headers };

    if (postData) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: serverPort,
        path,
        method,
        headers: reqHeaders,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(data);
          } catch {
            json = { raw: data };
          }
          resolve({ status: res.statusCode, headers: res.headers, data: json });
        });
      }
    );

    req.on('error', (err) => reject(err));
    if (postData) req.write(postData);
    req.end();
  });
}

async function runSecurityTestSuite() {
  console.log('==================================================================');
  console.log('PHASE 7B.6.2: PRODUCTION SECRET HARDENING & RATE LIMITING TESTS');
  console.log('Mode: Isolated Mock Environment (Zero Live Database Mutations)');
  console.log('==================================================================\n');

  // =========================================================================
  // 1. Production Secret Hardening & Validation Invariants
  // =========================================================================
  console.log('--- 1. Production Secret Hardening Invariants ---');

  // 1.1 Missing JWT_SECRET in production throws fatal exception
  try {
    validateProductionSecrets({
      NODE_ENV: 'production',
      JWT_REFRESH_SECRET: 'a_valid_refresh_secret_that_is_at_least_32_chars_long_12345',
    });
    assert(false, 'Test 1.1: Missing JWT_SECRET in production must throw fatal exception');
  } catch (err) {
    assert(
      err.message.includes('JWT_SECRET is missing or empty'),
      'Test 1.1: Missing JWT_SECRET throws expected fatal exception'
    );
  }

  // 1.2 Empty / whitespace JWT_SECRET in production throws fatal exception
  try {
    validateProductionSecrets({
      NODE_ENV: 'production',
      JWT_SECRET: '   ',
      JWT_REFRESH_SECRET: 'a_valid_refresh_secret_that_is_at_least_32_chars_long_12345',
    });
    assert(false, 'Test 1.2: Empty whitespace JWT_SECRET in production must throw fatal exception');
  } catch (err) {
    assert(
      err.message.includes('JWT_SECRET is missing or empty'),
      'Test 1.2: Empty whitespace JWT_SECRET throws expected fatal exception'
    );
  }

  // 1.3 Missing JWT_REFRESH_SECRET in production throws fatal exception
  try {
    validateProductionSecrets({
      NODE_ENV: 'production',
      JWT_SECRET: 'a_valid_access_secret_that_is_at_least_32_chars_long_12345',
    });
    assert(false, 'Test 1.3: Missing JWT_REFRESH_SECRET in production must throw fatal exception');
  } catch (err) {
    assert(
      err.message.includes('JWT_REFRESH_SECRET is missing or empty'),
      'Test 1.3: Missing JWT_REFRESH_SECRET throws expected fatal exception'
    );
  }

  // 1.4 Known insecure / development default JWT_SECRET rejection
  for (const insecure of KNOWN_INSECURE_SECRETS) {
    try {
      validateProductionSecrets({
        NODE_ENV: 'production',
        JWT_SECRET: insecure,
        JWT_REFRESH_SECRET: 'a_valid_refresh_secret_that_is_at_least_32_chars_long_12345',
      });
      assert(false, `Test 1.4: Known insecure secret "${insecure}" was unexpectedly accepted`);
      break;
    } catch (err) {
      // Expected
    }
  }
  assert(true, 'Test 1.4: All known insecure development secrets rejected for JWT_SECRET');

  // 1.5 Known insecure / development default JWT_REFRESH_SECRET rejection
  try {
    validateProductionSecrets({
      NODE_ENV: 'production',
      JWT_SECRET: 'a_valid_access_secret_that_is_at_least_32_chars_long_12345',
      JWT_REFRESH_SECRET: 'rekhta_refresh_secret_2026_super_secure',
    });
    assert(false, 'Test 1.5: Known insecure default refresh secret was unexpectedly accepted');
  } catch (err) {
    assert(
      err.message.includes('matches a known insecure/development default value'),
      'Test 1.5: Insecure default refresh secret correctly rejected'
    );
  }

  // 1.6 Short / weak JWT_SECRET (< 32 characters) rejection
  try {
    validateProductionSecrets({
      NODE_ENV: 'production',
      JWT_SECRET: 'short_secret_of_only_24_chars', // 28 chars
      JWT_REFRESH_SECRET: 'a_valid_refresh_secret_that_is_at_least_32_chars_long_12345',
    });
    assert(false, 'Test 1.6: Short JWT_SECRET was unexpectedly accepted');
  } catch (err) {
    assert(
      err.message.includes('is insufficiently long'),
      'Test 1.6: Secret under 32 characters correctly rejected'
    );
  }

  // 1.7 Short / weak JWT_REFRESH_SECRET (< 32 characters) rejection
  try {
    validateProductionSecrets({
      NODE_ENV: 'production',
      JWT_SECRET: 'a_valid_access_secret_that_is_at_least_32_chars_long_12345',
      JWT_REFRESH_SECRET: 'short_31_characters_long_secret', // 31 chars
    });
    assert(false, 'Test 1.7: 31-char JWT_REFRESH_SECRET was unexpectedly accepted');
  } catch (err) {
    assert(
      err.message.includes('is insufficiently long'),
      'Test 1.7: Refresh secret under 32 characters correctly rejected'
    );
  }

  // 1.8 Identical access and refresh secrets rejection
  const strongIdenticalKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  try {
    validateProductionSecrets({
      NODE_ENV: 'production',
      JWT_SECRET: strongIdenticalKey,
      JWT_REFRESH_SECRET: strongIdenticalKey,
    });
    assert(false, 'Test 1.8: Identical access and refresh secrets were unexpectedly accepted');
  } catch (err) {
    assert(
      err.message.includes('must be distinct, independently generated secrets'),
      'Test 1.8: Identical access and refresh secrets correctly rejected'
    );
  }

  // 1.9 Valid distinct 32+ char secrets accepted in production
  const validAccess = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_access';
  const validRefresh = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_refresh';
  const prodResult = validateProductionSecrets({
    NODE_ENV: 'production',
    JWT_SECRET: validAccess,
    JWT_REFRESH_SECRET: validRefresh,
  });
  assert(
    prodResult.valid && prodResult.mode === 'production_hardened',
    'Test 1.9: Valid distinct production secrets successfully accepted'
  );

  // 1.10 Development/test fallback behavior (no throw, safe defaults provided)
  const devResult = validateProductionSecrets({
    NODE_ENV: 'development',
  });
  assert(
    devResult.valid && devResult.mode === 'development_fallback' && devResult.accessSecret.length > 0,
    'Test 1.10: Safe development fallback active when NODE_ENV is not production'
  );

  // 1.11 Secret Generator Utility generates 64-char hex (256-bit) high-entropy strings
  const generatedSecret1 = generateSecureSecret(32);
  const generatedSecret2 = generateSecureSecret(32);
  assert(
    generatedSecret1.length === 64 && /^[0-9a-f]{64}$/.test(generatedSecret1),
    'Test 1.11: generateSecureSecret produces 64-character hexadecimal string'
  );
  assert(
    generatedSecret1 !== generatedSecret2,
    'Test 1.12: Repeated secret generations are cryptographically distinct'
  );

  const generatedValidation = validateProductionSecrets({
    NODE_ENV: 'production',
    JWT_SECRET: generatedSecret1,
    JWT_REFRESH_SECRET: generatedSecret2,
  });
  assert(
    generatedValidation.valid && generatedValidation.mode === 'production_hardened',
    'Test 1.13: Generator output passes full production validation'
  );

  // =========================================================================
  // 2. In-Memory Rate Limiter Unit Behavior
  // =========================================================================
  console.log('\n--- 2. Rate Limiter Unit Behavior ---');

  clearAllRateLimitStores();

  // 2.1 Test passthrough when TEST_ENABLE_RATE_LIMIT is false
  const oldEnv = process.env.TEST_ENABLE_RATE_LIMIT;
  process.env.TEST_ENABLE_RATE_LIMIT = 'false';

  const testLimiter = createRateLimiter({
    name: 'unit_test_limiter',
    max: 2,
    windowMs: 60000,
  });

  let nextCalled = false;
  const mockReq = { headers: {}, ip: '10.0.0.1' };
  const mockRes = {
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; return this; },
  };

  testLimiter(mockReq, mockRes, () => { nextCalled = true; });
  assert(nextCalled, 'Test 2.1: Rate limiter passes through when TEST_ENABLE_RATE_LIMIT is false');

  // Re-enable for remaining tests
  process.env.TEST_ENABLE_RATE_LIMIT = 'true';
  clearAllRateLimitStores();

  // 2.2 Header verification and count increment
  let mockNextCount = 0;
  testLimiter(mockReq, mockRes, () => { mockNextCount++; });
  assert(
    mockRes.headers['RateLimit-Limit'] === 2 && mockRes.headers['RateLimit-Remaining'] === 1,
    'Test 2.2: RateLimit-Limit and RateLimit-Remaining headers accurately set on first request'
  );

  testLimiter(mockReq, mockRes, () => { mockNextCount++; });
  assert(
    mockRes.headers['RateLimit-Remaining'] === 0,
    'Test 2.3: RateLimit-Remaining reaches 0 on request equal to max limit'
  );

  // 2.3 Exceeding limit triggers HTTP 429
  let nextCalledOnExceeded = false;
  testLimiter(mockReq, mockRes, () => { nextCalledOnExceeded = true; });
  assert(!nextCalledOnExceeded, 'Test 2.4: Middleware halts pipeline when rate limit exceeded');
  assert(mockRes.statusCode === 429, 'Test 2.5: Returns HTTP status 429 when limit exceeded');
  assert(
    mockRes.payload && mockRes.payload.code === 'RATE_LIMIT_EXCEEDED',
    'Test 2.6: Response body contains RATE_LIMIT_EXCEEDED error code'
  );
  assert(
    typeof mockRes.headers['Retry-After'] === 'number' && mockRes.headers['Retry-After'] > 0,
    'Test 2.7: Retry-After header present and positive integer'
  );

  // 2.4 Independent IP isolation
  const mockReqDifferentIp = { headers: {}, ip: '10.0.0.2' };
  const mockResDifferentIp = {
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; return this; },
  };
  let differentIpPassed = false;
  testLimiter(mockReqDifferentIp, mockResDifferentIp, () => { differentIpPassed = true; });
  assert(
    differentIpPassed && mockResDifferentIp.headers['RateLimit-Remaining'] === 1,
    'Test 2.8: Different client IP has its own independent rate-limiting bucket'
  );

  // 2.5 Store reset verification
  clearAllRateLimitStores();
  let resetIpPassed = false;
  testLimiter(mockReq, mockRes, () => { resetIpPassed = true; });
  assert(
    resetIpPassed && mockRes.headers['RateLimit-Remaining'] === 1,
    'Test 2.9: clearAllRateLimitStores resets rate-limiting bucket immediately'
  );

  // =========================================================================
  // 3. Integration Testing: Login Endpoint (POST /api/auth/login)
  // =========================================================================
  console.log('\n--- 3. Login Endpoint Rate Limiting Integration ---');

  // Seed test user in memory
  const defaultPassword = 'TestPassword123!';
  const hashedPassword = await bcrypt.hash(defaultPassword, 10);
  const testUser = {
    _id: '507f191e810c19729de860ea',
    id: '507f191e810c19729de860ea',
    name: 'Rate Limit Test User',
    email: 'ratelimit.user@rekhta.org',
    password: hashedPassword,
    role: 'super_admin',
    status: 'active',
    tokenVersion: 0,
  };
  setMemoryUser(testUser);

  clearAllRateLimitStores();

  // 3.1 Verify headers on initial request
  const initialLoginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Forwarded-For': '203.0.113.10' },
    body: { email: 'ratelimit.user@rekhta.org', password: 'WrongPassword' },
  });
  assert(
    initialLoginRes.status === 401,
    'Test 3.1: Invalid login returns 401'
  );
  assert(
    initialLoginRes.headers['ratelimit-limit'] === '10',
    'Test 3.2: Login response contains RateLimit-Limit: 10'
  );
  assert(
    initialLoginRes.headers['ratelimit-remaining'] === '9',
    'Test 3.3: Login response contains RateLimit-Remaining: 9 after 1 attempt'
  );

  // 3.2 Send 9 more attempts (reaching 10 total)
  for (let i = 2; i <= 10; i++) {
    await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      headers: { 'X-Forwarded-For': '203.0.113.10' },
      body: { email: 'ratelimit.user@rekhta.org', password: 'WrongPassword' },
    });
  }

  // 3.3 11th request MUST be rate limited with 429
  const throttledLoginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Forwarded-For': '203.0.113.10' },
    body: { email: 'ratelimit.user@rekhta.org', password: defaultPassword }, // Even with valid credentials
  });
  assert(
    throttledLoginRes.status === 429,
    'Test 3.4: 11th login attempt returns HTTP 429'
  );
  assert(
    throttledLoginRes.data.code === 'RATE_LIMIT_EXCEEDED',
    'Test 3.5: Throttled response contains code: RATE_LIMIT_EXCEEDED'
  );
  assert(
    Boolean(throttledLoginRes.headers['retry-after']),
    'Test 3.6: Throttled login includes Retry-After header'
  );

  // 3.4 Verify zero disclosure of account existence
  const nonExistentThrottled = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Forwarded-For': '203.0.113.10' },
    body: { email: 'doesnotexist@rekhta.org', password: 'SomePassword123' },
  });
  assert(
    nonExistentThrottled.status === 429 &&
    nonExistentThrottled.data.error === throttledLoginRes.data.error,
    'Test 3.7: Rate limit error payload is identical for registered and unregistered accounts (zero disclosure)'
  );

  // 3.5 Verify separate IP is not blocked
  const separateIpLoginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Forwarded-For': '203.0.113.20' },
    body: { email: 'ratelimit.user@rekhta.org', password: defaultPassword },
  });
  assert(
    separateIpLoginRes.status === 200 && separateIpLoginRes.data.success,
    'Test 3.8: Distinct IP address is not blocked by another IP exceeding rate limit'
  );

  // =========================================================================
  // 4. Integration Testing: Password Reset Endpoint (POST /api/auth/forgot-password)
  // =========================================================================
  console.log('\n--- 4. Password Reset Rate Limiting Integration ---');

  clearAllRateLimitStores();

  // 4.1 First request to forgot-password
  const initialResetRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/forgot-password',
    headers: { 'X-Forwarded-For': '198.51.100.50' },
    body: { email: 'ratelimit.user@rekhta.org' },
  });
  assert(
    initialResetRes.status === 200,
    'Test 4.1: Forgot password returns 200'
  );
  assert(
    initialResetRes.headers['ratelimit-limit'] === '5',
    'Test 4.2: Password reset response contains RateLimit-Limit: 5'
  );
  assert(
    initialResetRes.headers['ratelimit-remaining'] === '4',
    'Test 4.3: Password reset response contains RateLimit-Remaining: 4 after 1 request'
  );

  // 4.2 Send 4 more requests (reaching 5 total)
  for (let i = 2; i <= 5; i++) {
    await makeRequest({
      method: 'POST',
      path: '/api/auth/forgot-password',
      headers: { 'X-Forwarded-For': '198.51.100.50' },
      body: { email: 'ratelimit.user@rekhta.org' },
    });
  }

  // 4.3 6th request MUST be rate limited with 429
  const throttledResetRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/forgot-password',
    headers: { 'X-Forwarded-For': '198.51.100.50' },
    body: { email: 'ratelimit.user@rekhta.org' },
  });
  assert(
    throttledResetRes.status === 429,
    'Test 4.4: 6th password reset request returns HTTP 429'
  );
  assert(
    throttledResetRes.data.code === 'RATE_LIMIT_EXCEEDED',
    'Test 4.5: Password reset throttled response contains code: RATE_LIMIT_EXCEEDED'
  );
  assert(
    Boolean(throttledResetRes.headers['retry-after']),
    'Test 4.6: Throttled password reset includes Retry-After header'
  );

  // 4.4 Endpoint bucket isolation: rate limited on forgot-password does NOT block login
  const loginWhileResetThrottled = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Forwarded-For': '198.51.100.50' },
    body: { email: 'ratelimit.user@rekhta.org', password: defaultPassword },
  });
  assert(
    loginWhileResetThrottled.status === 200,
    'Test 4.7: Bucket isolation: Being rate limited on password-reset does NOT throttle login'
  );

  // 4.5 Store reset verification across endpoints
  clearAllRateLimitStores();
  const resetAfterClearRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/forgot-password',
    headers: { 'X-Forwarded-For': '198.51.100.50' },
    body: { email: 'ratelimit.user@rekhta.org' },
  });
  assert(
    resetAfterClearRes.status === 200,
    'Test 4.8: clearAllRateLimitStores restores access to password reset immediately'
  );

  // =========================================================================
  // 5. Test Suite Completion & Reporting
  // =========================================================================
  console.log('\n==================================================================');
  console.log(`TEST SUMMARY: ${passedTests} PASSED, ${failedTests} FAILED (TOTAL: ${passedTests + failedTests})`);
  console.log('==================================================================\n');

  server.close(() => {
    process.exit(failedTests > 0 ? 1 : 0);
  });
}

// Start temporary test server on an ephemeral port
server = http.createServer(app);
server.listen(0, '127.0.0.1', () => {
  serverPort = server.address().port;
  console.log(`[Phase 7B.6.2 Test Runner] Ephemeral server listening on port ${serverPort}...`);
  runSecurityTestSuite().catch((err) => {
    console.error('[Fatal Test Runner Error]:', err);
    server.close(() => process.exit(1));
  });
});
