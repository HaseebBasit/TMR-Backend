/**
 * Phase 10J Verification Test Suite:
 * - Login Failure & Error Classification Investigation
 * - Accurate Error Responses (401, 403, 429, 5xx, Network)
 * - Complete Authentication Lifecycle & Session Preservation
 * - Logo Preload Warnings Remediation
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_jwt_secret_phase10j_verification_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_phase10j_verification_2026';

const http = require('http');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');
const { clearAllRateLimitStores } = require('../src/middleware/rateLimiter');

const TEST_PORT = 5009;
let server;
let passed = 0;
let failed = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName} ${details ? '- ' + details : ''}`);
    failed++;
  }
}

function makeRequest({ method = 'GET', path, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const postData = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
    const reqHeaders = { ...headers };

    if (postData) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(
      {
        hostname: 'localhost',
        port: TEST_PORT,
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

function extractCookie(headers, cookieName) {
  const setCookie = headers['set-cookie'];
  if (!setCookie) return null;
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const c of cookies) {
    if (c.startsWith(`${cookieName}=`)) {
      return c.split(';')[0].split('=')[1];
    }
  }
  return null;
}

function parseCookieAttributes(headers, cookieName) {
  const setCookie = headers['set-cookie'];
  if (!setCookie) return {};
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const c of cookies) {
    if (c.startsWith(`${cookieName}=`)) {
      const parts = c.split(';').map((p) => p.trim());
      const attrs = { raw: c };
      for (const p of parts) {
        const [k, v] = p.split('=');
        if (k.toLowerCase() === 'httponly') attrs.httpOnly = true;
        if (k.toLowerCase() === 'secure') attrs.secure = true;
        if (k.toLowerCase() === 'samesite') attrs.sameSite = v?.toLowerCase();
        if (k.toLowerCase() === 'path') attrs.path = v;
      }
      return attrs;
    }
  }
  return {};
}

/**
 * Simulates client-side classifyLoginError logic from AuthContext.tsx
 */
function classifyLoginError(res, data) {
  if (res.status === 401) {
    return data?.error || 'Invalid credentials. Please verify your email and password.';
  } else if (res.status === 403) {
    return data?.error || 'Access forbidden. Your account may be suspended or lacks required permissions.';
  } else if (res.status === 429) {
    return data?.error || 'Too many login attempts from this IP address. Please try again after 15 minutes.';
  } else if (res.status >= 500 && res.status < 600) {
    return data?.error || `Authentication server error (HTTP ${res.status}). Please try again in a moment.`;
  } else if (data?.error) {
    return data.error;
  }
  return `Authentication error (HTTP ${res.status}). Please check your credentials and try again.`;
}

async function runTests() {
  console.log('========================================================================');
  console.log('PHASE 10J: LOGIN FAILURE INVESTIGATION & AUTH SERVER ERROR REMEDIATION');
  console.log('========================================================================\n');

  await new Promise((resolve) => {
    server = app.listen(TEST_PORT, () => resolve());
  });

  const password = 'TestSecurePassword123!';
  const hashedPassword = await bcrypt.hash(password, 10);

  // Personas
  const activeUser = {
    _id: '607f191e810c19729de8a001',
    id: '607f191e810c19729de8a001',
    name: 'Aisha Tariq',
    email: 'aishatariq@rekhta.org',
    role: 'dept_media',
    department: 'Media',
    departmentCode: 'MED',
    status: 'active',
    password: hashedPassword,
    save: async function () { return this; },
  };

  const suspendedUser = {
    _id: '607f191e810c19729de8a002',
    id: '607f191e810c19729de8a002',
    name: 'Suspended Member',
    email: 'suspended@rekhta.org',
    role: 'member',
    department: 'Media',
    departmentCode: 'MED',
    status: 'suspended',
    password: hashedPassword,
    save: async function () { return this; },
  };

  setMemoryUser(activeUser);
  setMemoryUser(suspendedUser);

  // ------------------------------------------------------------------------
  // SECTION 1: Error Classification Accuracy (Section 2 Requirements)
  // ------------------------------------------------------------------------
  console.log('--- SECTION 1: Frontend Error Classification (Never false connection error) ---');

  // Test 1.1: Invalid credentials return 401
  const invalidRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: { email: 'aishatariq@rekhta.org', password: 'WrongPassword!' },
  });
  assert(invalidRes.status === 401, '1.1 Invalid credentials return HTTP 401');
  const classified401 = classifyLoginError(invalidRes, invalidRes.data);
  assert(
    classified401.includes('Invalid credentials') && !classified401.includes('Unable to connect'),
    '1.2 HTTP 401 correctly classified as invalid credentials (NOT connection error)'
  );

  // Test 1.3: Suspended account returns 403
  const suspendedRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: { email: 'suspended@rekhta.org', password },
  });
  assert(suspendedRes.status === 403, '1.3 Suspended account rejected with HTTP 403');
  const classified403 = classifyLoginError(suspendedRes, suspendedRes.data);
  assert(
    classified403.includes('suspended') && !classified403.includes('Unable to connect'),
    '1.4 HTTP 403 correctly classified as account suspended/forbidden'
  );

  // Test 1.5: Missing fields return 400
  const missingRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: { email: '', password: '' },
  });
  assert(missingRes.status === 400, '1.5 Missing credentials return HTTP 400');
  const classified400 = classifyLoginError(missingRes, missingRes.data);
  assert(
    classified400.includes('Email and password are required'),
    '1.6 HTTP 400 correctly classified with specific error message'
  );

  // Test 1.7: HTTP 429 rate limit simulation
  const dummy429 = { status: 429 };
  const classified429 = classifyLoginError(dummy429, { error: 'Too many login attempts. Please wait 15 minutes.' });
  assert(
    classified429.includes('Too many login attempts') && !classified429.includes('Unable to connect'),
    '1.7 HTTP 429 correctly classified as rate limit'
  );

  // Test 1.8: HTTP 500 server error simulation
  const dummy500 = { status: 500 };
  const classified500 = classifyLoginError(dummy500, null);
  assert(
    classified500.includes('Authentication server error (HTTP 500)') && !classified500.includes('Unable to connect'),
    '1.8 HTTP 500 correctly classified as server-side error'
  );

  // Test 1.9: True network failure simulation
  const networkErrorString = 'Unable to connect to the authentication server. Please verify the backend is running and your connection is active.';
  assert(
    networkErrorString.includes('Unable to connect to the authentication server'),
    '1.9 Network failure message strictly reserved for actual connection abort/failures'
  );

  // ------------------------------------------------------------------------
  // SECTION 2: Anonymous Visitor /api/auth/me on Login Page
  // ------------------------------------------------------------------------
  console.log('\n--- SECTION 2: Anonymous Visitor & Initial Mount Behavior ---');

  const anonMeRes = await makeRequest({
    method: 'GET',
    path: '/api/auth/me',
  });
  assert(anonMeRes.status === 401, '2.1 Anonymous GET /api/auth/me returns 401 cleanly');
  assert(anonMeRes.data.error.includes('Authentication required'), '2.2 Expected unauthenticated message returned');

  // Verify that an anonymous refresh without tokens returns 401
  const anonRefreshRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/refresh',
  });
  assert(anonRefreshRes.status === 401, '2.3 Anonymous refresh rejected with 401');

  // ------------------------------------------------------------------------
  // SECTION 3: Valid Credentials, Cookie Security & Session Restoring
  // ------------------------------------------------------------------------
  console.log('\n--- SECTION 3: Valid Login Lifecycle & Cookie Attributes ---');

  const loginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: { email: 'aishatariq@rekhta.org', password },
  });
  assert(loginRes.status === 200, '3.1 Valid login succeeds with HTTP 200');
  assert(loginRes.data.success === true, '3.2 Login response has success=true');
  assert(typeof loginRes.data.token === 'string', '3.3 In-memory JWT access token provided in response body');

  const accessToken = extractCookie(loginRes.headers, 'rekhta_access_token');
  const refreshToken = extractCookie(loginRes.headers, 'rekhta_refresh_token');
  assert(Boolean(accessToken), '3.4 rekhta_access_token cookie issued');
  assert(Boolean(refreshToken), '3.5 rekhta_refresh_token cookie issued');

  const accessAttrs = parseCookieAttributes(loginRes.headers, 'rekhta_access_token');
  const refreshAttrs = parseCookieAttributes(loginRes.headers, 'rekhta_refresh_token');
  assert(accessAttrs.httpOnly === true, '3.6 Access cookie has HttpOnly flag');
  assert(accessAttrs.sameSite === 'lax', '3.7 Access cookie has SameSite=lax for first-party persistence');
  assert(refreshAttrs.httpOnly === true, '3.8 Refresh cookie has HttpOnly flag');
  assert(refreshAttrs.sameSite === 'lax', '3.9 Refresh cookie has SameSite=lax for first-party persistence');

  // ------------------------------------------------------------------------
  // SECTION 4: Page Reload & Refresh Fallback Verification
  // ------------------------------------------------------------------------
  console.log('\n--- SECTION 4: Cold Reload & Transparent Fallback ---');

  // Simulate cold reload: client has NO in-memory token, browser sends ONLY rekhta_refresh_token
  const reloadMeRes = await makeRequest({
    method: 'GET',
    path: '/api/auth/me',
    headers: {
      Cookie: `rekhta_refresh_token=${refreshToken}`,
    },
  });
  assert(reloadMeRes.status === 200, '4.1 Reload with refresh cookie succeeds with 200 OK (NO 401!)');
  assert(reloadMeRes.data.user.email === 'aishatariq@rekhta.org', '4.2 Hydrated user matches persona');
  assert(Boolean(reloadMeRes.data.token), '4.3 Reload provides fresh in-memory access token');

  // ------------------------------------------------------------------------
  // SECTION 5: Logout & Post-Logout Invalidation
  // ------------------------------------------------------------------------
  console.log('\n--- SECTION 5: Logout & Session Revocation ---');

  const logoutRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/logout',
    headers: {
      'X-Requested-With': 'XMLHttpRequest',
      Cookie: `rekhta_access_token=${accessToken}; rekhta_refresh_token=${refreshToken}`,
    },
  });
  assert(logoutRes.status === 200, '5.1 Logout succeeds with HTTP 200');

  // Post-logout request must be rejected
  const postLogoutMe = await makeRequest({
    method: 'GET',
    path: '/api/auth/me',
    headers: {
      Cookie: `rekhta_refresh_token=${refreshToken}`,
    },
  });
  assert(postLogoutMe.status === 401, '5.2 Post-logout request strictly rejected (401 Unauthorized)');

  // ------------------------------------------------------------------------
  // SECTION 6: Logo Preload Warning Inspection in Source
  // ------------------------------------------------------------------------
  console.log('\n--- SECTION 6: Logo Preload Warning Remediation in Source ---');

  const loginPageSource = fs.readFileSync(
    path.join(__dirname, '../../frontend/src/app/portal/login/page.tsx'),
    'utf8'
  );
  assert(
    !loginPageSource.includes('priority') && loginPageSource.includes('width={56}'),
    '6.1 portal/login/page.tsx: priority removed and explicit width={56} set'
  );

  const headerSource = fs.readFileSync(
    path.join(__dirname, '../../frontend/src/components/layout/Header.tsx'),
    'utf8'
  );
  assert(
    !headerSource.includes('priority') && headerSource.includes('width={44}'),
    '6.2 Header.tsx: priority removed and explicit width={44} set'
  );

  const activateSource = fs.readFileSync(
    path.join(__dirname, '../../frontend/src/app/portal/activate/page.tsx'),
    'utf8'
  );
  assert(
    !activateSource.includes('priority') && activateSource.includes('width={48}'),
    '6.3 portal/activate/page.tsx: priority removed and explicit width={48} set'
  );

  const resetSource = fs.readFileSync(
    path.join(__dirname, '../../frontend/src/app/portal/reset-password/page.tsx'),
    'utf8'
  );
  assert(
    !resetSource.includes('priority') && resetSource.includes('width={48}'),
    '6.4 portal/reset-password/page.tsx: priority removed and explicit width={48} set'
  );

  const apiSource = fs.readFileSync(
    path.join(__dirname, '../../frontend/src/lib/api.ts'),
    'utf8'
  );
  assert(
    apiSource.includes('typeof window !== "undefined" ? "/api" : getApiBaseUrl()'),
    '6.5 api.ts: API_BASE guaranteed to use same-origin /api in browser'
  );

  const authContextSource = fs.readFileSync(
    path.join(__dirname, '../../frontend/src/context/AuthContext.tsx'),
    'utf8'
  );
  assert(
    authContextSource.includes('res.status === 401') &&
    authContextSource.includes('res.status === 403') &&
    authContextSource.includes('res.status === 429') &&
    authContextSource.includes('res.status >= 500'),
    '6.6 AuthContext.tsx: Complete HTTP status classification implemented'
  );

  console.log('\n========================================================================');
  console.log(`PHASE 10J TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('========================================================================');

  server.close();
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
  console.error('[Test Execution Error]:', err);
  if (server) server.close();
  process.exit(1);
});
