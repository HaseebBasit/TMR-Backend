/**
 * Phase 7B.5.2 — First Login & Authentication Lifecycle Verification Script
 * 
 * Verifies:
 * 1. Login with designated email and owner-entered password (hidden prompt).
 * 2. HTTP-only secure cookie issuance (rekhta_access_token & rekhta_refresh_token).
 * 3. Zero token leakage in JSON response payloads.
 * 4. GET /api/auth/me returns super_admin role and organization-wide scope.
 * 5. Refresh token single-use rotation.
 * 6. Logout session revocation and cookie clearing.
 * 7. Replay rejection of revoked refresh token.
 * 8. Unauthorized request blocking.
 * 
 * Zero credential or token leakage in logs.
 */

const http = require('http');
const path = require('path');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const { askHidden, AUTHORIZED_SUPER_ADMIN_EMAIL } = require('./setup-super-admin');

const TEST_PORT = 5097;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;

let passedChecks = 0;
let failedChecks = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passedChecks++;
  } else {
    console.error(`  [FAIL] ${message}`);
    failedChecks++;
  }
}

function makeHttpRequest(path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${BASE_URL}${path}`);
    const reqOptions = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: options.headers || {},
    };

    const req = http.request(reqOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch {}
        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: json,
          raw: data,
        });
      });
    });

    req.on('error', reject);

    if (options.body) {
      req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
    }
    req.end();
  });
}

function parseCookies(headers) {
  const setCookie = headers['set-cookie'];
  if (!setCookie) return {};
  const cookies = {};
  const cookieList = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const c of cookieList) {
    const parts = c.split(';').map((p) => p.trim());
    const [name, val] = parts[0].split('=');
    cookies[name] = {
      value: val,
      httpOnly: parts.some((p) => p.toLowerCase() === 'httponly'),
      sameSite: parts.find((p) => p.toLowerCase().startsWith('samesite'))?.split('=')[1] || null,
      maxAge: parts.find((p) => p.toLowerCase().startsWith('max-age'))?.split('=')[1] || null,
      raw: c,
    };
  }
  return cookies;
}

async function verifyFirstLogin() {
  console.log('==================================================================');
  console.log('PHASE 7B.5.2: FIRST LOGIN & AUTHENTICATION VERIFICATION');
  console.log(`Target Administrator: ${AUTHORIZED_SUPER_ADMIN_EMAIL}`);
  console.log('==================================================================\n');

  // 1. Prompt owner for the Super Admin password via hidden terminal prompt
  console.log('[Authentication Prompt]');
  const password = await askHidden('Enter Super Admin Password for First-Login Verification: ');
  if (!password || password.length < 16) {
    console.error('[Verification Aborted] Password must be at least 16 characters long.');
    process.exit(1);
  }

  // 2. Start local backend connected to live Atlas database
  process.env.TEST_USE_LIVE_DB = 'true';
  const { connectDB } = require('../src/config/db');
  await connectDB();

  if (mongoose.connection.db?.databaseName !== 'tameer_rekhta') {
    console.error(`[Error] Connected to unexpected database: ${mongoose.connection.db?.databaseName}`);
    await mongoose.disconnect();
    process.exit(1);
  }

  const app = require('../src/server');
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(TEST_PORT, '127.0.0.1', resolve));
  console.log(`[Test Server] Local backend online on port ${TEST_PORT} connected to 'tameer_rekhta'.\n`);

  try {
    // -----------------------------------------------------------------------
    // CHECK 1: Login with designated email and owner password
    // -----------------------------------------------------------------------
    console.log('--- Check 1: Initial Login Verification ---');
    const loginRes = await makeHttpRequest('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:3000',
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: { email: AUTHORIZED_SUPER_ADMIN_EMAIL, password },
    });

    assert(loginRes.status === 200, `Login status is 200 OK (got: ${loginRes.status})`);
    assert(loginRes.data?.success === true, 'Login response confirms success: true');
    assert(loginRes.data?.user?.email === AUTHORIZED_SUPER_ADMIN_EMAIL, 'Login response confirms correct email');
    assert(loginRes.data?.user?.role === 'super_admin', 'Login response confirms role is super_admin');

    // -----------------------------------------------------------------------
    // CHECK 2: HTTP-only Secure Cookie Issuance
    // -----------------------------------------------------------------------
    console.log('\n--- Check 2: HTTP-only Secure Cookie Verification ---');
    const loginCookies = parseCookies(loginRes.headers);

    assert(loginCookies['rekhta_access_token'] !== undefined, 'rekhta_access_token cookie was issued');
    assert(loginCookies['rekhta_access_token']?.httpOnly === true, 'rekhta_access_token cookie has HttpOnly flag');
    assert(loginCookies['rekhta_access_token']?.sameSite?.toLowerCase() === 'lax', 'rekhta_access_token cookie has SameSite=Lax');

    assert(loginCookies['rekhta_refresh_token'] !== undefined, 'rekhta_refresh_token cookie was issued');
    assert(loginCookies['rekhta_refresh_token']?.httpOnly === true, 'rekhta_refresh_token cookie has HttpOnly flag');
    assert(loginCookies['rekhta_refresh_token']?.sameSite?.toLowerCase() === 'lax', 'rekhta_refresh_token cookie has SameSite=Lax');

    // Defensive check: Ensure initial cookies exist before proceeding
    if (!loginCookies['rekhta_access_token']?.value || !loginCookies['rekhta_refresh_token']?.value) {
      console.error('  [CRITICAL AUTH FAILURE] Login did not yield required authentication cookies. Aborting subsequent checks.');
      failedChecks++;
      return;
    }

    // -----------------------------------------------------------------------
    // CHECK 3: Zero JWT Leakage in JSON Payloads
    // -----------------------------------------------------------------------
    console.log('\n--- Check 3: JSON Payload Security Verification ---');
    assert(loginRes.data?.token === undefined, 'Access token is NOT leaked in JSON response body');
    assert(loginRes.data?.refreshToken === undefined, 'Refresh token is NOT leaked in JSON response body');

    // -----------------------------------------------------------------------
    // CHECK 4: Authenticated /api/auth/me Verification
    // -----------------------------------------------------------------------
    console.log('\n--- Check 4: Authenticated Profile & Role Check (/api/auth/me) ---');
    const cookieHeader = `rekhta_access_token=${loginCookies['rekhta_access_token'].value}`;
    const meRes = await makeHttpRequest('/api/auth/me', {
      method: 'GET',
      headers: {
        Cookie: cookieHeader,
        'X-Requested-With': 'XMLHttpRequest',
      },
    });

    assert(meRes.status === 200, `/api/auth/me status is 200 OK (got: ${meRes.status})`);
    assert(meRes.data?.user?.role === 'super_admin', '/api/auth/me returns role: super_admin');
    assert(meRes.data?.user?.department === null, '/api/auth/me confirms organization-wide scope (department: null)');
    assert(meRes.data?.user?.email === AUTHORIZED_SUPER_ADMIN_EMAIL, '/api/auth/me confirms user email');

    // -----------------------------------------------------------------------
    // CHECK 5: Refresh Token Rotation
    // -----------------------------------------------------------------------
    console.log('\n--- Check 5: Refresh Token Single-Use Rotation ---');
    const originalRefreshToken = loginCookies['rekhta_refresh_token'].value;
    const refreshRes = await makeHttpRequest('/api/auth/refresh', {
      method: 'POST',
      headers: {
        Cookie: `rekhta_refresh_token=${originalRefreshToken}`,
        Origin: 'http://localhost:3000',
        'X-Requested-With': 'XMLHttpRequest',
      },
    });

    assert(refreshRes.status === 200, `Token refresh status is 200 OK (got: ${refreshRes.status})`);
    const refreshedCookies = parseCookies(refreshRes.headers);

    if (refreshRes.status !== 200) {
      console.error(
        `  [Refresh Error] HTTP ${refreshRes.status} received: ${refreshRes.data?.error || refreshRes.data?.code || 'Unknown error'}`
      );
    }

    assert(refreshedCookies['rekhta_access_token'] !== undefined, 'New access token issued on refresh');
    assert(refreshedCookies['rekhta_refresh_token'] !== undefined, 'New refresh token issued on refresh');
    assert(
      Boolean(refreshedCookies['rekhta_refresh_token']?.value && refreshedCookies['rekhta_refresh_token']?.value !== originalRefreshToken),
      'Refresh token rotated: New token is cryptographically distinct from original'
    );

    // -----------------------------------------------------------------------
    // CHECK 6: Logout Revocation
    // -----------------------------------------------------------------------
    console.log('\n--- Check 6: Logout Revocation & Cookie Clearing ---');
    const hasRefreshedAccess = Boolean(refreshedCookies['rekhta_access_token']?.value);
    const hasRefreshedRefresh = Boolean(refreshedCookies['rekhta_refresh_token']?.value);

    if (hasRefreshedAccess && hasRefreshedRefresh) {
      const logoutRes = await makeHttpRequest('/api/auth/logout', {
        method: 'POST',
        headers: {
          Cookie: `rekhta_access_token=${refreshedCookies['rekhta_access_token'].value}; rekhta_refresh_token=${refreshedCookies['rekhta_refresh_token'].value}`,
          Origin: 'http://localhost:3000',
          'X-Requested-With': 'XMLHttpRequest',
        },
      });

      assert(logoutRes.status === 200, `Logout status is 200 OK (got: ${logoutRes.status})`);
      const logoutCookies = parseCookies(logoutRes.headers);
      assert(
        logoutCookies['rekhta_access_token']?.maxAge === '0' || logoutCookies['rekhta_access_token']?.value === '',
        'Access token cookie cleared on logout'
      );
      assert(
        logoutCookies['rekhta_refresh_token']?.maxAge === '0' || logoutCookies['rekhta_refresh_token']?.value === '',
        'Refresh token cookie cleared on logout'
      );
    } else {
      console.error('  [SKIP] Skipping logout assertions gracefully: valid refreshed tokens were not issued by /refresh.');
      failedChecks++;
    }

    // -----------------------------------------------------------------------
    // CHECK 7: Revoked Token Reuse Rejection (Replay Attack Defense)
    // -----------------------------------------------------------------------
    console.log('\n--- Check 7: Revoked Token Replay Rejection ---');
    const replayRes = await makeHttpRequest('/api/auth/refresh', {
      method: 'POST',
      headers: {
        Cookie: `rekhta_refresh_token=${originalRefreshToken}`,
        Origin: 'http://localhost:3000',
        'X-Requested-With': 'XMLHttpRequest',
      },
    });

    assert(
      replayRes.status === 401,
      `Replay of revoked/rotated refresh token strictly rejected with 401 Unauthorized (got: ${replayRes.status})`
    );

    // -----------------------------------------------------------------------
    // CHECK 8: Unauthorized Request Blocking
    // -----------------------------------------------------------------------
    console.log('\n--- Check 8: Unauthorized Requests Blocked ---');
    const unauthRes = await makeHttpRequest('/api/auth/me', {
      method: 'GET',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(unauthRes.status === 401, `Unauthenticated /api/auth/me blocked with 401 Unauthorized (got: ${unauthRes.status})`);

    console.log('\n==================================================================');
    console.log(`FIRST LOGIN VERIFICATION: ${passedChecks} PASSED, ${failedChecks} FAILED`);
    console.log('==================================================================\n');

  } finally {
    await new Promise((resolve) => server.close(resolve));
    await mongoose.disconnect();
    console.log('[Cleanup] Test server stopped and MongoDB Atlas disconnected cleanly.');
  }

  process.exit(failedChecks > 0 ? 1 : 0);
}

if (require.main === module) {
  verifyFirstLogin().catch((err) => {
    console.error('[Verification Error]:', err.message);
    if (mongoose.connection.readyState !== 0) {
      mongoose.disconnect().catch(() => null);
    }
    process.exit(1);
  });
}

module.exports = { verifyFirstLogin, parseCookies };
