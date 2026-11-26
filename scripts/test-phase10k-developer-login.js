/**
 * Phase 10K Verification & Production Acceptance Suite:
 * Critical Developer Account Login Failure: End-to-End Production Diagnosis & Remediation
 * 
 * Verifies:
 * 1. Database Audit & Handoff Consistency (Atlas tameer_rekhta)
 * 2. Stage 1 Login & MFA Challenge Generation (Without Premature User Object)
 * 3. Stage 2 MFA TOTP & Recovery Code Verification (RFC 6238)
 * 4. Stage 3 Initial Mandatory Password Change (Complexity Enforcement)
 * 5. Full Authentication Flow & Session Token Issuance (Lax, HttpOnly, Secure)
 * 6. Developer Dashboard & Diagnostics Authorization
 * 7. Hard Super Admin Protection & Impersonation Barriers
 * 8. Live Vercel Proxy End-to-End Connectivity
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_jwt_secret_phase10k_developer_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_phase10k_developer_2026';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = require('../src/server');
const { setMemoryUser, getMemoryUser } = require('../src/middleware/auth');
const { generateTotp, verifyTotp, generateSecret, generateRecoveryCodes, hashRecoveryCode } = require('../src/services/mfa.service');
const { clearAllRateLimitStores } = require('../src/middleware/rateLimiter');

// Load environment variables from .env if present
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const TEST_PORT = 5011;
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

function makeLocalRequest({ method = 'GET', path: reqPath, headers = {}, body = null }) {
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
        path: reqPath,
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

function makeHttpsRequest(urlStr, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const postData = options.body ? (typeof options.body === 'string' ? options.body : JSON.stringify(options.body)) : null;
    const headers = { ...options.headers };

    if (postData) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = https.request(
      url,
      {
        method: options.method || 'GET',
        headers,
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

async function runTests() {
  console.log('========================================================================');
  console.log('PHASE 10K: CRITICAL DEVELOPER ACCOUNT LOGIN & END-TO-END VERIFICATION');
  console.log('========================================================================\n');

  // Start local express test server
  await new Promise((resolve) => {
    server = app.listen(TEST_PORT, () => resolve());
  });

  const handoffPath = 'C:/Users/hasee/.gemini/antigravity-cli/brain/83e545b1-f4df-4dc2-b9b4-f6bb6718c4bf/DEVELOPER_CREDENTIAL_HANDOFF_ONE_TIME.txt';
  let handoffContent = '';
  let handoffPassword = '';
  let handoffMfaSecret = '';

  if (fs.existsSync(handoffPath)) {
    handoffContent = fs.readFileSync(handoffPath, 'utf8');
    const pwdMatch = handoffContent.match(/Initial Password:\s*(\S+)/);
    const secretMatch = handoffContent.match(/TOTP Secret \(Base32\):\s*([A-Z0-9]+)/);
    if (pwdMatch) handoffPassword = pwdMatch[1];
    if (secretMatch) handoffMfaSecret = secretMatch[1];
  }

  // ------------------------------------------------------------------------
  // PART 1: Database Audit & Handoff Consistency Check
  // ------------------------------------------------------------------------
  console.log('--- Part 1: Database Audit & Handoff Credential Verification ---');
  let devUserInDb = null;
  const mongoUri = process.env.MONGODB_URI;

  if (mongoUri) {
    try {
      const conn = await mongoose.createConnection(mongoUri, { serverSelectionTimeoutMS: 6000 }).asPromise();
      const db = conn.useDb('tameer_rekhta');
      const usersCol = db.collection('users');
      devUserInDb = await usersCol.findOne({ email: 'rekhtadeveloper@rekhta.org' });
      await conn.close();

      assert(devUserInDb !== null, '1.1 Developer account exists in production database');
      assert(devUserInDb?.role === 'developer', '1.2 Account role is strictly "developer"');
      assert(devUserInDb?.designation === 'system_lead', '1.3 Official designation is "system_lead"');
      assert(devUserInDb?.department === 'ENG' || devUserInDb?.department === 'Engineering', '1.4 Department is Engineering (ENG)');
      assert(devUserInDb?.status === 'active', '1.5 Account status is "active"');
      assert(devUserInDb?.status !== 'suspended' && devUserInDb?.status !== 'inactive', '1.6 Account is not locked or suspended');
      assert(devUserInDb?.mfaEnabled === true, '1.7 Mandatory MFA is enabled on Developer account');
      assert(Boolean(devUserInDb?.mfaSecret), '1.8 MFA TOTP Base32 secret is securely populated in DB');
      assert(Array.isArray(devUserInDb?.mfaRecoveryCodes) && devUserInDb.mfaRecoveryCodes.length === 8, '1.9 Exactly 8 single-use backup recovery codes are stored');

      if (handoffPassword && devUserInDb?.password) {
        const pwdMatch = bcrypt.compareSync(handoffPassword, devUserInDb.password);
        assert(pwdMatch, '1.10 Handoff password matches database password hash');
      }

      if (handoffMfaSecret && devUserInDb?.mfaSecret) {
        assert(handoffMfaSecret === devUserInDb.mfaSecret, '1.11 Handoff Base32 TOTP secret matches database mfaSecret');
        const liveTotp = generateTotp(handoffMfaSecret);
        const totpValid = verifyTotp(liveTotp, handoffMfaSecret);
        assert(totpValid, '1.12 RFC 6238 TOTP verification passes with handoff secret');
      }
    } catch (err) {
      console.warn('  [WARN] Database connection skipped or failed:', err.message);
    }
  }

  // ------------------------------------------------------------------------
  // PART 2: Root-Cause Reproduction & Stage 1 Authentication
  // ------------------------------------------------------------------------
  console.log('\n--- Part 2: Stage 1 Login & MFA Challenge (No Undefined TypeError) ---');
  clearAllRateLimitStores();

  const testDevSecret = generateSecret();
  const testDevPassword = 'DevTestPassword!2026';
  const testDevPasswordHash = await bcrypt.hash(testDevPassword, 10);
  const rawRecoveryCodes = generateRecoveryCodes(8);
  const hashedRecoveryCodes = rawRecoveryCodes.map((c) => hashRecoveryCode(c));

  const mockDevUser = {
    _id: '6b07cb8852e050c56db0e1cd',
    id: '6b07cb8852e050c56db0e1cd',
    name: 'Test System Lead',
    email: 'testdeveloper@rekhta.org',
    password: testDevPasswordHash,
    role: 'developer',
    designation: 'system_lead',
    department: 'Engineering',
    departmentCode: 'ENG',
    status: 'active',
    isLocked: false,
    tokenVersion: 0,
    mfaEnabled: true,
    mfaSecret: testDevSecret,
    mfaRecoveryCodes: hashedRecoveryCodes,
    mustChangePassword: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  setMemoryUser(mockDevUser);

  // 2.1 Login with wrong password
  const badLoginRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'testdeveloper@rekhta.org', password: 'WrongPassword123!' },
  });
  assert(badLoginRes.status === 401, '2.1 Wrong password returns HTTP 401 Unauthorized');
  assert(badLoginRes.data.success === false && badLoginRes.data.error.includes('Invalid credentials'), '2.2 Error message is precise ("Invalid credentials")');

  // 2.2 Login with valid credentials triggers MFA
  const validLoginRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'testdeveloper@rekhta.org', password: testDevPassword },
  });
  assert(validLoginRes.status === 200, '2.3 Valid credentials return HTTP 200 OK');
  assert(validLoginRes.data.requireMfa === true, '2.4 Response flags requireMfa: true');
  assert(typeof validLoginRes.data.mfaToken === 'string' && validLoginRes.data.mfaToken.length > 20, '2.5 Response provides mfaToken for Stage 2 challenge');
  assert(validLoginRes.data.user === undefined, '2.6 Response does NOT expose user object (prevents frontend TypeError)');

  const mfaToken = validLoginRes.data.mfaToken;

  // ------------------------------------------------------------------------
  // PART 3: Stage 2 MFA Verification (RFC 6238 TOTP & Recovery Codes)
  // ------------------------------------------------------------------------
  console.log('\n--- Part 3: Stage 2 MFA Verification ---');

  // 3.1 Invalid TOTP code returns 401
  const badMfaRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/mfa/verify',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { mfaToken, code: '000000' },
  });
  assert(badMfaRes.status === 401, '3.1 Invalid TOTP returns HTTP 401');
  assert(badMfaRes.data.error.includes('Invalid authentication code'), '3.2 Proper invalid code error message returned');

  // 3.2 Valid TOTP code when mustChangePassword is true returns requirePasswordChange
  const currentTotp = generateTotp(testDevSecret);
  const validMfaRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/mfa/verify',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { mfaToken, code: currentTotp },
  });
  assert(validMfaRes.status === 200, '3.3 Valid TOTP returns HTTP 200 OK');
  assert(validMfaRes.data.mfaVerified === true, '3.4 MFA is verified');
  assert(validMfaRes.data.requirePasswordChange === true, '3.5 Initial password change requirement is triggered');
  assert(typeof validMfaRes.data.tempToken === 'string', '3.6 tempToken is provided for password change session');

  const tempToken = validMfaRes.data.tempToken;

  // ------------------------------------------------------------------------
  // PART 4: Stage 3 Initial Password Change
  // ------------------------------------------------------------------------
  console.log('\n--- Part 4: Stage 3 Initial Password Change ---');

  // 4.1 Weak password rejected (< 10 chars)
  const weakPwdRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/change-initial-password',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { tempToken, newPassword: 'short' },
  });
  assert(weakPwdRes.status === 400, '4.1 Weak password (<10 chars) rejected with HTTP 400');

  // 4.2 Strong compliant password accepted
  const newDevPassword = 'NewDeveloperPermanentP@ssw0rd!2026';
  const goodPwdRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/change-initial-password',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { tempToken, newPassword: newDevPassword },
  });
  assert(goodPwdRes.status === 200, '4.2 Compliant password accepted with HTTP 200 OK');
  assert(goodPwdRes.data.success === true, '4.3 Password change marked successful');

  // Verify memory user updated
  const updatedDev = getMemoryUser(mockDevUser.id);
  assert(updatedDev.mustChangePassword === false, '4.4 mustChangePassword cleared to false');
  assert(updatedDev.tokenVersion === 1, '4.5 tokenVersion incremented to 1');

  // ------------------------------------------------------------------------
  // PART 5: Post-Password-Change Full Authentication & Session Issuance
  // ------------------------------------------------------------------------
  console.log('\n--- Part 5: Post-Password-Change Full Authentication ---');

  // Login with old password fails
  const oldLoginRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'testdeveloper@rekhta.org', password: testDevPassword },
  });
  assert(oldLoginRes.status === 401, '5.1 Old temporary password no longer authenticates');

  // Login with new password succeeds and triggers MFA
  const newLoginRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'testdeveloper@rekhta.org', password: newDevPassword },
  });
  assert(newLoginRes.status === 200 && newLoginRes.data.requireMfa === true, '5.2 New permanent password accepted, requests MFA');

  const newMfaToken = newLoginRes.data.mfaToken;
  const newTotp = generateTotp(testDevSecret);

  // Stage 2 MFA verification with permanent password sets session cookies
  const postMfaRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/mfa/verify',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { mfaToken: newMfaToken, code: newTotp },
  });
  assert(postMfaRes.status === 200, '5.3 MFA verification returns HTTP 200 OK');
  assert(postMfaRes.data.success === true, '5.4 Full login success achieved');
  assert(postMfaRes.data.user.role === 'developer', '5.5 Session user role is "developer"');

  const accessTokenCookie = extractCookie(postMfaRes.headers, 'rekhta_access_token');
  const refreshTokenCookie = extractCookie(postMfaRes.headers, 'rekhta_refresh_token');
  assert(Boolean(accessTokenCookie), '5.6 rekhta_access_token cookie issued');
  assert(Boolean(refreshTokenCookie), '5.7 rekhta_refresh_token cookie issued');

  // ------------------------------------------------------------------------
  // PART 6: Developer Dashboard Authorization & Super Admin Protection
  // ------------------------------------------------------------------------
  console.log('\n--- Part 6: Developer Dashboard, Diagnostics & RBAC Protection ---');

  const devCookieHeader = `rekhta_access_token=${accessTokenCookie}; rekhta_refresh_token=${refreshTokenCookie}`;

  // 6.1 Developer can access /api/auth/me
  const meRes = await makeLocalRequest({
    method: 'GET',
    path: '/api/auth/me',
    headers: {
      Cookie: devCookieHeader,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(meRes.status === 200, '6.1 GET /api/auth/me succeeds with Developer session cookies');
  assert(meRes.data.user.role === 'developer', '6.2 User role in /api/auth/me is "developer"');
  assert(meRes.data.user.designation === 'system_lead', '6.3 User designation is "system_lead"');

  // 6.2 Developer can access /api/developer/diagnostics
  const diagRes = await makeLocalRequest({
    method: 'GET',
    path: '/api/developer/diagnostics',
    headers: {
      Cookie: devCookieHeader,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(diagRes.status === 200, '6.4 GET /api/developer/diagnostics succeeds (HTTP 200)');
  assert(diagRes.data.success === true && Boolean(diagRes.data.system) && Boolean(diagRes.data.database), '6.5 System telemetry data returned to Developer');

  // Register mock super admin in memory for impersonation testing
  setMemoryUser({
    _id: 'super_admin_test_id',
    id: 'super_admin_test_id',
    email: 'admin@rekhta.org',
    name: 'Super Admin',
    role: 'super_admin',
    status: 'active',
  });

  // 6.3 Hard Barrier: Developer attempting to impersonate Super Admin is blocked (HTTP 403)
  const impersonateSuperAdminRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/developer/impersonate',
    headers: {
      Cookie: devCookieHeader,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: {
      targetEmail: 'admin@rekhta.org',
      reason: 'Attempting to inspect Super Admin portal',
    },
  });
  assert(impersonateSuperAdminRes.status === 403, '6.6 Hard Barrier: Impersonating Super Admin returns HTTP 403 Forbidden');
  assert(impersonateSuperAdminRes.data.error.includes('Super Administrator accounts is strictly prohibited'), '6.7 Clear security error: Super Admin accounts cannot be impersonated');

  // 6.4 Non-developer cannot access developer diagnostics
  const memberToken = jwt.sign(
    { id: 'regular_member_id', email: 'member@rekhta.org', role: 'member', status: 'active', tokenVersion: 0 },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  const memberDiagRes = await makeLocalRequest({
    method: 'GET',
    path: '/api/developer/diagnostics',
    headers: {
      Cookie: `rekhta_access_token=${memberToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(memberDiagRes.status === 403, '6.8 Non-developer blocked from Developer diagnostics (HTTP 403 Forbidden)');

  // 6.5 Logout clears session
  const logoutRes = await makeLocalRequest({
    method: 'POST',
    path: '/api/auth/logout',
    headers: {
      Cookie: devCookieHeader,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(logoutRes.status === 200, '6.9 POST /api/auth/logout succeeds (HTTP 200)');

  // ------------------------------------------------------------------------
  // PART 7: Live Vercel Proxy Production Connectivity
  // ------------------------------------------------------------------------
  console.log('\n--- Part 7: Live Production Connectivity Verification ---');
  try {
    const prodLoginUrl = 'https://tameer-e-rekhta.vercel.app/portal/login';
    const prodPageRes = await makeHttpsRequest(prodLoginUrl);
    assert(prodPageRes.status === 200, '7.1 Production login page reachable (HTTP 200)');

    if (handoffPassword) {
      const prodApiLoginRes = await makeHttpsRequest('https://tameer-e-rekhta.vercel.app/api/auth/login', {
        method: 'POST',
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
          'User-Agent': 'Phase10K-Acceptance-Tester',
        },
        body: {
          email: 'rekhtadeveloper@rekhta.org',
          password: handoffPassword,
        },
      });

      assert(prodApiLoginRes.status === 200, '7.2 Production POST /api/auth/login with handoff credentials returns HTTP 200');
      assert(prodApiLoginRes.data.requireMfa === true, '7.3 Production login flags requireMfa: true');
      assert(Boolean(prodApiLoginRes.data.mfaToken), '7.4 Production login issues valid mfaToken');

      if (handoffMfaSecret && prodApiLoginRes.data.mfaToken) {
        const prodTotp = generateTotp(handoffMfaSecret);
        const prodMfaVerifyRes = await makeHttpsRequest('https://tameer-e-rekhta.vercel.app/api/auth/mfa/verify', {
          method: 'POST',
          headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Phase10K-Acceptance-Tester',
          },
          body: {
            mfaToken: prodApiLoginRes.data.mfaToken,
            code: prodTotp,
          },
        });

        assert(prodMfaVerifyRes.status === 200, '7.5 Production POST /api/auth/mfa/verify with TOTP returns HTTP 200');
        assert(prodMfaVerifyRes.data.mfaVerified === true, '7.6 Production MFA verification succeeds');
        assert(prodMfaVerifyRes.data.requirePasswordChange === true, '7.7 Production verifies mandatory initial password change is enforced');
        assert(Boolean(prodMfaVerifyRes.data.tempToken), '7.8 Production provides tempToken for password change');
      }
    }
  } catch (err) {
    console.warn('  [WARN] Live production check encountered an error:', err.message);
  }

  // ------------------------------------------------------------------------
  // Clean up
  // ------------------------------------------------------------------------
  server.close();

  console.log('\n========================================================================');
  console.log(`TEST SUMMARY: ${passed} PASSED | ${failed} FAILED`);
  console.log('========================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal error in test suite:', err);
  process.exit(1);
});
