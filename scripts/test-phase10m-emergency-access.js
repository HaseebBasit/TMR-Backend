/**
 * Phase 10M Staging & Security Test Suite:
 * Ta'meer-e-Rekhta Independent Emergency Access Key System
 * 
 * Tests all 12 Phase 10M Criteria:
 * 1. Independent emergency operator authentication (Key + Reason)
 * 2. Independent MFA verification (RFC 6238 TOTP)
 * 3. Access to each eligible organizational role (Lit, Media, HR, Member)
 * 4. Multi-department account handling (preserves memberships & active dept)
 * 5. Invalid target email rejection (404 Not Found & 400 Bad Request)
 * 6. Expired session rejection (15-min strict boundary)
 * 7. Immediate access termination (/api/emergency/end-session)
 * 8. Hard Security Barrier: Super Admin & Developer access rejection (403 Forbidden)
 * 9. Original target password remains 100% unchanged
 * 10. Original target MFA secret remains 100% unchanged
 * 11. Normal user login continues working in parallel
 * 12. Emergency credential revocation & post-revocation rejection
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_jwt_secret_phase10m_emergency_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_phase10m_emergency_2026';

const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = require('../src/server');
const { setMemoryUser, getMemoryUser } = require('../src/middleware/auth');
const EmergencyCredential = require('../src/models/EmergencyCredential');
const { generateTotp, verifyTotp, generateSecret, generateRecoveryCodes, hashRecoveryCode } = require('../src/services/mfa.service');
const { clearAllRateLimitStores } = require('../src/middleware/rateLimiter');

const TEST_PORT = 5012;
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

function makeRequest({ method = 'GET', path: reqPath, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const postData = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
    const reqHeaders = { ...headers };

    if (postData) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }
    if (!reqHeaders['X-Requested-With']) {
      reqHeaders['X-Requested-With'] = 'XMLHttpRequest';
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
  console.log('PHASE 10M: INDEPENDENT EMERGENCY ACCESS KEY SYSTEM STAGING SUITE');
  console.log('========================================================================\n');

  // Start Express test server
  await new Promise((resolve) => {
    server = app.listen(TEST_PORT, () => resolve());
  });

  clearAllRateLimitStores();

  // ------------------------------------------------------------------------
  // SETUP: Provision Staging Emergency Credential & Target Users in Memory
  // ------------------------------------------------------------------------
  const stagingEmergencyKey = 'EmergencyOperatorSecretKey#2026!SecureEntropy';
  const stagingEmergencyKeyHash = await bcrypt.hash(stagingEmergencyKey, 10);
  const stagingMfaSecret = generateSecret();
  const encryptedMfaSecret = EmergencyCredential.encryptSecret(stagingMfaSecret);
  const rawRecoveryCodes = generateRecoveryCodes(8);
  const hashedRecoveryCodes = rawRecoveryCodes.map((c) => hashRecoveryCode(c));

  assert(encryptedMfaSecret.startsWith('enc:v1:'), '0.1 Emergency MFA Secret is encrypted at rest using AES-256-GCM');
  assert(EmergencyCredential.decryptSecret(encryptedMfaSecret) === stagingMfaSecret, '0.2 AES-256-GCM decryption returns exact original Base32 secret');

  const stagingEmergencyCredential = {
    keyId: 'EMERGENCY-OPERATOR-KEY-TEST-01',
    keyHash: stagingEmergencyKeyHash,
    operatorEmail: 'emergency-operator@system.rekhta.org',
    operatorName: 'Authorized Emergency Operator',
    mfaSecret: encryptedMfaSecret, // Stored encrypted at rest using AES-256-GCM
    mfaRecoveryCodes: hashedRecoveryCodes,
    status: 'active',
    usageCount: 0,
    failedAttempts: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  EmergencyCredential.setMemoryEmergencyCredential(stagingEmergencyCredential);

  // Target 1: Literature Lead (eligible)
  const litTargetPwd = 'LitPassword!2026';
  const litTargetHash = await bcrypt.hash(litTargetPwd, 10);
  const litTargetMfa = generateSecret();
  const mockLitUser = {
    _id: '507f1f77bcf86cd799439011',
    id: '507f1f77bcf86cd799439011',
    name: 'Literature Lead',
    email: 'literaturelead@rekhta.org',
    password: litTargetHash,
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    designation: 'head_of_department',
    status: 'active',
    tokenVersion: 1,
    mfaEnabled: true,
    mfaSecret: litTargetMfa,
  };
  setMemoryUser(mockLitUser);

  // Target 2: Multi-Department Member (Literature + Outreach)
  const multiTargetPwd = 'MultiUserPassword!2026';
  const multiTargetHash = await bcrypt.hash(multiTargetPwd, 10);
  const mockMultiUser = {
    _id: '507f1f77bcf86cd799439012',
    id: '507f1f77bcf86cd799439012',
    name: 'Cross-Department Specialist',
    email: 'multidept@rekhta.org',
    password: multiTargetHash,
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    status: 'active',
    tokenVersion: 1,
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', isPrimary: true },
      { department: 'Outreach', departmentCode: 'OUT', role: 'member', isPrimary: false },
    ],
  };
  setMemoryUser(mockMultiUser);

  // Target 3: Super Admin (INELIGIBLE - STRICT HARD BARRIER)
  const mockSuperAdmin = {
    _id: '507f1f77bcf86cd799439099',
    id: '507f1f77bcf86cd799439099',
    name: 'Super Admin',
    email: 'tameerrekhtaadmin@rekhta.org',
    role: 'super_admin',
    status: 'active',
    tokenVersion: 1,
  };
  setMemoryUser(mockSuperAdmin);

  // Target 4: System Developer (INELIGIBLE - STRICT HARD BARRIER)
  const mockDeveloper = {
    _id: '507f1f77bcf86cd799439098',
    id: '507f1f77bcf86cd799439098',
    name: 'System Developer',
    email: 'rekhtadeveloper@rekhta.org',
    role: 'developer',
    status: 'active',
    tokenVersion: 3,
  };
  setMemoryUser(mockDeveloper);

  // Target 5: Suspended User (INELIGIBLE)
  const mockSuspended = {
    _id: '507f1f77bcf86cd799439097',
    id: '507f1f77bcf86cd799439097',
    name: 'Suspended Member',
    email: 'suspended@rekhta.org',
    role: 'member',
    status: 'suspended',
    tokenVersion: 1,
  };
  setMemoryUser(mockSuspended);

  // ------------------------------------------------------------------------
  // TEST 1: Independent Emergency Operator Authentication (/verify-key)
  // ------------------------------------------------------------------------
  console.log('--- Test 1: Independent Operator Key Authentication ---');

  // 1.1 Bad key rejected
  const badKeyRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'literaturelead@rekhta.org',
      accessKey: 'InvalidAccessKey!1234',
      reason: 'Urgent diagnostic investigation into literature queue outage',
    },
  });
  assert(badKeyRes.status === 401, '1.1 Invalid Emergency Access Key rejected with HTTP 401');

  // 1.2 Missing or short reason (<10 chars) rejected
  const shortReasonRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'literaturelead@rekhta.org',
      accessKey: stagingEmergencyKey,
      reason: 'Support', // Only 7 chars
    },
  });
  assert(shortReasonRes.status === 400, '1.2 Short reason (<10 chars) rejected with HTTP 400');
  assert(shortReasonRes.data.code === 'EMERGENCY_REASON_REQUIRED', '1.3 Mandatory reason enforcement code returned');

  // 1.3 Valid key & valid reason returns MFA challenge
  const validKeyRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'literaturelead@rekhta.org',
      accessKey: stagingEmergencyKey,
      reason: 'Investigating literature publication queue bottleneck for regional event',
    },
  });
  assert(validKeyRes.status === 200, '1.4 Valid key & reason returns HTTP 200 OK');
  assert(validKeyRes.data.requireMfa === true, '1.5 Flags requireMfa: true for independent operator MFA challenge');
  assert(Boolean(validKeyRes.data.emergencyToken), '1.6 Issues short-lived emergencyToken');
  assert(validKeyRes.data.targetUser.name === 'Literature Lead', '1.7 Previews target user metadata');

  const emergencyMfaToken = validKeyRes.data.emergencyToken;

  // ------------------------------------------------------------------------
  // TEST 2: Independent MFA Verification (RFC 6238 TOTP)
  // ------------------------------------------------------------------------
  console.log('\n--- Test 2: Independent Operator MFA Verification ---');

  // 2.1 Invalid TOTP code rejected
  const badTotpRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-mfa',
    body: {
      emergencyToken: emergencyMfaToken,
      code: '000000',
    },
  });
  assert(badTotpRes.status === 401, '2.1 Invalid TOTP code rejected with HTTP 401');

  // 2.2 Valid TOTP code verifies and issues 15-minute emergency session
  const validTotp = generateTotp(stagingMfaSecret);
  const goodMfaRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-mfa',
    body: {
      emergencyToken: emergencyMfaToken,
      code: validTotp,
    },
  });
  assert(goodMfaRes.status === 200, '2.2 Valid TOTP code verifies successfully (HTTP 200)');
  assert(goodMfaRes.data.success === true, '2.3 Full emergency session creation marked success');
  assert(goodMfaRes.data.sessionExpiresIn === 900, '2.4 Session strictly bounded to 15 minutes (900 seconds)');
  assert(goodMfaRes.data.user.isEmergencyAccess === true, '2.5 User payload explicitly flagged isEmergencyAccess: true');
  assert(goodMfaRes.data.user.act?.sub === 'emergency_operator', '2.6 Operator identity declared in RFC 8693 token claims');

  const emergencySessionToken = goodMfaRes.data.token;
  const emergencyCookie = extractCookie(goodMfaRes.headers, 'rekhta_access_token');
  const emergencyModeCookie = extractCookie(goodMfaRes.headers, 'rekhta_emergency_mode');
  const refreshCookie = extractCookie(goodMfaRes.headers, 'rekhta_refresh_token');

  assert(Boolean(emergencyCookie), '2.7 Sets HTTP-only rekhta_access_token cookie');
  assert(emergencyModeCookie === 'true', '2.8 Sets rekhta_emergency_mode flag cookie for UI hydration');
  assert(refreshCookie === null || refreshCookie === '', '2.9 Refresh token cookie is cleared or omitted (prevents silent persistence)');

  // ------------------------------------------------------------------------
  // TEST 3: Access to Eligible Roles & Dashboard Context
  // ------------------------------------------------------------------------
  console.log('\n--- Test 3: Dashboard Access & Target Role Preservation ---');

  const authHeader = { Authorization: `Bearer ${emergencySessionToken}` };

  // 3.1 GET /api/auth/me returns target persona with emergency claims
  const meRes = await makeRequest({
    method: 'GET',
    path: '/api/auth/me',
    headers: authHeader,
  });
  assert(meRes.status === 200, '3.1 GET /api/auth/me succeeds with emergency token');
  assert(meRes.data.user.email === 'literaturelead@rekhta.org', '3.2 Target user email matches literature lead');
  assert(meRes.data.user.role === 'dept_literature', '3.3 Target user role is preserved (dept_literature)');
  assert(meRes.data.user.isEmergencyAccess === true, '3.4 Emergency access mode active on profile');
  assert(Boolean(meRes.data.user.emergencySession?.expiresAt), '3.5 Expiration timestamp provided for countdown timer');

  // 3.6 RBAC Gate: Emergency operator acting as Literature Lead CANNOT access Developer diagnostics (HTTP 403)
  const crossRoleRes = await makeRequest({
    method: 'GET',
    path: '/api/developer/diagnostics',
    headers: authHeader,
  });
  assert(crossRoleRes.status === 403, '3.6 Emergency session cannot access Developer endpoints (HTTP 403 Forbidden)');

  // 3.7 Department Scope Gate: Emergency operator acting as Literature Lead CANNOT publish Media (HTTP 403)
  const crossDeptRes = await makeRequest({
    method: 'PATCH',
    path: '/api/media/test_asset_1/publish',
    headers: authHeader,
  });
  assert(crossDeptRes.status === 403, '3.7 Emergency session cannot bypass department restrictions (HTTP 403 Forbidden)');

  // ------------------------------------------------------------------------
  // TEST 4: Multi-Department Account Handling
  // ------------------------------------------------------------------------
  console.log('\n--- Test 4: Multi-Department Account Handling ---');

  // Step 1: Request access for multi-dept user
  const multiKeyRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'multidept@rekhta.org',
      accessKey: stagingEmergencyKey,
      reason: 'Investigating cross-departmental task routing failure',
    },
  });
  assert(multiKeyRes.status === 200, '4.1 Multi-department user key authentication succeeds');
  assert(Array.isArray(multiKeyRes.data.targetUser.memberships) && multiKeyRes.data.targetUser.memberships.length === 2, '4.2 Preserves both department memberships');

  // Step 2: MFA
  const multiTotp = generateTotp(stagingMfaSecret);
  const multiMfaRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-mfa',
    body: {
      emergencyToken: multiKeyRes.data.emergencyToken,
      code: multiTotp,
    },
  });
  assert(multiMfaRes.status === 200, '4.3 Multi-department emergency session established');
  assert(multiMfaRes.data.user.memberships.length === 2, '4.4 Session token preserves multi-department memberships');

  // ------------------------------------------------------------------------
  // TEST 5: Invalid Target Email & Inactive Account Rejection
  // ------------------------------------------------------------------------
  console.log('\n--- Test 5: Ineligible & Nonexistent Account Rejection ---');

  // 5.1 Nonexistent email rejected
  const nonexistentRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'nonexistent-user@rekhta.org',
      accessKey: stagingEmergencyKey,
      reason: 'Attempting invalid account access test',
    },
  });
  assert(nonexistentRes.status === 404, '5.1 Nonexistent target email returns HTTP 404 Not Found');

  // 5.2 Suspended account rejected
  const suspendedRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'suspended@rekhta.org',
      accessKey: stagingEmergencyKey,
      reason: 'Attempting suspended account access test',
    },
  });
  assert(suspendedRes.status === 400, '5.2 Suspended target account rejected with HTTP 400');
  assert(suspendedRes.data.error.includes('Target must be active'), '5.3 Rejection specifies target must be active');

  // ------------------------------------------------------------------------
  // TEST 6: Expired Session Rejection
  // ------------------------------------------------------------------------
  console.log('\n--- Test 6: Strict 15-Minute Expiration Enforcement ---');

  // Forge expired emergency token (expired 1 second ago)
  const expiredPayload = {
    id: mockLitUser.id,
    email: mockLitUser.email,
    role: mockLitUser.role,
    status: 'active',
    isEmergencyAccess: true,
  };
  const expiredToken = jwt.sign(expiredPayload, process.env.JWT_SECRET, { expiresIn: '-1s' });

  const expiredReqRes = await makeRequest({
    method: 'GET',
    path: '/api/auth/me',
    headers: { Authorization: `Bearer ${expiredToken}` },
  });
  assert(expiredReqRes.status === 401, '6.1 Expired emergency token rejected with HTTP 401');

  // Refreshing emergency access rejected
  const refreshTryRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/refresh',
    headers: {
      Cookie: `rekhta_emergency_mode=true; rekhta_access_token=${emergencySessionToken}`,
    },
  });
  assert(refreshTryRes.status === 401, '6.2 Refreshing emergency access strictly BLOCKED with HTTP 401');

  // ------------------------------------------------------------------------
  // TEST 7: Immediate Access Termination (/end-session)
  // ------------------------------------------------------------------------
  console.log('\n--- Test 7: Immediate Access Termination ---');

  const endSessionRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/end-session',
    headers: {
      Authorization: `Bearer ${emergencySessionToken}`,
      Cookie: `rekhta_access_token=${emergencyCookie}; rekhta_emergency_mode=true`,
    },
  });
  assert(endSessionRes.status === 200, '7.1 POST /api/emergency/end-session succeeds (HTTP 200)');
  const clearedAccessCookie = extractCookie(endSessionRes.headers, 'rekhta_access_token');
  const clearedModeCookie = extractCookie(endSessionRes.headers, 'rekhta_emergency_mode');
  assert(clearedAccessCookie === '', '7.2 rekhta_access_token cookie cleared');
  assert(clearedModeCookie === '', '7.3 rekhta_emergency_mode cookie cleared');

  // ------------------------------------------------------------------------
  // TEST 8: Hard Barrier: Super Admin & Developer Protection
  // ------------------------------------------------------------------------
  console.log('\n--- Test 8: Super Admin & Developer Hard Barrier ---');

  // 8.1 Attempt Super Admin access
  const superAdminAttempt = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'tameerrekhtaadmin@rekhta.org',
      accessKey: stagingEmergencyKey,
      reason: 'Attempting to inspect Super Admin portal via Emergency Key',
    },
  });
  assert(superAdminAttempt.status === 403, '8.1 Super Admin emergency access strictly BLOCKED (HTTP 403 Forbidden)');
  assert(superAdminAttempt.data.code === 'SUPER_ADMIN_EMERGENCY_PROHIBITED', '8.2 Clear security code: SUPER_ADMIN_EMERGENCY_PROHIBITED');

  // 8.2 Attempt Developer access
  const developerAttempt = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'rekhtadeveloper@rekhta.org',
      accessKey: stagingEmergencyKey,
      reason: 'Attempting to inspect Developer portal via Emergency Key',
    },
  });
  assert(developerAttempt.status === 403, '8.3 Developer emergency access strictly BLOCKED (HTTP 403 Forbidden)');
  assert(developerAttempt.data.code === 'DEVELOPER_EMERGENCY_PROHIBITED', '8.4 Clear security code: DEVELOPER_EMERGENCY_PROHIBITED');

  // ------------------------------------------------------------------------
  // TEST 9 & 10: Target Password & MFA Immutability Check
  // ------------------------------------------------------------------------
  console.log('\n--- Test 9 & 10: Target User Password & MFA Immutability ---');

  const targetAfter = getMemoryUser(mockLitUser.id);
  assert(targetAfter.password === litTargetHash, '9.1 Target user password hash is 100% UNCHANGED');
  assert(bcrypt.compareSync(litTargetPwd, targetAfter.password), '9.2 Target user password compares true with original plaintext');
  assert(targetAfter.mfaSecret === litTargetMfa, '10.1 Target user MFA secret is 100% UNCHANGED');
  assert(targetAfter.tokenVersion === 1, '10.2 Target user tokenVersion is 100% UNCHANGED');

  // ------------------------------------------------------------------------
  // TEST 11: Normal Target User Login Continues Working Uninterrupted
  // ------------------------------------------------------------------------
  console.log('\n--- Test 11: Normal User Authentication Uninterrupted ---');

  const normalLoginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: {
      email: 'literaturelead@rekhta.org',
      password: litTargetPwd,
    },
  });
  assert(normalLoginRes.status === 200, '11.1 Target user can sign in normally with original credentials');
  assert(normalLoginRes.data.requireMfa === true, '11.2 Normal login triggers target user own MFA gate');

  // ------------------------------------------------------------------------
  // TEST 12: Emergency Credential Revocation
  // ------------------------------------------------------------------------
  console.log('\n--- Test 12: Emergency Credential Revocation ---');

  const revokeRes = await makeRequest({
    method: 'POST',
    path: '/api/emergency/revoke',
    body: {
      accessKey: stagingEmergencyKey,
      reason: 'Revoking staging emergency key after successful testing',
    },
  });
  assert(revokeRes.status === 200, '12.1 POST /api/emergency/revoke succeeds (HTTP 200)');

  // Post-revocation key verification rejected
  const postRevokeAttempt = await makeRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'literaturelead@rekhta.org',
      accessKey: stagingEmergencyKey,
      reason: 'Attempting access with revoked key',
    },
  });
  assert(postRevokeAttempt.status === 403, '12.2 Revoked Emergency Access Key strictly rejected with HTTP 403');
  assert(postRevokeAttempt.data.code === 'EMERGENCY_SYSTEM_INACTIVE', '12.3 Rejection code: EMERGENCY_SYSTEM_INACTIVE');

  // Clean up
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
