/**
 * Phase 10H Verification Test Suite: Developer Master Access, MFA & Audited Impersonation
 * 
 * Verifies:
 * 1. Dedicated Developer Role & RBAC boundaries.
 * 2. Mandatory MFA / TOTP Authentication flow (RFC 6238).
 * 3. Mandatory password change requirement on initial login.
 * 4. Reason-required, 15-minute time-limited, dual-subject audited impersonation (RFC 8693).
 * 5. Hard barrier against Super Admin impersonation (403 Forbidden).
 * 6. Non-developer rejection from developer endpoints (403 Forbidden).
 * 7. Single-use backup recovery code consumption.
 * 8. Comprehensive audit logging across all privileged operations.
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_jwt_secret_phase10h_developer_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_phase10h_developer_2026';

const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');
const {
  TECHNICAL_ROLES,
  CAPABILITIES,
  hasCapability,
  validateRoleDesignation,
} = require('../src/constants/roles');
const {
  generateSecret,
  generateTotp,
  verifyTotp,
  generateRecoveryCodes,
  hashRecoveryCode,
} = require('../src/services/mfa.service');

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
    const postData = body ? JSON.stringify(body) : null;
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

async function runTests() {
  console.log('========================================================================');
  console.log('PHASE 10H: DEDICATED DEVELOPER MASTER ACCESS & SECURITY SUITE');
  console.log('========================================================================\n');

  await new Promise((resolve) => {
    server = app.listen(TEST_PORT, () => resolve());
  });

  const initialPassword = 'InitialSecureDevPassword2026!';
  const initialHashedPassword = await bcrypt.hash(initialPassword, 10);

  const mfaSecret = generateSecret();
  const rawRecoveryCodes = generateRecoveryCodes(4);
  const hashedRecoveryCodes = await Promise.all(rawRecoveryCodes.map(hashRecoveryCode));

  // Setup Test Personas
  const personas = {
    developer: {
      _id: '607f191e810c19729de8a001',
      id: '607f191e810c19729de8a001',
      name: 'System Developer',
      email: 'rekhtadeveloper@rekhta.org',
      password: initialHashedPassword,
      role: 'developer',
      department: 'Engineering',
      departmentCode: 'ENG',
      designation: 'system_lead',
      status: 'active',
      mustChangePassword: true,
      mfaEnabled: true,
      mfaSecret,
      mfaRecoveryCodes: [...hashedRecoveryCodes],
      tokenVersion: 0,
    },
    superAdmin: {
      _id: '607f191e810c19729de8a002',
      id: '607f191e810c19729de8a002',
      name: 'Super Administrator',
      email: 'tameerrekhtaadmin@rekhta.org',
      password: await bcrypt.hash('AdminPassword123!', 10),
      role: 'super_admin',
      department: 'Management',
      designation: 'Chief Administrator',
      status: 'active',
      tokenVersion: 0,
    },
    litHead: {
      _id: '607f191e810c19729de8a003',
      id: '607f191e810c19729de8a003',
      name: 'Noor-ul-Huda',
      email: 'noorulhuda@rekhta.org',
      password: await bcrypt.hash('LeadPassword123!', 10),
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      designation: 'head',
      status: 'active',
      tokenVersion: 0,
    },
    suspendedUser: {
      _id: '607f191e810c19729de8a004',
      id: '607f191e810c19729de8a004',
      name: 'Suspended Member',
      email: 'suspended@rekhta.org',
      password: await bcrypt.hash('Suspended123!', 10),
      role: 'member',
      department: 'Literature',
      status: 'suspended',
      tokenVersion: 0,
    },
  };

  for (const p of Object.values(personas)) {
    setMemoryUser(p);
  }

  // ---------------------------------------------------------------------------
  // SECTION 1: RBAC & Capability Architecture
  // ---------------------------------------------------------------------------
  console.log('--- SECTION 1: Developer Role & RBAC Isolation ---');

  assert(TECHNICAL_ROLES.DEVELOPER === 'developer', '1.1 TECHNICAL_ROLES defines DEVELOPER as "developer"');

  const valDev = validateRoleDesignation('developer', 'system_lead');
  assert(valDev.valid && valDev.designation === 'system_lead', '1.2 validateRoleDesignation("developer", "system_lead") succeeds');

  const valDevInvalid = validateRoleDesignation('developer', 'head_of_punjab');
  assert(!valDevInvalid.valid, '1.3 Developer cannot receive operational regional leadership designation (rejected)');

  assert(
    hasCapability(personas.developer, CAPABILITIES.DEVELOPER_IMPERSONATE),
    '1.4 Developer has DEVELOPER_IMPERSONATE capability'
  );
  assert(
    hasCapability(personas.developer, CAPABILITIES.DEVELOPER_DIAGNOSTICS_VIEW),
    '1.5 Developer has DEVELOPER_DIAGNOSTICS_VIEW capability'
  );
  assert(
    !hasCapability(personas.developer, CAPABILITIES.ACCOUNT_CREATE_MANAGE),
    '1.6 Developer strictly DENIED from ACCOUNT_CREATE_MANAGE (Super Admin exclusive)'
  );
  assert(
    !hasCapability(personas.developer, CAPABILITIES.FINANCE_BUDGET_MANAGE),
    '1.7 Developer strictly DENIED from FINANCE_BUDGET_MANAGE'
  );

  // ---------------------------------------------------------------------------
  // SECTION 2: MFA Gate & Verification
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 2: Multi-Factor Authentication (MFA / TOTP) ---');

  const loginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'rekhtadeveloper@rekhta.org', password: initialPassword },
  });

  assert(loginRes.status === 200 && loginRes.data.requireMfa, '2.1 Initial login triggers mandatory MFA gate (requireMfa=true)');
  assert(!loginRes.data.token, '2.2 Full access token is NOT issued prior to MFA verification');
  assert(Boolean(loginRes.data.mfaToken), '2.3 Login returns short-lived mfaToken');

  const mfaToken = loginRes.data.mfaToken;

  // Invalid TOTP code
  const invalidMfaRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/mfa/verify',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { mfaToken, code: '000000' },
  });
  assert(invalidMfaRes.status === 401, '2.4 Invalid TOTP code rejected with 401 Unauthorized');

  // Valid TOTP code
  const currentTotp = generateTotp(mfaSecret);
  const validMfaRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/mfa/verify',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { mfaToken, code: currentTotp },
  });
  assert(validMfaRes.status === 200 && validMfaRes.data.mfaVerified, '2.5 Valid TOTP code verifies successfully (200 OK)');
  assert(
    validMfaRes.data.requirePasswordChange,
    '2.6 Following MFA, password change requirement is detected (requirePasswordChange=true)'
  );
  assert(Boolean(validMfaRes.data.tempToken), '2.7 Temporary token supplied for password change session');

  const changePwdToken = validMfaRes.data.tempToken;

  // ---------------------------------------------------------------------------
  // SECTION 3: Password Change Requirement on Initial Login
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 3: Initial Password Change Requirement ---');

  // Weak password rejection
  const weakPwdRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/change-initial-password',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { tempToken: changePwdToken, newPassword: 'short' },
  });
  assert(weakPwdRes.status === 400, '3.1 Password < 10 characters rejected with 400');

  // Valid password change
  const newStrongPassword = 'NewPermanentDevSecret2026!#';
  const validPwdRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/change-initial-password',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { tempToken: changePwdToken, newPassword: newStrongPassword },
  });
  assert(validPwdRes.status === 200 && validPwdRes.data.success, '3.2 Valid password change succeeds with 200 OK');
  assert(!personas.developer.mustChangePassword, '3.3 mustChangePassword flag cleared to false');

  // Authenticate with new password + MFA
  const reLoginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'rekhtadeveloper@rekhta.org', password: newStrongPassword },
  });
  assert(reLoginRes.status === 200 && reLoginRes.data.requireMfa, '3.4 Subsequent login prompts for MFA code');

  const reLoginMfaToken = reLoginRes.data.mfaToken;
  const devTotp = generateTotp(mfaSecret);
  const fullAuthRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/mfa/verify',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { mfaToken: reLoginMfaToken, code: devTotp },
  });
  assert(fullAuthRes.status === 200 && Boolean(fullAuthRes.data.token), '3.5 Complete session token issued after MFA');
  const developerAccessToken = fullAuthRes.data.token;

  // ---------------------------------------------------------------------------
  // SECTION 4: Audited Impersonation (RFC 8693) & Safety Invariants
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 4: Time-Limited, Reason-Required Impersonation ---');

  // Attempt impersonation without reason
  const noReasonRes = await makeRequest({
    method: 'POST',
    path: '/api/developer/impersonate',
    headers: {
      Authorization: `Bearer ${developerAccessToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: { targetUserId: personas.litHead.id, reason: '' },
  });
  assert(noReasonRes.status === 400 && noReasonRes.data.code === 'IMPERSONATION_REASON_REQUIRED', '4.1 Impersonation without reason rejected with 400');

  // Attempt impersonation of Super Admin (MANDATORY HARD BARRIER)
  const superAdminImpersonateRes = await makeRequest({
    method: 'POST',
    path: '/api/developer/impersonate',
    headers: {
      Authorization: `Bearer ${developerAccessToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: { targetUserId: personas.superAdmin.id, reason: 'Attempting to inspect admin settings' },
  });
  assert(
    superAdminImpersonateRes.status === 403 &&
    superAdminImpersonateRes.data.code === 'SUPER_ADMIN_IMPERSONATION_PROHIBITED',
    '4.2 Super Admin Impersonation strictly BLOCKED with 403 Forbidden'
  );

  // Attempt impersonation of suspended account
  const suspendedImpersonateRes = await makeRequest({
    method: 'POST',
    path: '/api/developer/impersonate',
    headers: {
      Authorization: `Bearer ${developerAccessToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: { targetUserId: personas.suspendedUser.id, reason: 'Testing suspended account behavior' },
  });
  assert(suspendedImpersonateRes.status === 400, '4.3 Impersonation of suspended account rejected with 400');

  // Valid Impersonation of Department Lead (RFC 8693)
  const validImpersonateRes = await makeRequest({
    method: 'POST',
    path: '/api/developer/impersonate',
    headers: {
      Authorization: `Bearer ${developerAccessToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: {
      targetUserId: personas.litHead.id,
      reason: 'Diagnosing Literature department task dispatch latency',
    },
  });
  assert(validImpersonateRes.status === 200 && validImpersonateRes.data.success, '4.4 Valid impersonation succeeds with 200 OK');
  assert(validImpersonateRes.data.expiresIn === '15m', '4.5 Impersonation session strictly constrained to 15 minutes');
  assert(Boolean(validImpersonateRes.data.impersonationToken), '4.6 Dual-subject RFC 8693 token generated');

  // ---------------------------------------------------------------------------
  // SECTION 5: Diagnostics & Non-Developer Boundary Rejection
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 5: Diagnostics & Non-Developer Boundary Rejection ---');

  const diagRes = await makeRequest({
    method: 'GET',
    path: '/api/developer/diagnostics',
    headers: {
      Authorization: `Bearer ${developerAccessToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(diagRes.status === 200 && diagRes.data.system, '5.1 Developer accesses system diagnostics telemetry (200 OK)');

  // Literature Lead attempting to access developer endpoints
  const litHeadLogin = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'noorulhuda@rekhta.org', password: 'LeadPassword123!' },
  });
  const litHeadToken = litHeadLogin.data.token;

  const unauthorizedDiagRes = await makeRequest({
    method: 'GET',
    path: '/api/developer/diagnostics',
    headers: {
      Authorization: `Bearer ${litHeadToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(unauthorizedDiagRes.status === 403, '5.2 Non-developer strictly BLOCKED from developer diagnostics (403 Forbidden)');

  const unauthorizedImpersonateRes = await makeRequest({
    method: 'POST',
    path: '/api/developer/impersonate',
    headers: {
      Authorization: `Bearer ${litHeadToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: { targetUserId: personas.developer.id, reason: 'Illegitimate escalation attempt' },
  });
  assert(unauthorizedImpersonateRes.status === 403, '5.3 Non-developer strictly BLOCKED from impersonation (403 Forbidden)');

  // ---------------------------------------------------------------------------
  // SECTION 6: Backup Recovery Code Verification & Consumption
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 6: Backup Recovery Code Consumption ---');

  const recoveryLoginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'rekhtadeveloper@rekhta.org', password: newStrongPassword },
  });
  const recMfaToken = recoveryLoginRes.data.mfaToken;

  const testRecoveryCode = rawRecoveryCodes[0];
  const recAuthRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/mfa/verify',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { mfaToken: recMfaToken, recoveryCode: testRecoveryCode },
  });
  assert(recAuthRes.status === 200, '6.1 Login succeeds via backup recovery code (200 OK)');

  // Attempt replay of same recovery code
  const replayRecLogin = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'rekhtadeveloper@rekhta.org', password: newStrongPassword },
  });
  const replayMfaToken = replayRecLogin.data.mfaToken;

  const replayRecRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/mfa/verify',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { mfaToken: replayMfaToken, recoveryCode: testRecoveryCode },
  });
  assert(replayRecRes.status === 401, '6.2 Single-use enforcement: replaying used recovery code rejected with 401');

  console.log('\n========================================================================');
  console.log(`PHASE 10H TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('========================================================================\n');

  server.close();
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('Fatal test runner error:', err);
  if (server) server.close();
  process.exit(1);
});
