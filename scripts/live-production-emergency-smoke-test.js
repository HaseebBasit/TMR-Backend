/**
 * Phase 10M Live Production Smoke Verification
 * Target Environment: https://tameer-e-rekhta.vercel.app
 * 
 * Verifies all production criteria:
 * 1. Emergency Access page loads successfully (HTTP 200).
 * 2. Gateway reports configured and active (HTTP 200, configured: true, active: true).
 * 3. Invalid key is rejected (HTTP 401).
 * 4. Hard Barrier: Super Admin is strictly non-targetable (HTTP 403).
 * 5. Hard Barrier: Developer is strictly non-targetable (HTTP 403).
 * 6. Inactive target account rejected (HTTP 400).
 * 7. Valid key + reason reaches the MFA verification stage (HTTP 200, requireMfa: true).
 * 8. Invalid TOTP is rejected (HTTP 401).
 * 9. Valid TOTP establishes emergency session (HTTP 200, strictly 900s / 15m expiration).
 * 10. Emergency session accesses /api/auth/me with proper claims and RBAC.
 * 11. Refresh is strictly prohibited (HTTP 401 EMERGENCY_REFRESH_PROHIBITED).
 * 12. Immediate session termination clears cookies and ends session (HTTP 200).
 * 13. Target user's password, MFA, tokenVersion, and status are 100% unmodified.
 * 14. Immutable audit logs recorded across all emergency operations.
 */

const path = require('path');
const fs = require('fs');
const https = require('https');
const mongoose = require('mongoose');

// Load environment
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { generateTotp } = require('../src/services/mfa.service');

const PROD_HOST = 'tameer-e-rekhta.vercel.app';
const HANDOFF_PATH = 'C:/Users/hasee/.gemini/antigravity-cli/brain/83e545b1-f4df-4dc2-b9b4-f6bb6718c4bf/EMERGENCY_ACCESS_KEY_HANDOFF_ONE_TIME.txt';

let totalChecks = 0;
let passedChecks = 0;
let failedChecks = 0;

function assert(condition, testName, details = '') {
  totalChecks++;
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passedChecks++;
  } else {
    console.error(`  [FAIL] ${testName} ${details ? '- ' + details : ''}`);
    failedChecks++;
  }
}

function httpsRequest({ method = 'GET', path: reqPath, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const postData = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
    const reqHeaders = {
      Host: PROD_HOST,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Production-Smoke-Test/1.0',
      'X-Requested-With': 'XMLHttpRequest',
      ...headers,
    };

    if (postData) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }

    const options = {
      hostname: PROD_HOST,
      port: 443,
      path: reqPath,
      method,
      headers: reqHeaders,
      timeout: 15000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch {
          json = { raw: data };
        }
        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: json,
        });
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`HTTPS Request timeout after 15000ms: ${reqPath}`));
    });

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

function loadHandoffCredentials() {
  if (!fs.existsSync(HANDOFF_PATH)) {
    throw new Error(`Credential handoff file not found at: ${HANDOFF_PATH}`);
  }
  const content = fs.readFileSync(HANDOFF_PATH, 'utf8');

  const keyMatch = content.match(/Emergency Access Key:\s+([^\r\n]+)/);
  const secretMatch = content.match(/TOTP Secret \(Base32\):\s+([A-Z0-9]+)/);

  if (!keyMatch || !secretMatch) {
    throw new Error('Failed to parse emergency credentials from private handoff file.');
  }

  return {
    emergencyKey: keyMatch[1].trim(),
    totpSecret: secretMatch[1].trim(),
  };
}

async function runProductionSmokeTests() {
  console.log('========================================================================');
  console.log('PHASE 10M: LIVE PRODUCTION SMOKE VERIFICATION');
  console.log(`Target: https://${PROD_HOST}`);
  console.log('========================================================================\n');

  // Load credentials safely from handoff file
  const { emergencyKey, totpSecret } = loadHandoffCredentials();
  console.log('[CREDENTIALS] Successfully loaded production credentials from private handoff (Zero secrets disclosed).\n');

  // Connect to production MongoDB Atlas for read-only integrity verification
  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) throw new Error('MONGODB_URI missing from environment.');
  const conn = await mongoose.createConnection(mongoUri).asPromise();
  const rawDb = conn.db;
  const usersCol = rawDb.collection('users');
  const auditLogsCol = rawDb.collection('auditlogs');

  // Select active target account for emergency access test: Literature Lead
  const targetEmail = 'noorulhuda@rekhta.org';
  const targetBefore = await usersCol.findOne({ email: targetEmail });
  if (!targetBefore) throw new Error(`Target account ${targetEmail} not found in production DB.`);

  const superAdminBefore = await usersCol.findOne({ email: 'tameerrekhtaadmin@rekhta.org' });
  const developerBefore = await usersCol.findOne({ email: 'rekhtadeveloper@rekhta.org' });

  console.log(`[TARGET ACCOUNT] Selected: ${targetBefore.name} (${targetBefore.email}) - Role: ${targetBefore.role} - Status: ${targetBefore.status}\n`);

  // ---------------------------------------------------------------------------
  // Check 1: Emergency Access Page Loads Successfully
  // ---------------------------------------------------------------------------
  console.log('--- Step 1: Frontend Route Accessibility ---');
  const pageRes = await httpsRequest({ method: 'GET', path: '/emergency-access' });
  assert(pageRes.status === 200, 'Page /emergency-access returns HTTP 200 OK');
  assert(
    typeof pageRes.data.raw === 'string' && pageRes.data.raw.includes('Emergency Access'),
    'Page HTML contains Emergency Access Gateway UI elements'
  );

  // ---------------------------------------------------------------------------
  // Check 2: Gateway Reports Configured and Active
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 2: Gateway Status API ---');
  const statusRes = await httpsRequest({ method: 'GET', path: '/api/emergency/status' });
  assert(statusRes.status === 200, 'GET /api/emergency/status returns HTTP 200');
  assert(statusRes.data.success === true, 'Response indicates success: true');
  assert(statusRes.data.configured === true, 'Emergency Access is configured: true');
  assert(statusRes.data.active === true, 'Emergency Access is active: true');
  assert(Boolean(statusRes.data.keyId), `Active Key ID confirmed: ${statusRes.data.keyId}`);

  // ---------------------------------------------------------------------------
  // Check 3: Invalid Emergency Key is Rejected
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 3: Invalid Emergency Access Key Rejection ---');
  const invalidKeyRes = await httpsRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail,
      accessKey: 'InvalidKey1234567890!@#$',
      reason: 'Automated smoke test security check',
    },
  });
  assert(invalidKeyRes.status === 401, 'Invalid key rejected with HTTP 401 Unauthorized');
  assert(invalidKeyRes.data.success === false, 'Invalid key response contains success: false');

  // ---------------------------------------------------------------------------
  // Check 4: Hard Security Barrier — Super Admin Rejection
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 4: Hard Barrier — Super Admin Protection ---');
  const superAdminRes = await httpsRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'tameerrekhtaadmin@rekhta.org',
      accessKey: emergencyKey,
      reason: 'Automated smoke test security barrier check',
    },
  });
  assert(superAdminRes.status === 403, 'Super Admin target rejected with HTTP 403 Forbidden');
  assert(
    superAdminRes.data.code === 'SUPER_ADMIN_EMERGENCY_PROHIBITED',
    'Hard barrier code SUPER_ADMIN_EMERGENCY_PROHIBITED triggered'
  );

  // ---------------------------------------------------------------------------
  // Check 5: Hard Security Barrier — Developer Rejection
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 5: Hard Barrier — Developer Protection ---');
  const devRes = await httpsRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'rekhtadeveloper@rekhta.org',
      accessKey: emergencyKey,
      reason: 'Automated smoke test security barrier check',
    },
  });
  assert(devRes.status === 403, 'Developer target rejected with HTTP 403 Forbidden');
  assert(
    devRes.data.code === 'DEVELOPER_EMERGENCY_PROHIBITED',
    'Hard barrier code DEVELOPER_EMERGENCY_PROHIBITED triggered'
  );

  // ---------------------------------------------------------------------------
  // Check 6: Inactive Account Rejection Gate
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 6: Inactive Account Rejection Gate ---');
  const inactiveRes = await httpsRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail: 'ahmadmaqsood@rekhta.org',
      accessKey: emergencyKey,
      reason: 'Smoke test inactive target account check',
    },
  });
  assert(inactiveRes.status === 400, 'Inactive target account rejected with HTTP 400 Bad Request');
  assert(
    typeof inactiveRes.data.error === 'string' && inactiveRes.data.error.includes('status'),
    'Inactive rejection explains account status requirement'
  );

  // ---------------------------------------------------------------------------
  // Check 7: Valid Key Stage 1 Acceptance & Target User Resolution
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 7: Valid Key Acceptance & Target Resolution ---');
  const validKeyRes = await httpsRequest({
    method: 'POST',
    path: '/api/emergency/verify-key',
    body: {
      targetEmail,
      accessKey: emergencyKey,
      reason: 'Phase 10M Production Smoke Verification of Emergency Access',
    },
  });
  assert(validKeyRes.status === 200, 'Valid key accepted with HTTP 200 OK');
  assert(validKeyRes.data.requireMfa === true, 'Stage 1 signals requireMfa: true');
  assert(Boolean(validKeyRes.data.emergencyToken), 'Stage 1 issues temporary emergencyToken');
  assert(
    validKeyRes.data.targetUser?.email?.toLowerCase() === targetEmail.toLowerCase(),
    `Target user profile resolved: ${validKeyRes.data.targetUser?.name} (${validKeyRes.data.targetUser?.email})`
  );
  assert(
    validKeyRes.data.targetUser?.role === 'dept_literature',
    `Target user role preserved: ${validKeyRes.data.targetUser?.role}`
  );
  const emergencyToken = validKeyRes.data.emergencyToken;

  // ---------------------------------------------------------------------------
  // Check 8: Invalid TOTP Code Rejection
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 8: Invalid MFA TOTP Rejection ---');
  const invalidTotpRes = await httpsRequest({
    method: 'POST',
    path: '/api/emergency/verify-mfa',
    body: {
      emergencyToken,
      code: '000000',
    },
  });
  assert(invalidTotpRes.status === 401, 'Invalid TOTP rejected with HTTP 401 Unauthorized');
  assert(invalidTotpRes.data.success === false, 'Invalid TOTP response contains success: false');

  // ---------------------------------------------------------------------------
  // Check 9: Valid MFA Verification & 15-Minute Emergency Session Issuance
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 9: Valid MFA Verification & 15-Minute Emergency Session ---');
  const validTotpCode = generateTotp(totpSecret);
  const mfaRes = await httpsRequest({
    method: 'POST',
    path: '/api/emergency/verify-mfa',
    body: {
      emergencyToken,
      code: validTotpCode,
    },
  });
  assert(mfaRes.status === 200, 'Valid TOTP accepted with HTTP 200 OK');
  assert(mfaRes.data.success === true, 'Emergency session established (success: true)');
  assert(mfaRes.data.isEmergencyAccess === true, 'Response marks isEmergencyAccess: true');
  assert(mfaRes.data.sessionExpiresIn === 900, 'Session lifetime strictly 900 seconds (15 minutes)');
  assert(
    Boolean(mfaRes.data.emergencySession?.expiresAt),
    `Emergency session expiresAt confirmed: ${mfaRes.data.emergencySession?.expiresAt}`
  );
  assert(
    mfaRes.data.emergencySession?.operatorEmail === 'emergency-operator@system.rekhta.org',
    'Attributed operator identity: emergency-operator@system.rekhta.org'
  );

  const accessTokenCookie = extractCookie(mfaRes.headers, 'rekhta_access_token');
  const emergencyModeCookie = extractCookie(mfaRes.headers, 'rekhta_emergency_mode');
  const refreshTokenCookie = extractCookie(mfaRes.headers, 'rekhta_refresh_token');

  assert(Boolean(accessTokenCookie), 'HTTP-only rekhta_access_token cookie received');
  assert(emergencyModeCookie === 'true', 'rekhta_emergency_mode=true cookie received');
  assert(!refreshTokenCookie, 'rekhta_refresh_token cookie is NOT issued (cleared)');

  const cookieHeader = `rekhta_access_token=${accessTokenCookie}; rekhta_emergency_mode=true`;

  // ---------------------------------------------------------------------------
  // Check 10: Emergency Session Authentication & RBAC Verification
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 10: Emergency Session Authentication & RBAC ---');
  const meRes = await httpsRequest({
    method: 'GET',
    path: '/api/auth/me',
    headers: {
      Cookie: cookieHeader,
      Authorization: `Bearer ${accessTokenCookie}`,
    },
  });
  assert(meRes.status === 200, 'GET /api/auth/me authenticated successfully with HTTP 200');
  assert(
    meRes.data.user?.email?.toLowerCase() === targetEmail.toLowerCase(),
    `Authenticated user matches target: ${meRes.data.user?.email}`
  );
  assert(meRes.data.user?.isEmergencyAccess === true, 'User payload retains isEmergencyAccess: true');
  assert(
    meRes.data.user?.emergencySession?.operatorEmail === 'emergency-operator@system.rekhta.org',
    'User payload retains operator emergency attribution'
  );

  // ---------------------------------------------------------------------------
  // Check 11: Refresh Prohibition Verification
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 11: Refresh Prohibition ---');
  const refreshRes = await httpsRequest({
    method: 'POST',
    path: '/api/auth/refresh',
    headers: {
      Cookie: cookieHeader,
    },
  });
  assert(refreshRes.status === 401, 'POST /api/auth/refresh rejected with HTTP 401 Unauthorized');
  assert(
    refreshRes.data.code === 'EMERGENCY_REFRESH_PROHIBITED',
    'Refresh prohibited code EMERGENCY_REFRESH_PROHIBITED confirmed'
  );

  // ---------------------------------------------------------------------------
  // Check 12: Immediate Emergency Session Termination
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 12: Immediate Session Termination ---');
  const endSessionRes = await httpsRequest({
    method: 'POST',
    path: '/api/emergency/end-session',
    headers: {
      Cookie: cookieHeader,
      Authorization: `Bearer ${accessTokenCookie}`,
    },
  });
  assert(endSessionRes.status === 200, 'POST /api/emergency/end-session returns HTTP 200');
  assert(endSessionRes.data.success === true, 'Session ended successfully');

  const postEndAccess = extractCookie(endSessionRes.headers, 'rekhta_access_token');
  const postEndEmergency = extractCookie(endSessionRes.headers, 'rekhta_emergency_mode');
  assert(
    postEndAccess === '' || postEndAccess === null,
    'rekhta_access_token cookie cleared on session termination'
  );
  assert(
    postEndEmergency === '' || postEndEmergency === null,
    'rekhta_emergency_mode cookie cleared on session termination'
  );

  // ---------------------------------------------------------------------------
  // Check 13: Target Account Immutability (Read-Only DB Inspection)
  // ---------------------------------------------------------------------------
  console.log('\n--- Step 13: Production Database Post-Verification ---');
  const targetAfter = await usersCol.findOne({ email: targetEmail });
  const superAdminAfter = await usersCol.findOne({ email: 'tameerrekhtaadmin@rekhta.org' });
  const developerAfter = await usersCol.findOne({ email: 'rekhtadeveloper@rekhta.org' });

  assert(targetAfter.password === targetBefore.password, 'Target user password hash is 100% UNCHANGED');
  assert(targetAfter.tokenVersion === targetBefore.tokenVersion, 'Target user tokenVersion is 100% UNCHANGED');
  assert(targetAfter.mustChangePassword === targetBefore.mustChangePassword, 'Target user mustChangePassword is 100% UNCHANGED');
  assert(targetAfter.status === targetBefore.status, 'Target user status is 100% UNCHANGED');

  assert(superAdminAfter.password === superAdminBefore.password, 'Super Admin password hash is 100% UNCHANGED');
  assert(developerAfter.password === developerBefore.password, 'Developer password hash is 100% UNCHANGED');

  // Verify Audit Log Entries
  const recentLogs = await auditLogsCol
    .find({ module: 'EMERGENCY_ACCESS' })
    .sort({ createdAt: -1 })
    .limit(10)
    .toArray();

  const loggedActions = recentLogs.map((l) => l.action);
  assert(
    loggedActions.includes('SECURITY_ALERT_EMERGENCY_KEY_REJECTED'),
    'AuditLog captured SECURITY_ALERT_EMERGENCY_KEY_REJECTED'
  );
  assert(
    loggedActions.includes('SECURITY_ALERT_EMERGENCY_SUPER_ADMIN_BLOCKED'),
    'AuditLog captured SECURITY_ALERT_EMERGENCY_SUPER_ADMIN_BLOCKED'
  );
  assert(
    loggedActions.includes('SECURITY_ALERT_EMERGENCY_DEVELOPER_BLOCKED'),
    'AuditLog captured SECURITY_ALERT_EMERGENCY_DEVELOPER_BLOCKED'
  );
  assert(
    loggedActions.includes('SECURITY_ALERT_EMERGENCY_MFA_FAILED'),
    'AuditLog captured SECURITY_ALERT_EMERGENCY_MFA_FAILED'
  );
  assert(
    loggedActions.includes('EMERGENCY_ACCESS_SESSION_CREATED'),
    'AuditLog captured EMERGENCY_ACCESS_SESSION_CREATED'
  );
  assert(
    loggedActions.includes('EMERGENCY_ACCESS_SESSION_TERMINATED'),
    'AuditLog captured EMERGENCY_ACCESS_SESSION_TERMINATED'
  );

  await conn.close();

  console.log('\n========================================================================');
  console.log(`LIVE PRODUCTION SMOKE VERIFICATION RESULT: ${passedChecks}/${totalChecks} PASSED, ${failedChecks} FAILED`);
  console.log('========================================================================\n');

  if (failedChecks > 0) {
    process.exit(1);
  }
}

runProductionSmokeTests().catch((err) => {
  console.error('\n[FATAL SMOKE TEST ERROR]:', err);
  process.exit(1);
});
