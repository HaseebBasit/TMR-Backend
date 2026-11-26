/**
 * Live Production Acceptance Script: Dedicated Developer Account Verification
 * Production Frontend: https://tameer-e-rekhta.vercel.app
 * Account: rekhtadeveloper@rekhta.org
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const { generateTotp, verifyTotp } = require('../src/services/mfa.service');

const PROD_BASE = 'https://tameer-e-rekhta.vercel.app';
const HANDOFF_PATH = 'C:/Users/hasee/.gemini/antigravity-cli/brain/83e545b1-f4df-4dc2-b9b4-f6bb6718c4bf/DEVELOPER_CREDENTIAL_HANDOFF_ONE_TIME.txt';
const PERMANENT_DEVELOPER_PASSWORD = 'RekhtaDev#2026!SecureMasterKey';

function makeRequest(pathOrUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const fullUrl = pathOrUrl.startsWith('http') ? pathOrUrl : `${PROD_BASE}${pathOrUrl}`;
    const url = new URL(fullUrl);
    const postData = options.body ? (typeof options.body === 'string' ? options.body : JSON.stringify(options.body)) : null;
    const headers = { ...options.headers };

    if (postData) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(postData);
    }
    if (!headers['X-Requested-With']) {
      headers['X-Requested-With'] = 'XMLHttpRequest';
    }
    headers['User-Agent'] = 'TameerRekhta-Acceptance-Tester/1.0';

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

function buildCookieHeader(headers) {
  const setCookie = headers['set-cookie'];
  if (!setCookie) return '';
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  return cookies.map((c) => c.split(';')[0]).join('; ');
}

async function runAcceptance() {
  console.log('========================================================================');
  console.log('LIVE PRODUCTION ACCEPTANCE: DEVELOPER ACCOUNT END-TO-END VERIFICATION');
  console.log('========================================================================\n');

  if (!fs.existsSync(HANDOFF_PATH)) {
    throw new Error(`Handoff file not found at ${HANDOFF_PATH}`);
  }

  const handoffContent = fs.readFileSync(HANDOFF_PATH, 'utf8');
  const initialPwdMatch = handoffContent.match(/Initial Password:\s*(\S+)/);
  const secretMatch = handoffContent.match(/TOTP Secret \(Base32\):\s*([A-Z0-9]+)/);

  if (!secretMatch) {
    throw new Error('TOTP Secret not found in handoff file.');
  }

  const initialPassword = initialPwdMatch ? initialPwdMatch[1] : null;
  const mfaSecret = secretMatch[1];
  console.log(`[INFO] Loaded Developer MFA Secret: ${mfaSecret.slice(0, 6)}...`);

  // Step 1: Verify /portal/developer route is live
  console.log('\n--- Step 1: Verify Production Portal Routing ---');
  const portalDevRes = await makeRequest('/portal/developer');
  console.log(`GET /portal/developer -> HTTP ${portalDevRes.status}`);
  if (portalDevRes.status !== 200) {
    throw new Error(`Expected /portal/developer to return HTTP 200, got ${portalDevRes.status}`);
  }
  console.log('  [PASS] /portal/developer route is deployed and accessible in production');

  // Step 2: Attempt Login (first try with permanent password if already changed, otherwise initial)
  console.log('\n--- Step 2: Developer Authentication Challenge ---');
  let currentPassword = initialPassword;
  let loginRes = await makeRequest('/api/auth/login', {
    method: 'POST',
    body: { email: 'rekhtadeveloper@rekhta.org', password: currentPassword },
  });

  if (loginRes.status === 401) {
    console.log('[INFO] Initial password failed (possibly already changed). Trying permanent password...');
    currentPassword = PERMANENT_DEVELOPER_PASSWORD;
    loginRes = await makeRequest('/api/auth/login', {
      method: 'POST',
      body: { email: 'rekhtadeveloper@rekhta.org', password: currentPassword },
    });
  }

  console.log(`POST /api/auth/login -> HTTP ${loginRes.status}, requireMfa: ${loginRes.data?.requireMfa}`);
  if (loginRes.status !== 200 || !loginRes.data?.requireMfa) {
    throw new Error(`Login failed or did not return requireMfa: ${JSON.stringify(loginRes.data)}`);
  }
  console.log('  [PASS] Stage 1 authentication succeeded; MFA challenge issued');
  const mfaToken = loginRes.data.mfaToken;

  // Step 3: MFA TOTP Verification
  console.log('\n--- Step 3: MFA TOTP Challenge Verification ---');
  const totpCode = generateTotp(mfaSecret);
  console.log(`Generated live RFC 6238 TOTP: ${totpCode}`);

  const mfaRes = await makeRequest('/api/auth/mfa/verify', {
    method: 'POST',
    body: { mfaToken, code: totpCode },
  });

  console.log(`POST /api/auth/mfa/verify -> HTTP ${mfaRes.status}`);
  console.log(`  mfaVerified: ${mfaRes.data?.mfaVerified}, requirePasswordChange: ${mfaRes.data?.requirePasswordChange}`);

  let sessionCookies = '';

  if (mfaRes.data?.requirePasswordChange) {
    console.log('\n--- Step 4: Enforce Mandatory Initial Password Change ---');
    const tempToken = mfaRes.data.tempToken;
    console.log('  tempToken received for initial password change');

    const changePwdRes = await makeRequest('/api/auth/change-initial-password', {
      method: 'POST',
      body: {
        tempToken,
        newPassword: PERMANENT_DEVELOPER_PASSWORD,
      },
    });

    console.log(`POST /api/auth/change-initial-password -> HTTP ${changePwdRes.status}: ${JSON.stringify(changePwdRes.data)}`);
    if (changePwdRes.status !== 200 || !changePwdRes.data?.success) {
      throw new Error(`Password change failed: ${JSON.stringify(changePwdRes.data)}`);
    }
    console.log('  [PASS] Initial mandatory password change succeeded!');

    // Re-authenticate with new permanent password
    console.log('\n--- Step 5: Post-Change Login with Permanent Password ---');
    const reLoginRes = await makeRequest('/api/auth/login', {
      method: 'POST',
      body: { email: 'rekhtadeveloper@rekhta.org', password: PERMANENT_DEVELOPER_PASSWORD },
    });

    if (reLoginRes.status !== 200 || !reLoginRes.data?.requireMfa) {
      throw new Error(`Re-login with new password failed: ${JSON.stringify(reLoginRes.data)}`);
    }
    console.log('  [PASS] Login with permanent password succeeded; MFA requested');

    const reTotp = generateTotp(mfaSecret);
    const postChangeMfaRes = await makeRequest('/api/auth/mfa/verify', {
      method: 'POST',
      body: { mfaToken: reLoginRes.data.mfaToken, code: reTotp },
    });

    if (postChangeMfaRes.status !== 200 || !postChangeMfaRes.data?.success) {
      throw new Error(`Post-change MFA verification failed: ${JSON.stringify(postChangeMfaRes.data)}`);
    }
    console.log('  [PASS] Full session established with new permanent password!');
    sessionCookies = buildCookieHeader(postChangeMfaRes.headers);
  } else if (mfaRes.data?.success) {
    console.log('  [PASS] Full session established without mandatory password change!');
    sessionCookies = buildCookieHeader(mfaRes.headers);
  } else {
    throw new Error(`Unexpected MFA verification outcome: ${JSON.stringify(mfaRes.data)}`);
  }

  // Step 6: Verify Session Hydration & Developer Profile
  console.log('\n--- Step 6: Session Hydration & Developer Profile Verification ---');
  const meRes = await makeRequest('/api/auth/me', {
    method: 'GET',
    headers: { Cookie: sessionCookies },
  });

  console.log(`GET /api/auth/me -> HTTP ${meRes.status}`);
  console.log(`  User: ${meRes.data?.user?.email}, Role: ${meRes.data?.user?.role}, Designation: ${meRes.data?.user?.designation}`);
  if (meRes.status !== 200 || meRes.data?.user?.role !== 'developer') {
    throw new Error(`User profile mismatch: ${JSON.stringify(meRes.data)}`);
  }
  console.log('  [PASS] Developer session hydrated correctly with role="developer"');

  // Step 7: Access Developer Diagnostics Telemetry
  console.log('\n--- Step 7: Developer System Diagnostics Telemetry ---');
  const diagRes = await makeRequest('/api/developer/diagnostics', {
    method: 'GET',
    headers: { Cookie: sessionCookies },
  });

  console.log(`GET /api/developer/diagnostics -> HTTP ${diagRes.status}`);
  if (diagRes.status !== 200 || !diagRes.data?.success) {
    throw new Error(`Developer diagnostics failed: ${JSON.stringify(diagRes.data)}`);
  }
  console.log(`  System Node: ${diagRes.data?.system?.nodeVersion}, Platform: ${diagRes.data?.system?.platform}`);
  console.log(`  Database Status: ${diagRes.data?.database?.status}, Users: ${diagRes.data?.database?.metrics?.users}, Tasks: ${diagRes.data?.database?.metrics?.tasks}`);
  console.log('  [PASS] Developer successfully accessed system telemetry');

  // Step 8: Verify Super Admin Protection & Impersonation Barrier
  console.log('\n--- Step 8: Super Admin Protection & Impersonation Hard Barrier ---');
  const impersonateRes = await makeRequest('/api/developer/impersonate', {
    method: 'POST',
    headers: { Cookie: sessionCookies },
    body: {
      targetEmail: 'tameerrekhtaadmin@rekhta.org',
      reason: 'Automated verification test of Super Admin security barrier',
    },
  });

  console.log(`POST /api/developer/impersonate (Super Admin target) -> HTTP ${impersonateRes.status}`);
  if (impersonateRes.status !== 403) {
    throw new Error(`Expected HTTP 403 Forbidden when attempting Super Admin impersonation, got ${impersonateRes.status}`);
  }
  console.log(`  Response Code: ${impersonateRes.data?.code}, Error: ${impersonateRes.data?.error}`);
  console.log('  [PASS] Hard Barrier Active: Super Admin is strictly non-impersonatable!');

  // Step 9: Verify Logout
  console.log('\n--- Step 9: Developer Session Termination (Logout) ---');
  const logoutRes = await makeRequest('/api/auth/logout', {
    method: 'POST',
    headers: { Cookie: sessionCookies },
  });

  console.log(`POST /api/auth/logout -> HTTP ${logoutRes.status}`);
  if (logoutRes.status !== 200) {
    throw new Error(`Logout failed: ${JSON.stringify(logoutRes.data)}`);
  }
  console.log('  [PASS] Developer session successfully terminated');

  // Step 10: Re-login verification with permanent password + fresh MFA
  console.log('\n--- Step 10: Final Re-Login Verification with Permanent Password ---');
  const finalLoginRes = await makeRequest('/api/auth/login', {
    method: 'POST',
    body: { email: 'rekhtadeveloper@rekhta.org', password: PERMANENT_DEVELOPER_PASSWORD },
  });

  if (finalLoginRes.status !== 200 || !finalLoginRes.data?.requireMfa) {
    throw new Error(`Final re-login failed: ${JSON.stringify(finalLoginRes.data)}`);
  }

  const finalTotp = generateTotp(mfaSecret);
  const finalMfaRes = await makeRequest('/api/auth/mfa/verify', {
    method: 'POST',
    body: { mfaToken: finalLoginRes.data.mfaToken, code: finalTotp },
  });

  if (finalMfaRes.status !== 200 || !finalMfaRes.data?.success) {
    throw new Error(`Final MFA verification failed: ${JSON.stringify(finalMfaRes.data)}`);
  }
  console.log('  [PASS] Credential persistence verified: Developer can consistently authenticate!');

  // Step 11: Update handoff artifact with permanent status
  console.log('\n--- Step 11: Updating Handoff Documentation ---');
  const updatedHandoff = `========================================================================
TA'MEER-E-REKHTA — CONFIDENTIAL DEVELOPER CREDENTIAL RECORD
========================================================================
Status:                 ACTIVATED & PERMANENT PASSWORD ESTABLISHED
Account:                rekhtadeveloper@rekhta.org
Role:                   developer (Dedicated Developer Master Access)
Official Designation:   System Lead (system_lead)
Department:             Engineering (ENG)
User ID:                6b07cb8852e050c56db0e1cc
Last Activated:         ${new Date().toISOString()}
------------------------------------------------------------------------
AUTHENTICATION CREDENTIALS:
------------------------------------------------------------------------
Active Password:        ${PERMANENT_DEVELOPER_PASSWORD}
Must Change Password:   FALSE (Established & Verified)

MFA / TWO-FACTOR AUTHENTICATION:
MFA Enabled:            TRUE (Mandatory RFC 6238 TOTP)
TOTP Secret (Base32):   ${mfaSecret}
TOTP Authenticator URI:
otpauth://totp/Ta'meer-e-Rekhta:rekhtadeveloper%40rekhta.org?secret=${mfaSecret}&issuer=Ta'meer-e-Rekhta&algorithm=SHA1&digits=6&period=30

BACKUP RECOVERY CODES:
  Code 1: 2187-E1A2
  Code 2: BC3D-195B
  Code 3: 182E-EE67
  Code 4: 745C-0776
  Code 5: 8889-C384
  Code 6: BD7A-94CC
  Code 7: 7C44-2B7A
  Code 8: 2F1D-34B2
------------------------------------------------------------------------
AUDIT & GOVERNANCE NOTES:
1. Dedicated Developer Master Access is active and operational.
2. Developer Dashboard: https://tameer-e-rekhta.vercel.app/portal/developer
3. Super Admin impersonation is mathematically and architecturally barred (HTTP 403).
4. All privileged actions are audited under the DEVELOPER audit domain.
========================================================================
`;
  fs.writeFileSync(HANDOFF_PATH, updatedHandoff, 'utf8');
  console.log(`  [PASS] Updated credential handoff record written to ${HANDOFF_PATH}`);

  console.log('\n========================================================================');
  console.log('ALL LIVE PRODUCTION ACCEPTANCE TESTS PASSED SUCCESSFULLY (11/11 STEPS)!');
  console.log('========================================================================');
}

runAcceptance().catch((err) => {
  console.error('\n[FATAL ERROR IN LIVE ACCEPTANCE]:', err.message);
  process.exit(1);
});
