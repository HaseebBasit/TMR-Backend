process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'rekhta_access_secret_2026_super_secure';
process.env.JWT_REFRESH_SECRET = 'rekhta_refresh_secret_2026_super_secure';

const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = require('../src/server');
const { setMemoryUser, getMemoryUsersList } = require('../src/middleware/auth');
const {
  setMemoryApplication,
  getMemoryApplicationsList,
} = require('../src/routes/hr.routes');

const TEST_PORT = 5007;
let server;

function makeRequest({ method = 'GET', path, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const reqHeaders = {
      'X-Requested-With': 'XMLHttpRequest',
      ...headers,
    };

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

function generateToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
}

async function runTestSuite() {
  console.log('======================================================================');
  console.log('  TA\'MEER-E-REKHTA PHASE 6A.1: INTEGRATION & ONBOARDING SECURITY AUDIT');
  console.log('======================================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName, details = '') {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName}`);
      if (details) console.error(`       -> ${details}`);
      failed++;
    }
  }

  try {
    // -------------------------------------------------------------------------
    // Setup Test Personas
    // -------------------------------------------------------------------------
    const hash = await bcrypt.hash('SecurePass123!', 10);

    const superAdmin = {
      _id: 'usr_sa_audit_01',
      id: 'usr_sa_audit_01',
      name: 'Super Admin User',
      email: 'sa_audit@rekhta.org',
      password: hash,
      role: 'super_admin',
      department: null,
      status: 'active',
      tokenVersion: 0,
    };

    const hrLead = {
      _id: 'usr_hr_audit_01',
      id: 'usr_hr_audit_01',
      name: 'Hania Mehmood (HR Lead)',
      email: 'hr_audit@rekhta.org',
      password: hash,
      role: 'hr',
      department: 'HR',
      departmentCode: 'HR',
      isPrivilegedHR: true,
      status: 'active',
      tokenVersion: 0,
    };

    setMemoryUser(superAdmin);
    setMemoryUser(hrLead);

    const tokenHR = generateToken({
      id: hrLead.id,
      role: hrLead.role,
      name: hrLead.name,
      email: hrLead.email,
      department: hrLead.department,
      tokenVersion: 0,
    });

    const authHeaders = (token) => ({ Authorization: `Bearer ${token}` });

    // =========================================================================
    // SECTION 1: PUBLIC VOLUNTEER FORWARDING, IDEMPOTENCY & DEDUPLICATION
    // =========================================================================
    console.log('>>> [SECTION 1]: Public Volunteer Forwarding & Duplicate Idempotency');

    const testSubmissionId = `SUB_TEST_${Date.now()}_audit`;
    const volunteerPayload = {
      submissionId: testSubmissionId,
      fullName: 'Farhan Tariq',
      email: 'farhan.tariq@audit.org',
      phone: '+92 333 4445555',
      instagramId: 'farhan_rekhta',
      city: 'Karachi',
      age: '24',
      areaOfInterest: 'Content Creation',
      motivation: 'Aspiring video editor and Urdu documentary producer.',
    };

    // Test 1.1: Public volunteer submission succeeds with submissionId
    const resVol1 = await makeRequest({
      method: 'POST',
      path: '/api/volunteer',
      body: volunteerPayload,
    });
    assert(
      resVol1.status === 200 && resVol1.data.success && resVol1.data.submissionId === testSubmissionId,
      'Test 1.1: Public volunteer submission via /api/volunteer succeeds with submissionId (200 OK)'
    );

    const initialAppsCount = getMemoryApplicationsList().length;

    // Test 1.2: Duplicate submission with the same submissionId returns idempotent duplicate response
    const resVolDuplicate = await makeRequest({
      method: 'POST',
      path: '/api/volunteer',
      body: volunteerPayload,
    });
    assert(
      resVolDuplicate.status === 200 &&
        resVolDuplicate.data.success === true &&
        resVolDuplicate.data.duplicate === true,
      'Test 1.2: Duplicate submission with same submissionId is safely deduplicated (duplicate: true, 200 OK)'
    );

    // Test 1.3: Duplicate submission did NOT create duplicate Application records in memory or DB
    const finalAppsCount = getMemoryApplicationsList().length;
    assert(
      initialAppsCount === finalAppsCount,
      'Test 1.3: Deduplication verified: Candidate application count remained unchanged after duplicate forward'
    );

    // Test 1.4: Missing required fields rejected with 400 Bad Request
    const resVolInvalid = await makeRequest({
      method: 'POST',
      path: '/api/volunteer',
      body: { fullName: 'Incomplete User' }, // missing email, phone, areaOfInterest
    });
    assert(
      resVolInvalid.status === 400 && resVolInvalid.data.success === false,
      'Test 1.4: Malformed volunteer submission missing required fields rejected with 400 Bad Request'
    );

    // =========================================================================
    // SECTION 2: HR ONBOARDING DUPLICATION & ACTIVATION SECURITY
    // =========================================================================
    console.log('\n>>> [SECTION 2]: HR Onboarding Duplication & Activation Security');

    // Create a fresh candidate application for onboarding audit
    const candidateAppId = `app_audit_onboard_${Date.now()}`;
    const candidateApp = {
      _id: candidateAppId,
      id: candidateAppId,
      fullName: 'Maryam Asif',
      email: 'maryam.asif@rekhta.org',
      phoneNumber: '+92 345 6789012',
      department: 'Marketing',
      areaOfInterest: 'Marketing',
      source: 'portal_recruitment',
      status: 'shortlisted',
      createdAt: new Date(),
    };
    setMemoryApplication(candidateApp);

    // Test 2.1: HR successfully onboards candidate into member role
    const resOnboard = await makeRequest({
      method: 'POST',
      path: `/api/hr/applications/${candidateAppId}/onboard`,
      headers: authHeaders(tokenHR),
      body: {
        role: 'member',
        department: 'Marketing',
        designation: 'Marketing Associate',
      },
    });
    assert(
      resOnboard.status === 201 &&
        resOnboard.data.success &&
        resOnboard.data.user?.status === 'inactive' &&
        typeof resOnboard.data.activationToken === 'string',
      'Test 2.1: HR successfully onboards candidate into member role, initializing user as inactive (201 Created)'
    );

    const rawActivationToken = resOnboard.data.activationToken;
    const onboardedUserId = resOnboard.data.user?.id;

    // Test 2.2: Plaintext password is NEVER stored; temporary password is a bcrypt hash
    const createdUserRecord = getMemoryUsersList().find((u) => (u._id || u.id) === onboardedUserId);
    assert(
      Boolean(createdUserRecord?.password) &&
        createdUserRecord.password.startsWith('$2') &&
        !createdUserRecord.password.includes('Password'),
      'Test 2.2: Plaintext passwords are never persisted: Temporary password is verified bcrypt hash'
    );

    // Test 2.3: Duplicate onboarding attempt on the SAME application is rejected
    const resDuplicateOnboard = await makeRequest({
      method: 'POST',
      path: `/api/hr/applications/${candidateAppId}/onboard`,
      headers: authHeaders(tokenHR),
      body: {
        role: 'member',
        department: 'Marketing',
      },
    });
    assert(
      resDuplicateOnboard.status === 400 &&
        resDuplicateOnboard.data.error?.toLowerCase().includes('already been onboarded'),
      'Test 2.3: Duplicate onboarding attempt on already-onboarded application is rejected with 400 Bad Request'
    );

    // Test 2.4: Attempting to onboard another application with an existing email is rejected
    const secondAppId = `app_audit_second_${Date.now()}`;
    setMemoryApplication({
      _id: secondAppId,
      id: secondAppId,
      fullName: 'Maryam Asif Duplicate',
      email: 'maryam.asif@rekhta.org', // Existing user email!
      phoneNumber: '+92 345 6789012',
      department: 'Marketing',
      status: 'shortlisted',
      createdAt: new Date(),
    });
    const resEmailConflictOnboard = await makeRequest({
      method: 'POST',
      path: `/api/hr/applications/${secondAppId}/onboard`,
      headers: authHeaders(tokenHR),
      body: { role: 'member', department: 'Marketing' },
    });
    assert(
      resEmailConflictOnboard.status === 400 &&
        resEmailConflictOnboard.data.error?.includes('already exists'),
      'Test 2.4: Duplicate User account creation prevented when email already exists (400 Bad Request)'
    );

    // Test 2.5: Non-admin HR attempting to onboard candidate into super_admin role blocked
    const thirdAppId = `app_audit_third_${Date.now()}`;
    setMemoryApplication({
      _id: thirdAppId,
      id: thirdAppId,
      fullName: 'Escalation Target',
      email: 'escalation.target@rekhta.org',
      phoneNumber: '+92 345 9999999',
      department: 'Literature',
      status: 'shortlisted',
      createdAt: new Date(),
    });
    const resEscalateRole = await makeRequest({
      method: 'POST',
      path: `/api/hr/applications/${thirdAppId}/onboard`,
      headers: authHeaders(tokenHR),
      body: { role: 'super_admin', department: 'Literature' },
    });
    assert(
      resEscalateRole.status === 403,
      'Test 2.5: Role Escalation Defense: HR attempting to onboard candidate as super_admin is blocked with 403 Forbidden'
    );

    // Test 2.6: Activation token expiration is set to 7 days in the future
    const expectedExpiryMin = Date.now() + 6.9 * 24 * 60 * 60 * 1000;
    const expectedExpiryMax = Date.now() + 7.1 * 24 * 60 * 60 * 1000;
    const actualExpiry = new Date(createdUserRecord.activationExpires).getTime();
    assert(
      actualExpiry >= expectedExpiryMin && actualExpiry <= expectedExpiryMax,
      'Test 2.6: Activation token expiration is verified to be 7 days from creation'
    );

    // Test 2.7: Privilege Escalation Tampering during activation is strictly rejected
    const resTamperActivation = await makeRequest({
      method: 'POST',
      path: '/api/auth/activate',
      body: {
        token: rawActivationToken,
        password: 'ValidSecurePass123!',
        role: 'super_admin', // Malicious attempt to escalate role
        department: 'Literature',
      },
    });
    assert(
      resTamperActivation.status === 400 &&
        resTamperActivation.data.error?.includes('Privilege tampering detected'),
      'Test 2.7: Privilege Tampering Defense: Activation payload containing role/department is rejected with 400'
    );

    // Test 2.8: Candidate successfully activates account with valid token and password
    const resValidActivation = await makeRequest({
      method: 'POST',
      path: '/api/auth/activate',
      body: {
        token: rawActivationToken,
        password: 'MaryamValidPassword2026!',
      },
    });
    assert(
      resValidActivation.status === 200 && resValidActivation.data.success === true,
      'Test 2.8: Candidate successfully activates account using activation token (200 OK)'
    );

    // Test 2.9: User status transitioned to active and activation token invalidated
    const activatedUserRecord = getMemoryUsersList().find((u) => (u._id || u.id) === onboardedUserId);
    assert(
      activatedUserRecord.status === 'active' &&
        activatedUserRecord.activationToken === undefined &&
        activatedUserRecord.activationExpires === undefined,
      'Test 2.9: Single-use enforcement: activationToken and activationExpires are purged upon activation'
    );

    // Test 2.10: Replay / reuse attempt of the same token is strictly rejected
    const resReplayActivation = await makeRequest({
      method: 'POST',
      path: '/api/auth/activate',
      body: {
        token: rawActivationToken,
        password: 'AnotherPassword123!',
      },
    });
    assert(
      resReplayActivation.status === 400 &&
        resReplayActivation.data.error?.includes('Invalid or expired activation token'),
      'Test 2.10: Replay Attack Defense: Reusing an already-activated token is rejected with 400 Bad Request'
    );

    // Test 2.11: Expired activation token is strictly rejected
    const expiredRawToken = crypto.randomBytes(32).toString('hex');
    const expiredHashedToken = crypto.createHash('sha256').update(expiredRawToken).digest('hex');
    const expiredUser = {
      _id: 'usr_expired_audit_01',
      id: 'usr_expired_audit_01',
      name: 'Expired Token User',
      email: 'expired.user@rekhta.org',
      password: hash,
      role: 'member',
      status: 'inactive',
      activationToken: expiredHashedToken,
      activationExpires: new Date(Date.now() - 24 * 60 * 60 * 1000), // Expired yesterday!
      tokenVersion: 0,
    };
    setMemoryUser(expiredUser);

    const resExpiredActivation = await makeRequest({
      method: 'POST',
      path: '/api/auth/activate',
      body: {
        token: expiredRawToken,
        password: 'NewPassword123!',
      },
    });
    assert(
      resExpiredActivation.status === 400 &&
        resExpiredActivation.data.error?.includes('Invalid or expired activation token'),
      'Test 2.11: Expired Token Defense: Activating with an expired token (>7 days) is rejected with 400 Bad Request'
    );
  } catch (err) {
    console.error('[Audit Test Error]:', err);
    failed++;
  }

  console.log('\n======================================================================');
  console.log(`  PHASE 6A.1 TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('======================================================================\n');

  server.close(() => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

server = http.createServer(app);
server.listen(TEST_PORT, () => {
  console.log(`[Phase 6A.1 Test Runner] Server listening on port ${TEST_PORT}...`);
  runTestSuite();
});
