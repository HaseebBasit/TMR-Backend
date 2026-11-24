process.env.NODE_ENV = 'test';
const http = require('http');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');

const JWT_SECRET = process.env.JWT_SECRET || 'rekhta_access_secret_2026_super_secure';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'rekhta_refresh_secret_2026_super_secure';

const TEST_PORT = 5003;
let server;

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

async function runTestSuite() {
  console.log('================================================================');
  console.log('  TA\'MEER-E-REKHTA PHASE 4: AUTH & RBAC INTEGRATION TEST SUITE  ');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName, details = '') {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName} - ${details}`);
      failed++;
    }
  }

  // Pre-seed test users with valid 24-character ObjectIds
  const defaultPassword = 'TestPassword123!';
  const hashedPassword = await bcrypt.hash(defaultPassword, 10);

  const testUsers = {
    superAdmin: {
      _id: '507f191e810c19729de860ea',
      id: '507f191e810c19729de860ea',
      name: 'Super Admin Officer',
      email: 'admin.test@rekhta.org',
      password: hashedPassword,
      role: 'super_admin',
      status: 'active',
      tokenVersion: 0,
    },
    deptLiterature: {
      _id: '507f191e810c19729de860eb',
      id: '507f191e810c19729de860eb',
      name: 'Noor-ul-Huda (Literature Lead)',
      email: 'lit.lead@rekhta.org',
      password: hashedPassword,
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      tokenVersion: 0,
    },
    deptMedia: {
      _id: '507f191e810c19729de860ec',
      id: '507f191e810c19729de860ec',
      name: 'Aisha Tariq (Media Lead)',
      email: 'media.lead@rekhta.org',
      password: hashedPassword,
      role: 'dept_media',
      department: 'Media',
      departmentCode: 'MED',
      status: 'active',
      tokenVersion: 0,
    },
    hrUserStandard: {
      _id: '507f191e810c19729de860ed',
      id: '507f191e810c19729de860ed',
      name: 'HR Associate',
      email: 'hr.standard@rekhta.org',
      password: hashedPassword,
      role: 'hr',
      department: 'HR',
      status: 'active',
      isPrivilegedHR: false,
      tokenVersion: 0,
    },
    hrUserPrivileged: {
      _id: '507f191e810c19729de860ee',
      id: '507f191e810c19729de860ee',
      name: 'Hania Mehmood (Head of HR)',
      email: 'hr.lead@rekhta.org',
      password: hashedPassword,
      role: 'hr',
      department: 'HR',
      status: 'active',
      isPrivilegedHR: true,
      tokenVersion: 0,
    },
    financeUser: {
      _id: '507f191e810c19729de860ef',
      id: '507f191e810c19729de860ef',
      name: 'Ahmad Maqsood (Finance Lead)',
      email: 'finance.lead@rekhta.org',
      password: hashedPassword,
      role: 'finance',
      department: 'Finance',
      status: 'active',
      tokenVersion: 0,
    },
    memberAlice: {
      _id: '507f191e810c19729de860f0',
      id: '507f191e810c19729de860f0',
      name: 'Alice Member',
      email: 'alice@rekhta.org',
      password: hashedPassword,
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      tokenVersion: 0,
    },
    memberBob: {
      _id: '507f191e810c19729de860f1',
      id: '507f191e810c19729de860f1',
      name: 'Bob Member',
      email: 'bob@rekhta.org',
      password: hashedPassword,
      role: 'member',
      department: 'Media',
      departmentCode: 'MED',
      status: 'active',
      tokenVersion: 0,
    },
    suspendedUser: {
      _id: '507f191e810c19729de860f2',
      id: '507f191e810c19729de860f2',
      name: 'Suspended Account',
      email: 'suspended@rekhta.org',
      password: hashedPassword,
      role: 'member',
      status: 'suspended',
      tokenVersion: 0,
    },
  };

  for (const u of Object.values(testUsers)) {
    setMemoryUser(u);
  }

  // Helper to issue tokens directly for tests
  function getToken(user, options = {}) {
    return jwt.sign(
      {
        id: user.id || user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        department: user.department,
        departmentCode: user.departmentCode,
        status: user.status,
        isPrivilegedHR: Boolean(user.isPrivilegedHR),
        tokenVersion: user.tokenVersion || 0,
        ...options,
      },
      JWT_SECRET,
      { expiresIn: options.expiresIn || '1h' }
    );
  }

  try {
    // TEST 1: Valid and invalid login
    const loginValid = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      body: { email: 'admin.test@rekhta.org', password: 'TestPassword123!' },
    });
    assert(
      loginValid.status === 200 && loginValid.data.success && loginValid.data.user.role === 'super_admin',
      'Test 1.1: Valid login returns 200 and user role'
    );

    const loginInvalid = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      body: { email: 'admin.test@rekhta.org', password: 'WrongPassword' },
    });
    assert(loginInvalid.status === 401 && !loginInvalid.data.success, 'Test 1.2: Invalid password rejected with 401');

    // TEST 2: Token verification & expiration
    const expiredToken = getToken(testUsers.superAdmin, { expiresIn: '-10s' });
    const expiredRes = await makeRequest({
      path: '/api/auth/me',
      headers: { Authorization: `Bearer ${expiredToken}` },
    });
    assert(
      expiredRes.status === 401 && expiredRes.data.code === 'TOKEN_EXPIRED',
      'Test 2: Expired access token rejected with 401 TOKEN_EXPIRED'
    );

    // TEST 3: Refresh-token rotation
    const superAdminRefreshToken = jwt.sign(
      { id: testUsers.superAdmin.id, email: testUsers.superAdmin.email, tokenVersion: 0 },
      REFRESH_SECRET,
      { expiresIn: '7d' }
    );
    testUsers.superAdmin.refreshToken = superAdminRefreshToken;
    setMemoryUser(testUsers.superAdmin);

    const refreshRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/refresh',
      headers: { 'X-Request-Token': 'true' },
      body: { refreshToken: superAdminRefreshToken },
    });
    assert(
      refreshRes.status === 200 && (Boolean(refreshRes.data.token) || Boolean(refreshRes.headers['set-cookie'])),
      'Test 3: Refresh-token rotation successfully returns new access token'
    );

    // TEST 4: Session revocation
    const revokeRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/revoke-sessions',
      headers: { Authorization: `Bearer ${getToken(testUsers.superAdmin)}` },
      body: { userId: testUsers.superAdmin.id },
    });
    assert(revokeRes.status === 200 && revokeRes.data.success, 'Test 4.1: Sessions revoked endpoint succeeds');

    // Old token with tokenVersion 0 should now be rejected because tokenVersion is 1
    const oldVersionToken = getToken(testUsers.superAdmin, { tokenVersion: 0 });
    const revokedCheck = await makeRequest({
      path: '/api/auth/me',
      headers: { Authorization: `Bearer ${oldVersionToken}` },
    });
    assert(revokedCheck.status === 401, 'Test 4.2: Revoked session token rejected with 401');

    // TEST 5: Unauthorized unauthenticated access
    const noAuth = await makeRequest({ path: '/api/super-admin/audit-logs' });
    assert(noAuth.status === 401, 'Test 5: Unauthenticated access to protected route returns 401');

    // TEST 6: Department isolation
    // dept_literature attempts to access Literature (allowed)
    const litValid = await makeRequest({
      path: '/api/department/Literature/overview',
      headers: { Authorization: `Bearer ${getToken(testUsers.deptLiterature)}` },
    });
    assert(litValid.status === 200, 'Test 6.1: Department Head accesses own department (200 OK)');

    // dept_literature attempts to access Media (MUST BE BLOCKED)
    const litCrossDept = await makeRequest({
      path: '/api/department/Media/overview',
      headers: { Authorization: `Bearer ${getToken(testUsers.deptLiterature)}` },
    });
    assert(
      litCrossDept.status === 403,
      'Test 6.2: Department Head cross-access attempt blocked with 403 Forbidden'
    );

    // TEST 7: HR permission restrictions
    const hrAccessAuditLogs = await makeRequest({
      path: '/api/super-admin/audit-logs',
      headers: { Authorization: `Bearer ${getToken(testUsers.hrUserPrivileged)}` },
    });
    assert(hrAccessAuditLogs.status === 403, 'Test 7.1: HR blocked from Super Admin Audit Logs (403)');

    const hrRecruitment = await makeRequest({
      path: '/api/recruitment/applications',
      headers: { Authorization: `Bearer ${getToken(testUsers.hrUserPrivileged)}` },
    });
    assert(hrRecruitment.status === 200, 'Test 7.2: HR authorized to access Recruitment Applications (200)');

    // TEST 8: Finance permission restrictions
    const finIncome = await makeRequest({
      path: '/api/finance/income',
      headers: { Authorization: `Bearer ${getToken(testUsers.financeUser)}` },
    });
    assert(finIncome.status === 200, 'Test 8.1: Finance authorized to access Income Ledger (200)');

    const finApplications = await makeRequest({
      path: '/api/recruitment/applications',
      headers: { Authorization: `Bearer ${getToken(testUsers.financeUser)}` },
    });
    assert(finApplications.status === 403, 'Test 8.2: Finance blocked from HR Applications (403)');

    // TEST 9: Member ownership restrictions
    // Alice requests her own tasks (allowed)
    const aliceOwnTasks = await makeRequest({
      path: `/api/members/${testUsers.memberAlice.id}/tasks`,
      headers: { Authorization: `Bearer ${getToken(testUsers.memberAlice)}` },
    });
    assert(aliceOwnTasks.status === 200, 'Test 9.1: Member accesses own personal tasks (200 OK)');

    // Alice attempts to access Bob's tasks by manipulating userId (MUST BE BLOCKED)
    const aliceTamperBob = await makeRequest({
      path: `/api/members/${testUsers.memberBob.id}/tasks`,
      headers: { Authorization: `Bearer ${getToken(testUsers.memberAlice)}` },
    });
    assert(
      aliceTamperBob.status === 403,
      'Test 9.2: Member attempting to access another member\'s tasks blocked (403)'
    );

    // TEST 10: Confidential grading security
    // 10.1: Department Head can submit assessment (Blind write)
    const assessmentSubmit = await makeRequest({
      method: 'POST',
      path: '/api/assessments',
      headers: { Authorization: `Bearer ${getToken(testUsers.deptLiterature)}` },
      body: {
        memberId: testUsers.memberAlice.id,
        memberName: testUsers.memberAlice.name,
        department: 'Literature',
        period: '2026-Q4',
        criteriaScores: { taskExecution: 9, deliverableQuality: 8, punctuality: 10, teamCollaboration: 9 },
        qualitativeFeedback: 'Outstanding dedication to Urdu editorial reviews.',
      },
    });
    const blindResponseValid =
      assessmentSubmit.status === 201 &&
      assessmentSubmit.data.success &&
      assessmentSubmit.data.totalScore === undefined; // Score must NOT be returned!
    assert(
      blindResponseValid,
      'Test 10.1: Department Head submits assessment; response confirms receipt WITHOUT leaking score'
    );

    // 10.2: Department Head attempts to query GET /api/assessments (MUST BE BLOCKED)
    const deptHeadQueryGrading = await makeRequest({
      path: '/api/assessments',
      headers: { Authorization: `Bearer ${getToken(testUsers.deptLiterature)}` },
    });
    assert(
      deptHeadQueryGrading.status === 403,
      'Test 10.2: Department Head blocked from reading grading reports (403 Forbidden)'
    );

    // 10.3: HR and Member attempts to query GET /api/assessments (MUST BE BLOCKED)
    const hrQueryGrading = await makeRequest({
      path: '/api/assessments',
      headers: { Authorization: `Bearer ${getToken(testUsers.hrUserPrivileged)}` },
    });
    const memberQueryGrading = await makeRequest({
      path: '/api/assessments',
      headers: { Authorization: `Bearer ${getToken(testUsers.memberAlice)}` },
    });
    assert(
      hrQueryGrading.status === 403 && memberQueryGrading.status === 403,
      'Test 10.3: HR and Member blocked from reading grading reports (403 Forbidden)'
    );

    // 10.4: Super Admin queries GET /api/assessments (ALLOWED)
    const adminQueryGrading = await makeRequest({
      path: '/api/assessments',
      headers: { Authorization: `Bearer ${getToken(testUsers.superAdmin, { tokenVersion: testUsers.superAdmin.tokenVersion })}` },
    });
    assert(
      adminQueryGrading.status === 200 && adminQueryGrading.data.success,
      'Test 10.4: Super Admin authorized to view confidential grading reports (200 OK)'
    );

    // TEST 11: Privilege escalation attempt
    const memberAttemptEscalate = await makeRequest({
      method: 'PATCH',
      path: `/api/auth/users/${testUsers.memberAlice.id}/status`,
      headers: { Authorization: `Bearer ${getToken(testUsers.memberAlice)}` },
      body: { status: 'suspended' },
    });
    assert(
      memberAttemptEscalate.status === 403,
      'Test 11: Member privilege escalation to Super Admin endpoint rejected with 403'
    );

    // TEST 12: Deactivated account access
    const suspendedReq = await makeRequest({
      path: '/api/auth/me',
      headers: { Authorization: `Bearer ${getToken(testUsers.suspendedUser)}` },
    });
    assert(
      suspendedReq.status === 403 && suspendedReq.data.accountStatus === 'suspended',
      'Test 12: Suspended account access rejected by protect middleware with 403'
    );

    // TEST 13: Password reset flow
    const forgotRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/forgot-password',
      body: { email: 'alice@rekhta.org' },
    });
    const devToken = forgotRes.data?.devResetToken;
    assert(
      forgotRes.status === 200 && Boolean(devToken),
      'Test 13.1: Forgot password generates secure reset token'
    );

    const resetRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/reset-password',
      body: { token: devToken, newPassword: 'NewSecurePassword2026!' },
    });
    assert(resetRes.status === 200 && resetRes.data.success, 'Test 13.2: Reset password succeeds with valid token');

    // TEST 14: Account activation flow
    const activationRawToken = 'raw_act_token_123';
    const activationHashedToken = require('crypto').createHash('sha256').update(activationRawToken).digest('hex');
    const inactiveUser = {
      _id: '507f191e810c19729de860f3',
      id: '507f191e810c19729de860f3',
      name: 'New Onboarded Member',
      email: 'newbie@rekhta.org',
      password: 'dummy',
      role: 'member',
      status: 'inactive',
      activationToken: activationHashedToken,
      activationExpires: Date.now() + 3600000,
    };
    setMemoryUser(inactiveUser);

    const activateRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/activate',
      body: { token: activationRawToken, password: 'ActivatedPassword123!' },
    });
    assert(
      activateRes.status === 200 && activateRes.data.success,
      'Test 14: Account activation succeeds with token and activates user'
    );
  } catch (err) {
    console.error('[Test Execution Error]:', err);
    failed++;
  }

  console.log('\n================================================================');
  console.log(`  TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('================================================================\n');

  server.close(() => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

// Start temporary test server
server = http.createServer(app);
server.listen(TEST_PORT, () => {
  console.log(`[Test Runner] Server listening on port ${TEST_PORT}...`);
  runTestSuite();
});
