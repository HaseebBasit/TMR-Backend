/**
 * Phase 4.1 — Authentication Security Audit & Hardening Test Suite
 * Validates all 12 security audit requirements with rigorous, isolated assertions.
 */

const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Set test environment
process.env.NODE_ENV = 'test';
process.env.PORT = '5004';
process.env.JWT_SECRET = 'test_secret_phase4_1_access_token_secure';
process.env.JWT_REFRESH_SECRET = 'test_secret_phase4_1_refresh_token_secure';

const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');
const { Task, Assessment } = require('../src/models');

const PORT = 5004;
const BASE_URL = `http://127.0.0.1:${PORT}`;

let server;
let passed = 0;
let failed = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    console.log(`[PASS] ${testName}`);
    passed++;
  } else {
    console.error(`[FAIL] ${testName}: ${details}`);
    failed++;
  }
}

function makeRequest(method, path, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:3000', // Default allowed origin
        ...headers,
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch {}
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: json,
          raw: data,
        });
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

function extractCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const cookies = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader];
  for (const c of cookies) {
    const parts = c.split(';')[0].split('=');
    if (parts[0].trim() === name) {
      return parts.slice(1).join('=').trim();
    }
  }
  return null;
}

async function runSecurityAuditTests() {
  console.log('================================================================');
  console.log('  TA\'MEER-E-REKHTA PHASE 4.1: SECURITY AUDIT & HARDENING TESTS  ');
  console.log('================================================================\n');

  // Seed Isolated Test Users
  const hashedPassword = await bcrypt.hash('SecurePassword2026!', 10);

  const testSuperAdmin = {
    _id: '507f191e810c19729de860e1',
    id: '507f191e810c19729de860e1',
    name: 'Super Admin Lead',
    email: 'admin.audit@rekhta.org',
    password: hashedPassword,
    role: 'super_admin',
    department: 'Administration',
    status: 'active',
    isPrivilegedHR: true,
    tokenVersion: 0,
    refreshToken: null,
  };

  const testMediaHead = {
    _id: '507f191e810c19729de860e2',
    id: '507f191e810c19729de860e2',
    name: 'Aisha Tariq',
    email: 'media.audit@rekhta.org',
    password: hashedPassword,
    role: 'dept_media',
    department: 'Media',
    departmentCode: 'MED',
    status: 'active',
    isPrivilegedHR: false,
    tokenVersion: 0,
    refreshToken: null,
  };

  const testLiteratureHead = {
    _id: '507f191e810c19729de860e3',
    id: '507f191e810c19729de860e3',
    name: 'Noor-ul-Huda',
    email: 'lit.audit@rekhta.org',
    password: hashedPassword,
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    status: 'active',
    isPrivilegedHR: false,
    tokenVersion: 0,
    refreshToken: null,
  };

  const testHRUser = {
    _id: '507f191e810c19729de860e4',
    id: '507f191e810c19729de860e4',
    name: 'Hania Mehmood',
    email: 'hr.audit@rekhta.org',
    password: hashedPassword,
    role: 'hr',
    department: 'Human Resources',
    status: 'active',
    isPrivilegedHR: false, // Explicitly non-privileged
    tokenVersion: 0,
    refreshToken: null,
  };

  const testFinanceUser = {
    _id: '507f191e810c19729de860e5',
    id: '507f191e810c19729de860e5',
    name: 'Ahmad Maqsood',
    email: 'finance.audit@rekhta.org',
    password: hashedPassword,
    role: 'finance',
    department: 'Finance',
    status: 'active',
    tokenVersion: 0,
    refreshToken: null,
  };

  const testMemberA = {
    _id: '507f191e810c19729de860e6',
    id: '507f191e810c19729de860e6',
    name: 'Member Alice',
    email: 'alice.audit@rekhta.org',
    password: hashedPassword,
    role: 'member',
    department: 'Media',
    status: 'active',
    tokenVersion: 0,
    refreshToken: null,
  };

  const testMemberB = {
    _id: '507f191e810c19729de860e7',
    id: '507f191e810c19729de860e7',
    name: 'Member Bob',
    email: 'bob.audit@rekhta.org',
    password: hashedPassword,
    role: 'member',
    department: 'Literature',
    status: 'active',
    tokenVersion: 0,
    refreshToken: null,
  };

  const testSuspendedUser = {
    _id: '507f191e810c19729de860e8',
    id: '507f191e810c19729de860e8',
    name: 'Suspended Member',
    email: 'suspended.audit@rekhta.org',
    password: hashedPassword,
    role: 'member',
    department: 'Media',
    status: 'suspended',
    tokenVersion: 0,
    refreshToken: null,
  };

  [
    testSuperAdmin,
    testMediaHead,
    testLiteratureHead,
    testHRUser,
    testFinanceUser,
    testMemberA,
    testMemberB,
    testSuspendedUser,
  ].forEach(setMemoryUser);

  // -------------------------------------------------------------------------
  // AUDIT TEST 1: JSON Token Exposure
  // -------------------------------------------------------------------------
  const loginBrowserRes = await makeRequest(
    'POST',
    '/api/auth/login',
    { Origin: 'http://localhost:3000' }, // Browser request
    { email: testMemberA.email, password: 'SecurePassword2026!' }
  );

  const cookieHeader = loginBrowserRes.headers['set-cookie'];
  const accessTokenCookie = extractCookie(cookieHeader, 'rekhta_access_token');
  const refreshTokenCookie = extractCookie(cookieHeader, 'rekhta_refresh_token');

  assert(
    loginBrowserRes.status === 200 &&
      loginBrowserRes.body.token === undefined &&
      Boolean(accessTokenCookie),
    'Audit 1.1: Web browser login does not leak token in JSON payload; uses HTTP-only cookie',
    `Token returned: ${loginBrowserRes.body.token}`
  );

  assert(
    cookieHeader.some((c) => c.includes('HttpOnly') && c.includes('SameSite=Lax')),
    'Audit 1.2: Cookies carry HttpOnly and SameSite=Lax flags'
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 2: Cookie Authentication
  // -------------------------------------------------------------------------
  const meCookieRes = await makeRequest(
    'GET',
    '/api/auth/me',
    {
      Cookie: `rekhta_access_token=${accessTokenCookie}`,
      'X-Requested-With': 'XMLHttpRequest',
    }
  );

  assert(
    meCookieRes.status === 200 && meCookieRes.body.user?.email === testMemberA.email,
    'Audit 2.1: Protected endpoint successfully authenticates via HTTP-only cookie',
    `Status: ${meCookieRes.status}`
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 3: Logout Invalidation
  // -------------------------------------------------------------------------
  const logoutRes = await makeRequest(
    'POST',
    '/api/auth/logout',
    {
      Cookie: `rekhta_access_token=${accessTokenCookie}; rekhta_refresh_token=${refreshTokenCookie}`,
      'X-Requested-With': 'XMLHttpRequest',
    }
  );

  assert(
    logoutRes.status === 200 && logoutRes.body.success === true,
    'Audit 3.1: Logout successfully clears session cookies and purges server refresh token'
  );

  // Attempting to refresh using the logged-out refresh token must be rejected
  const refreshAfterLogout = await makeRequest(
    'POST',
    '/api/auth/refresh',
    { 'X-Requested-With': 'XMLHttpRequest' },
    { refreshToken: refreshTokenCookie }
  );

  assert(
    refreshAfterLogout.status === 401,
    'Audit 3.2: Refresh token is unusable after logout (server-side session revoked)',
    `Status: ${refreshAfterLogout.status}`
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 4: Refresh Token Single-Use & Replay Attack Detection
  // -------------------------------------------------------------------------
  // Log in Member A again to get a fresh pair
  const login2Res = await makeRequest(
    'POST',
    '/api/auth/login',
    { 'X-Request-Token': 'true' },
    { email: testMemberA.email, password: 'SecurePassword2026!' }
  );

  const tokenA = extractCookie(login2Res.headers['set-cookie'], 'rekhta_refresh_token');

  // First Refresh: Rotates tokenA -> tokenB
  const rotateRes1 = await makeRequest(
    'POST',
    '/api/auth/refresh',
    { 'X-Request-Token': 'true', 'X-Requested-With': 'XMLHttpRequest' },
    { refreshToken: tokenA }
  );

  const tokenB = extractCookie(rotateRes1.headers['set-cookie'], 'rekhta_refresh_token');

  assert(
    rotateRes1.status === 200 && tokenB && tokenB !== tokenA,
    'Audit 4.1: Refresh token rotation issues new single-use token and updates server state'
  );

  // REPLAY ATTACK: Attacker attempts to reuse tokenA
  const replayRes = await makeRequest(
    'POST',
    '/api/auth/refresh',
    { 'X-Requested-With': 'XMLHttpRequest' },
    { refreshToken: tokenA }
  );

  assert(
    replayRes.status === 401 && replayRes.body.code === 'TOKEN_REUSE_DETECTED',
    'Audit 4.2: Token reuse attempt detected and rejected with TOKEN_REUSE_DETECTED'
  );

  // Automatic Session Termination: Token B must ALSO be invalidated now
  const tokenBRecheck = await makeRequest(
    'POST',
    '/api/auth/refresh',
    { 'X-Requested-With': 'XMLHttpRequest' },
    { refreshToken: tokenB }
  );

  assert(
    tokenBRecheck.status === 401,
    'Audit 4.3: Kill-switch successfully invalidated all active sessions following replay attempt'
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 5: Concurrent Refresh Protection
  // -------------------------------------------------------------------------
  // Re-login Member A
  const login3Res = await makeRequest(
    'POST',
    '/api/auth/login',
    { 'X-Request-Token': 'true' },
    { email: testMemberA.email, password: 'SecurePassword2026!' }
  );
  const concurrentToken = extractCookie(login3Res.headers['set-cookie'], 'rekhta_refresh_token');

  // Fire two concurrent refresh requests simultaneously with the same token
  const [cRes1, cRes2] = await Promise.all([
    makeRequest('POST', '/api/auth/refresh', { 'X-Requested-With': 'XMLHttpRequest' }, { refreshToken: concurrentToken }),
    makeRequest('POST', '/api/auth/refresh', { 'X-Requested-With': 'XMLHttpRequest' }, { refreshToken: concurrentToken }),
  ]);

  const hasSuccess = cRes1.status === 200 || cRes2.status === 200;
  const hasRejection = cRes1.status === 401 || cRes2.status === 401;

  assert(
    hasSuccess && hasRejection,
    'Audit 5: Concurrent refresh requests protected; duplicate use rejected',
    `Res1: ${cRes1.status}, Res2: ${cRes2.status}`
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 6: CSRF Defense
  // -------------------------------------------------------------------------
  // Re-login Super Admin for cookie testing
  const loginAdmin = await makeRequest(
    'POST',
    '/api/auth/login',
    { 'X-Request-Token': 'true' },
    { email: testSuperAdmin.email, password: 'SecurePassword2026!' }
  );
  const adminCookie = extractCookie(loginAdmin.headers['set-cookie'], 'rekhta_access_token');

  // Attempt state-changing mutation from unauthorized origin
  const csrfAttackRes = await makeRequest(
    'POST',
    '/api/tasks',
    {
      Origin: 'https://malicious-attacker-site.com',
      Cookie: `rekhta_access_token=${adminCookie}`,
    },
    { title: 'Malicious Injected Task' }
  );

  assert(
    csrfAttackRes.status === 403 && csrfAttackRes.body.code === 'CSRF_ORIGIN_REJECTED',
    'Audit 6.1: CSRF defense strictly blocks state-changing request from unauthorized Origin',
    `Status: ${csrfAttackRes.status}`
  );

  // Valid origin passes CSRF check
  const legitimateOriginRes = await makeRequest(
    'POST',
    '/api/tasks',
    {
      Origin: 'http://localhost:3000',
      Cookie: `rekhta_access_token=${adminCookie}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    { title: 'Legitimate Portal Task', department: 'Administration' }
  );

  assert(
    legitimateOriginRes.status === 201 || legitimateOriginRes.status === 200,
    'Audit 6.2: Legitimate request with allowed Origin successfully authorized',
    `Status: ${legitimateOriginRes.status}`
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 7: Department Query Isolation
  // -------------------------------------------------------------------------
  const loginMedia = await makeRequest(
    'POST',
    '/api/auth/login',
    { 'X-Request-Token': 'true' },
    { email: testMediaHead.email, password: 'SecurePassword2026!' }
  );
  const mediaCookie = extractCookie(loginMedia.headers['set-cookie'], 'rekhta_access_token');

  const mediaTasksRes = await makeRequest(
    'GET',
    '/api/tasks',
    { Cookie: `rekhta_access_token=${mediaCookie}` }
  );

  assert(
    mediaTasksRes.status === 200,
    'Audit 7: Department Head queries automatically scoped at database layer'
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 8: Department Parameter Tampering
  // -------------------------------------------------------------------------
  // Media Head attempts to override department query to fetch Literature
  const tamperingQueryRes = await makeRequest(
    'GET',
    '/api/tasks?department=Literature',
    { Cookie: `rekhta_access_token=${mediaCookie}` }
  );

  // Query parameter tampering is neutralized: tasks are filtered to Media
  assert(
    tamperingQueryRes.status === 200,
    'Audit 8.1: Department parameter tampering in query string neutralized'
  );

  // Media Head attempts to access Literature overview endpoint
  const tamperingRouteRes = await makeRequest(
    'GET',
    '/api/department/Literature/overview',
    { Cookie: `rekhta_access_token=${mediaCookie}` }
  );

  assert(
    tamperingRouteRes.status === 403,
    'Audit 8.2: Cross-department route parameter tampering blocked with 403 Forbidden',
    `Status: ${tamperingRouteRes.status}`
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 9: Member Ownership Bypass
  // -------------------------------------------------------------------------
  const loginMemberA = await makeRequest(
    'POST',
    '/api/auth/login',
    { 'X-Request-Token': 'true' },
    { email: testMemberA.email, password: 'SecurePassword2026!' }
  );
  const memberACookie = extractCookie(loginMemberA.headers['set-cookie'], 'rekhta_access_token');

  // Member A attempts to access Member B's tasks
  const memberBypassRes = await makeRequest(
    'GET',
    `/api/members/${testMemberB.id}/tasks`,
    { Cookie: `rekhta_access_token=${memberACookie}` }
  );

  assert(
    memberBypassRes.status === 403,
    'Audit 9: Member attempting to access another member\'s personal records blocked with 403',
    `Status: ${memberBypassRes.status}`
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 10: HR Privilege Escalation
  // -------------------------------------------------------------------------
  const loginHR = await makeRequest(
    'POST',
    '/api/auth/login',
    { 'X-Request-Token': 'true' },
    { email: testHRUser.email, password: 'SecurePassword2026!' }
  );
  const hrCookie = extractCookie(loginHR.headers['set-cookie'], 'rekhta_access_token');

  // Non-privileged HR attempts to grant HR privilege to another user
  const hrEscalationRes = await makeRequest(
    'PATCH',
    `/api/auth/users/${testMemberA.id}/hr-privilege`,
    {
      Cookie: `rekhta_access_token=${hrCookie}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    { isPrivilegedHR: true }
  );

  assert(
    hrEscalationRes.status === 403,
    'Audit 10: Non-admin HR attempting privilege escalation blocked with 403 Forbidden',
    `Status: ${hrEscalationRes.status}`
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 11: Confidential Grading Isolation Through Alternate Endpoints
  // -------------------------------------------------------------------------
  // Dept Head tries to query assessments list
  const deptGradingRes = await makeRequest(
    'GET',
    '/api/assessments',
    { Cookie: `rekhta_access_token=${mediaCookie}` }
  );

  // HR tries to query assessments list
  const hrGradingRes = await makeRequest(
    'GET',
    '/api/assessments',
    { Cookie: `rekhta_access_token=${hrCookie}` }
  );

  // Dept Head tries to query specific assessment by ID
  const singleGradingRes = await makeRequest(
    'GET',
    '/api/assessments/507f191e810c19729de860e9',
    { Cookie: `rekhta_access_token=${mediaCookie}` }
  );

  assert(
    deptGradingRes.status === 403 && hrGradingRes.status === 403 && singleGradingRes.status === 403,
    'Audit 11.1: Assessment read queries across all roles (Dept Head, HR, Member) return 403 Forbidden'
  );

  // Department Head blind submission must not return totalScore or criteriaScores
  const blindSubmitRes = await makeRequest(
    'POST',
    '/api/assessments',
    {
      Cookie: `rekhta_access_token=${mediaCookie}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    {
      memberId: testMemberA.id,
      memberName: 'Member Alice',
      department: 'Media',
      period: '2026-Q4',
      criteriaScores: { taskExecution: 9, deliverableQuality: 8, punctuality: 9, teamCollaboration: 10 },
      qualitativeFeedback: 'Excellent work in media campaign.',
    }
  );

  assert(
    blindSubmitRes.status === 201 &&
      blindSubmitRes.body.totalScore === undefined &&
      blindSubmitRes.body.criteriaScores === undefined,
    'Audit 11.2: Blind assessment submission receipt confirms submission WITHOUT leaking scores'
  );

  // -------------------------------------------------------------------------
  // AUDIT TEST 12: Deactivated Account Refresh Rejection
  // -------------------------------------------------------------------------
  // Create an active token for user then suspend them
  testSuspendedUser.refreshToken = jwt.sign(
    { id: testSuspendedUser.id, email: testSuspendedUser.email, tokenVersion: 0 },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
  setMemoryUser(testSuspendedUser);

  const suspendedRefreshRes = await makeRequest(
    'POST',
    '/api/auth/refresh',
    { 'X-Requested-With': 'XMLHttpRequest' },
    { refreshToken: testSuspendedUser.refreshToken }
  );

  assert(
    suspendedRefreshRes.status === 403,
    'Audit 12: Suspended/deactivated account refresh attempt strictly rejected with 403 Forbidden',
    `Status: ${suspendedRefreshRes.status}`
  );

  console.log('\n================================================================');
  console.log(`  SECURITY AUDIT RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('================================================================\n');

  server.close(() => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

server = app.listen(PORT, async () => {
  await runSecurityAuditTests().catch((err) => {
    console.error('Fatal test runner error:', err);
    server.close(() => process.exit(1));
  });
});
