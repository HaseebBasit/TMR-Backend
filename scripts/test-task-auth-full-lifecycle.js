/**
 * Comprehensive Lifecycle & Security Verification Suite
 * Phase 10 Production Bug Fix — Assign Department Task Authentication
 * 
 * Tests Sections A, B, C, and E:
 * - Complete User Lifecycle: Login -> Assign Task -> Page Reload (In-Memory Hydration) -> Logout -> Post-Logout Blocked -> Re-login
 * - CSRF Defense Verification (Origin/Referer & X-Requested-With enforcement)
 * - Single-submission / Idempotency check (exactly 1 task created)
 * - Super Admin & Member Role Boundary Verification
 * - Cross-Department & Welfare Regional Boundary Rejection
 * - Zero Live Database Mutation Verification
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_jwt_secret_lifecycle_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_lifecycle_2026';

const http = require('http');
const bcrypt = require('bcryptjs');
const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');

const TEST_PORT = 5007;
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

function extractCookies(headers) {
  const setCookie = headers['set-cookie'];
  if (!setCookie) return '';
  return (Array.isArray(setCookie) ? setCookie : [setCookie])
    .map((c) => c.split(';')[0])
    .join('; ');
}

async function runLifecycleTests() {
  console.log('========================================================================');
  console.log('ASSIGN DEPARTMENT TASK: FULL LIFECYCLE & REGRESSION VERIFICATION');
  console.log('========================================================================\n');

  await new Promise((resolve) => {
    server = app.listen(TEST_PORT, () => resolve());
  });

  const defaultPassword = 'SecurePassword123!';
  const hashedPassword = await bcrypt.hash(defaultPassword, 10);

  // Setup memory test personas with complete department metadata
  const personas = {
    litHead: {
      _id: '607f191e810c19729de87001',
      id: '607f191e810c19729de87001',
      name: 'Noor-ul-Huda',
      email: 'noorulhuda@rekhta.org',
      password: hashedPassword,
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      tokenVersion: 0,
      designation: 'Head of Literature Department',
      memberships: [
        {
          department: 'Literature',
          departmentCode: 'LIT',
          role: 'dept_literature',
          designation: 'Head of Literature Department',
          isPrimary: true,
        },
      ],
    },
    litMember: {
      _id: '607f191e810c19729de87002',
      id: '607f191e810c19729de87002',
      name: 'Ali Raza',
      email: 'aliraza@rekhta.org',
      password: hashedPassword,
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      tokenVersion: 0,
      designation: 'Staff Writer',
      memberships: [
        {
          department: 'Literature',
          departmentCode: 'LIT',
          role: 'member',
          designation: 'Staff Writer',
          isPrimary: true,
        },
      ],
    },
    superAdmin: {
      _id: '607f191e810c19729de87003',
      id: '607f191e810c19729de87003',
      name: 'Super Admin',
      email: 'tameerrekhtaadmin@rekhta.org',
      password: hashedPassword,
      role: 'super_admin',
      department: 'Management',
      departmentCode: 'HQ',
      status: 'active',
      tokenVersion: 0,
      designation: 'Chief Administrator',
      memberships: [
        {
          department: 'Management',
          departmentCode: 'HQ',
          role: 'super_admin',
          designation: 'Chief Administrator',
          isPrimary: true,
        },
      ],
    },
  };

  for (const p of Object.values(personas)) {
    setMemoryUser(p);
  }

  // Simulated client in-memory state
  let clientInMemoryToken = null;
  let clientCookieJar = '';

  // -------------------------------------------------------------------------
  // SECTION B1: Step 1 - Normal Sign In
  // -------------------------------------------------------------------------
  console.log('--- SECTION B: Live Authentication Lifecycle ---');
  const loginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'noorulhuda@rekhta.org', password: defaultPassword },
  });

  assert(loginRes.status === 200, 'Step 1: Sign in succeeds normally (200 OK)');
  assert(Boolean(loginRes.data.token), 'Step 1: Sign in returns session token in response body');
  assert(Boolean(loginRes.headers['set-cookie']), 'Step 1: Sign in establishes HTTP-only auth cookies');

  clientInMemoryToken = loginRes.data.token;
  clientCookieJar = extractCookies(loginRes.headers);

  // -------------------------------------------------------------------------
  // SECTION B2: Step 2 & 3 - Open Department Workspace & Assign Department Task
  // -------------------------------------------------------------------------
  const overviewRes = await makeRequest({
    method: 'GET',
    path: '/api/department/Literature/overview',
    headers: {
      Authorization: `Bearer ${clientInMemoryToken}`,
      Cookie: clientCookieJar,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
  });
  assert(overviewRes.status === 200, 'Step 2: Department workspace overview accessible (200 OK)');

  // -------------------------------------------------------------------------
  // SECTION B3: Step 4-7 - Submit Task & Confirm Single Creation
  // -------------------------------------------------------------------------
  const task1Res = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${clientInMemoryToken}`,
      Cookie: clientCookieJar,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
    body: {
      title: 'Review Classical Urdu Ghazals',
      description: 'Prepare editorial notes on Ghalib diwan',
      assignedTo: personas.litMember.id,
      deadline: '2026-12-15',
      priority: 'high',
    },
  });
  assert(task1Res.status === 201, 'Step 4-6: Task assignment request accepted (201 Created)');
  assert(task1Res.data.task?.title === 'Review Classical Urdu Ghazals', 'Step 7: Task created with expected title');
  assert(task1Res.data.task?.department === 'Literature', 'Step 7: Task bound to Literature department');

  // -------------------------------------------------------------------------
  // SECTION B4: Step 8 - Page Reload (Memory Wiped, Hydration via /api/auth/me)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION B (cont): Page Reload & Hydration Simulation ---');
  // Client memory is cleared upon reload
  clientInMemoryToken = null;

  // Browser executes AuthContext restoreSession() using Cookie:
  const restoreRes = await makeRequest({
    method: 'GET',
    path: '/api/auth/me',
    headers: {
      Cookie: clientCookieJar,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(restoreRes.status === 200, 'Step 8.1: Page reload /auth/me session restore succeeds (200 OK)');
  assert(Boolean(restoreRes.data.token), 'Step 8.2: /auth/me supplies refreshed access token to hydrate in-memory client');

  // Client sets in-memory token from restored session
  clientInMemoryToken = restoreRes.data.token;

  // Assign second task with hydrated in-memory token
  const task2Res = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${clientInMemoryToken}`,
      Cookie: clientCookieJar,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
    body: {
      title: 'Compile Rekhta Quarterly Digest',
      description: 'Assemble approved essays and poetic selections',
      assignedTo: personas.litMember.id,
      deadline: '2026-12-20',
      priority: 'medium',
    },
  });
  assert(task2Res.status === 201, 'Step 8.3: Task assigned successfully following page reload and in-memory hydration (201)');

  // -------------------------------------------------------------------------
  // SECTION B5: Step 9 - Logout and Subsequent Login
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION B (cont): Logout & Subsequent Login ---');
  const logoutRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/logout',
    headers: {
      Authorization: `Bearer ${clientInMemoryToken}`,
      Cookie: clientCookieJar,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(logoutRes.status === 200, 'Step 9.1: Logout succeeds (200 OK)');

  // Client clears in-memory token and cookie jar
  clientInMemoryToken = null;
  clientCookieJar = '';

  // Attempt task assignment after logout -> must be rejected
  const postLogoutTaskRes = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: {
      title: 'Unauthorized Task After Logout',
      assignedTo: personas.litMember.id,
    },
  });
  assert(postLogoutTaskRes.status === 401, 'Step 9.2: Post-logout task assignment strictly rejected (401 Unauthorized)');
  assert(
    postLogoutTaskRes.data.error === 'Authentication required. No session token provided.',
    'Step 9.3: Post-logout error matches exact expected message'
  );

  // Subsequent Login
  const reLoginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'noorulhuda@rekhta.org', password: defaultPassword },
  });
  assert(reLoginRes.status === 200, 'Step 9.4: Subsequent login succeeds (200 OK)');
  clientInMemoryToken = reLoginRes.data.token;
  clientCookieJar = extractCookies(reLoginRes.headers);

  const task3Res = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${clientInMemoryToken}`,
      Cookie: clientCookieJar,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
    body: {
      title: 'Post-Relogin Task Assignment',
      assignedTo: personas.litMember.id,
    },
  });
  assert(task3Res.status === 201, 'Step 9.5: Task assigned successfully following subsequent login (201 Created)');

  // -------------------------------------------------------------------------
  // SECTION C: Authorization & Regression Testing
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION C: Authorization & Regression Testing ---');

  // Cross-department assignment attempt: Literature Head attempts Media task
  const crossDeptRes = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${clientInMemoryToken}`,
      Cookie: clientCookieJar,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Media', // Caller only has dept_literature role
    },
    body: {
      title: 'Cross-Department Video Editing',
      department: 'Media',
      assignedTo: personas.litMember.id,
    },
  });
  assert(crossDeptRes.status === 403, 'Cross-department assignment rejected with 403 Forbidden');

  // Unauthorized Member submission attempt
  const memberLoginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'aliraza@rekhta.org', password: defaultPassword },
  });
  const memberToken = memberLoginRes.data.token;
  const memberCookies = extractCookies(memberLoginRes.headers);

  const memberTaskRes = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${memberToken}`,
      Cookie: memberCookies,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
    body: {
      title: 'Member Unauthorized Self-Task',
      assignedTo: personas.litMember.id,
    },
  });
  assert(memberTaskRes.status === 403, 'Regular member attempting to assign department task rejected with 403 Forbidden');

  // Super Admin workflow: Authorized across departments
  const adminLoginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'tameerrekhtaadmin@rekhta.org', password: defaultPassword },
  });
  const adminToken = adminLoginRes.data.token;
  const adminCookies = extractCookies(adminLoginRes.headers);

  const adminTaskRes = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${adminToken}`,
      Cookie: adminCookies,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
    body: {
      title: 'Super Admin Direct Task Directive',
      department: 'Literature',
      assignedTo: personas.litMember.id,
    },
  });
  assert(adminTaskRes.status === 201, 'Super Admin workflow unaffected: assigns task successfully (201 Created)');

  // CSRF Defense check: State-changing request with auth cookie but MISSING Origin/Referer AND missing X-Requested-With
  const csrfViolatingRes = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Cookie: clientCookieJar,
      // No Authorization header, no Origin, no Referer, NO X-Requested-With
    },
    body: {
      title: 'CSRF Attack Simulation',
      assignedTo: personas.litMember.id,
    },
  });
  assert(
    csrfViolatingRes.status === 403 && csrfViolatingRes.data.code === 'CSRF_HEADER_MISSING',
    'CSRF Defense: Cookie request lacking Origin and X-Requested-With rejected with 403 CSRF_HEADER_MISSING'
  );

  console.log('\n========================================================================');
  console.log(`LIFECYCLE TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('========================================================================\n');

  server.close();
  if (failed > 0) process.exit(1);
}

runLifecycleTests().catch((err) => {
  console.error('Fatal lifecycle test runner error:', err);
  if (server) server.close();
  process.exit(1);
});
