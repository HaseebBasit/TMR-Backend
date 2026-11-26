/**
 * Verification Test Suite: Assign Department Task Authentication & Session Token Fix
 * 
 * Tests the fix for:
 * "Authentication required. No session token provided."
 * 
 * Verifies:
 * 1. Login returns session token in response payload alongside HTTP-only cookies.
 * 2. Authenticated Department Head creates task via Authorization: Bearer <token>.
 * 3. Authenticated Department Head creates task via Cookie: rekhta_access_token=<token>.
 * 4. Dual-channel authentication (Bearer + Cookie) succeeds.
 * 5. Unauthenticated request (no token, no cookie) is rejected with 401.
 * 6. Malformed/invalid token is rejected with 401.
 * 7. Unauthorized user (regular member) is rejected with 403.
 * 8. Welfare Regional isolation is preserved (Punjab Head cannot assign Sindh task).
 * 9. Multi-department context switching returns fresh session token.
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_jwt_secret_for_task_auth_verification_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_for_task_auth_verification_2026';

const http = require('http');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');
const { User, Task } = require('../src/models');

const TEST_PORT = 5006;
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
  console.log("PRODUCTION BUG FIX VERIFICATION: ASSIGN DEPARTMENT TASK AUTHENTICATION");
  console.log('========================================================================\n');

  // Start test server
  await new Promise((resolve) => {
    server = app.listen(TEST_PORT, () => resolve());
  });

  const defaultPassword = 'SecurePassword123!';
  const hashedPassword = await bcrypt.hash(defaultPassword, 10);

  // Setup test personas
  const personas = {
    litHead: {
      _id: '607f191e810c19729de86001',
      id: '607f191e810c19729de86001',
      name: 'Noor-ul-Huda',
      email: 'lit.head@rekhta.org',
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
      _id: '607f191e810c19729de86002',
      id: '607f191e810c19729de86002',
      name: 'Rumaisa',
      email: 'rumaisa.lit@rekhta.org',
      password: hashedPassword,
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      tokenVersion: 0,
      designation: 'Literature Team Member',
      memberships: [
        {
          department: 'Literature',
          departmentCode: 'LIT',
          role: 'member',
          designation: 'Literature Team Member',
          isPrimary: true,
        },
      ],
    },
    welfarePunjabHead: {
      _id: '607f191e810c19729de86003',
      id: '607f191e810c19729de86003',
      name: 'Asfand Yar Karimi',
      email: 'welfare.punjab@rekhta.org',
      password: hashedPassword,
      role: 'dept_welfare',
      department: 'Welfare',
      departmentCode: 'WEL',
      region: 'Punjab',
      status: 'active',
      tokenVersion: 0,
      designation: 'Head of Welfare Department Punjab',
      memberships: [
        {
          department: 'Welfare',
          departmentCode: 'WEL',
          role: 'dept_welfare',
          region: 'Punjab',
          designation: 'Head of Welfare Department Punjab',
          isPrimary: true,
        },
      ],
    },
    welfareSindhMember: {
      _id: '607f191e810c19729de86004',
      id: '607f191e810c19729de86004',
      name: 'Sindh Volunteer',
      email: 'sindh.member@rekhta.org',
      password: hashedPassword,
      role: 'member',
      department: 'Welfare',
      departmentCode: 'WEL',
      region: 'Sindh',
      status: 'active',
      tokenVersion: 0,
      designation: 'Welfare Sindh Volunteer',
      memberships: [
        {
          department: 'Welfare',
          departmentCode: 'WEL',
          role: 'member',
          region: 'Sindh',
          designation: 'Welfare Sindh Volunteer',
          isPrimary: true,
        },
      ],
    },
    multiDeptUser: {
      _id: '607f191e810c19729de86005',
      id: '607f191e810c19729de86005',
      name: 'Hafiz Muhammad Moosa',
      email: 'moosa@rekhta.org',
      password: hashedPassword,
      role: 'dept_content',
      department: 'Content Creation',
      departmentCode: 'CON',
      status: 'active',
      tokenVersion: 0,
      designation: 'Content Lead',
      memberships: [
        {
          department: 'Content Creation',
          departmentCode: 'CON',
          role: 'dept_content',
          designation: 'Content Lead',
          isPrimary: true,
        },
        {
          department: 'Literature',
          departmentCode: 'LIT',
          role: 'member',
          designation: 'Content Writer',
          isPrimary: false,
        },
      ],
    },
  };

  for (const p of Object.values(personas)) {
    setMemoryUser(p);
  }

  // ---------------------------------------------------------------------------
  // TEST GROUP 1: LOGIN RETURNS JWT ACCESS TOKEN
  // ---------------------------------------------------------------------------
  console.log('--- TEST GROUP 1: Login Response Token Availability ---');

  const loginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: { email: personas.litHead.email, password: defaultPassword },
  });

  assert(loginRes.status === 200 && loginRes.data.success, 'Login succeeds with 200 OK');
  assert(
    typeof loginRes.data.token === 'string' && loginRes.data.token.length > 20,
    'Login response includes valid JWT session token in payload',
    `Received token type: ${typeof loginRes.data.token}`
  );
  assert(
    Boolean(loginRes.headers['set-cookie']),
    'Login response includes Set-Cookie for HTTP-only cookie authentication'
  );

  const litHeadToken = loginRes.data.token;
  const cookieHeader = Array.isArray(loginRes.headers['set-cookie'])
    ? loginRes.headers['set-cookie'].join('; ')
    : loginRes.headers['set-cookie'] || '';

  // ---------------------------------------------------------------------------
  // TEST GROUP 2: TASK ASSIGNMENT VIA BEARER TOKEN
  // ---------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 2: Task Assignment via Bearer Token ---');

  const taskViaBearer = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${litHeadToken}`,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
    body: {
      title: 'Compose 5 Ghazal Analyses for Weekly Journal',
      description: 'Analyze selected works of Mir and Ghalib with commentary.',
      department: 'Literature',
      priority: 'high',
      assignedTo: personas.litMember.id,
      assignedMemberName: personas.litMember.name,
      assignedMemberEmail: personas.litMember.email,
    },
  });

  assert(
    taskViaBearer.status === 201 && taskViaBearer.data.success,
    'Task created successfully via Bearer token (201 Created)',
    `Status: ${taskViaBearer.status}, Error: ${taskViaBearer.data?.error}`
  );
  assert(
    taskViaBearer.data?.task?.department === 'Literature',
    'Created task is bound to caller active department (Literature)'
  );
  assert(
    taskViaBearer.data?.task?.assignedTo === personas.litMember.id,
    'Created task correctly assigned to target department member'
  );

  // ---------------------------------------------------------------------------
  // TEST GROUP 3: TASK ASSIGNMENT VIA HTTP-ONLY COOKIE
  // ---------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 3: Task Assignment via HTTP-Only Cookie ---');

  const taskViaCookie = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Cookie: cookieHeader,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
    body: {
      title: 'Proofread Quarterly Literary Anthology Draft',
      description: 'Review compiled manuscripts for typesetting accuracy.',
      department: 'Literature',
      priority: 'medium',
    },
  });

  assert(
    taskViaCookie.status === 201 && taskViaCookie.data.success,
    'Task created successfully via HTTP-only cookie (201 Created)',
    `Status: ${taskViaCookie.status}, Error: ${taskViaCookie.data?.error}`
  );

  // ---------------------------------------------------------------------------
  // TEST GROUP 4: DUAL-CHANNEL AUTHENTICATION (BEARER + COOKIE)
  // ---------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 4: Dual-Channel Authentication (Bearer + Cookie) ---');

  const taskViaDual = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${litHeadToken}`,
      Cookie: cookieHeader,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
    body: {
      title: 'Digitize Classical Urdu Manuscripts Archive',
      description: 'Scan and index historical manuscripts for the digital repository.',
      department: 'Literature',
      priority: 'urgent',
    },
  });

  assert(
    taskViaDual.status === 201 && taskViaDual.data.success,
    'Dual-channel request succeeds with 201 Created'
  );

  // ---------------------------------------------------------------------------
  // TEST GROUP 5: UNAUTHENTICATED & MALFORMED REJECTION (SECURITY INVARIANTS)
  // ---------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 5: Unauthenticated & Invalid Token Rejection ---');

  // A. No token, no cookie
  const unauthRes = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { title: 'Unauthenticated Attack Task' },
  });

  assert(
    unauthRes.status === 401 && !unauthRes.data.success,
    'Unauthenticated request rejected with 401 Unauthorized'
  );
  assert(
    unauthRes.data.error === 'Authentication required. No session token provided.',
    'Returns exact expected error message when session token is missing'
  );

  // B. Malformed Bearer token
  const malformedRes = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: 'Bearer invalid.bogus.jwt.token',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: { title: 'Forged Token Task' },
  });

  assert(
    malformedRes.status === 401 && !malformedRes.data.success,
    'Malformed/forged Bearer token rejected with 401 Unauthorized'
  );

  // C. Regular member without task creation authority
  const memberLogin = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: { email: personas.litMember.email, password: defaultPassword },
  });
  const memberToken = memberLogin.data.token;

  const memberCreateTask = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${memberToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: { title: 'Member Unauthorized Task Creation Attempt' },
  });

  assert(
    memberCreateTask.status === 403 && !memberCreateTask.data.success,
    'Regular member forbidden from creating department tasks (403 Forbidden)'
  );

  // ---------------------------------------------------------------------------
  // TEST GROUP 6: WELFARE REGIONAL ISOLATION & CONTEXT PRESERVATION
  // ---------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 6: Welfare Regional Isolation Enforcement ---');

  const welfareLogin = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: { email: personas.welfarePunjabHead.email, password: defaultPassword },
  });
  const welfareToken = welfareLogin.data.token;

  // Punjab Head creating Punjab task -> SUCCEEDS
  const punjabTask = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${welfareToken}`,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Welfare',
    },
    body: {
      title: 'Distribute Food Rations in Lahore',
      department: 'Welfare',
      region: 'Punjab',
    },
  });

  assert(
    punjabTask.status === 201 && punjabTask.data.success,
    'Welfare Head of Punjab successfully creates Punjab regional task (201 Created)'
  );

  // Punjab Head creating Sindh task -> FORBIDDEN
  const sindhViolation = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${welfareToken}`,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Welfare',
    },
    body: {
      title: 'Karachi Medical Camp Logistics',
      department: 'Welfare',
      region: 'Sindh',
    },
  });

  assert(
    sindhViolation.status === 403 && !sindhViolation.data.success,
    'Welfare Head of Punjab forbidden from creating Sindh regional task (403 Forbidden)'
  );

  // Punjab Head assigning Punjab task to Sindh member -> REJECTED
  const crossRegionAssignment = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${welfareToken}`,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Welfare',
    },
    body: {
      title: 'Punjab Winter Relief Drive',
      department: 'Welfare',
      region: 'Punjab',
      assignedTo: personas.welfareSindhMember.id,
    },
  });

  assert(
    crossRegionAssignment.status === 400 && !crossRegionAssignment.data.success,
    'Cross-regional assignment to Sindh member rejected (400 Bad Request)'
  );

  // ---------------------------------------------------------------------------
  // TEST GROUP 7: MULTI-DEPARTMENT CONTEXT SWITCHING REFRESHES TOKEN
  // ---------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 7: Multi-Department Context Switching Token Refresh ---');

  const moosaLogin = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: { email: personas.multiDeptUser.email, password: defaultPassword },
  });
  const moosaInitialToken = moosaLogin.data.token;

  // Switch to Literature
  const switchRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/switch-department',
    headers: {
      Authorization: `Bearer ${moosaInitialToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: { department: 'Literature' },
  });

  assert(
    switchRes.status === 200 && switchRes.data.success,
    'Department context switch succeeds (200 OK)'
  );
  assert(
    typeof switchRes.data.token === 'string' && switchRes.data.token.length > 20,
    'Department context switch returns fresh JWT token with updated active context'
  );

  // ---------------------------------------------------------------------------
  // TEST GROUP 8: GET /api/auth/me SUPPLIES ACTIVE TOKEN FOR IN-MEMORY HYDRATION
  // ---------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 8: /api/auth/me Token Supply for In-Memory Hydration ---');

  const meRes = await makeRequest({
    method: 'GET',
    path: '/api/auth/me',
    headers: {
      Cookie: cookieHeader,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });

  assert(
    meRes.status === 200 && meRes.data.success,
    'GET /api/auth/me via HTTP-only cookie succeeds (200 OK)'
  );
  assert(
    typeof meRes.data.token === 'string' && meRes.data.token.length > 20,
    'GET /api/auth/me returns active access token for client in-memory hydration on page reload'
  );

  // ---------------------------------------------------------------------------
  // TEST GROUP 9: JWT SECURITY INVARIANTS (IN-MEMORY STORAGE & ZERO LEAKAGE)
  // ---------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 9: JWT Security Invariants (In-Memory Storage) ---');

  const fs = require('fs');
  const path = require('path');
  const apiTsContent = fs.readFileSync(
    path.join(__dirname, '..', '..', 'frontend', 'src', 'lib', 'api.ts'),
    'utf8'
  );

  assert(
    !apiTsContent.includes('localStorage.setItem') &&
    !apiTsContent.includes('localStorage["') &&
    !apiTsContent.includes("localStorage['"),
    'JWT access tokens are NOT written to localStorage (pure in-memory storage verified)'
  );
  assert(
    !apiTsContent.includes('sessionStorage.setItem') &&
    !apiTsContent.includes('sessionStorage["') &&
    !apiTsContent.includes("sessionStorage['"),
    'JWT access tokens are NOT written to sessionStorage (pure in-memory storage verified)'
  );
  assert(
    apiTsContent.includes('inMemoryAccessToken'),
    'Strict in-memory access token storage module variable verified'
  );

  // Close test server
  await new Promise((resolve) => server.close(resolve));

  console.log('\n========================================================================');
  console.log(`TEST SUITE COMPLETE: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Test execution failed:', err);
  if (server) server.close();
  process.exit(1);
});
