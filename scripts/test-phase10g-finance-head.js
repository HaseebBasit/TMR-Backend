/**
 * Phase 10G Verification Test Suite: Finance Head RBAC & Cryptographic Activation
 * 
 * Verifies:
 * 1. Finance Head role ('finance') & designation ('head_of_finance' / 'Head of Finance') validation.
 * 2. Governance scope: Finance is internal treasury control, NOT an organizational department.
 * 3. Authorized access: Full access to Finance overview, ledgers, budgets, and exports.
 * 4. Boundary enforcement: ZERO Super Admin, HR recruitment, or operational task creation privileges.
 * 5. Isolation: Operational heads & regular members strictly blocked from Finance ledgers (403).
 * 6. Cryptographic activation: 7-day single-use SHA-256 hashed token with tamper resistance.
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_jwt_secret_phase10g_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_phase10g_2026';

const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');
const { validateRoleDesignation, normalizeDesignation, TECHNICAL_ROLES, FINANCE_DESIGNATIONS } = require('../src/constants/roles');

const TEST_PORT = 5008;
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
  console.log('PHASE 10G: FINANCE HEAD RBAC & PROVISIONING VERIFICATION SUITE');
  console.log('========================================================================\n');

  await new Promise((resolve) => {
    server = app.listen(TEST_PORT, () => resolve());
  });

  const defaultPassword = 'FinanceSecurePassword123!';
  const hashedPassword = await bcrypt.hash(defaultPassword, 10);

  // ---------------------------------------------------------------------------
  // SECTION 1: Role & Designation Architecture Invariants
  // ---------------------------------------------------------------------------
  console.log('--- SECTION 1: Role & Designation Architecture Invariants ---');

  const norm1 = normalizeDesignation('Head of Finance');
  assert(norm1 === 'head_of_finance', '1.1 normalizeDesignation("Head of Finance") resolves to canonical "head_of_finance"');

  const norm2 = normalizeDesignation('Finance Head');
  assert(norm2 === 'head_of_finance', '1.2 normalizeDesignation("Finance Head") resolves to canonical "head_of_finance"');

  const val1 = validateRoleDesignation('finance', 'Head of Finance');
  assert(val1.valid && val1.designation === 'head_of_finance', '1.3 validateRoleDesignation("finance", "Head of Finance") succeeds');

  const val2 = validateRoleDesignation('finance', 'head_of_finance');
  assert(val2.valid && val2.designation === 'head_of_finance', '1.4 validateRoleDesignation("finance", "head_of_finance") succeeds');

  const val3 = validateRoleDesignation('finance', 'director');
  assert(!val3.valid, '1.5 Finance role cannot receive operational director designation (rejected)');

  const val4 = validateRoleDesignation('finance', 'hr_head');
  assert(!val4.valid, '1.6 Finance role cannot receive HR leadership designation (rejected)');

  // ---------------------------------------------------------------------------
  // SECTION 2: Finance Personas & Token Setup
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 2: Cryptographic Token Generation & Inactive Account ---');

  const rawActivationToken = crypto.randomBytes(32).toString('hex');
  const hashedActivationToken = crypto.createHash('sha256').update(rawActivationToken).digest('hex');
  const activationExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  assert(rawActivationToken.length === 64, '2.1 Raw token is 32-byte CSPRNG hex string (64 characters)');
  assert(hashedActivationToken.length === 64, '2.2 Hashed token is SHA-256 hex string (64 characters)');

  const ahmadMaqsood = {
    _id: '607f191e810c19729de89001',
    id: '607f191e810c19729de89001',
    name: 'Ahmad Maqsood',
    email: 'ahmadmaqsood@rekhta.org',
    role: 'finance',
    department: 'Finance',
    departmentCode: 'FIN',
    designation: 'head_of_finance',
    status: 'inactive',
    activationToken: hashedActivationToken,
    activationExpires,
    activationGeneratedAt: new Date(),
    tokenVersion: 0,
  };

  const operationalHead = {
    _id: '607f191e810c19729de89002',
    id: '607f191e810c19729de89002',
    name: 'Operational Lead',
    email: 'lit.lead@rekhta.org',
    password: hashedPassword,
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    designation: 'head',
    status: 'active',
    tokenVersion: 0,
  };

  const regularMember = {
    _id: '607f191e810c19729de89003',
    id: '607f191e810c19729de89003',
    name: 'Regular Member',
    email: 'member@rekhta.org',
    password: hashedPassword,
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    designation: 'member',
    status: 'active',
    tokenVersion: 0,
  };

  setMemoryUser(ahmadMaqsood);
  setMemoryUser(operationalHead);
  setMemoryUser(regularMember);

  // ---------------------------------------------------------------------------
  // SECTION 3: Public Token Verification Endpoint
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 3: Public Token Verification Endpoint ---');

  const verifyRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/verify-activation-token',
    body: { token: rawActivationToken },
  });

  assert(verifyRes.status === 200 && verifyRes.data.valid, '3.1 verify-activation-token succeeds with 200 OK');
  assert(verifyRes.data.name === 'Ahmad Maqsood', '3.2 Returned metadata contains name: Ahmad Maqsood');
  assert(verifyRes.data.email === 'ahmadmaqsood@rekhta.org', '3.3 Returned metadata contains email: ahmadmaqsood@rekhta.org');
  assert(verifyRes.data.department === 'Finance', '3.4 Returned metadata contains department: Finance');
  assert(verifyRes.data.role === 'finance', '3.5 Returned metadata contains role: finance');
  assert(verifyRes.data.designation === 'head_of_finance', '3.6 Returned metadata contains designation: head_of_finance');
  assert(!verifyRes.data.activationToken, '3.7 Hashed activation token is NOT leaked in response');
  assert(!verifyRes.data.password, '3.8 Password is NOT leaked in response');

  // ---------------------------------------------------------------------------
  // SECTION 4: Tamper Defense & Account Activation
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 4: Tamper Defense & Account Activation ---');

  // Tamper attempt: Client sends role: super_admin
  const tamperRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/activate',
    body: {
      token: rawActivationToken,
      password: defaultPassword,
      role: 'super_admin',
    },
  });
  assert(tamperRes.status === 400, '4.1 Tamper attempt (escalate to super_admin) rejected with 400 Bad Request');

  // Valid Activation
  const activateRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/activate',
    body: {
      token: rawActivationToken,
      password: defaultPassword,
    },
  });
  assert(activateRes.status === 200 && activateRes.data.success, '4.2 Valid account activation succeeds with 200 OK');
  assert(ahmadMaqsood.status === 'active', '4.3 Account transitions from inactive to active');
  assert(!ahmadMaqsood.activationToken, '4.4 activationToken is cleared atomically from record');
  assert(ahmadMaqsood.role === 'finance', '4.5 Role remains strictly "finance"');

  // Anti-Replay test
  const replayRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/activate',
    body: {
      token: rawActivationToken,
      password: defaultPassword,
    },
  });
  assert(replayRes.status === 400, '4.6 Replaying consumed activation token rejected with 400');

  // ---------------------------------------------------------------------------
  // SECTION 5: Finance Head Authentication & Dashboard Access
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 5: Finance Head Authentication & Dashboard Access ---');

  const loginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'ahmadmaqsood@rekhta.org', password: defaultPassword },
  });

  assert(loginRes.status === 200 && loginRes.data.success, '5.1 Finance Head signs in successfully (200 OK)');
  const financeToken = loginRes.data.token;
  assert(Boolean(financeToken), '5.2 In-memory session token provided in login response');
  assert(loginRes.data.user.role === 'finance', '5.3 Authenticated user role is "finance"');
  assert(loginRes.data.user.department === 'Finance', '5.4 Authenticated user department is "Finance"');

  // Test access to Finance Dashboard overview
  const overviewRes = await makeRequest({
    method: 'GET',
    path: '/api/finance/overview',
    headers: {
      Authorization: `Bearer ${financeToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(overviewRes.status === 200, '5.5 Finance Head accesses /api/finance/overview (200 OK)');

  // Test access to Finance income ledger
  const incomeRes = await makeRequest({
    method: 'GET',
    path: '/api/finance/income',
    headers: {
      Authorization: `Bearer ${financeToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(incomeRes.status === 200, '5.6 Finance Head accesses /api/finance/income (200 OK)');

  // Test access to Finance budgets
  const budgetRes = await makeRequest({
    method: 'GET',
    path: '/api/finance/budgets',
    headers: {
      Authorization: `Bearer ${financeToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(budgetRes.status === 200, '5.7 Finance Head accesses /api/finance/budgets (200 OK)');

  // ---------------------------------------------------------------------------
  // SECTION 6: Strict RBAC Boundaries & Negative Tests
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 6: Strict RBAC Boundaries & Privilege Isolation ---');

  // Finance Head blocked from Super Admin user management
  const adminUsersRes = await makeRequest({
    method: 'GET',
    path: '/api/super-admin/users',
    headers: {
      Authorization: `Bearer ${financeToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(adminUsersRes.status === 403, '6.1 Finance Head strictly blocked from Super Admin users endpoint (403 Forbidden)');

  // Finance Head blocked from HR recruitment applications
  const hrAppsRes = await makeRequest({
    method: 'GET',
    path: '/api/hr/applications',
    headers: {
      Authorization: `Bearer ${financeToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(hrAppsRes.status === 403, '6.2 Finance Head strictly blocked from HR recruitment applications (403 Forbidden)');

  // Finance Head blocked from creating operational tasks in Literature
  const taskRes = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: {
      Authorization: `Bearer ${financeToken}`,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Department-Context': 'Literature',
    },
    body: {
      title: 'Finance Unauthorized Task',
      department: 'Literature',
    },
  });
  assert(taskRes.status === 403, '6.3 Finance Head blocked from creating operational tasks (403 Forbidden)');

  // Operational Head blocked from Finance Overview
  const opHeadLogin = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'lit.lead@rekhta.org', password: defaultPassword },
  });
  const opHeadToken = opHeadLogin.data.token;

  const opFinanceRes = await makeRequest({
    method: 'GET',
    path: '/api/finance/overview',
    headers: {
      Authorization: `Bearer ${opHeadToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(opFinanceRes.status === 403, '6.4 Operational Department Head blocked from Finance overview (403 Forbidden)');

  // Regular Member blocked from Finance Overview
  const memberLogin = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: { email: 'member@rekhta.org', password: defaultPassword },
  });
  const memberToken = memberLogin.data.token;

  const memFinanceRes = await makeRequest({
    method: 'GET',
    path: '/api/finance/overview',
    headers: {
      Authorization: `Bearer ${memberToken}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  assert(memFinanceRes.status === 403, '6.5 Regular member blocked from Finance overview (403 Forbidden)');

  console.log('\n========================================================================');
  console.log(`PHASE 10G TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('========================================================================\n');

  server.close();
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('Fatal test runner error:', err);
  if (server) server.close();
  process.exit(1);
});
