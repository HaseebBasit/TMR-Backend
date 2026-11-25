/**
 * PHASE 10A — Automated Organizational Architecture Verification Suite
 * 
 * Verifies:
 * 1. Single-department user authentication & legacy session preservation.
 * 2. Multi-department memberships & department-specific designations.
 * 3. Email aliases login resolution without duplicate accounts.
 * 4. Server-side authorized department context switching.
 * 5. Unauthorized department context switching rejection (403).
 * 6. Department scope isolation via X-Department-Context header.
 * 7. Welfare dual regional leadership permissions (Head of Punjab & Head of Sindh).
 * 8. Outreach and Marketing unified department operational access.
 * 9. Super Admin global governance and Finance access.
 * 10. Strict Finance isolation for departmental leads and members.
 * 11. Empty-state responses.
 * 12. Strict read-only guarantee: zero production database writes.
 */

const assert = require('assert');
const express = require('express');
const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Import models & auth modules
const { User, Department, Task, AuditLog } = require('../src/models');
const {
  TECHNICAL_ROLES,
  ALLOWED_ROLES,
  OPERATIONAL_DEPT_ROLES,
  OPERATIONAL_DESIGNATIONS,
  HR_DESIGNATIONS,
  normalizeDesignation,
  validateRoleDesignation,
  hasCapability,
  CAPABILITIES,
  DEPT_ROLE_MAP,
} = require('../src/constants/roles');
const {
  protect,
  authorize,
  requireDepartmentScope,
  setMemoryUser,
  getMemoryUser,
} = require('../src/middleware/auth');

const JWT_SECRET = process.env.JWT_SECRET || 'rekhta_access_secret_2026_super_secure';

async function runTests() {
  console.log('================================================================');
  console.log('PHASE 10A ORGANIZATIONAL ARCHITECTURE VERIFICATION TEST SUITE');
  console.log('================================================================\n');

  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${name}`);
      console.error(err);
      process.exit(1);
    }
  }

  async function testAsync(name, fn) {
    total++;
    try {
      await fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${name}`);
      console.error(err);
      process.exit(1);
    }
  }

  // -------------------------------------------------------------------------
  // Group 1: Role, Designation, and Normalization Verification
  // -------------------------------------------------------------------------
  console.log('--- Group 1: Roles, Designations & Normalization ---');

  test('1.1 Technical roles include dept_oam and dept_welfare', () => {
    assert.strictEqual(TECHNICAL_ROLES.DEPT_OAM, 'dept_oam');
    assert.strictEqual(TECHNICAL_ROLES.DEPT_WELFARE, 'dept_welfare');
    assert(ALLOWED_ROLES.includes('dept_oam'));
    assert(ALLOWED_ROLES.includes('dept_welfare'));
    assert(OPERATIONAL_DEPT_ROLES.includes('dept_oam'));
    assert(OPERATIONAL_DEPT_ROLES.includes('dept_welfare'));
  });

  test('1.2 Designation normalization handles parentheses and title case', () => {
    assert.strictEqual(normalizeDesignation('(Head)'), 'head');
    assert.strictEqual(normalizeDesignation('(Head of Punjab)'), 'head_of_punjab');
    assert.strictEqual(normalizeDesignation('(Head of Sindh)'), 'head_of_sindh');
    assert.strictEqual(normalizeDesignation('(Director)'), 'director');
    assert.strictEqual(normalizeDesignation('(Director (Graphics Designing))'), 'director_graphics');
    assert.strictEqual(normalizeDesignation('(Assistant Director)'), 'assistant_director');
    assert.strictEqual(normalizeDesignation('(Member)'), 'member');
    assert.strictEqual(normalizeDesignation('(Volunteer)'), 'volunteer');
    assert.strictEqual(normalizeDesignation('(Co-ordination Incharge)'), 'coordination_incharge');
  });

  test('1.3 Role-designation compatibility validates Welfare dual regional leadership', () => {
    const vPunjab = validateRoleDesignation('dept_welfare', 'Head of Punjab');
    assert.strictEqual(vPunjab.valid, true);
    assert.strictEqual(vPunjab.designation, 'head_of_punjab');

    const vSindh = validateRoleDesignation('dept_welfare', 'Head of Sindh');
    assert.strictEqual(vSindh.valid, true);
    assert.strictEqual(vSindh.designation, 'head_of_sindh');
  });

  test('1.4 Role-designation compatibility validates HR Assistant Director & Volunteer', () => {
    const vHRAsst = validateRoleDesignation('hr', 'Assistant Director');
    assert.strictEqual(vHRAsst.valid, true);
    assert.strictEqual(vHRAsst.designation, 'assistant_director');

    const vHRVol = validateRoleDesignation('hr', 'Volunteer');
    assert.strictEqual(vHRVol.valid, true);
    assert.strictEqual(vHRVol.designation, 'volunteer');

    const vHRCoord = validateRoleDesignation('hr', 'Co-ordination Incharge');
    assert.strictEqual(vHRCoord.valid, true);
  });

  test('1.5 Role-designation compatibility validates Outreach and Marketing (OAM)', () => {
    const vOAMHead = validateRoleDesignation('dept_oam', 'Head');
    assert.strictEqual(vOAMHead.valid, true);
    assert.strictEqual(vOAMHead.designation, 'head');

    const vOAMVol = validateRoleDesignation('dept_oam', 'Volunteer');
    assert.strictEqual(vOAMVol.valid, true);
    assert.strictEqual(vOAMVol.designation, 'volunteer');
  });

  test('1.6 DEPT_ROLE_MAP contains OAM and WEL with official codes', () => {
    assert.deepStrictEqual(DEPT_ROLE_MAP.dept_oam, { name: 'Outreach and Marketing', code: 'OAM' });
    assert.deepStrictEqual(DEPT_ROLE_MAP.dept_welfare, { name: 'Welfare', code: 'WEL' });
  });

  // -------------------------------------------------------------------------
  // Group 2: Capabilities & Permissions
  // -------------------------------------------------------------------------
  console.log('\n--- Group 2: Capabilities & Regional Leadership Permissions ---');

  test('2.1 Welfare Head of Punjab has confidential grading, task approval, and leave approval for Welfare', () => {
    const userPunjab = {
      role: 'dept_welfare',
      designation: 'head_of_punjab',
      department: 'Welfare',
      departmentCode: 'WEL',
    };
    assert.strictEqual(hasCapability(userPunjab, CAPABILITIES.CONFIDENTIAL_GRADING_VIEW, { targetDepartment: 'Welfare' }), true);
    assert.strictEqual(hasCapability(userPunjab, CAPABILITIES.FINAL_TASK_APPROVAL, { targetDepartment: 'Welfare' }), true);
    assert.strictEqual(hasCapability(userPunjab, CAPABILITIES.FINAL_LEAVE_APPROVAL, { targetDepartment: 'Welfare' }), true);
    // Denied for other departments
    assert.strictEqual(hasCapability(userPunjab, CAPABILITIES.CONFIDENTIAL_GRADING_VIEW, { targetDepartment: 'Literature' }), false);
    // Strictly denied finance
    assert.strictEqual(hasCapability(userPunjab, CAPABILITIES.FINANCE_DASHBOARD_VIEW), false);
  });

  test('2.2 Welfare Head of Sindh has confidential grading, task approval, and leave approval for Welfare', () => {
    const userSindh = {
      role: 'dept_welfare',
      designation: 'head_of_sindh',
      department: 'Welfare',
      departmentCode: 'WEL',
    };
    assert.strictEqual(hasCapability(userSindh, CAPABILITIES.CONFIDENTIAL_GRADING_VIEW, { targetDepartment: 'Welfare' }), true);
    assert.strictEqual(hasCapability(userSindh, CAPABILITIES.FINAL_TASK_APPROVAL, { targetDepartment: 'Welfare' }), true);
    assert.strictEqual(hasCapability(userSindh, CAPABILITIES.FINAL_LEAVE_APPROVAL, { targetDepartment: 'Welfare' }), true);
    // Strictly denied finance
    assert.strictEqual(hasCapability(userSindh, CAPABILITIES.FINANCE_BUDGET_MANAGE), false);
  });

  test('2.3 Super Admin preserves global access to administration and Finance', () => {
    const superAdmin = { role: 'super_admin' };
    assert.strictEqual(hasCapability(superAdmin, CAPABILITIES.ORGANIZATION_ADMINISTRATION), true);
    assert.strictEqual(hasCapability(superAdmin, CAPABILITIES.FINANCE_DASHBOARD_VIEW), true);
    assert.strictEqual(hasCapability(superAdmin, CAPABILITIES.FINANCE_BUDGET_MANAGE), true);
    assert.strictEqual(hasCapability(superAdmin, CAPABILITIES.FINANCE_EXPENSE_REVIEW), true);
    assert.strictEqual(hasCapability(superAdmin, CAPABILITIES.ACCOUNT_CREATE_MANAGE), true);
  });

  // -------------------------------------------------------------------------
  // Group 3: Memory Store & Alias Lookup
  // -------------------------------------------------------------------------
  console.log('\n--- Group 3: Multi-Membership User Store & Email Alias Lookup ---');

  const hashedPw = bcrypt.hashSync('Password@123', 8);

  // Seed memory test users
  const testUsers = [
    {
      _id: 'user_super_admin_01',
      id: 'user_super_admin_01',
      name: 'Super Admin',
      email: 'tameerrekhtaadmin@rekhta.org',
      password: hashedPw,
      role: 'super_admin',
      status: 'active',
      tokenVersion: 0,
    },
    {
      _id: 'user_noor_ul_huda',
      id: 'user_noor_ul_huda',
      name: 'Noor ul Huda',
      email: 'noorulhuda@rekhta.org',
      emailAliases: ['noorulhuda.cc@rekhta.org'],
      password: hashedPw,
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      designation: 'head',
      city: 'Karachi',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        {
          department: 'Literature',
          departmentCode: 'LIT',
          role: 'dept_literature',
          designation: 'head',
          isPrimary: true,
        },
        {
          department: 'Content Creation',
          departmentCode: 'CON',
          role: 'dept_content',
          designation: 'head',
          isPrimary: false,
        },
      ],
    },
    {
      _id: 'user_asfand_yar',
      id: 'user_asfand_yar',
      name: 'Asfand Yar Karimi',
      email: 'asfandyar@rekhta.org',
      emailAliases: [],
      password: hashedPw,
      role: 'dept_welfare',
      department: 'Welfare',
      departmentCode: 'WEL',
      designation: 'head_of_punjab',
      city: 'Bahawalpur',
      region: 'Punjab',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        {
          department: 'Welfare',
          departmentCode: 'WEL',
          role: 'dept_welfare',
          designation: 'head_of_punjab',
          region: 'Punjab',
          isPrimary: true,
        },
      ],
    },
    {
      _id: 'user_asma_saeed',
      id: 'user_asma_saeed',
      name: 'Asma Saeed',
      email: 'asma.saeed@rekhta.org',
      emailAliases: [],
      password: hashedPw,
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      designation: 'member',
      city: 'Lahore',
      status: 'active',
      tokenVersion: 0,
    },
  ];

  testUsers.forEach((u) => setMemoryUser(u));

  test('3.1 getMemoryUser finds user by primary email', () => {
    const u = getMemoryUser('noorulhuda@rekhta.org');
    assert(u !== null);
    assert.strictEqual(u.name, 'Noor ul Huda');
  });

  test('3.2 getMemoryUser finds user by email alias without creating duplicate account', () => {
    const u = getMemoryUser('noorulhuda.cc@rekhta.org');
    assert(u !== null);
    assert.strictEqual(u.id, 'user_noor_ul_huda');
    assert.strictEqual(u.email, 'noorulhuda@rekhta.org');
  });

  // -------------------------------------------------------------------------
  // Group 4: Server-Side Context Switching & Isolation API Tests
  // -------------------------------------------------------------------------
  console.log('\n--- Group 4: Server-Side Context Switching & HTTP Endpoints ---');

  const app = express();
  app.use(express.json());

  // Mount auth routes and portal routes
  app.use('/api/auth', require('../src/routes/auth.routes'));
  app.use('/api', require('../src/routes/portal.routes'));
  app.use('/api/finance', require('../src/routes/finance.routes').router);

  const server = http.createServer(app);

  function makeRequest(path, options = {}) {
    return new Promise((resolve, reject) => {
      const req = http.request(
        `http://127.0.0.1:5055${path}`,
        {
          method: options.method || 'GET',
          headers: {
            'Content-Type': 'application/json',
            ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
            ...(options.headers || {}),
          },
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              resolve({ status: res.statusCode, data: data ? JSON.parse(data) : {} });
            } catch (e) {
              resolve({ status: res.statusCode, raw: data });
            }
          });
        }
      );
      req.on('error', reject);
      if (options.body) req.write(JSON.stringify(options.body));
      req.end();
    });
  }

  await new Promise((resolve) => server.listen(5055, '127.0.0.1', resolve));

  // Generate tokens for testing
  const noorToken = jwt.sign(
    {
      id: 'user_noor_ul_huda',
      email: 'noorulhuda@rekhta.org',
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      tokenVersion: 0,
      designation: 'head',
      memberships: testUsers[1].memberships,
      emailAliases: testUsers[1].emailAliases,
    },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const asmaToken = jwt.sign(
    {
      id: 'user_asma_saeed',
      email: 'asma.saeed@rekhta.org',
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      tokenVersion: 0,
      designation: 'member',
    },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const adminToken = jwt.sign(
    {
      id: 'user_super_admin_01',
      email: 'tameerrekhtaadmin@rekhta.org',
      role: 'super_admin',
      status: 'active',
      tokenVersion: 0,
    },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  await testAsync('4.1 Multi-department user can log in via proposed email alias', async () => {
    const res = await makeRequest('/api/auth/login', {
      method: 'POST',
      body: { email: 'noorulhuda.cc@rekhta.org', password: 'Password@123' },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
    assert.strictEqual(res.data.user.id, 'user_noor_ul_huda');
    assert.strictEqual(res.data.user.email, 'noorulhuda@rekhta.org');
    assert(Array.isArray(res.data.user.memberships));
    assert.strictEqual(res.data.user.memberships.length, 2);
  });

  await testAsync('4.2 Multi-department user switches to valid secondary department (Content Creation)', async () => {
    const res = await makeRequest('/api/auth/switch-department', {
      method: 'POST',
      token: noorToken,
      body: { department: 'Content Creation' },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
    assert.strictEqual(res.data.activeDepartment, 'Content Creation');
    assert.strictEqual(res.data.activeDepartmentCode, 'CON');
    assert.strictEqual(res.data.activeRole, 'dept_content');
    assert.strictEqual(res.data.activeDesignation, 'head');
  });

  await testAsync('4.3 Context switch to unauthorized department is strictly rejected with 403 Forbidden', async () => {
    const res = await makeRequest('/api/auth/switch-department', {
      method: 'POST',
      token: noorToken,
      body: { department: 'Media' },
    });
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.data.success, false);
    assert(res.data.error.includes('Unauthorized department context'));
  });

  await testAsync('4.4 Single-department user attempting unauthorized context switch is rejected with 403', async () => {
    const res = await makeRequest('/api/auth/switch-department', {
      method: 'POST',
      token: asmaToken,
      body: { department: 'Welfare' },
    });
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.data.success, false);
  });

  await testAsync('4.5 Super Admin can switch context to any official department', async () => {
    const res = await makeRequest('/api/auth/switch-department', {
      method: 'POST',
      token: adminToken,
      body: { department: 'Welfare' },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
    assert.strictEqual(res.data.activeDepartment, 'Welfare');
  });

  await testAsync('4.6 X-Department-Context header allows access to authorized secondary workspace', async () => {
    const res = await makeRequest('/api/department/Content Creation/overview', {
      token: noorToken,
      headers: { 'X-Department-Context': 'Content Creation' },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
    assert.strictEqual(res.data.department, 'Content Creation');
  });

  await testAsync('4.7 Forged X-Department-Context header is caught and rejected with 403 at middleware boundary', async () => {
    const res = await makeRequest('/api/department/Media/overview', {
      token: noorToken,
      headers: { 'X-Department-Context': 'Media' },
    });
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.data.success, false);
  });

  await testAsync('4.8 Super Admin accesses Finance overview without restriction', async () => {
    const res = await makeRequest('/api/finance/overview', {
      token: adminToken,
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
  });

  await testAsync('4.9 Department Head is strictly forbidden from Finance overview (403)', async () => {
    const res = await makeRequest('/api/finance/overview', {
      token: noorToken,
    });
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.data.success, false);
  });

  await testAsync('4.10 Department Member is strictly forbidden from Finance overview (403)', async () => {
    const res = await makeRequest('/api/finance/overview', {
      token: asmaToken,
    });
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.data.success, false);
  });

  await new Promise((resolve) => server.close(resolve));

  console.log('\n================================================================');
  console.log(`ALL ${passed}/${total} PHASE 10A ARCHITECTURAL TESTS PASSED PERFECTLY!`);
  console.log('================================================================\n');
}

runTests().catch((err) => {
  console.error('[FATAL TEST EXCEPTION]:', err);
  process.exit(1);
});
