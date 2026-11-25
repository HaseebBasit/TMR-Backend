/**
 * PHASE 10A.R2 — Security Remediation & Regional Data Isolation Test Suite
 * 
 * Verifies:
 * - SEC-01: Operational model schema compatibility across Task, LeaveRequest, Assessment, Announcement, Campaign.
 * - SEC-02: Multi-department role authorization for dept_oam & dept_welfare.
 * - SEC-03: Active membership role authorization, unauthorized context rejection, Super Admin bypass.
 * - SEC-04: Welfare strict provincial data partitioning (Punjab vs Sindh vs National).
 * - SEC-05: Cross-department member privacy in requireOwnershipOrPrivilege and member tasks endpoint.
 */

const assert = require('assert');
const express = require('express');
const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Import models
const { Task, LeaveRequest, Assessment, Announcement, Campaign, User } = require('../src/models');
const {
  TECHNICAL_ROLES,
  ALLOWED_ROLES,
  OPERATIONAL_DEPT_ROLES,
  normalizeDesignation,
  validateRoleDesignation,
  hasCapability,
  DEPT_ROLE_MAP,
  getWelfareRegionalScope,
} = require('../src/constants/roles');

const {
  protect,
  authorize,
  requireDepartmentScope,
  requireOwnershipOrPrivilege,
  setMemoryUser,
  getMemoryUser,
} = require('../src/middleware/auth');

const JWT_SECRET = process.env.JWT_SECRET || 'rekhta_access_secret_2026_super_secure';

async function runTests() {
  console.log('================================================================');
  console.log('PHASE 10A.R2 SECURITY REMEDIATION & REGIONAL ISOLATION TEST SUITE');
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
  // Group 1: SEC-01 Operational Model Schema Compatibility
  // -------------------------------------------------------------------------
  console.log('--- Group 1: SEC-01 Operational Model Schema Compatibility ---');

  test('1.1 TaskSchema validates Welfare and Outreach and Marketing departments and codes', () => {
    const taskWelfare = new Task({
      title: 'Welfare Task Test',
      department: 'Welfare',
      departmentCode: 'WEL',
      region: 'Punjab',
    });
    const errWelfare = taskWelfare.validateSync();
    assert.strictEqual(errWelfare, undefined, 'Task with Welfare and WEL must pass schema validation');

    const taskOAM = new Task({
      title: 'OAM Task Test',
      department: 'Outreach and Marketing',
      departmentCode: 'OAM',
    });
    const errOAM = taskOAM.validateSync();
    assert.strictEqual(errOAM, undefined, 'Task with Outreach and Marketing and OAM must pass schema validation');
  });

  test('1.2 TaskSchema validates region field and rejects invalid region', () => {
    const taskValidRegion = new Task({
      title: 'Valid Region Task',
      department: 'Welfare',
      departmentCode: 'WEL',
      region: 'Sindh',
    });
    assert.strictEqual(taskValidRegion.validateSync(), undefined);

    const taskInvalidRegion = new Task({
      title: 'Invalid Region Task',
      department: 'Welfare',
      departmentCode: 'WEL',
      region: 'Khyber',
    });
    const err = taskInvalidRegion.validateSync();
    assert(err && err.errors && err.errors.region, 'Task with invalid region Khyber must fail validation');
  });

  test('1.3 LeaveRequestSchema validates Welfare, Outreach and Marketing, and region field', () => {
    const leaveWelfare = new LeaveRequest({
      memberId: '6b052657bc489333fdf64931',
      memberName: 'Test Member',
      memberEmail: 'test@rekhta.org',
      department: 'Welfare',
      region: 'Punjab',
      startDate: new Date(),
      endDate: new Date(),
      reason: 'Medical Leave',
    });
    assert.strictEqual(leaveWelfare.validateSync(), undefined);

    const leaveOAM = new LeaveRequest({
      memberId: '6b052657bc489333fdf64931',
      memberName: 'Test Member',
      memberEmail: 'test@rekhta.org',
      department: 'Outreach and Marketing',
      startDate: new Date(),
      endDate: new Date(),
      reason: 'Personal Leave',
    });
    assert.strictEqual(leaveOAM.validateSync(), undefined);
  });

  test('1.4 AssessmentSchema validates Welfare and Outreach and Marketing', () => {
    const assessmentWelfare = new Assessment({
      memberId: '6b052657bc489333fdf64931',
      memberName: 'Test Member',
      evaluatorId: '6b052657bc489333fdf64931',
      evaluatorName: 'Test Evaluator',
      evaluatorRole: 'dept_welfare',
      department: 'Welfare',
      departmentCode: 'WEL',
      period: '2026-Q1',
      criteriaScores: { taskExecution: 8, deliverableQuality: 8, punctuality: 8, teamCollaboration: 8 },
      totalScore: 32,
      percentage: 80,
    });
    assert.strictEqual(assessmentWelfare.validateSync(), undefined);
  });

  test('1.5 AnnouncementSchema and CampaignSchema validate official departments', () => {
    const announcement = new Announcement({
      announcementId: 'ann_test_01',
      title: 'Official Announcement',
      message: 'Test Announcement Message',
      targetDepartment: 'Welfare',
      senderId: '6b052657bc489333fdf64931',
      senderName: 'HR Coordinator',
      senderRole: 'hr',
    });
    assert.strictEqual(announcement.validateSync(), undefined);

    const campaign = new Campaign({
      title: 'Welfare Volunteer Drive',
      department: 'Welfare',
      description: 'Volunteer recruitment for welfare programs',
    });
    assert.strictEqual(campaign.validateSync(), undefined);
  });

  // -------------------------------------------------------------------------
  // Group 2: SEC-02 & SEC-03 Active Membership Role Authorization & Context
  // -------------------------------------------------------------------------
  console.log('\n--- Group 2: SEC-02 & SEC-03 Multi-Department & Active Membership Authorization ---');

  const hashedPw = bcrypt.hashSync('Password123!', 8);

  const testUsers = [
    {
      _id: 'user_super_admin',
      id: 'user_super_admin',
      name: 'Super Admin',
      email: 'admin@rekhta.org',
      password: hashedPw,
      role: 'super_admin',
      status: 'active',
      tokenVersion: 0,
    },
    {
      _id: 'user_multi_dept',
      id: 'user_multi_dept',
      name: 'Noor ul Huda',
      email: 'noor@rekhta.org',
      password: hashedPw,
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      designation: 'member',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        {
          department: 'Literature',
          departmentCode: 'LIT',
          role: 'member',
          designation: 'member',
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
      _id: 'user_punjab_head',
      id: 'user_punjab_head',
      name: 'Asfand Yar Karimi',
      email: 'asfand@rekhta.org',
      password: hashedPw,
      role: 'dept_welfare',
      department: 'Welfare',
      departmentCode: 'WEL',
      designation: 'head_of_punjab',
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
      _id: 'user_sindh_head',
      id: 'user_sindh_head',
      name: 'Daniyal Asim',
      email: 'daniyal@rekhta.org',
      password: hashedPw,
      role: 'dept_welfare',
      department: 'Welfare',
      departmentCode: 'WEL',
      designation: 'head_of_sindh',
      region: 'Sindh',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        {
          department: 'Welfare',
          departmentCode: 'WEL',
          role: 'dept_welfare',
          designation: 'head_of_sindh',
          region: 'Sindh',
          isPrimary: true,
        },
      ],
    },
    {
      _id: 'user_punjab_member',
      id: 'user_punjab_member',
      name: 'Punjab Welfare Member',
      email: 'punjab.member@rekhta.org',
      password: hashedPw,
      role: 'member',
      department: 'Welfare',
      departmentCode: 'WEL',
      designation: 'member',
      region: 'Punjab',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        {
          department: 'Welfare',
          departmentCode: 'WEL',
          role: 'member',
          designation: 'member',
          region: 'Punjab',
          isPrimary: true,
        },
      ],
    },
    {
      _id: 'user_sindh_member',
      id: 'user_sindh_member',
      name: 'Sindh Welfare Member',
      email: 'sindh.member@rekhta.org',
      password: hashedPw,
      role: 'member',
      department: 'Welfare',
      departmentCode: 'WEL',
      designation: 'member',
      region: 'Sindh',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        {
          department: 'Welfare',
          departmentCode: 'WEL',
          role: 'member',
          designation: 'member',
          region: 'Sindh',
          isPrimary: true,
        },
      ],
    },
    {
      _id: 'user_oam_head',
      id: 'user_oam_head',
      name: 'Laiba Malik',
      email: 'laiba@rekhta.org',
      password: hashedPw,
      role: 'dept_oam',
      department: 'Outreach and Marketing',
      departmentCode: 'OAM',
      designation: 'head',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        {
          department: 'Outreach and Marketing',
          departmentCode: 'OAM',
          role: 'dept_oam',
          designation: 'head',
          isPrimary: true,
        },
      ],
    },
    {
      _id: 'user_literature_head',
      id: 'user_literature_head',
      name: 'Literature Lead',
      email: 'lit.lead@rekhta.org',
      password: hashedPw,
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      designation: 'head',
      status: 'active',
      tokenVersion: 0,
    },
    {
      _id: 'user_media_member',
      id: 'user_media_member',
      name: 'Media Exclusive Member',
      email: 'media.member@rekhta.org',
      password: hashedPw,
      role: 'member',
      department: 'Media',
      departmentCode: 'MED',
      designation: 'member',
      status: 'active',
      tokenVersion: 0,
    },
  ];

  testUsers.forEach((u) => setMemoryUser(u));

  // Build Express test server
  const app = express();
  app.use(express.json());
  app.use('/api/auth', require('../src/routes/auth.routes'));
  app.use('/api', require('../src/routes/portal.routes'));
  app.use('/api/hr', require('../src/routes/hr.routes').router);
  app.use('/api/finance', require('../src/routes/finance.routes').router);
  app.use('/api/assessments', require('../src/routes/assessment.routes'));

  const server = http.createServer(app);
  const PORT = 5066;

  await new Promise((resolve) => server.listen(PORT, resolve));

  function makeRequest(path, options = {}) {
    return new Promise((resolve, reject) => {
      const req = http.request(
        `http://127.0.0.1:${PORT}${path}`,
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
              const parsed = data ? JSON.parse(data) : {};
              resolve({ status: res.statusCode, headers: res.headers, data: parsed });
            } catch {
              resolve({ status: res.statusCode, headers: res.headers, raw: data });
            }
          });
        }
      );
      req.on('error', reject);
      if (options.body) {
        req.write(JSON.stringify(options.body));
      }
      req.end();
    });
  }

  function signToken(user) {
    return jwt.sign(
      {
        id: user.id || user._id,
        role: user.role,
        department: user.department,
        departmentCode: user.departmentCode,
        designation: user.designation,
        tokenVersion: user.tokenVersion || 0,
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
  }

  const tokenAdmin = signToken(getMemoryUser('user_super_admin'));
  const tokenMultiDept = signToken(getMemoryUser('user_multi_dept'));
  const tokenPunjabHead = signToken(getMemoryUser('user_punjab_head'));
  const tokenSindhHead = signToken(getMemoryUser('user_sindh_head'));
  const tokenPunjabMember = signToken(getMemoryUser('user_punjab_member'));
  const tokenOAMHead = signToken(getMemoryUser('user_oam_head'));
  const tokenLitHead = signToken(getMemoryUser('user_literature_head'));

  await testAsync('2.1 Multi-department user in default context (member) is rejected on task creation (403)', async () => {
    const res = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenMultiDept,
      body: { title: 'Unauthorized Task' },
    });
    assert.strictEqual(res.status, 403, 'User with primary role member must be rejected');
    assert.strictEqual(res.data.success, false);
  });

  await testAsync('2.2 Multi-department user with X-Department-Context: Content Creation is authorized to create task (201)', async () => {
    const res = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenMultiDept,
      headers: { 'X-Department-Context': 'Content Creation' },
      body: { title: 'Content Creation Head Task' },
    });
    assert.strictEqual(res.status, 201, 'User with active role dept_content must be authorized');
    assert.strictEqual(res.data.success, true);
    assert.strictEqual(res.data.task.department, 'Content Creation');
  });

  await testAsync('2.3 Unauthorized department context is rejected with 403 at middleware boundary', async () => {
    const res = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenMultiDept,
      headers: { 'X-Department-Context': 'HR' },
      body: { title: 'HR Escalation Task' },
    });
    assert.strictEqual(res.status, 403, 'Unauthorized department context must return 403');
    assert(res.data.error.includes('Unauthorized department context'));
  });

  await testAsync('2.4 Context switching cannot escalate to Finance (403)', async () => {
    const res = await makeRequest('/api/finance/overview', {
      method: 'GET',
      token: tokenMultiDept,
      headers: { 'X-Department-Context': 'Finance' },
    });
    assert.strictEqual(res.status, 403, 'Context switch to Finance without membership must be rejected');
  });

  await testAsync('2.5 Super Admin has global bypass across all protected routes', async () => {
    const res = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenAdmin,
      body: { title: 'Super Admin Global Task', department: 'Welfare', region: 'National' },
    });
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.data.task.department, 'Welfare');
    assert.strictEqual(res.data.task.region, 'National');
  });

  await testAsync('2.6 OAM Head (dept_oam) is authorized for task creation, assessments, and department expenses', async () => {
    const resTask = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenOAMHead,
      body: { title: 'OAM Campaign Strategy' },
    });
    assert.strictEqual(resTask.status, 201);
    assert.strictEqual(resTask.data.task.department, 'Outreach and Marketing');

    const resExp = await makeRequest('/api/finance/expenses/department', {
      method: 'GET',
      token: tokenOAMHead,
    });
    assert.strictEqual(resExp.status, 200);
    assert.strictEqual(resExp.data.department, 'Outreach and Marketing');
  });

  await testAsync('2.7 Welfare Head (dept_welfare) is authorized for department expenses', async () => {
    const resExp = await makeRequest('/api/finance/expenses/department', {
      method: 'GET',
      token: tokenPunjabHead,
    });
    assert.strictEqual(resExp.status, 200);
    assert.strictEqual(resExp.data.department, 'Welfare');
  });

  // -------------------------------------------------------------------------
  // Group 3: SEC-04 Welfare Strict Provincial Data Partitioning
  // -------------------------------------------------------------------------
  console.log('\n--- Group 3: SEC-04 Welfare Strict Provincial Data Partitioning ---');

  let punjabTaskId = null;
  let sindhTaskId = null;
  let nationalTaskId = null;

  await testAsync('3.1 Welfare Head of Punjab creates a task in Punjab (201)', async () => {
    const res = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenPunjabHead,
      body: { title: 'Punjab Winter Relief Drive', assignedTo: 'user_punjab_member' },
    });
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.data.task.department, 'Welfare');
    assert.strictEqual(res.data.task.region, 'Punjab');
    punjabTaskId = res.data.task.id || res.data.task._id;
  });

  await testAsync('3.2 Welfare Head of Punjab attempting to create a task in Sindh is rejected (403)', async () => {
    const res = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenPunjabHead,
      body: { title: 'Cross Province Task', region: 'Sindh' },
    });
    assert.strictEqual(res.status, 403);
    assert(res.data.error.includes('Regional Isolation Violation'));
  });

  await testAsync('3.3 Welfare Head of Punjab attempting to create a National task is rejected (403)', async () => {
    const res = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenPunjabHead,
      body: { title: 'Unauthorized National Task', region: 'National' },
    });
    assert.strictEqual(res.status, 403);
    assert(res.data.error.includes('Regional Isolation Violation'));
  });

  await testAsync('3.4 Welfare Head of Sindh creates a Sindh task and cannot create Punjab task (201, 403)', async () => {
    const resSindh = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenSindhHead,
      body: { title: 'Sindh Flood Relief Monitoring', assignedTo: 'user_sindh_member' },
    });
    assert.strictEqual(resSindh.status, 201);
    assert.strictEqual(resSindh.data.task.region, 'Sindh');
    sindhTaskId = resSindh.data.task.id || resSindh.data.task._id;

    const resPunjabAttempt = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenSindhHead,
      body: { title: 'Sindh Head into Punjab', region: 'Punjab' },
    });
    assert.strictEqual(resPunjabAttempt.status, 403);
    assert(resPunjabAttempt.data.error.includes('Regional Isolation Violation'));
  });

  await testAsync('3.5 Super Admin creates a National Welfare task (201)', async () => {
    const res = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenAdmin,
      body: { title: 'National Welfare Policy 2026', department: 'Welfare', region: 'National' },
    });
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.data.task.region, 'National');
    nationalTaskId = res.data.task.id || res.data.task._id;
  });

  await testAsync('3.6 Cross-region task assignment is strictly rejected (400)', async () => {
    const res = await makeRequest('/api/tasks', {
      method: 'POST',
      token: tokenPunjabHead,
      body: {
        title: 'Illegal Cross Assignment',
        assignedTo: 'user_sindh_member', // Assigning Punjab task to Sindh member
      },
    });
    assert.strictEqual(res.status, 400);
    assert(res.data.error.includes('Cross-Region Assignment Violation'));
  });

  await testAsync('3.7 Welfare Head of Punjab querying tasks receives Punjab + National, NEVER Sindh', async () => {
    const res = await makeRequest('/api/department/Welfare/tasks', {
      method: 'GET',
      token: tokenPunjabHead,
    });
    assert.strictEqual(res.status, 200);
    const regions = res.data.tasks.map((t) => t.region);
    assert(regions.includes('Punjab'), 'Must include Punjab tasks');
    assert(regions.includes('National'), 'Must include National tasks');
    assert(!regions.includes('Sindh'), 'Must strictly NEVER include Sindh tasks');
  });

  await testAsync('3.8 Welfare Head of Sindh querying tasks receives Sindh + National, NEVER Punjab', async () => {
    const res = await makeRequest('/api/department/Welfare/tasks', {
      method: 'GET',
      token: tokenSindhHead,
    });
    assert.strictEqual(res.status, 200);
    const regions = res.data.tasks.map((t) => t.region);
    assert(regions.includes('Sindh'), 'Must include Sindh tasks');
    assert(regions.includes('National'), 'Must include National tasks');
    assert(!regions.includes('Punjab'), 'Must strictly NEVER include Punjab tasks');
  });

  await testAsync('3.9 Welfare Head of Punjab querying members receives Punjab + National, NEVER Sindh', async () => {
    const res = await makeRequest('/api/department/Welfare/members', {
      method: 'GET',
      token: tokenPunjabHead,
    });
    assert.strictEqual(res.status, 200);
    const names = res.data.members.map((m) => m.name);
    assert(names.includes('Punjab Welfare Member'), 'Must include Punjab members');
    assert(!names.includes('Sindh Welfare Member'), 'Must strictly NEVER include Sindh members');
  });

  await testAsync('3.10 Punjab Head attempting to approve Sindh regional task is rejected (403)', async () => {
    const res = await makeRequest(`/api/tasks/${sindhTaskId}/final-approval`, {
      method: 'POST',
      token: tokenPunjabHead,
      body: { action: 'approve', notes: 'Unauthorized cross-region approval' },
    });
    assert.strictEqual(res.status, 403);
    assert(res.data.error.includes('Regional Access Violation'));
  });

  await testAsync('3.11 Punjab Head attempting to approve National Welfare task is rejected (403)', async () => {
    const res = await makeRequest(`/api/tasks/${nationalTaskId}/final-approval`, {
      method: 'POST',
      token: tokenPunjabHead,
      body: { action: 'approve' },
    });
    assert.strictEqual(res.status, 403);
    assert(res.data.error.includes('National Welfare tasks can only be approved by Super Admin'));
  });

  await testAsync('3.12 Leave Request regional isolation and review authority', async () => {
    // Member creates Punjab leave request
    const resLeavePunjab = await makeRequest('/api/hr/leaves', {
      method: 'POST',
      token: tokenPunjabMember,
      body: {
        startDate: '2026-12-01',
        endDate: '2026-12-05',
        reason: 'Exam preparation',
        leaveType: 'Exam',
      },
    });
    assert.strictEqual(resLeavePunjab.status, 201);
    const leaveId = resLeavePunjab.data.leave?.id || resLeavePunjab.data.leave?._id;

    // Sindh Head attempting to view Punjab leave request is rejected (403)
    const resSindhView = await makeRequest(`/api/hr/leaves/${leaveId}`, {
      method: 'GET',
      token: tokenSindhHead,
    });
    assert.strictEqual(resSindhView.status, 403);
    assert(resSindhView.data.error.includes('Regional Access Violation'));

    // Sindh Head attempting to approve Punjab leave request is rejected (403)
    const resSindhApprove = await makeRequest(`/api/hr/leaves/${leaveId}/review`, {
      method: 'PATCH',
      token: tokenSindhHead,
      body: { action: 'approve' },
    });
    assert.strictEqual(resSindhApprove.status, 403);
    assert(resSindhApprove.data.error.includes('Regional Access Violation'));

    // Punjab Head successfully approves Punjab leave request (200)
    const resPunjabApprove = await makeRequest(`/api/hr/leaves/${leaveId}/review`, {
      method: 'PATCH',
      token: tokenPunjabHead,
      body: { action: 'approve' },
    });
    assert.strictEqual(resPunjabApprove.status, 200);
    assert.strictEqual(resPunjabApprove.data.leave.status, 'approved');
  });

  // -------------------------------------------------------------------------
  // Group 4: SEC-05 Cross-Department Member Privacy
  // -------------------------------------------------------------------------
  console.log('\n--- Group 4: SEC-05 Cross-Department Member Privacy ---');

  await testAsync('4.1 Member self-access to personal tasks succeeds (200)', async () => {
    const res = await makeRequest('/api/members/user_punjab_member/tasks', {
      method: 'GET',
      token: tokenPunjabMember,
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
  });

  await testAsync('4.2 Regular member cannot view another member tasks (403)', async () => {
    const res = await makeRequest('/api/members/user_sindh_member/tasks', {
      method: 'GET',
      token: tokenPunjabMember,
    });
    assert.strictEqual(res.status, 403);
    assert(res.data.error.includes('Access denied'));
  });

  await testAsync('4.3 Super Admin has privileged access to any member tasks (200)', async () => {
    const res = await makeRequest('/api/members/user_punjab_member/tasks', {
      method: 'GET',
      token: tokenAdmin,
    });
    assert.strictEqual(res.status, 200);
  });

  await testAsync('4.4 Department Head (Literature) attempting to access tasks of Media-exclusive member is rejected (403)', async () => {
    const res = await makeRequest('/api/members/user_media_member/tasks', {
      method: 'GET',
      token: tokenLitHead,
    });
    assert.strictEqual(res.status, 403);
    assert(res.data.error.includes('Department Privacy Violation'));
  });

  await testAsync('4.5 Welfare Head of Punjab attempting to access tasks of Welfare Sindh member is rejected (403)', async () => {
    const res = await makeRequest('/api/members/user_sindh_member/tasks', {
      method: 'GET',
      token: tokenPunjabHead,
    });
    assert.strictEqual(res.status, 403);
    assert(res.data.error.includes('Regional Access Violation'));
  });

  await testAsync('4.6 Welfare Head of Punjab querying Punjab member tasks succeeds and returns Punjab tasks (200)', async () => {
    const res = await makeRequest('/api/members/user_punjab_member/tasks', {
      method: 'GET',
      token: tokenPunjabHead,
    });
    assert.strictEqual(res.status, 200);
    assert(res.data.tasks.every((t) => t.department === 'Welfare' && t.region === 'Punjab'));
  });

  server.close();

  console.log('\n================================================================');
  console.log(`TEST SUITE COMPLETE: ${passed}/${total} TESTS PASSED (100%)`);
  console.log('================================================================\n');
}

runTests().catch((err) => {
  console.error('[FATAL TEST ERROR]:', err);
  process.exit(1);
});
