/**
 * Phase 5.1 RBAC Consistency & Dashboard Security Verification Suite
 *
 * Validates:
 * 1. Strict 9-Role Architecture (super_admin, dept_literature, dept_media, dept_marketing,
 *    dept_outreach, dept_content, hr, finance, member). Rejection of legacy/generic roles.
 * 2. Staff Registration Security (POST /api/super-admin/users): Super Admin only, role validation,
 *    server-enforced department binding, password hashing, no public registration.
 * 3. Department Workspace Isolation: Scoped access for all 5 Dept Heads, cross-department blocking,
 *    regular member blocking.
 * 4. Task Ownership & Workflow Security: Cross-department assignment blocking, member anti-self-approval,
 *    tamper-proof history, restricted reassignment.
 * 5. Assessment Confidentiality: Blind submission, department scoping, strict Super Admin archive gating.
 * 6. Module Isolation: Strict boundary between HR, Finance, and Super Admin audit logs.
 */

const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

process.env.NODE_ENV = 'test';
process.env.PORT = '5007';
process.env.JWT_SECRET = 'test_secret_phase5_dashboards_access_secure';
process.env.JWT_REFRESH_SECRET = 'test_secret_phase5_dashboards_refresh_secure';

const app = require('../src/server');
const { User } = require('../src/models');
const {
  DEPT_ROLE_MAP,
  ALLOWED_ROLES,
  setMemoryUser,
  getMemoryUser,
} = require('../src/middleware/auth');

const TEST_PORT = 5007;
const JWT_SECRET = process.env.JWT_SECRET || 'rekhta_access_secret_2026_super_secure';

let server;
let passCount = 0;
let failCount = 0;

function assert(condition, testName, detail = '') {
  if (condition) {
    console.log(`[PASS] ${testName}`);
    passCount++;
  } else {
    console.error(`[FAIL] ${testName} ${detail ? '- ' + detail : ''}`);
    failCount++;
  }
}

// Helper: HTTP request wrapper
function request(method, path, body = null, token = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const reqHeaders = {
      'Content-Type': 'application/json',
      Origin: 'http://localhost:3000',
      'X-Requested-With': 'XMLHttpRequest',
      ...headers,
    };

    if (token) {
      reqHeaders['Authorization'] = `Bearer ${token}`;
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
        let rawData = '';
        res.on('data', (chunk) => {
          rawData += chunk;
        });
        res.on('end', () => {
          let data = null;
          try {
            data = JSON.parse(rawData);
          } catch {
            data = rawData;
          }
          resolve({ status: res.statusCode, data, headers: res.headers });
        });
      }
    );

    req.on('error', reject);

    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

// Generate JWT token for test identity
function makeToken(user) {
  const payload = {
    id: user._id || user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    department: user.department || DEPT_ROLE_MAP[user.role]?.name || null,
    departmentCode: user.departmentCode || DEPT_ROLE_MAP[user.role]?.code || null,
    status: user.status || 'active',
    isPrivilegedHR: Boolean(user.isPrivilegedHR),
    tokenVersion: user.tokenVersion || 0,
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

// Seed Users for all 9 roles and members
const testUsers = {
  superAdmin: {
    _id: 'usr_super_admin',
    id: 'usr_super_admin',
    name: 'Super Admin User',
    email: 'admin@rekhta.org',
    role: 'super_admin',
    department: 'Administration',
    status: 'active',
    tokenVersion: 0,
  },
  litHead: {
    _id: 'usr_head_lit',
    id: 'usr_head_lit',
    name: 'Noor-ul-Huda',
    email: 'lit.head@rekhta.org',
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    status: 'active',
    tokenVersion: 0,
  },
  medHead: {
    _id: 'usr_head_med',
    id: 'usr_head_med',
    name: 'Aisha Tariq',
    email: 'med.head@rekhta.org',
    role: 'dept_media',
    department: 'Media',
    departmentCode: 'MED',
    status: 'active',
    tokenVersion: 0,
  },
  mktHead: {
    _id: 'usr_head_mkt',
    id: 'usr_head_mkt',
    name: 'Ahmad Raza Waseem',
    email: 'mkt.head@rekhta.org',
    role: 'dept_marketing',
    department: 'Marketing',
    departmentCode: 'MKT',
    status: 'active',
    tokenVersion: 0,
  },
  outHead: {
    _id: 'usr_head_out',
    id: 'usr_head_out',
    name: 'Asfand Yar Karimi',
    email: 'out.head@rekhta.org',
    role: 'dept_outreach',
    department: 'Outreach',
    departmentCode: 'OUT',
    status: 'active',
    tokenVersion: 0,
  },
  conHead: {
    _id: 'usr_head_con',
    id: 'usr_head_con',
    name: 'Salman Mallana',
    email: 'con.head@rekhta.org',
    role: 'dept_content',
    department: 'Content Creation',
    departmentCode: 'CON',
    status: 'active',
    tokenVersion: 0,
  },
  hrLead: {
    _id: 'usr_hr_lead',
    id: 'usr_hr_lead',
    name: 'Hania Mehmood',
    email: 'hr.lead@rekhta.org',
    role: 'hr',
    department: 'HR',
    departmentCode: 'HR',
    status: 'active',
    tokenVersion: 0,
  },
  finLead: {
    _id: 'usr_fin_lead',
    id: 'usr_fin_lead',
    name: 'Ahmad Maqsood',
    email: 'fin.lead@rekhta.org',
    role: 'finance',
    department: 'Finance',
    departmentCode: 'FIN',
    status: 'active',
    tokenVersion: 0,
  },
  litMember1: {
    _id: 'usr_mem_lit_1',
    id: 'usr_mem_lit_1',
    name: 'Taha Hashmi',
    email: 'taha.lit@rekhta.org',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    status: 'active',
    tokenVersion: 0,
  },
  medMember1: {
    _id: 'usr_mem_med_1',
    id: 'usr_mem_med_1',
    name: 'Bilal Khan',
    email: 'bilal.med@rekhta.org',
    role: 'member',
    department: 'Media',
    departmentCode: 'MED',
    status: 'active',
    tokenVersion: 0,
  },
};

// Start test harness
async function startServer() {
  // Seed memory store
  Object.values(testUsers).forEach(setMemoryUser);

  return new Promise((resolve) => {
    server = app.listen(TEST_PORT, () => {
      resolve();
    });
  });
}

async function runTests() {
  console.log('======================================================================');
  console.log("  TA'MEER-E-REKHTA PHASE 5.1: RBAC & DASHBOARD SECURITY TEST SUITE   ");
  console.log('======================================================================\n');

  await startServer();

  const tokens = {};
  for (const [key, user] of Object.entries(testUsers)) {
    tokens[key] = makeToken(user);
  }

  try {
    // -------------------------------------------------------------------------
    // GROUP 1: ELEVEN-ROLE ARCHITECTURE ENFORCEMENT & MODEL INTEGRITY
    // -------------------------------------------------------------------------
    console.log('>>> [GROUP 1]: Eleven-Role Architecture & Model Integrity');

    const expectedApprovedRoles = [
      'super_admin',
      'dept_literature',
      'dept_media',
      'dept_marketing',
      'dept_outreach',
      'dept_oam',
      'dept_content',
      'dept_welfare',
      'hr',
      'finance',
      'member',
    ];

    // Test 1.1: ALLOWED_ROLES contains exactly the 11 approved roles
    const rolesMatch =
      ALLOWED_ROLES.length === 11 &&
      expectedApprovedRoles.every((r) => ALLOWED_ROLES.includes(r));
    assert(rolesMatch, 'Test 1.1: ALLOWED_ROLES strictly defines the 11 approved roles');

    // Test 1.2: User Mongoose Schema enum strictly contains only the 11 approved roles
    const userRoleEnum = User.schema.path('role').enumValues;
    const enumStrict =
      userRoleEnum.length === 11 &&
      expectedApprovedRoles.every((r) => userRoleEnum.includes(r)) &&
      !userRoleEnum.includes('department_head') &&
      !userRoleEnum.includes('finance_lead') &&
      !userRoleEnum.includes('hr_lead') &&
      !userRoleEnum.includes('volunteer');
    assert(
      enumStrict,
      'Test 1.2: User model schema strictly enforces 11 roles (no generic department_head or volunteer in enum)'
    );

    // Test 1.3: Super Admin cannot create a user with legacy/generic role ('department_head')
    const resCreateGeneric = await request(
      'POST',
      '/api/super-admin/users',
      {
        name: 'Generic Head',
        email: 'generic.head@rekhta.org',
        role: 'department_head',
        department: 'Literature',
      },
      tokens.superAdmin
    );
    assert(
      resCreateGeneric.status === 400 && resCreateGeneric.data.success === false,
      "Test 1.3: Creation of legacy generic role 'department_head' is rejected with 400 Bad Request"
    );

    // Test 1.4: Super Admin cannot create a user with unauthorized escalation role ('root' / 'admin')
    const resCreateEscalated = await request(
      'POST',
      '/api/super-admin/users',
      {
        name: 'Root Attempt',
        email: 'root@rekhta.org',
        role: 'root',
      },
      tokens.superAdmin
    );
    assert(
      resCreateEscalated.status === 400 && resCreateEscalated.data.success === false,
      "Test 1.4: Creation of unauthorized escalation role 'root' is rejected with 400 Bad Request"
    );

    // -------------------------------------------------------------------------
    // GROUP 2: STAFF REGISTRATION & SERVER-ENFORCED DEPARTMENT BINDING
    // -------------------------------------------------------------------------
    console.log('\n>>> [GROUP 2]: Staff Registration Security & Department Binding');

    // Test 2.1: Super Admin creates a dept_literature staff -> server enforces Literature department
    const resCreateLitStaff = await request(
      'POST',
      '/api/super-admin/users',
      {
        name: 'Fatima Literature Staff',
        email: 'fatima.lit@rekhta.org',
        role: 'dept_literature',
        department: 'Media', // Tampering attempt: claims Media for literature role
      },
      tokens.superAdmin
    );
    const litCreated = resCreateLitStaff.data?.user;
    assert(
      resCreateLitStaff.status === 201 &&
        litCreated?.role === 'dept_literature' &&
        litCreated?.department === 'Literature' &&
        litCreated?.departmentCode === 'LIT',
      'Test 2.1: Server overrides client tampering and strictly binds dept_literature to Literature (LIT)'
    );

    // Test 2.2: Super Admin creates HR account -> server binds to HR department
    const resCreateHR = await request(
      'POST',
      '/api/super-admin/users',
      {
        name: 'Zainab HR Officer',
        email: 'zainab.hr@rekhta.org',
        role: 'hr',
      },
      tokens.superAdmin
    );
    assert(
      resCreateHR.status === 201 &&
        resCreateHR.data?.user?.department === 'HR' &&
        resCreateHR.data?.user?.departmentCode === 'HR',
      'Test 2.2: HR account creation is strictly bound to HR department'
    );

    // Test 2.3: Super Admin creates Finance account -> server binds to Finance department
    const resCreateFin = await request(
      'POST',
      '/api/super-admin/users',
      {
        name: 'Usman Finance Officer',
        email: 'usman.fin@rekhta.org',
        role: 'finance',
      },
      tokens.superAdmin
    );
    assert(
      resCreateFin.status === 201 &&
        resCreateFin.data?.user?.department === 'Finance' &&
        resCreateFin.data?.user?.departmentCode === 'FIN',
      'Test 2.3: Finance account creation is strictly bound to Finance department'
    );

    // Test 2.4: Non-Super-Admin (Department Head) cannot create users via /api/super-admin/users
    const resDeptHeadCreate = await request(
      'POST',
      '/api/super-admin/users',
      {
        name: 'Illegal User',
        email: 'illegal@rekhta.org',
        role: 'member',
      },
      tokens.litHead
    );
    assert(
      resDeptHeadCreate.status === 403,
      'Test 2.4: Department Head attempting administrative staff creation is rejected with 403 Forbidden'
    );

    // Test 2.5: Regular member cannot create users via /api/super-admin/users
    const resMemberCreate = await request(
      'POST',
      '/api/super-admin/users',
      {
        name: 'Illegal Member',
        email: 'illegal.mem@rekhta.org',
        role: 'member',
      },
      tokens.litMember1
    );
    assert(
      resMemberCreate.status === 403,
      'Test 2.5: Regular member attempting administrative staff creation is rejected with 403 Forbidden'
    );

    // Test 2.6: Passwords are encrypted; plaintext is never persisted in storage
    const storedUser = getMemoryUser('fatima.lit@rekhta.org');
    const isBcrypt = storedUser && storedUser.password.startsWith('$2');
    assert(isBcrypt, 'Test 2.6: Created user password is verified to be hashed with bcrypt');

    // Test 2.7: Activation privilege escalation tampering is rejected
    const resTamperActivation = await request(
      'POST',
      '/api/auth/activate',
      {
        token: 'mock_activation_token_123',
        password: 'Password123!',
        role: 'super_admin',
        department: 'Administration',
      }
    );
    assert(
      resTamperActivation.status === 400 && resTamperActivation.data.success === false,
      'Test 2.7: Activation request with privilege escalation tampering (role/department) is rejected with 400'
    );

    // -------------------------------------------------------------------------
    // GROUP 3: DEPARTMENT WORKSPACE ISOLATION & BOUNDARY ENFORCEMENT
    // -------------------------------------------------------------------------
    console.log('\n>>> [GROUP 3]: Department Workspace Isolation');

    // Test 3.1: All 5 Department Heads can access their own workspace
    const deptWorkspaces = [
      { token: tokens.litHead, dept: 'Literature' },
      { token: tokens.medHead, dept: 'Media' },
      { token: tokens.mktHead, dept: 'Marketing' },
      { token: tokens.outHead, dept: 'Outreach' },
      { token: tokens.conHead, dept: 'Content Creation' },
    ];

    let allDeptsOk = true;
    for (const d of deptWorkspaces) {
      const res = await request('GET', `/api/department/${encodeURIComponent(d.dept)}/overview`, null, d.token);
      if (res.status !== 200 || !res.data.success) {
        allDeptsOk = false;
        break;
      }
    }
    assert(allDeptsOk, 'Test 3.1: All 5 distinct Department Heads access their own workspace overview (200 OK)');

    // Test 3.2: Literature Head accessing Media workspace is blocked
    const resCrossDept = await request('GET', '/api/department/Media/overview', null, tokens.litHead);
    assert(
      resCrossDept.status === 403,
      'Test 3.2: Literature Head attempting to access Media workspace is blocked with 403 Forbidden'
    );

    // Test 3.3: Literature Head accessing Media tasks is blocked
    const resCrossTasks = await request('GET', '/api/department/Media/tasks', null, tokens.litHead);
    assert(
      resCrossTasks.status === 403,
      'Test 3.3: Literature Head attempting to query Media department tasks is blocked with 403 Forbidden'
    );

    // Test 3.4: Literature Head accessing Media members is blocked
    const resCrossMembers = await request('GET', '/api/department/Media/members', null, tokens.litHead);
    assert(
      resCrossMembers.status === 403,
      'Test 3.4: Literature Head attempting to query Media members roster is blocked with 403 Forbidden'
    );

    // Test 3.5: Regular member attempting to access department workspace overview is blocked
    const resMemberDeptOverview = await request('GET', '/api/department/Literature/overview', null, tokens.litMember1);
    assert(
      resMemberDeptOverview.status === 403,
      'Test 3.5: Regular member attempting to access department workspace overview is blocked with 403 Forbidden'
    );

    // Test 3.6: Regular member attempting to access department tasks list is blocked
    const resMemberDeptTasks = await request('GET', '/api/department/Literature/tasks', null, tokens.litMember1);
    assert(
      resMemberDeptTasks.status === 403,
      'Test 3.6: Regular member attempting to access department tasks list is blocked with 403 Forbidden'
    );

    // -------------------------------------------------------------------------
    // GROUP 4: TASK ASSIGNMENT, OWNERSHIP & ANTI-SELF-APPROVAL
    // -------------------------------------------------------------------------
    console.log('\n>>> [GROUP 4]: Task Assignment & Anti-Self-Approval');

    // Test 4.1: Literature Head cannot assign a task to a Media member (Cross-department assignment)
    const resIllegalAssign = await request(
      'POST',
      '/api/tasks',
      {
        title: 'Cross-Dept Task Attempt',
        assignedTo: testUsers.medMember1.id,
      },
      tokens.litHead
    );
    assert(
      resIllegalAssign.status === 400 && resIllegalAssign.data.success === false,
      'Test 4.1: Department Head attempting cross-department task assignment is rejected with 400 Bad Request'
    );

    // Test 4.2: Literature Head assigns task to Literature member (Valid)
    const resValidTask = await request(
      'POST',
      '/api/tasks',
      {
        title: 'Kalam-e-Iqbal Poetic Critique',
        description: 'Prepare an academic analytical essay on Iqbal Shikwa and Jawab-e-Shikwa.',
        priority: 'high',
        assignedTo: testUsers.litMember1.id,
        assignedMemberName: testUsers.litMember1.name,
      },
      tokens.litHead
    );
    const createdTaskId = resValidTask.data?.task?._id || resValidTask.data?.task?.id;
    assert(
      resValidTask.status === 201 && createdTaskId,
      'Test 4.2: Department Head assigns task to authorized department member (201 Created)'
    );

    // Test 4.2b: Out-of-order rejection: Member cannot submit deliverable while task is still in 'assigned' status
    const resIllegalSubmitEarly = await request(
      'POST',
      `/api/tasks/${createdTaskId}/submit`,
      { notes: 'Premature submission before starting task' },
      tokens.litMember1
    );
    assert(
      resIllegalSubmitEarly.status === 400,
      "Test 4.2b: Out-of-order rejection: Member cannot submit deliverable while task is in 'assigned' status (400)"
    );

    // Test 4.3: Assigned member can advance task from assigned -> in_progress
    const resStartTask = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/status`,
      { status: 'in_progress', notes: 'Commencing research.' },
      tokens.litMember1
    );
    assert(
      resStartTask.status === 200 && resStartTask.data?.task?.status === 'in_progress',
      'Test 4.3: Assigned member transitions assigned task to in_progress (200 OK)'
    );

    // Test 4.3b: Out-of-order rejection: Department Head cannot review task while in 'in_progress' status
    const resIllegalReviewEarly = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/review`,
      { action: 'approve' },
      tokens.litHead
    );
    assert(
      resIllegalReviewEarly.status === 400,
      "Test 4.3b: Out-of-order rejection: Department Head cannot review task while in 'in_progress' status (400)"
    );

    // Test 4.4: ANTI-SELF-APPROVAL: Member CANNOT set status to 'approved'
    const resMemberSelfApprove = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/status`,
      { status: 'approved', notes: 'I hereby approve my own work!' },
      tokens.litMember1
    );
    assert(
      resMemberSelfApprove.status === 403,
      'Test 4.4: Member attempting to self-approve assigned task is strictly rejected with 403 Forbidden'
    );

    // Test 4.5: Member CANNOT set status to 'completed' or 'revision_requested'
    const resMemberComplete = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/status`,
      { status: 'completed' },
      tokens.litMember1
    );
    assert(
      resMemberComplete.status === 403,
      'Test 4.5: Member attempting arbitrary status transition to completed is strictly rejected with 403 Forbidden'
    );

    // Test 4.6: Unassigned member (Media member) cannot update Literature member's task
    const resUnassignedMember = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/status`,
      { status: 'in_progress' },
      tokens.medMember1
    );
    assert(
      resUnassignedMember.status === 403,
      "Test 4.6: Unassigned member attempting to update another member's task is rejected with 403 Forbidden"
    );

    // Test 4.7: Invalid status strings are rejected
    const resInvalidStatus = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/status`,
      { status: 'hacked_status' },
      tokens.superAdmin
    );
    assert(
      resInvalidStatus.status === 400,
      'Test 4.7: Invalid task status value rejected with 400 Bad Request'
    );

    // -------------------------------------------------------------------------
    // GROUP 5: WORKFLOW LIFECYCLE, SUBMISSION & TAMPER-PROOF HISTORY
    // -------------------------------------------------------------------------
    console.log('\n>>> [GROUP 5]: Workflow Lifecycle, Review & Tamper-Proof History');

    // Test 5.1: Member submits completed work
    const resSubmitWork = await request(
      'POST',
      `/api/tasks/${createdTaskId}/submit`,
      {
        notes: 'Full analysis draft completed with classical references.',
        links: ['https://drive.google.com/file/d/iqbal-analysis-doc'],
      },
      tokens.litMember1
    );
    assert(
      resSubmitWork.status === 200 && resSubmitWork.data?.task?.status === 'submitted',
      'Test 5.1: Member submits deliverable with external links and notes (status -> submitted)'
    );

    // Test 5.2: Member cannot self-review deliverable
    const resMemberReview = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/review`,
      { action: 'approve', feedback: 'Self approval.' },
      tokens.litMember1
    );
    assert(
      resMemberReview.status === 403,
      'Test 5.2: Member attempting to review deliverable is rejected with 403 Forbidden'
    );

    // Test 5.3: Cross-department head (Media Head) cannot review Literature task
    const resCrossReview = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/review`,
      { action: 'approve', feedback: 'Media head review.' },
      tokens.medHead
    );
    assert(
      resCrossReview.status === 403,
      'Test 5.3: Media Head attempting to review Literature deliverable is rejected with 403 Forbidden'
    );

    // Test 5.4: Literature Head requests revision
    const resRevision = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/review`,
      { action: 'request_revision', revisionNotes: 'Please add poetic meter scansion analysis.' },
      tokens.litHead
    );
    assert(
      resRevision.status === 200 && resRevision.data?.task?.status === 'revision_requested',
      'Test 5.4: Department Head reviews submission and requests revision (status -> revision_requested)'
    );

    // Test 5.4b: Mandatory Restart: Member CANNOT submit deliverable directly from 'revision_requested' without restarting
    const resPrematureResubmit = await request(
      'POST',
      `/api/tasks/${createdTaskId}/submit`,
      { notes: 'Attempting to resubmit without restarting task' },
      tokens.litMember1
    );
    assert(
      resPrematureResubmit.status === 400,
      "Test 5.4b: Mandatory Restart: Member cannot submit directly from 'revision_requested' without restarting (400)"
    );

    // Test 5.5: Member restarts task (in_progress) and re-submits deliverable
    const resRestartTask = await request('PATCH', `/api/tasks/${createdTaskId}/status`, { status: 'in_progress' }, tokens.litMember1);
    const resResubmit = await request(
      'POST',
      `/api/tasks/${createdTaskId}/submit`,
      {
        notes: 'Revised with meter scansion table included.',
        links: ['https://drive.google.com/file/d/iqbal-analysis-v2'],
      },
      tokens.litMember1
    );
    assert(
      resRestartTask.status === 200 && resResubmit.status === 200 && resResubmit.data?.task?.status === 'submitted',
      'Test 5.5: Member restarts work (in_progress) and re-submits deliverable (status -> submitted)'
    );

    // Test 5.6: Department Head approves revised deliverable (approved)
    const resApprove = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/review`,
      { action: 'approve', feedback: 'Outstanding academic rigor. Approved!' },
      tokens.litHead
    );
    assert(
      resApprove.status === 200 && resApprove.data?.task?.status === 'approved',
      'Test 5.6: Department Head approves revised deliverable (status -> approved)'
    );

    // Test 5.6b: Operational Closure: Task transitions to 'completed' with completion timestamp
    const resComplete = await request(
      'PATCH',
      `/api/tasks/${createdTaskId}/review`,
      { action: 'complete', feedback: 'Final archival and publication sign-off.' },
      tokens.litHead
    );
    assert(
      resComplete.status === 200 &&
        resComplete.data?.task?.status === 'completed' &&
        resComplete.data?.task?.completedAt,
      'Test 5.6b: Supervisor marks approved task as completed with completedAt timestamp'
    );

    // Test 5.7: Tamper-proof history verification
    const finalHistory = resApprove.data?.task?.history;
    const historyPreserved =
      Array.isArray(finalHistory) &&
      finalHistory.length >= 5 &&
      finalHistory.some((h) => h.status === 'revision_requested') &&
      finalHistory.some((h) => h.status === 'approved');
    assert(
      historyPreserved,
      'Test 5.7: Tamper-proof history preserved across complete multi-stage review cycle'
    );

    // -------------------------------------------------------------------------
    // GROUP 6: TASK REASSIGNMENT SECURITY
    // -------------------------------------------------------------------------
    console.log('\n>>> [GROUP 6]: Task Reassignment Security');

    // Create a new task to test reassignment
    const resTaskForReassign = await request(
      'POST',
      '/api/tasks',
      {
        title: 'Urdu Lexicon Documentation',
        priority: 'medium',
        assignedTo: testUsers.litMember1.id,
      },
      tokens.litHead
    );
    const reassignTaskId = resTaskForReassign.data?.task?._id || resTaskForReassign.data?.task?.id;

    // Test 6.1: Member cannot reassign tasks
    const resMemberReassign = await request(
      'PATCH',
      `/api/tasks/${reassignTaskId}/reassign`,
      { assignedTo: testUsers.medMember1.id },
      tokens.litMember1
    );
    assert(
      resMemberReassign.status === 403,
      'Test 6.1: Regular member attempting task reassignment is rejected with 403 Forbidden'
    );

    // Test 6.2: Department Head cannot reassign task to member of another department
    const resCrossReassign = await request(
      'PATCH',
      `/api/tasks/${reassignTaskId}/reassign`,
      { assignedTo: testUsers.medMember1.id },
      tokens.litHead
    );
    assert(
      resCrossReassign.status === 400 && resCrossReassign.data.success === false,
      'Test 6.2: Department Head attempting reassignment to another department member rejected with 400'
    );

    // -------------------------------------------------------------------------
    // GROUP 7: ASSESSMENT CONFIDENTIALITY & EVALUATION SCOPE
    // -------------------------------------------------------------------------
    console.log('\n>>> [GROUP 7]: Assessment Confidentiality & Scoping');

    // Test 7.1: Department Head submits blind assessment for department member
    const resValidAssessment = await request(
      'POST',
      '/api/assessments',
      {
        memberId: testUsers.litMember1.id,
        memberName: testUsers.litMember1.name,
        department: 'Literature',
        period: '2026-Q4',
        criteriaScores: {
          taskExecution: 9,
          deliverableQuality: 9,
          punctuality: 8,
          teamCollaboration: 9,
        },
        qualitativeFeedback: 'Exemplary scholarly research.',
      },
      tokens.litHead
    );
    assert(
      resValidAssessment.status === 201 &&
        resValidAssessment.data.success === true &&
        resValidAssessment.data.assessmentId &&
        resValidAssessment.data.totalScore === undefined && // Blind: scores never returned
        resValidAssessment.data.criteriaScores === undefined,
      'Test 7.1: Department Head submits blind performance assessment (201 Created, score strictly omitted)'
    );

    // Test 7.2: Department Head attempting assessment for member of another department is rejected
    const resCrossAssessment = await request(
      'POST',
      '/api/assessments',
      {
        memberId: testUsers.medMember1.id, // Member belongs to Media!
        memberName: testUsers.medMember1.name,
        department: 'Literature',
        period: '2026-Q4',
        criteriaScores: {
          taskExecution: 8,
          deliverableQuality: 8,
          punctuality: 8,
          teamCollaboration: 8,
        },
      },
      tokens.litHead
    );
    assert(
      resCrossAssessment.status === 403,
      'Test 7.2: Department Head evaluating member of another department is rejected with 403 Forbidden'
    );

    // Test 7.3: Department Head cannot retrieve assessment archive
    const resDeptGetAssessments = await request('GET', '/api/assessments', null, tokens.litHead);
    assert(
      resDeptGetAssessments.status === 403,
      'Test 7.3: Department Head attempting to query assessment archive is rejected with 403 Forbidden'
    );

    // Test 7.4: Department Head cannot retrieve single assessment
    const resDeptGetSingleAssessment = await request(
      'GET',
      `/api/assessments/${resValidAssessment.data?.assessmentId || 'mock_id'}`,
      null,
      tokens.litHead
    );
    assert(
      resDeptGetSingleAssessment.status === 403,
      'Test 7.4: Department Head attempting to query individual assessment is rejected with 403 Forbidden'
    );

    // Test 7.5: Regular member cannot retrieve assessment archive
    const resMemberGetAssessments = await request('GET', '/api/assessments', null, tokens.litMember1);
    assert(
      resMemberGetAssessments.status === 403,
      'Test 7.5: Regular member attempting to query assessment archive is rejected with 403 Forbidden'
    );

    // Test 7.6: Super Admin is strictly authorized to retrieve confidential assessments
    const resSuperAdminAssessments = await request('GET', '/api/assessments', null, tokens.superAdmin);
    assert(
      resSuperAdminAssessments.status === 200 && resSuperAdminAssessments.data.success === true,
      'Test 7.6: Super Admin strictly authorized to retrieve confidential grading archive (200 OK)'
    );

    // -------------------------------------------------------------------------
    // GROUP 8: MODULE ISOLATION (FINANCE, HR, AUDIT LOGS)
    // -------------------------------------------------------------------------
    console.log('\n>>> [GROUP 8]: Module Isolation (Finance, HR & Super Admin Audit)');

    // Test 8.1: HR cannot access Finance Income ledger
    const resHRAccessFinance = await request('GET', '/api/finance/income', null, tokens.hrLead);
    assert(
      resHRAccessFinance.status === 403,
      'Test 8.1: HR role attempting to access Finance Income records is rejected with 403 Forbidden'
    );

    // Test 8.1b: Finance stats accessible by Finance, blocked for HR and Member
    const resFinStats = await request('GET', '/api/finance/stats', null, tokens.finLead);
    const resFinStatsHR = await request('GET', '/api/finance/stats', null, tokens.hrLead);
    const resFinStatsMem = await request('GET', '/api/finance/stats', null, tokens.litMember1);
    assert(
      resFinStats.status === 200 && resFinStatsHR.status === 403 && resFinStatsMem.status === 403,
      'Test 8.1b: Finance summary stats authorized for Finance (200), strictly blocked for HR and Members (403)'
    );

    // Test 8.1c: Single income record lookup blocked for HR and Members
    const resFinSingleHR = await request('GET', '/api/finance/income/mock_inc_123', null, tokens.hrLead);
    const resFinSingleMem = await request('GET', '/api/finance/income/mock_inc_123', null, tokens.litMember1);
    assert(
      resFinSingleHR.status === 403 && resFinSingleMem.status === 403,
      'Test 8.1c: Single Finance income record lookup blocked for HR and Members (403 Forbidden)'
    );

    // Test 8.2: Finance cannot access HR Recruitment Applications
    const resFinanceAccessHR = await request('GET', '/api/recruitment/applications', null, tokens.finLead);
    assert(
      resFinanceAccessHR.status === 403,
      'Test 8.2: Finance role attempting to access HR Recruitment Applications is rejected with 403 Forbidden'
    );

    // Test 8.2b: Recruitment stats accessible by HR, blocked for Finance and Members
    const resHRStats = await request('GET', '/api/recruitment/stats', null, tokens.hrLead);
    const resHRStatsFin = await request('GET', '/api/recruitment/stats', null, tokens.finLead);
    const resHRStatsMem = await request('GET', '/api/recruitment/stats', null, tokens.litMember1);
    assert(
      resHRStats.status === 200 && resHRStatsFin.status === 403 && resHRStatsMem.status === 403,
      'Test 8.2b: HR Recruitment summary stats authorized for HR (200), strictly blocked for Finance and Members (403)'
    );

    // Test 8.2c: Single recruitment application lookup blocked for Finance and Members
    const resHRSingleFin = await request('GET', '/api/recruitment/applications/mock_app_123', null, tokens.finLead);
    const resHRSingleMem = await request('GET', '/api/recruitment/applications/mock_app_123', null, tokens.litMember1);
    assert(
      resHRSingleFin.status === 403 && resHRSingleMem.status === 403,
      'Test 8.2c: Single Recruitment application lookup blocked for Finance and Members (403 Forbidden)'
    );

    // Test 8.2d: Candidate status update blocked for Finance and Members
    const resHRStatusFin = await request('PATCH', '/api/recruitment/applications/mock_app_123/status', { status: 'accepted' }, tokens.finLead);
    const resHRStatusMem = await request('PATCH', '/api/recruitment/applications/mock_app_123/status', { status: 'accepted' }, tokens.litMember1);
    assert(
      resHRStatusFin.status === 403 && resHRStatusMem.status === 403,
      'Test 8.2d: Recruitment application status update blocked for Finance and Members (403 Forbidden)'
    );

    // Test 8.3: Department Head cannot access Super Admin Audit Trail
    const resDeptAccessAudit = await request('GET', '/api/super-admin/audit-logs', null, tokens.litHead);
    assert(
      resDeptAccessAudit.status === 403,
      'Test 8.3: Department Head attempting to access Super Admin Audit Trail is rejected with 403 Forbidden'
    );

    // Test 8.4: Member cannot access Super Admin Audit Trail
    const resMemberAccessAudit = await request('GET', '/api/super-admin/audit-logs', null, tokens.litMember1);
    assert(
      resMemberAccessAudit.status === 403,
      'Test 8.4: Member attempting to access Super Admin Audit Trail is rejected with 403 Forbidden'
    );

    // Test 8.5: Super Admin can access Audit Trail
    const resAdminAudit = await request('GET', '/api/super-admin/audit-logs', null, tokens.superAdmin);
    assert(
      resAdminAudit.status === 200 && resAdminAudit.data.success === true,
      'Test 8.5: Super Admin authorized to access organization-wide Audit Trail (200 OK)'
    );
  } finally {
    if (server) {
      server.close();
    }
  }

  console.log('\n======================================================================');
  console.log(`PHASE 5.1 RBAC & SECURITY AUDIT RESULTS: ${passCount} PASSED, ${failCount} FAILED (TOTAL: ${passCount + failCount})`);
  console.log('======================================================================\n');

  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal Test Runner Exception:', err);
  if (server) server.close();
  process.exit(1);
});
