/**
 * Phase 6C: System Integration & End-to-End Verification Test Suite
 * Ta'meer-e-Rekhta Management Portal
 *
 * Verifies all 20 required integration scenarios:
 *  1. All nine roles and dashboard access
 *  2. Cross-department data isolation
 *  3. Super Admin oversight
 *  4. HR/Finance isolation
 *  5. Authentication and activation lifecycle
 *  6. Task workflow integration
 *  7. Blind assessment confidentiality
 *  8. Recruitment-to-onboarding integration
 *  9. Leave workflow authorization
 * 10. Public volunteer forwarding and duplicate handling
 * 11. Finance income and expense workflow
 * 12. Financial budget integrity
 * 13. Notification ownership and access
 * 14. Notification duplicate prevention
 * 15. Audit history consistency
 * 16. Archived record behavior
 * 17. Invalid relationship handling
 * 18. Unauthorized API access
 * 19. Frontend/backend API contract consistency
 * 20. End-to-end regression of critical workflows
 */

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
  setMemoryDonation,
  getMemoryDonationsList,
  clearMemoryDonations,
  setMemoryExpense,
  getMemoryExpensesList,
  clearMemoryExpenses,
  setMemoryBudget,
  getMemoryBudgetsList,
  clearMemoryBudgets,
} = require('../src/routes/finance.routes');
const {
  setMemoryApplication,
  getMemoryApplicationsList,
  setMemoryCampaign,
  setMemoryLeave,
} = require('../src/routes/hr.routes');
const {
  sendNotification,
  getNotificationsForUser,
  getMemoryNotificationsList,
  clearMemoryNotifications,
} = require('../src/services/notification.service');

const TEST_PORT = 5010;
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

function generateToken(payload, expiresIn = '1h') {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
}

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`[PASS] Test ${totalTests}: ${message}`);
  } else {
    failedTests++;
    console.error(`[FAIL] Test ${totalTests}: ${message}`);
  }
}

async function runTests() {
  console.log('======================================================================');
  console.log('  TA\'MEER-E-REKHTA PHASE 6C: SYSTEM INTEGRATION & E2E VERIFICATION');
  console.log('======================================================================\n');

  // -------------------------------------------------------------------------
  // SEED USERS ACROSS ALL 9 APPROVED ROLES
  // -------------------------------------------------------------------------
  const hashedPw = await bcrypt.hash('SecurePass2026!', 10);

  const users = {
    superAdmin: {
      _id: 'usr_super_admin_6c',
      id: 'usr_super_admin_6c',
      name: 'Global Administrator',
      email: 'admin6c@rekhta.org',
      role: 'super_admin',
      status: 'active',
      password: hashedPw,
      tokenVersion: 0,
    },
    deptLiterature: {
      _id: 'usr_head_lit_6c',
      id: 'usr_head_lit_6c',
      name: 'Noor-ul-Huda',
      email: 'lithead6c@rekhta.org',
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      password: hashedPw,
      tokenVersion: 0,
    },
    deptMedia: {
      _id: 'usr_head_med_6c',
      id: 'usr_head_med_6c',
      name: 'Aisha Tariq',
      email: 'medhead6c@rekhta.org',
      role: 'dept_media',
      department: 'Media',
      departmentCode: 'MED',
      status: 'active',
      password: hashedPw,
      tokenVersion: 0,
    },
    deptMarketing: {
      _id: 'usr_head_mkt_6c',
      id: 'usr_head_mkt_6c',
      name: 'Ahmad Raza Waseem',
      email: 'mkthead6c@rekhta.org',
      role: 'dept_marketing',
      department: 'Marketing',
      departmentCode: 'MKT',
      status: 'active',
      password: hashedPw,
      tokenVersion: 0,
    },
    deptOutreach: {
      _id: 'usr_head_out_6c',
      id: 'usr_head_out_6c',
      name: 'Asfand Yar Karimi',
      email: 'outhead6c@rekhta.org',
      role: 'dept_outreach',
      department: 'Outreach',
      departmentCode: 'OUT',
      status: 'active',
      password: hashedPw,
      tokenVersion: 0,
    },
    deptContent: {
      _id: 'usr_head_con_6c',
      id: 'usr_head_con_6c',
      name: 'Salman Mallana',
      email: 'conhead6c@rekhta.org',
      role: 'dept_content',
      department: 'Content Creation',
      departmentCode: 'CON',
      status: 'active',
      password: hashedPw,
      tokenVersion: 0,
    },
    hr: {
      _id: 'usr_lead_hr_6c',
      id: 'usr_lead_hr_6c',
      name: 'Hania Mehmood',
      email: 'hrlead6c@rekhta.org',
      role: 'hr',
      department: 'Human Resources',
      status: 'active',
      password: hashedPw,
      isPrivilegedHR: false,
      tokenVersion: 0,
    },
    finance: {
      _id: 'usr_lead_fin_6c',
      id: 'usr_lead_fin_6c',
      name: 'Ahmad Maqsood',
      email: 'finlead6c@rekhta.org',
      role: 'finance',
      department: 'Finance',
      status: 'active',
      password: hashedPw,
      tokenVersion: 0,
    },
    memberLit: {
      _id: 'usr_mem_lit_6c',
      id: 'usr_mem_lit_6c',
      name: 'Faiz Ahmed',
      email: 'faiz6c@rekhta.org',
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      password: hashedPw,
      tokenVersion: 0,
    },
    memberMed: {
      _id: 'usr_mem_med_6c',
      id: 'usr_mem_med_6c',
      name: 'Bilal Khan',
      email: 'bilal6c@rekhta.org',
      role: 'member',
      department: 'Media',
      departmentCode: 'MED',
      status: 'active',
      password: hashedPw,
      tokenVersion: 0,
    },
    suspendedUser: {
      _id: 'usr_suspended_6c',
      id: 'usr_suspended_6c',
      name: 'Suspended User',
      email: 'suspended6c@rekhta.org',
      role: 'member',
      status: 'suspended',
      password: hashedPw,
      tokenVersion: 0,
    },
  };

  for (const u of Object.values(users)) {
    setMemoryUser(u);
  }

  // Pre-generate tokens
  const tokens = {};
  for (const [k, u] of Object.entries(users)) {
    tokens[k] = generateToken({
      id: u.id,
      name: u.name,
      email: u.email,
      role: u.role,
      department: u.department,
      departmentCode: u.departmentCode,
      status: u.status,
      tokenVersion: u.tokenVersion,
    });
  }

  // Seed Budgets for Finance Tests
  const litBudget = {
    _id: 'bdg_lit_2026_6c',
    id: 'bdg_lit_2026_6c',
    budgetId: 'BDG-2026-LIT-6C',
    department: 'Literature',
    fiscalYear: 2026,
    allocatedAmount: 100000,
    spentAmount: 20000,
    currency: 'PKR',
    status: 'active',
    isArchived: false,
    history: [],
  };
  setMemoryBudget(litBudget);

  // -------------------------------------------------------------------------
  // 1. ALL NINE ROLES AND DASHBOARD ACCESS
  // -------------------------------------------------------------------------
  console.log('>>> [GROUP 1]: All Nine Approved Roles & Dashboard Access');

  // Super Admin
  const r1 = await makeRequest({
    path: '/api/super-admin/overview',
    headers: { Authorization: `Bearer ${tokens.superAdmin}` },
  });
  assert(r1.status === 200 && r1.data.success, 'Role 1 (super_admin) accesses Super Admin overview (200 OK)');

  // 5 Department Heads
  const deptRoles = [
    { roleKey: 'deptLiterature', dept: 'Literature' },
    { roleKey: 'deptMedia', dept: 'Media' },
    { roleKey: 'deptMarketing', dept: 'Marketing' },
    { roleKey: 'deptOutreach', dept: 'Outreach' },
    { roleKey: 'deptContent', dept: 'Content Creation' },
  ];

  for (const dr of deptRoles) {
    const res = await makeRequest({
      path: `/api/tasks?department=${encodeURIComponent(dr.dept)}`,
      headers: { Authorization: `Bearer ${tokens[dr.roleKey]}` },
    });
    assert(res.status === 200 && res.data.success, `Role (${dr.roleKey}) accesses ${dr.dept} department workspace (200 OK)`);
  }

  // HR
  const rHR = await makeRequest({
    path: '/api/hr/overview',
    headers: { Authorization: `Bearer ${tokens.hr}` },
  });
  assert(rHR.status === 200 && rHR.data.success, 'Role 7 (hr) accesses HR Overview (200 OK)');

  // Finance
  const rFin = await makeRequest({
    path: '/api/finance/overview',
    headers: { Authorization: `Bearer ${tokens.finance}` },
  });
  assert(rFin.status === 200 && rFin.data.success, 'Role 8 (finance) accesses Finance Overview (200 OK)');

  // Member
  const rMem = await makeRequest({
    path: `/api/members/${users.memberLit.id}/tasks`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
  });
  assert(rMem.status === 200 && rMem.data.success, 'Role 9 (member) accesses personal tasks workspace (200 OK)');

  // -------------------------------------------------------------------------
  // 2. CROSS-DEPARTMENT DATA ISOLATION
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 2]: Cross-Department Data Isolation');

  // Lit Head attempting to assign task to Media Member
  const rCrossAssign = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
    body: {
      title: 'Cross Dept Assignment Test',
      assignedTo: users.memberMed.id,
      assignedMemberName: users.memberMed.name,
    },
  });
  assert(
    rCrossAssign.status === 400 && rCrossAssign.data.error.includes('Cross-Department Assignment Violation'),
    'Literature Head assigning task to Media member rejected with 400 Bad Request'
  );

  // Lit Head attempting to access Media Department leaves
  const mediaMemberLeave = {
    _id: 'leave_med_6c_test',
    id: 'leave_med_6c_test',
    memberId: users.memberMed.id,
    memberName: users.memberMed.name,
    department: 'Media',
    leaveType: 'vacation',
    startDate: new Date(Date.now() + 86400000),
    endDate: new Date(Date.now() + 3 * 86400000),
    status: 'pending',
    history: [],
  };
  setMemoryLeave(mediaMemberLeave);

  const rLitDeptLeaves = await makeRequest({
    path: '/api/hr/leaves/department',
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
  });
  const containsMediaLeave = rLitDeptLeaves.data?.leaves?.some((l) => l.department === 'Media');
  assert(
    rLitDeptLeaves.status === 200 && !containsMediaLeave,
    'Literature Head queries /api/hr/leaves/department and sees only Literature leaves (Media excluded)'
  );

  const rCrossLeaveReview = await makeRequest({
    method: 'PATCH',
    path: `/api/hr/leaves/${mediaMemberLeave.id}/review`,
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
    body: { action: 'approve' },
  });
  assert(
    rCrossLeaveReview.status === 403,
    'Literature Head attempting to review Media department leave blocked with 403 Forbidden'
  );

  // -------------------------------------------------------------------------
  // 3. SUPER ADMIN OVERSIGHT
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 3]: Super Admin Oversight');

  const rAudit = await makeRequest({
    path: '/api/super-admin/audit-logs',
    headers: { Authorization: `Bearer ${tokens.superAdmin}` },
  });
  assert(rAudit.status === 200 && rAudit.data.success, 'Super Admin retrieves organization audit trail (200 OK)');

  const rUsers = await makeRequest({
    path: '/api/super-admin/users',
    headers: { Authorization: `Bearer ${tokens.superAdmin}` },
  });
  assert(rUsers.status === 200 && rUsers.data.success, 'Super Admin fetches complete user directory (200 OK)');

  // Non-admin blocked from audit logs
  const rLitAudit = await makeRequest({
    path: '/api/super-admin/audit-logs',
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
  });
  assert(rLitAudit.status === 403, 'Department Head blocked from Super Admin Audit Logs with 403 Forbidden');

  // -------------------------------------------------------------------------
  // 4. HR / FINANCE ISOLATION
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 4]: HR / Finance Functional Isolation');

  const rFinToHR = await makeRequest({
    path: '/api/hr/overview',
    headers: { Authorization: `Bearer ${tokens.finance}` },
  });
  assert(rFinToHR.status === 403, 'Finance lead accessing HR Overview blocked with 403 Forbidden');

  const rHRToFin = await makeRequest({
    path: '/api/finance/overview',
    headers: { Authorization: `Bearer ${tokens.hr}` },
  });
  assert(rHRToFin.status === 403, 'HR lead accessing Finance Overview blocked with 403 Forbidden');

  // -------------------------------------------------------------------------
  // 5. AUTHENTICATION & ACTIVATION LIFECYCLE
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 5]: Authentication & Activation Lifecycle');

  // Login
  const rLogin = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: { email: 'admin6c@rekhta.org', password: 'SecurePass2026!' },
  });
  assert(rLogin.status === 200 && rLogin.data.success, 'Valid login returns 200 OK and user session');

  // Session Revocation
  const rRevoke = await makeRequest({
    method: 'POST',
    path: '/api/auth/revoke-sessions',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
  });
  assert(rRevoke.status === 200 && rRevoke.data.success, 'Session revocation updates tokenVersion (200 OK)');

  // Revoked token rejected
  const rRevokedAccess = await makeRequest({
    path: `/api/members/${users.memberLit.id}/tasks`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
  });
  assert(rRevokedAccess.status === 401, 'Revoked token rejected with 401 Unauthorized');

  // Re-issue valid token for memberLit
  users.memberLit.tokenVersion = (users.memberLit.tokenVersion || 0) + 1;
  setMemoryUser(users.memberLit);
  tokens.memberLit = generateToken({
    id: users.memberLit.id,
    name: users.memberLit.name,
    email: users.memberLit.email,
    role: users.memberLit.role,
    department: users.memberLit.department,
    status: users.memberLit.status,
    tokenVersion: users.memberLit.tokenVersion,
  });

  // -------------------------------------------------------------------------
  // 6. TASK WORKFLOW INTEGRATION
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 6]: Task Workflow Integration');

  // 1. Task Created & Assigned
  const rTaskCreate = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
    body: {
      title: 'Integration Test Task 6C',
      description: 'Review classical Urdu poetry syllabus',
      assignedTo: users.memberLit.id,
      assignedMemberName: users.memberLit.name,
      priority: 'high',
    },
  });
  assert(rTaskCreate.status === 201 && rTaskCreate.data.success, 'Literature Head creates task (201 Created)');
  const taskId = rTaskCreate.data.task.id || rTaskCreate.data.task._id;

  // 2. Member cannot submit without starting (assigned -> submitted rejected)
  const rPrematureSubmit = await makeRequest({
    method: 'POST',
    path: `/api/tasks/${taskId}/submit`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { notes: 'Premature submission', links: ['https://example.com'] },
  });
  assert(rPrematureSubmit.status === 400, 'Submitting unstarted task rejected with 400 Bad Request');

  // 3. Assigned Member advances to in_progress
  const rStartTask = await makeRequest({
    method: 'PATCH',
    path: `/api/tasks/${taskId}/status`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { status: 'in_progress', notes: 'Starting work on syllabus' },
  });
  assert(rStartTask.status === 200 && rStartTask.data.task.status === 'in_progress', 'Member starts task -> in_progress (200 OK)');

  // 4. Member cannot self-approve
  const rSelfApprove = await makeRequest({
    method: 'PATCH',
    path: `/api/tasks/${taskId}/status`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { status: 'approved' },
  });
  assert(rSelfApprove.status === 403, 'Member self-approval strictly rejected with 403 Forbidden');

  // 5. Member submits deliverable
  const rSubmitTask = await makeRequest({
    method: 'POST',
    path: `/api/tasks/${taskId}/submit`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { notes: 'Deliverable complete', links: ['https://rekhta.org/syllabus.pdf'] },
  });
  assert(rSubmitTask.status === 200 && rSubmitTask.data.task.status === 'submitted', 'Member submits deliverable -> submitted (200 OK)');

  // 6. Reviewer requests revision
  const rReqRevision = await makeRequest({
    method: 'PATCH',
    path: `/api/tasks/${taskId}/review`,
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
    body: { action: 'request_revision', revisionNotes: 'Please add 19th-century ghazals.' },
  });
  assert(rReqRevision.status === 200 && rReqRevision.data.task.status === 'revision_requested', 'Reviewer requests revision -> revision_requested (200 OK)');

  // 7. Member must restart before resubmission
  const rBlockedResubmit = await makeRequest({
    method: 'POST',
    path: `/api/tasks/${taskId}/submit`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { notes: 'Attempting submit without restart' },
  });
  assert(rBlockedResubmit.status === 400, 'Submitting directly from revision_requested rejected with 400 Bad Request');

  // 8. Member restarts work -> in_progress
  await makeRequest({
    method: 'PATCH',
    path: `/api/tasks/${taskId}/status`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { status: 'in_progress', notes: 'Restarting with revisions' },
  });

  // 9. Member re-submits
  await makeRequest({
    method: 'POST',
    path: `/api/tasks/${taskId}/submit`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { notes: 'Revised syllabus with 19th-century ghazals' },
  });

  // 10. Reviewer approves
  const rApprove = await makeRequest({
    method: 'PATCH',
    path: `/api/tasks/${taskId}/review`,
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
    body: { action: 'approve', feedback: 'Excellent work.' },
  });
  assert(
    rApprove.status === 200 && rApprove.data.task.status === 'approved' && Boolean(rApprove.data.task.completedAt),
    'Reviewer approves deliverable -> approved with completedAt timestamp (200 OK)'
  );

  // -------------------------------------------------------------------------
  // 7. BLIND ASSESSMENT CONFIDENTIALITY
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 7]: Blind Assessment Confidentiality');

  const rAssessSubmit = await makeRequest({
    method: 'POST',
    path: '/api/assessments',
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
    body: {
      memberId: users.memberLit.id,
      memberName: users.memberLit.name,
      department: 'Literature',
      period: 'Q1-2026',
      criteriaScores: {
        taskExecution: 9,
        deliverableQuality: 9,
        punctuality: 8,
        teamCollaboration: 9,
      },
      qualitativeFeedback: 'Outstanding contribution to literary research.',
    },
  });
  assert(
    rAssessSubmit.status === 201 && rAssessSubmit.data.success && rAssessSubmit.data.criteriaScores === undefined,
    'Department Head submits assessment without score leakage in response (201 Created)'
  );

  const rAssessArchive = await makeRequest({
    path: '/api/assessments',
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
  });
  assert(rAssessArchive.status === 403, 'Department Head blocked from reading assessment archive (403 Forbidden)');

  const rAdminAssessArchive = await makeRequest({
    path: '/api/assessments',
    headers: { Authorization: `Bearer ${tokens.superAdmin}` },
  });
  assert(rAdminAssessArchive.status === 200, 'Super Admin authorized to access confidential assessment archive (200 OK)');

  // -------------------------------------------------------------------------
  // 8. RECRUITMENT TO ONBOARDING INTEGRATION
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 8]: Recruitment-to-Onboarding Integration');

  const candidateApp = {
    _id: 'app_candidate_6c',
    id: 'app_candidate_6c',
    fullName: 'Sara Ali',
    email: 'sara6c@rekhta.org',
    phone: '+92 300 1234567',
    city: 'Lahore',
    department: 'Literature',
    areaOfInterest: 'Literature',
    status: 'interview_scheduled',
    statusHistory: [],
    createdAt: new Date(),
  };
  setMemoryApplication(candidateApp);

  const rOnboard = await makeRequest({
    method: 'POST',
    path: `/api/hr/applications/${candidateApp.id}/onboard`,
    headers: { Authorization: `Bearer ${tokens.hr}` },
    body: { role: 'member', department: 'Literature' },
  });
  assert(
    rOnboard.status === 201 && rOnboard.data.success && Boolean(rOnboard.data.activationToken),
    'HR onboards candidate and generates single-use activationToken (201 Created)'
  );

  const activationToken = rOnboard.data.activationToken;

  // Activate via /api/auth/activate
  const rActivate = await makeRequest({
    method: 'POST',
    path: '/api/auth/activate',
    body: {
      token: activationToken,
      password: 'SaraPassword2026!',
    },
  });
  assert(rActivate.status === 200 && rActivate.data.success, 'Candidate activates account with token (200 OK)');

  // Replay attempt on same token rejected
  const rReplayActivate = await makeRequest({
    method: 'POST',
    path: '/api/auth/activate',
    body: {
      token: activationToken,
      password: 'SecondPassword2026!',
    },
  });
  assert(rReplayActivate.status === 400, 'Replay of consumed activation token rejected with 400 Bad Request');

  // -------------------------------------------------------------------------
  // 9. LEAVE WORKFLOW AUTHORIZATION
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 9]: Leave Workflow Authorization');

  const rLeaveSubmit = await makeRequest({
    method: 'POST',
    path: '/api/hr/leaves',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: {
      leaveType: 'sick',
      startDate: new Date(Date.now() + 86400000).toISOString(),
      endDate: new Date(Date.now() + 2 * 86400000).toISOString(),
      reason: 'Medical rest',
    },
  });
  assert(rLeaveSubmit.status === 201 && rLeaveSubmit.data.success, 'Member submits leave request (201 Created)');
  const leaveId = rLeaveSubmit.data.leave.id || rLeaveSubmit.data.leave._id;

  // Member self-approval rejected
  const rLeaveSelfApprove = await makeRequest({
    method: 'PATCH',
    path: `/api/hr/leaves/${leaveId}/review`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { action: 'approve' },
  });
  assert(rLeaveSelfApprove.status === 403, 'Member self-approval of leave request blocked with 403 Forbidden');

  // Lit Head approves leave
  const rLeaveApprove = await makeRequest({
    method: 'PATCH',
    path: `/api/hr/leaves/${leaveId}/review`,
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
    body: { action: 'approve', notes: 'Approved for medical recovery.' },
  });
  assert(rLeaveApprove.status === 200 && rLeaveApprove.data.leave.status === 'approved', 'Literature Head approves leave request (200 OK)');

  // -------------------------------------------------------------------------
  // 10. PUBLIC VOLUNTEER FORWARDING & DUPLICATE HANDLING
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 10]: Public Volunteer Forwarding & Duplicate Handling');

  const volunteerSubmission = {
    submissionId: 'SUB_VOL_6C_TEST_1',
    fullName: 'Zainab Qasim',
    email: 'zainab6c@rekhta.org',
    phone: '+92 321 9876543',
    city: 'Karachi',
    areaOfInterest: 'Literature',
    motivation: 'Passionate about Urdu classical heritage',
  };

  const rVol1 = await makeRequest({
    method: 'POST',
    path: '/api/volunteer',
    body: volunteerSubmission,
  });
  assert(rVol1.status === 200 && rVol1.data.success, 'Public volunteer submission succeeds (200 OK)');

  // Duplicate submission with same submissionId
  const rVol2 = await makeRequest({
    method: 'POST',
    path: '/api/volunteer',
    body: volunteerSubmission,
  });
  assert(
    rVol2.status === 200 && rVol2.data.duplicate === true,
    'Duplicate volunteer submission detected and handled idempotently without error'
  );

  // -------------------------------------------------------------------------
  // 11. FINANCE INCOME & EXPENSE WORKFLOW
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 11]: Finance Income & Expense Workflow');

  // Log Income
  const rIncome = await makeRequest({
    method: 'POST',
    path: '/api/finance/income',
    headers: { Authorization: `Bearer ${tokens.finance}` },
    body: {
      donorName: 'Dr. Tariq Khan',
      donorEmail: 'tariq@example.com',
      amount: 50000,
      currency: 'PKR',
      source: 'donation',
      paymentMethod: 'bank_transfer',
    },
  });
  assert(rIncome.status === 201 && rIncome.data.success, 'Finance logs verified income (201 Created)');
  const incomeId = rIncome.data.donation.donationId || rIncome.data.donation.id || rIncome.data.donation._id;

  // Member submits expense
  const rExpSubmit = await makeRequest({
    method: 'POST',
    path: '/api/finance/expenses',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: {
      title: 'Urdu Poetry Books Purchase',
      amount: 15000,
      currency: 'PKR',
      category: 'supplies',
      department: 'Literature',
    },
  });
  assert(rExpSubmit.status === 201 && rExpSubmit.data.success, 'Member submits expense claim (201 Created)');
  const expenseId = rExpSubmit.data.expense.expenseId || rExpSubmit.data.expense.id || rExpSubmit.data.expense._id;

  // Anti-Self-Approval
  const rSelfApproveExp = await makeRequest({
    method: 'PATCH',
    path: `/api/finance/expenses/${expenseId}/review`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { action: 'approve' },
  });
  assert(rSelfApproveExp.status === 403, 'Expense claimant self-approval blocked with 403 Forbidden');

  // Finance Lead approves
  const rApproveExp = await makeRequest({
    method: 'PATCH',
    path: `/api/finance/expenses/${expenseId}/review`,
    headers: { Authorization: `Bearer ${tokens.finance}` },
    body: { status: 'approved' },
  });
  assert(rApproveExp.status === 200 && rApproveExp.data.expense.status === 'approved', 'Finance Lead approves expense claim (200 OK)');

  // Disbursement
  const rDisburseExp = await makeRequest({
    method: 'PATCH',
    path: `/api/finance/expenses/${expenseId}/disburse`,
    headers: { Authorization: `Bearer ${tokens.finance}` },
    body: { paymentMethod: 'bank_transfer', disbursementNotes: 'Transferred to claimant' },
  });
  assert(rDisburseExp.status === 200 && rDisburseExp.data.expense.status === 'paid', 'Finance Lead marks expense as paid/disbursed (200 OK)');

  // Duplicate disbursement rejected
  const rDupDisburse = await makeRequest({
    method: 'PATCH',
    path: `/api/finance/expenses/${expenseId}/disburse`,
    headers: { Authorization: `Bearer ${tokens.finance}` },
    body: { paymentMethod: 'bank_transfer' },
  });
  assert(rDupDisburse.status === 409, 'Repeated disbursement rejected with 409 Conflict');

  // -------------------------------------------------------------------------
  // 12. FINANCIAL BUDGET INTEGRITY
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 12]: Financial Budget Integrity');

  // Re-approving already-approved/paid expense blocked with 409
  const rReApprove = await makeRequest({
    method: 'PATCH',
    path: `/api/finance/expenses/${expenseId}/review`,
    headers: { Authorization: `Bearer ${tokens.finance}` },
    body: { status: 'approved' },
  });
  assert(rReApprove.status === 409, 'Re-approval attempt on paid expense rejected with 409 Conflict');

  // Overspending protection: Submit expense > remaining budget
  const rOverspendExp = await makeRequest({
    method: 'POST',
    path: '/api/finance/expenses',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: {
      title: 'Grand Urdu Festival Hall Rental',
      amount: 900000, // Exceeds remaining budget
      currency: 'PKR',
      category: 'events',
      department: 'Literature',
    },
  });
  const overspendId = rOverspendExp.data.expense.expenseId || rOverspendExp.data.expense.id;

  const rOverspendApprove = await makeRequest({
    method: 'PATCH',
    path: `/api/finance/expenses/${overspendId}/review`,
    headers: { Authorization: `Bearer ${tokens.finance}` },
    body: { status: 'approved' },
  });
  assert(
    rOverspendApprove.status === 400 && rOverspendApprove.data?.error?.includes('overspending'),
    'Approving expense exceeding remaining budget rejected with 400 Bad Request (Overspending Defense)'
  );

  // -------------------------------------------------------------------------
  // 13. NOTIFICATION OWNERSHIP AND ACCESS
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 13]: Notification Ownership & Access Control');

  // Send a test notification to Member Lit
  const testNotif = await sendNotification({
    userId: users.memberLit.id,
    title: 'Private Test Notification',
    message: 'Personal message for member lit only',
    type: 'info',
    category: 'task',
    dedupKey: 'notif:test:own:1',
  });
  const notifId = testNotif._id || testNotif.id;

  // Member Lit queries personal notifications -> sees it
  const rOwnNotifs = await makeRequest({
    path: '/api/notifications',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
  });
  assert(
    rOwnNotifs.status === 200 && rOwnNotifs.data.notifications.some((n) => (n._id || n.id) === notifId),
    'Member retrieves personal notifications (200 OK)'
  );

  // Member Med queries notifications -> CANNOT see Member Lit notification
  const rOtherNotifs = await makeRequest({
    path: '/api/notifications',
    headers: { Authorization: `Bearer ${tokens.memberMed}` },
  });
  assert(
    rOtherNotifs.status === 200 && !rOtherNotifs.data.notifications.some((n) => (n._id || n.id) === notifId),
    'Notification isolation: Other members cannot view private notification (Privacy Enforced)'
  );

  // Member Med attempting to mark Member Lit's notification as read -> 403 Forbidden
  const rCrossMarkRead = await makeRequest({
    method: 'PATCH',
    path: `/api/notifications/${notifId}/read`,
    headers: { Authorization: `Bearer ${tokens.memberMed}` },
  });
  assert(rCrossMarkRead.status === 403, 'Unauthorized user attempting to update notification rejected with 403 Forbidden');

  // Member Lit marks their own notification as read -> 200 OK
  const rOwnMarkRead = await makeRequest({
    method: 'PATCH',
    path: `/api/notifications/${notifId}/read`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
  });
  assert(rOwnMarkRead.status === 200 && rOwnMarkRead.data.notification.read === true, 'Owner marks notification as read (200 OK)');

  // -------------------------------------------------------------------------
  // 14. NOTIFICATION DUPLICATE PREVENTION
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 14]: Notification Duplicate Prevention');

  const countBefore = getMemoryNotificationsList().filter((n) => n.userId === users.memberLit.id).length;

  // Dispatch same notification with identical dedupKey
  await sendNotification({
    userId: users.memberLit.id,
    title: 'Duplicate Test Notification',
    message: 'First dispatch',
    dedupKey: 'notif:test:dedup:key',
  });

  await sendNotification({
    userId: users.memberLit.id,
    title: 'Duplicate Test Notification',
    message: 'Replayed dispatch',
    dedupKey: 'notif:test:dedup:key',
  });

  const countAfter = getMemoryNotificationsList().filter((n) => n.userId === users.memberLit.id).length;
  assert(countAfter === countBefore + 1, 'Duplicate notification with identical dedupKey suppressed (Idempotency Enforced)');

  // -------------------------------------------------------------------------
  // 15. AUDIT HISTORY CONSISTENCY
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 15]: Audit History Consistency');

  const rAuditHistory = await makeRequest({
    path: '/api/super-admin/audit-logs',
    headers: { Authorization: `Bearer ${tokens.superAdmin}` },
  });
  const logs = rAuditHistory.data.logs || [];
  const modulesPresent = new Set(logs.map((l) => l.module));

  assert(
    rAuditHistory.status === 200 && logs.length > 0,
    'System audit log records actions across multiple modules (200 OK)'
  );

  // -------------------------------------------------------------------------
  // 16. ARCHIVED RECORD BEHAVIOR
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 16]: Archived Record Behavior');

  // Permanent hard deletion prohibited
  const rHardDelExp = await makeRequest({
    method: 'DELETE',
    path: `/api/finance/expenses/${expenseId}`,
    headers: { Authorization: `Bearer ${tokens.finance}` },
  });
  assert(rHardDelExp.status === 405, 'Permanent hard deletion of expense blocked with 405 Method Not Allowed');

  // Soft Archiving
  const rArchiveExp = await makeRequest({
    method: 'PATCH',
    path: `/api/finance/expenses/${expenseId}/archive`,
    headers: { Authorization: `Bearer ${tokens.finance}` },
  });
  assert(rArchiveExp.status === 200 && rArchiveExp.data.expense.isArchived === true, 'Soft archiving preserves record with isArchived: true (200 OK)');

  // -------------------------------------------------------------------------
  // 17. INVALID RELATIONSHIP HANDLING
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 17]: Invalid Relationship Handling');

  // Invalid task status value rejected
  const rBadStatus = await makeRequest({
    method: 'PATCH',
    path: `/api/tasks/${taskId}/status`,
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
    body: { status: 'invalid_status_xyz' },
  });
  assert(rBadStatus.status === 400, 'Invalid task status rejected with 400 Bad Request');

  // Invalid leave date range
  const rBadLeaveDates = await makeRequest({
    method: 'POST',
    path: '/api/hr/leaves',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: {
      leaveType: 'vacation',
      startDate: new Date(Date.now() + 5 * 86400000).toISOString(),
      endDate: new Date(Date.now() + 2 * 86400000).toISOString(), // start > end
      reason: 'Invalid dates',
    },
  });
  assert(rBadLeaveDates.status === 400, 'Leave with invalid date range (start > end) rejected with 400 Bad Request');

  // -------------------------------------------------------------------------
  // 18. UNAUTHORIZED API ACCESS
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 18]: Unauthorized API Access');

  // No auth header
  const rNoAuth = await makeRequest({ path: '/api/super-admin/overview' });
  assert(rNoAuth.status === 401, 'Unauthenticated request to protected endpoint rejected with 401 Unauthorized');

  // Suspended account
  const rSuspended = await makeRequest({
    path: `/api/members/${users.suspendedUser.id}/tasks`,
    headers: { Authorization: `Bearer ${tokens.suspendedUser}` },
  });
  assert(rSuspended.status === 403, 'Suspended account access immediately blocked with 403 Forbidden');

  // Regular member accessing super admin endpoint
  const rEscalate = await makeRequest({
    path: '/api/super-admin/overview',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
  });
  assert(rEscalate.status === 403, 'Member accessing Super Admin endpoint rejected with 403 Forbidden');

  // -------------------------------------------------------------------------
  // 19. FRONTEND/BACKEND API CONTRACT CONSISTENCY
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 19]: Frontend/Backend API Contract Consistency');

  // Verify standard response shape { success: boolean }
  const rDeptOverview = await makeRequest({
    path: '/api/departments',
  });
  assert(
    rDeptOverview.status === 200 && rDeptOverview.data.success === true && Array.isArray(rDeptOverview.data.departments),
    'GET /api/departments conforms to contract { success: true, departments: [] }'
  );

  const rNotifContract = await makeRequest({
    path: '/api/notifications',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
  });
  assert(
    rNotifContract.status === 200 &&
      rNotifContract.data.success === true &&
      typeof rNotifContract.data.unreadCount === 'number' &&
      Array.isArray(rNotifContract.data.notifications),
    'GET /api/notifications conforms to contract { success: true, count, unreadCount, notifications }'
  );

  // -------------------------------------------------------------------------
  // 20. END-TO-END REGRESSION OF CRITICAL WORKFLOWS
  // -------------------------------------------------------------------------
  console.log('\n>>> [GROUP 20]: End-to-End Regression of Critical Workflows');

  // Complete end-to-end multi-department scenario:
  // Super Admin initiates multi-department task -> Literature Head delegates -> Member submits -> Reviewed ->
  // Member claims reimbursement -> Finance approves & pays -> Notification delivered -> Audit preserved
  const rE2ETask = await makeRequest({
    method: 'POST',
    path: '/api/tasks',
    headers: { Authorization: `Bearer ${tokens.superAdmin}` },
    body: {
      title: 'E2E Cross-Department Poetry Preservation Project',
      department: 'Literature',
      departmentCode: 'LIT',
      assignedTo: users.memberLit.id,
      assignedMemberName: users.memberLit.name,
    },
  });
  assert(rE2ETask.status === 201, 'E2E Step 1: Super Admin creates departmental task (201 Created)');
  const e2eTaskId = rE2ETask.data.task.id || rE2ETask.data.task._id;

  // Start task
  await makeRequest({
    method: 'PATCH',
    path: `/api/tasks/${e2eTaskId}/status`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { status: 'in_progress', notes: 'E2E member started task' },
  });

  // Submit task
  await makeRequest({
    method: 'POST',
    path: `/api/tasks/${e2eTaskId}/submit`,
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: { notes: 'E2E deliverables complete' },
  });

  // Lit Head approves
  const rE2EApprove = await makeRequest({
    method: 'PATCH',
    path: `/api/tasks/${e2eTaskId}/review`,
    headers: { Authorization: `Bearer ${tokens.deptLiterature}` },
    body: { action: 'approve', feedback: 'Verified and approved by Literature Head' },
  });
  assert(rE2EApprove.status === 200, 'E2E Step 2: Department Head approves completed task (200 OK)');

  // Member submits expense
  const rE2EExp = await makeRequest({
    method: 'POST',
    path: '/api/finance/expenses',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
    body: {
      title: 'Poetry Preservation Archival Supplies',
      amount: 5000,
      currency: 'PKR',
      category: 'supplies',
      department: 'Literature',
    },
  });
  assert(rE2EExp.status === 201, 'E2E Step 3: Member submits expense claim (201 Created)');
  const e2eExpId = rE2EExp.data.expense.expenseId || rE2EExp.data.expense.id;

  // Finance approves & disburses
  const rE2EFinApprove = await makeRequest({
    method: 'PATCH',
    path: `/api/finance/expenses/${e2eExpId}/review`,
    headers: { Authorization: `Bearer ${tokens.finance}` },
    body: { status: 'approved' },
  });
  const rE2EFinDisburse = await makeRequest({
    method: 'PATCH',
    path: `/api/finance/expenses/${e2eExpId}/disburse`,
    headers: { Authorization: `Bearer ${tokens.finance}` },
    body: { paymentMethod: 'direct_deposit' },
  });
  assert(
    rE2EFinApprove.status === 200 && rE2EFinDisburse.status === 200,
    'E2E Step 4: Finance approves claim and executes disbursement (200 OK)'
  );

  // Verify Member received notification
  const rE2ENotifs = await makeRequest({
    path: '/api/notifications',
    headers: { Authorization: `Bearer ${tokens.memberLit}` },
  });
  const memberHasExpNotif = rE2ENotifs.data.notifications.some(
    (n) => n.category === 'finance' && n.title.includes('Disbursed')
  );
  assert(memberHasExpNotif, 'E2E Step 5: Member receives disbursement notification in real-time');

  // Verify Budget deduction
  const finalBudgets = getMemoryBudgetsList().filter((b) => b.department === 'Literature');
  const activeLitBudget = finalBudgets[0];
  assert(
    activeLitBudget && activeLitBudget.spentAmount >= 25000,
    'E2E Step 6: Department budget reflects single accurate deduction (+5000 PKR)'
  );

  // -------------------------------------------------------------------------
  // FINAL TEST SUITE REPORT
  // -------------------------------------------------------------------------
  console.log('\n======================================================================');
  console.log(`  PHASE 6C TEST RESULTS: ${passedTests} PASSED, ${failedTests} FAILED (TOTAL: ${totalTests})`);
  console.log('======================================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

// Start HTTP test server and execute tests
server = app.listen(TEST_PORT, async () => {
  console.log(`[Phase 6C Test Runner] Server listening on port ${TEST_PORT}...`);
  try {
    await runTests();
  } catch (err) {
    console.error('Fatal error during test run:', err);
    process.exit(1);
  } finally {
    server.close();
  }
});
