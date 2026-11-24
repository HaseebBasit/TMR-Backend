/**
 * Phase 5 — Super Admin & Department Head Dashboards Integration Test Suite
 * Validates all Phase 5 capabilities, task lifecycle workflows, and RBAC isolation.
 */

const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

process.env.NODE_ENV = 'test';
process.env.PORT = '5006';
process.env.JWT_SECRET = 'test_secret_phase5_dashboards_access_secure';
process.env.JWT_REFRESH_SECRET = 'test_secret_phase5_dashboards_refresh_secure';

const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');

const PORT = 5006;
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
        Origin: 'http://localhost:3000',
        'X-Requested-With': 'XMLHttpRequest',
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

function getToken(user) {
  return jwt.sign(
    {
      id: user._id || user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      department: user.department,
      departmentCode: user.departmentCode,
      status: user.status,
      isPrivilegedHR: Boolean(user.isPrivilegedHR),
      tokenVersion: user.tokenVersion || 0,
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function runPhase5Tests() {
  console.log('================================================================');
  console.log('  TA\'MEER-E-REKHTA PHASE 5: DASHBOARDS & WORKFLOWS TEST SUITE   ');
  console.log('================================================================\n');

  const hashedPassword = await bcrypt.hash('SecurePassword2026!', 10);

  const superAdmin = {
    _id: '507f191e810c19729de860a1',
    id: '507f191e810c19729de860a1',
    name: 'Super Admin Lead',
    email: 'admin.phase5@rekhta.org',
    password: hashedPassword,
    role: 'super_admin',
    department: 'Administration',
    status: 'active',
    isPrivilegedHR: true,
    tokenVersion: 0,
  };

  const mediaHead = {
    _id: '507f191e810c19729de860a2',
    id: '507f191e810c19729de860a2',
    name: 'Aisha Tariq (Media Head)',
    email: 'media.head@rekhta.org',
    password: hashedPassword,
    role: 'dept_media',
    department: 'Media',
    departmentCode: 'MED',
    status: 'active',
    isPrivilegedHR: false,
    tokenVersion: 0,
  };

  const literatureHead = {
    _id: '507f191e810c19729de860a3',
    id: '507f191e810c19729de860a3',
    name: 'Noor-ul-Huda (Literature Head)',
    email: 'lit.head@rekhta.org',
    password: hashedPassword,
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    status: 'active',
    isPrivilegedHR: false,
    tokenVersion: 0,
  };

  const marketingHead = {
    _id: '507f191e810c19729de860a4',
    id: '507f191e810c19729de860a4',
    name: 'Ahmad Raza Waseem (Marketing Head)',
    email: 'mkt.head@rekhta.org',
    password: hashedPassword,
    role: 'dept_marketing',
    department: 'Marketing',
    departmentCode: 'MKT',
    status: 'active',
    tokenVersion: 0,
  };

  const outreachHead = {
    _id: '507f191e810c19729de860a5',
    id: '507f191e810c19729de860a5',
    name: 'Asfand Yar Karimi (Outreach Head)',
    email: 'out.head@rekhta.org',
    password: hashedPassword,
    role: 'dept_outreach',
    department: 'Outreach',
    departmentCode: 'OUT',
    status: 'active',
    tokenVersion: 0,
  };

  const contentHead = {
    _id: '507f191e810c19729de860a6',
    id: '507f191e810c19729de860a6',
    name: 'Salman Mallana (Content Head)',
    email: 'con.head@rekhta.org',
    password: hashedPassword,
    role: 'dept_content',
    department: 'Content Creation',
    departmentCode: 'CON',
    status: 'active',
    tokenVersion: 0,
  };

  const mediaMember = {
    _id: '507f191e810c19729de860a7',
    id: '507f191e810c19729de860a7',
    name: 'Member Bilal',
    email: 'bilal.media@rekhta.org',
    password: hashedPassword,
    role: 'member',
    department: 'Media',
    departmentCode: 'MED',
    status: 'active',
    tokenVersion: 0,
  };

  [superAdmin, mediaHead, literatureHead, marketingHead, outreachHead, contentHead, mediaMember].forEach(setMemoryUser);

  // -------------------------------------------------------------------------
  // TEST 1: Super Admin Dashboard Overview & Metrics
  // -------------------------------------------------------------------------
  const adminOverviewRes = await makeRequest(
    'GET',
    '/api/super-admin/overview',
    { Authorization: `Bearer ${getToken(superAdmin)}` }
  );

  assert(
    adminOverviewRes.status === 200 &&
      adminOverviewRes.body.success === true &&
      adminOverviewRes.body.stats &&
      Array.isArray(adminOverviewRes.body.departmentDistribution),
    'Test 1.1: Super Admin retrieves organization-wide dashboard overview and metrics'
  );

  // Non-admin rejected from Super Admin overview
  const deptOverviewReject = await makeRequest(
    'GET',
    '/api/super-admin/overview',
    { Authorization: `Bearer ${getToken(mediaHead)}` }
  );

  assert(
    deptOverviewReject.status === 403,
    'Test 1.2: Department Head rejected from Super Admin overview with 403 Forbidden'
  );

  // -------------------------------------------------------------------------
  // TEST 2: Super Admin User Management Operations
  // -------------------------------------------------------------------------
  const usersListRes = await makeRequest(
    'GET',
    '/api/super-admin/users',
    { Authorization: `Bearer ${getToken(superAdmin)}` }
  );

  assert(
    usersListRes.status === 200 && usersListRes.body.users.length > 0,
    'Test 2.1: Super Admin fetches full organization user directory'
  );

  // Create new user by Super Admin
  const createUserRes = await makeRequest(
    'POST',
    '/api/super-admin/users',
    { Authorization: `Bearer ${getToken(superAdmin)}` },
    {
      name: 'Farhan Zaidi',
      email: 'farhan.phase5@rekhta.org',
      role: 'member',
      department: 'Content Creation',
      designation: 'Staff Writer',
    }
  );

  assert(
    createUserRes.status === 201 && createUserRes.body.user?.email === 'farhan.phase5@rekhta.org',
    'Test 2.2: Super Admin creates new member with role and department assignment'
  );

  // Non-admin prohibited from creating users
  const unauthorizedCreateUser = await makeRequest(
    'POST',
    '/api/super-admin/users',
    { Authorization: `Bearer ${getToken(mediaHead)}` },
    { name: 'Fake User', email: 'fake@rekhta.org', role: 'member' }
  );

  assert(
    unauthorizedCreateUser.status === 403,
    'Test 2.3: Department Head prohibited from admin user creation endpoint (403)'
  );

  // -------------------------------------------------------------------------
  // TEST 3: All 5 Department Head Dashboards Access & Scoping
  // -------------------------------------------------------------------------
  const litRes = await makeRequest('GET', '/api/department/Literature/overview', {
    Authorization: `Bearer ${getToken(literatureHead)}`,
  });
  const medRes = await makeRequest('GET', '/api/department/Media/overview', {
    Authorization: `Bearer ${getToken(mediaHead)}`,
  });
  const mktRes = await makeRequest('GET', '/api/department/Marketing/overview', {
    Authorization: `Bearer ${getToken(marketingHead)}`,
  });
  const outRes = await makeRequest('GET', '/api/department/Outreach/overview', {
    Authorization: `Bearer ${getToken(outreachHead)}`,
  });
  const conRes = await makeRequest('GET', '/api/department/Content Creation/overview', {
    Authorization: `Bearer ${getToken(contentHead)}`,
  });

  assert(
    litRes.status === 200 &&
      medRes.status === 200 &&
      mktRes.status === 200 &&
      outRes.status === 200 &&
      conRes.status === 200,
    'Test 3.1: All 5 Department Heads access their respective department workspaces (200 OK)'
  );

  // -------------------------------------------------------------------------
  // TEST 4: Cross-Department Access Restrictions
  // -------------------------------------------------------------------------
  // Media Head attempts to access Literature overview
  const crossDeptRes = await makeRequest('GET', '/api/department/Literature/overview', {
    Authorization: `Bearer ${getToken(mediaHead)}`,
  });

  assert(
    crossDeptRes.status === 403,
    'Test 4: Media Head attempting cross-department access to Literature rejected with 403 Forbidden'
  );

  // -------------------------------------------------------------------------
  // TEST 5: Complete Task Lifecycle & Review Workflow
  // -------------------------------------------------------------------------
  // Step 1: Media Head creates a department task assigned to Member Bilal
  const createTaskRes = await makeRequest(
    'POST',
    '/api/tasks',
    { Authorization: `Bearer ${getToken(mediaHead)}` },
    {
      title: 'Produce 3 Urdu Calligraphy Reels',
      description: 'Film and edit reels showcasing Nastaliq calligraphy.',
      priority: 'high',
      assignedTo: mediaMember.id,
      assignedMemberName: mediaMember.name,
    }
  );

  const createdTask = createTaskRes.body.task;
  assert(
    createTaskRes.status === 201 && createdTask && createdTask.status === 'assigned',
    'Test 5.1: Task assigned: Department Head successfully creates and assigns deliverable'
  );

  const taskId = createdTask.id || createdTask._id;

  // Step 2: Member Bilal starts the task (advances to in_progress)
  const startTaskRes = await makeRequest(
    'PATCH',
    `/api/tasks/${taskId}/status`,
    { Authorization: `Bearer ${getToken(mediaMember)}` },
    { status: 'in_progress', notes: 'Began recording footage in studio.' }
  );

  assert(
    startTaskRes.status === 200 && startTaskRes.body.task.status === 'in_progress',
    'Test 5.2: In Progress: Assigned member starts task and status advances'
  );

  // Step 3: Member Bilal submits completed work
  const submitWorkRes = await makeRequest(
    'POST',
    `/api/tasks/${taskId}/submit`,
    { Authorization: `Bearer ${getToken(mediaMember)}` },
    {
      notes: 'Final video edits rendered at 4K 60fps.',
      links: ['https://drive.google.com/drive/folders/sample_reels_folder'],
    }
  );

  assert(
    submitWorkRes.status === 200 && submitWorkRes.body.task.status === 'submitted',
    'Test 5.3: Submitted: Member submits work with deliverable links and notes'
  );

  // Step 4: Media Head reviews and requests revision
  const requestRevisionRes = await makeRequest(
    'PATCH',
    `/api/tasks/${taskId}/review`,
    { Authorization: `Bearer ${getToken(mediaHead)}` },
    {
      action: 'request_revision',
      revisionNotes: 'Color grading on reel #2 is too dark. Please adjust brightness.',
    }
  );

  assert(
    requestRevisionRes.status === 200 && requestRevisionRes.body.task.status === 'revision_requested',
    'Test 5.4: Revision Requested: Department Head reviews and requests revisions with feedback'
  );

  // Step 4.5: Mandatory workflow restart - Member Bilal restarts work (in_progress) before resubmission
  await makeRequest(
    'PATCH',
    `/api/tasks/${taskId}/status`,
    { Authorization: `Bearer ${getToken(mediaMember)}` },
    { status: 'in_progress', notes: 'Restarting task to address color balance revisions.' }
  );

  // Step 5: Member Bilal re-submits adjusted deliverable
  const resubmitWorkRes = await makeRequest(
    'POST',
    `/api/tasks/${taskId}/submit`,
    { Authorization: `Bearer ${getToken(mediaMember)}` },
    {
      notes: 'Brightness increased by +15% and color balance corrected.',
      links: ['https://drive.google.com/drive/folders/sample_reels_folder_v2'],
    }
  );

  assert(
    resubmitWorkRes.status === 200 && resubmitWorkRes.body.task.status === 'submitted',
    'Test 5.5: Re-submitted: Member submits revised work for second review'
  );

  // Step 6: Media Head approves deliverable
  const approveTaskRes = await makeRequest(
    'PATCH',
    `/api/tasks/${taskId}/review`,
    { Authorization: `Bearer ${getToken(mediaHead)}` },
    {
      action: 'approve',
      feedback: 'Excellent color grading. Approved for publication!',
    }
  );

  assert(
    approveTaskRes.status === 200 &&
      approveTaskRes.body.task.status === 'approved' &&
      approveTaskRes.body.task.completedAt,
    'Test 5.6: Approved: Department Head approves deliverable and records completion timestamp'
  );

  // Step 7: Verify task history audit trail
  const finalTask = approveTaskRes.body.task;
  assert(
    Array.isArray(finalTask.history) && finalTask.history.length >= 4,
    'Test 5.7: Task historical audit trail preserved across all workflow transitions'
  );

  // -------------------------------------------------------------------------
  // TEST 6: Blind Assessment Submission & Confidentiality Enforcement
  // -------------------------------------------------------------------------
  // Media Head submits blind assessment
  const blindAssessmentRes = await makeRequest(
    'POST',
    '/api/assessments',
    { Authorization: `Bearer ${getToken(mediaHead)}` },
    {
      memberId: mediaMember.id,
      memberName: mediaMember.name,
      department: 'Media',
      period: '2026-Q4',
      criteriaScores: { taskExecution: 10, deliverableQuality: 9, punctuality: 9, teamCollaboration: 10 },
      qualitativeFeedback: 'Exceptional video production quality and dedication.',
    }
  );

  assert(
    blindAssessmentRes.status === 201 &&
      blindAssessmentRes.body.totalScore === undefined &&
      blindAssessmentRes.body.assessmentId,
    'Test 6.1: Department Head blind evaluation confirmed WITHOUT leaking score values'
  );

  // Department Head prohibited from viewing assessment reports
  const deptGradingRead = await makeRequest(
    'GET',
    '/api/assessments',
    { Authorization: `Bearer ${getToken(mediaHead)}` }
  );

  assert(
    deptGradingRead.status === 403,
    'Test 6.2: Department Head reading assessments returns 403 Forbidden'
  );

  // Super Admin authorized to view confidential scores
  const adminGradingRead = await makeRequest(
    'GET',
    '/api/assessments',
    { Authorization: `Bearer ${getToken(superAdmin)}` }
  );

  assert(
    adminGradingRead.status === 200 && Array.isArray(adminGradingRead.body.assessments),
    'Test 6.3: Super Admin authorized to view confidential grading archive'
  );

  console.log('\n================================================================');
  console.log(`  PHASE 5 TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('================================================================\n');

  server.close(() => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

server = app.listen(PORT, async () => {
  await runPhase5Tests().catch((err) => {
    console.error('Fatal test runner error:', err);
    server.close(() => process.exit(1));
  });
});
