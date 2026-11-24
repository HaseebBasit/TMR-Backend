process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'rekhta_access_secret_2026_super_secure';
process.env.JWT_REFRESH_SECRET = 'rekhta_refresh_secret_2026_super_secure';

const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');
const {
  setMemoryCampaign,
  setMemoryApplication,
  setMemoryLeave,
} = require('../src/routes/hr.routes');

const TEST_PORT = 5006;
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

function generateToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
}

async function runTestSuite() {
  console.log('======================================================================');
  console.log('  TA\'MEER-E-REKHTA PHASE 6A: HR MANAGEMENT TEST SUITE');
  console.log('======================================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName, details = '') {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName}`);
      if (details) console.error(`       -> ${details}`);
      failed++;
    }
  }

  try {
    // -------------------------------------------------------------------------
    // Setup Test Personas
    // -------------------------------------------------------------------------
    const hash = await bcrypt.hash('SecurePass123!', 10);

    const superAdmin = {
      _id: 'usr_sa_hr_01',
      id: 'usr_sa_hr_01',
      name: 'Super Admin User',
      email: 'superadmin_hr@rekhta.org',
      password: hash,
      role: 'super_admin',
      department: null,
      status: 'active',
      tokenVersion: 0,
    };

    const hrLead = {
      _id: 'usr_hr_lead_01',
      id: 'usr_hr_lead_01',
      name: 'Hania Mehmood (HR Lead)',
      email: 'hr_lead@rekhta.org',
      password: hash,
      role: 'hr',
      department: 'HR',
      departmentCode: 'HR',
      isPrivilegedHR: true,
      status: 'active',
      tokenVersion: 0,
    };

    const litHead = {
      _id: 'usr_lit_head_01',
      id: 'usr_lit_head_01',
      name: 'Noor-ul-Huda (Literature Lead)',
      email: 'lit_head@rekhta.org',
      password: hash,
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      tokenVersion: 0,
    };

    const mediaHead = {
      _id: 'usr_media_head_01',
      id: 'usr_media_head_01',
      name: 'Aisha Tariq (Media Lead)',
      email: 'media_head@rekhta.org',
      password: hash,
      role: 'dept_media',
      department: 'Media',
      departmentCode: 'MED',
      status: 'active',
      tokenVersion: 0,
    };

    const financeLead = {
      _id: 'usr_fin_lead_01',
      id: 'usr_fin_lead_01',
      name: 'Ahmad Maqsood (Finance Lead)',
      email: 'finance_lead@rekhta.org',
      password: hash,
      role: 'finance',
      department: 'Finance',
      departmentCode: 'FIN',
      status: 'active',
      tokenVersion: 0,
    };

    const litMember = {
      _id: 'usr_lit_mem_01',
      id: 'usr_lit_mem_01',
      name: 'Bilal Ahmad (Lit Member)',
      email: 'bilal_lit@rekhta.org',
      password: hash,
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
      tokenVersion: 0,
    };

    setMemoryUser(superAdmin);
    setMemoryUser(hrLead);
    setMemoryUser(litHead);
    setMemoryUser(mediaHead);
    setMemoryUser(financeLead);
    setMemoryUser(litMember);

    const tokenSA = generateToken({ id: superAdmin.id, role: superAdmin.role, name: superAdmin.name, email: superAdmin.email, tokenVersion: 0 });
    const tokenHR = generateToken({ id: hrLead.id, role: hrLead.role, name: hrLead.name, email: hrLead.email, department: hrLead.department, tokenVersion: 0 });
    const tokenLitHead = generateToken({ id: litHead.id, role: litHead.role, name: litHead.name, email: litHead.email, department: litHead.department, tokenVersion: 0 });
    const tokenMediaHead = generateToken({ id: mediaHead.id, role: mediaHead.role, name: mediaHead.name, email: mediaHead.email, department: mediaHead.department, tokenVersion: 0 });
    const tokenFin = generateToken({ id: financeLead.id, role: financeLead.role, name: financeLead.name, email: financeLead.email, department: financeLead.department, tokenVersion: 0 });
    const tokenMember = generateToken({ id: litMember.id, role: litMember.role, name: litMember.name, email: litMember.email, department: litMember.department, tokenVersion: 0 });

    const authHeaders = (token) => ({ Authorization: `Bearer ${token}` });

    // =========================================================================
    // GROUP 1: RECRUITMENT CAMPAIGNS MANAGEMENT
    // =========================================================================
    console.log('>>> [GROUP 1]: Recruitment Campaigns Management');

    let createdCampaignId = null;

    // Test 1.1: HR successfully creates a new campaign
    const resCreateCamp = await makeRequest({
      method: 'POST',
      path: '/api/hr/campaigns',
      headers: authHeaders(tokenHR),
      body: {
        title: 'Spring 2026 Content Writers Recruitment',
        department: 'Literature',
        description: 'Seeking passionate writers for Urdu classical poetry analysis.',
        requirements: ['Fluent in Urdu', 'Research ability', 'Portfolio samples'],
        openingsCount: 5,
        deadline: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
      },
    });
    assert(
      resCreateCamp.status === 201 && resCreateCamp.data.success && resCreateCamp.data.campaign?.title,
      'Test 1.1: HR successfully creates a new recruitment campaign (201 Created)'
    );
    createdCampaignId = resCreateCamp.data.campaign?._id || resCreateCamp.data.campaign?.id;

    // Test 1.2: Campaign with invalid department rejected with 400
    const resInvalidDept = await makeRequest({
      method: 'POST',
      path: '/api/hr/campaigns',
      headers: authHeaders(tokenHR),
      body: {
        title: 'Invalid Dept Campaign',
        department: 'NonExistentDept',
        description: 'Test description',
      },
    });
    assert(
      resInvalidDept.status === 400 && resInvalidDept.data.success === false,
      'Test 1.2: Creation of campaign with invalid department rejected with 400 Bad Request'
    );

    // Test 1.3: Regular member attempting to create campaign blocked with 403
    const resMemCamp = await makeRequest({
      method: 'POST',
      path: '/api/hr/campaigns',
      headers: authHeaders(tokenMember),
      body: {
        title: 'Member Unauthorized Campaign',
        department: 'Literature',
        description: 'Member trying to create campaign',
      },
    });
    assert(
      resMemCamp.status === 403,
      'Test 1.3: Regular member attempting to create a campaign is blocked with 403 Forbidden'
    );

    // Test 1.4: Finance lead attempting to create campaign blocked with 403
    const resFinCamp = await makeRequest({
      method: 'POST',
      path: '/api/hr/campaigns',
      headers: authHeaders(tokenFin),
      body: {
        title: 'Finance Unauthorized Campaign',
        department: 'Finance',
        description: 'Finance lead trying to create campaign',
      },
    });
    assert(
      resFinCamp.status === 403,
      'Test 1.4: Finance lead attempting to create a campaign is blocked with 403 Forbidden'
    );

    // Test 1.5: Authenticated users can list recruitment campaigns
    const resListCamps = await makeRequest({
      method: 'GET',
      path: '/api/hr/campaigns',
      headers: authHeaders(tokenMember),
    });
    assert(
      resListCamps.status === 200 && Array.isArray(resListCamps.data.campaigns) && resListCamps.data.campaigns.length >= 1,
      'Test 1.5: Authenticated users can list active recruitment campaigns (200 OK)'
    );

    // Test 1.6: HR successfully updates campaign
    const resUpdateCamp = await makeRequest({
      method: 'PATCH',
      path: `/api/hr/campaigns/${createdCampaignId}`,
      headers: authHeaders(tokenHR),
      body: { openingsCount: 8, description: 'Updated: Seeking 8 passionate writers.' },
    });
    assert(
      resUpdateCamp.status === 200 && resUpdateCamp.data.campaign?.openingsCount === 8,
      'Test 1.6: HR successfully updates campaign details (200 OK)'
    );

    // Test 1.7: HR successfully closes a campaign
    const resCloseCamp = await makeRequest({
      method: 'DELETE',
      path: `/api/hr/campaigns/${createdCampaignId}`,
      headers: authHeaders(tokenHR),
    });
    assert(
      resCloseCamp.status === 200 && resCloseCamp.data.campaign?.status === 'closed',
      'Test 1.7: HR successfully closes a campaign (200 OK)'
    );

    // =========================================================================
    // GROUP 2: PUBLIC VOLUNTEER INGESTION & SYNCHRONIZATION
    // =========================================================================
    console.log('\n>>> [GROUP 2]: Public Volunteer Ingestion & Synchronization');

    const volunteerPayload = {
      fullName: 'Zainab Fatima',
      email: 'zainab.fatima@example.com',
      phone: '+92 300 1234567',
      instagramId: 'zainab_rekhta',
      city: 'Lahore',
      age: '22',
      areaOfInterest: 'Literature',
      motivation: 'Deeply devoted to promoting classical Urdu literature and poetry among Gen-Z.',
    };

    // Test 2.1: Public volunteer form submission
    const resVolunteer = await makeRequest({
      method: 'POST',
      path: '/api/volunteer',
      body: volunteerPayload,
    });
    assert(
      resVolunteer.status === 200 && resVolunteer.data.success && resVolunteer.data.submissionId,
      'Test 2.1: Public volunteer form submission /api/volunteer succeeds (200 OK)'
    );
    const volunteerSubmissionId = resVolunteer.data.submissionId;

    // Test 2.2: Application appears in HR candidate pool
    const resCheckVolInHR = await makeRequest({
      method: 'GET',
      path: '/api/hr/applications',
      headers: authHeaders(tokenHR),
    });
    const foundVol = resCheckVolInHR.data.applications?.find(
      (a) => a.email === 'zainab.fatima@example.com' || a.submissionId === volunteerSubmissionId
    );
    assert(
      resCheckVolInHR.status === 200 && Boolean(foundVol) && foundVol.source === 'website_volunteer_form',
      'Test 2.2: Application submitted via volunteer form appears in HR candidate pool with source website_volunteer_form'
    );

    const applicationId = foundVol?._id || foundVol?.id;

    // =========================================================================
    // GROUP 3: CANDIDATE REVIEW LIFECYCLE & INTERVIEW SCHEDULING
    // =========================================================================
    console.log('\n>>> [GROUP 3]: Candidate Review Lifecycle & Interview Scheduling');

    // Test 3.1: HR lists candidate applications
    assert(
      resCheckVolInHR.status === 200 && resCheckVolInHR.data.applications?.length >= 1,
      'Test 3.1: HR lists candidate applications (200 OK)'
    );

    // Test 3.2: Member attempting to access candidate applications blocked with 403
    const resMemApps = await makeRequest({
      method: 'GET',
      path: '/api/hr/applications',
      headers: authHeaders(tokenMember),
    });
    assert(
      resMemApps.status === 403,
      'Test 3.2: Member attempting to access candidate applications is blocked with 403 Forbidden'
    );

    // Test 3.3: Finance lead attempting to access candidate applications blocked with 403
    const resFinApps = await makeRequest({
      method: 'GET',
      path: '/api/hr/applications',
      headers: authHeaders(tokenFin),
    });
    assert(
      resFinApps.status === 403,
      'Test 3.3: Finance lead attempting to access candidate applications is blocked with 403 Forbidden'
    );

    // Test 3.4: HR updates status to shortlisted
    const resShortlist = await makeRequest({
      method: 'PATCH',
      path: `/api/hr/applications/${applicationId}/status`,
      headers: authHeaders(tokenHR),
      body: { status: 'shortlisted', notes: 'Excellent literature background and passion.' },
    });
    assert(
      resShortlist.status === 200 && resShortlist.data.application?.status === 'shortlisted',
      'Test 3.4: HR updates candidate status to shortlisted with review notes (200 OK)'
    );

    // Test 3.5: HR schedules an interview
    const interviewDate = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString();
    const resInterview = await makeRequest({
      method: 'POST',
      path: `/api/hr/applications/${applicationId}/interview`,
      headers: authHeaders(tokenHR),
      body: {
        scheduledAt: interviewDate,
        interviewers: ['Hania Mehmood', 'Noor-ul-Huda'],
        mode: 'Online',
        meetingLink: 'https://meet.google.com/rekhta-test-interview',
        notes: 'Panel interview assessing Urdu textual proficiency.',
      },
    });
    assert(
      resInterview.status === 200 &&
        resInterview.data.application?.status === 'interview_scheduled' &&
        resInterview.data.application?.interviewDetails?.meetingLink?.includes('google.com'),
      'Test 3.5: HR schedules an interview with interviewers, meeting link, and notes (200 OK)'
    );

    // Test 3.6: Status history preserves chronological records
    const resAppHistory = await makeRequest({
      method: 'GET',
      path: `/api/hr/applications/${applicationId}`,
      headers: authHeaders(tokenHR),
    });
    const history = resAppHistory.data.application?.statusHistory || [];
    assert(
      resAppHistory.status === 200 && history.length >= 2,
      'Test 3.6: Status history and audit records are preserved across application transitions'
    );

    // =========================================================================
    // GROUP 4: CANDIDATE SELECTION & AUTOMATED STAFF ONBOARDING
    // =========================================================================
    console.log('\n>>> [GROUP 4]: Candidate Selection & Automated Staff Onboarding');

    // Test 4.1: HR onboards candidate into 'member' role
    const resOnboard = await makeRequest({
      method: 'POST',
      path: `/api/hr/applications/${applicationId}/onboard`,
      headers: authHeaders(tokenHR),
      body: {
        role: 'member',
        department: 'Literature',
        designation: 'Literary Research Volunteer',
      },
    });
    assert(
      resOnboard.status === 201 &&
        resOnboard.data.success &&
        resOnboard.data.user?.email === 'zainab.fatima@example.com' &&
        resOnboard.data.activationToken,
      'Test 4.1: HR onboards shortlisted candidate into member role with activation token (201 Created)'
    );
    const rawActivationToken = resOnboard.data.activationToken;

    // Test 4.2: User created in 'inactive' status awaiting token activation
    assert(
      resOnboard.data.user?.status === 'inactive',
      'Test 4.2: Onboarded user account is initialized in inactive status awaiting activation'
    );

    // Test 4.3: HR attempting to onboard candidate into super_admin role blocked with 403
    const resEscalateOnboard = await makeRequest({
      method: 'POST',
      path: `/api/hr/applications/${applicationId}/onboard`,
      headers: authHeaders(tokenHR),
      body: {
        role: 'super_admin',
        department: 'Literature',
      },
    });
    assert(
      resEscalateOnboard.status === 403,
      'Test 4.3: HR attempting to onboard candidate into super_admin role is blocked with 403 Forbidden'
    );

    // Test 4.4: Application status updated to 'selected'
    const resCheckSelected = await makeRequest({
      method: 'GET',
      path: `/api/hr/applications/${applicationId}`,
      headers: authHeaders(tokenHR),
    });
    assert(
      resCheckSelected.status === 200 &&
        resCheckSelected.data.application?.status === 'selected' &&
        Boolean(resCheckSelected.data.application?.onboardingDetails?.onboardedAt),
      'Test 4.4: Application status updated to selected with linked onboardingDetails'
    );

    // Test 4.5: Onboarded user successfully activates account using activation token
    const resActivate = await makeRequest({
      method: 'POST',
      path: '/api/auth/activate',
      body: {
        token: rawActivationToken,
        password: 'ZainabPassword123!',
      },
    });
    assert(
      resActivate.status === 200 && resActivate.data.success,
      'Test 4.5: Onboarded candidate successfully activates account via /api/auth/activate (200 OK)'
    );

    // =========================================================================
    // GROUP 5: EMPLOYEE DIRECTORY & CONFIDENTIALITY
    // =========================================================================
    console.log('\n>>> [GROUP 5]: Employee Directory & Confidentiality');

    // Test 5.1: HR accesses organization employee directory
    const resEmployees = await makeRequest({
      method: 'GET',
      path: '/api/hr/employees',
      headers: authHeaders(tokenHR),
    });
    assert(
      resEmployees.status === 200 && Array.isArray(resEmployees.data.employees) && resEmployees.data.employees.length >= 5,
      'Test 5.1: HR and Super Admin access organization employee directory (200 OK)'
    );

    // Test 5.2: Member attempting to access employee directory blocked with 403
    const resMemDir = await makeRequest({
      method: 'GET',
      path: '/api/hr/employees',
      headers: authHeaders(tokenMember),
    });
    assert(
      resMemDir.status === 403,
      'Test 5.2: Regular member attempting to access employee directory is blocked with 403 Forbidden'
    );

    // Test 5.3: Finance lead attempting to access employee directory blocked with 403
    const resFinDir = await makeRequest({
      method: 'GET',
      path: '/api/hr/employees',
      headers: authHeaders(tokenFin),
    });
    assert(
      resFinDir.status === 403,
      'Test 5.3: Finance lead attempting to access employee directory is blocked with 403 Forbidden'
    );

    // Test 5.4: HR updates employee designation and contact info
    const resUpdateEmp = await makeRequest({
      method: 'PATCH',
      path: `/api/hr/employees/${litMember.id}`,
      headers: authHeaders(tokenHR),
      body: {
        designation: 'Senior Literary Contributor',
        phoneNumber: '+92 321 9876543',
      },
    });
    assert(
      resUpdateEmp.status === 200 && resUpdateEmp.data.employee?.designation === 'Senior Literary Contributor',
      'Test 5.4: HR updates employee designation and contact information (200 OK)'
    );

    // Test 5.5: HR attempting to modify Super Admin account blocked with 403
    const resModifySA = await makeRequest({
      method: 'PATCH',
      path: `/api/hr/employees/${superAdmin.id}`,
      headers: authHeaders(tokenHR),
      body: { designation: 'Demoted' },
    });
    assert(
      resModifySA.status === 403,
      'Test 5.5: HR attempting to alter Super Admin account is blocked with 403 Forbidden'
    );

    // =========================================================================
    // GROUP 6: LEAVE MANAGEMENT LIFECYCLE & ANTI-SELF-APPROVAL
    // =========================================================================
    console.log('\n>>> [GROUP 6]: Leave Management Lifecycle & Anti-Self-Approval');

    let memberLeaveId = null;

    // Test 6.1: Member submits a valid leave request
    const leaveStart = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString();
    const leaveEnd = new Date(Date.now() + 8 * 24 * 60 * 60 * 1000).toISOString();
    const resSubmitLeave = await makeRequest({
      method: 'POST',
      path: '/api/hr/leaves',
      headers: authHeaders(tokenMember),
      body: {
        leaveType: 'Exam',
        startDate: leaveStart,
        endDate: leaveEnd,
        reason: 'University mid-term examinations for Urdu literature major.',
        supportingDoc: 'https://docs.rekhta.org/exam-schedule-2026.pdf',
      },
    });
    assert(
      resSubmitLeave.status === 201 &&
        resSubmitLeave.data.success &&
        resSubmitLeave.data.leave?.status === 'pending' &&
        resSubmitLeave.data.leave?.leaveType === 'Exam',
      'Test 6.1: Member submits a valid leave request (201 Created)'
    );
    memberLeaveId = resSubmitLeave.data.leave?._id || resSubmitLeave.data.leave?.id;

    // Test 6.2: Leave request with invalid date range rejected with 400
    const resInvalidDates = await makeRequest({
      method: 'POST',
      path: '/api/hr/leaves',
      headers: authHeaders(tokenMember),
      body: {
        leaveType: 'Sick',
        startDate: leaveEnd,
        endDate: leaveStart, // End before start
        reason: 'Invalid dates',
      },
    });
    assert(
      resInvalidDates.status === 400 && resInvalidDates.data.success === false,
      'Test 6.2: Leave request with invalid date range (start > end) rejected with 400 Bad Request'
    );

    // Test 6.3: Member accesses their own leave requests
    const resMyLeaves = await makeRequest({
      method: 'GET',
      path: '/api/hr/leaves/my',
      headers: authHeaders(tokenMember),
    });
    assert(
      resMyLeaves.status === 200 && Array.isArray(resMyLeaves.data.leaves) && resMyLeaves.data.leaves.length >= 1,
      'Test 6.3: Member accesses their own leave requests via /api/hr/leaves/my (200 OK)'
    );

    // Test 6.4: Anti-Self-Approval: Member attempting to approve their own leave request blocked with 403
    const resSelfApprove = await makeRequest({
      method: 'PATCH',
      path: `/api/hr/leaves/${memberLeaveId}/review`,
      headers: authHeaders(tokenMember),
      body: { action: 'approve', notes: 'Self approving my own leave' },
    });
    assert(
      resSelfApprove.status === 403,
      'Test 6.4: Member attempting to self-approve leave request is blocked with 403 Forbidden (Anti-Self-Approval)'
    );

    // Test 6.5: Department Head of member's department approves leave request
    const resApproveLeave = await makeRequest({
      method: 'PATCH',
      path: `/api/hr/leaves/${memberLeaveId}/review`,
      headers: authHeaders(tokenLitHead),
      body: { action: 'approve', notes: 'Best of luck with your university examinations!' },
    });
    assert(
      resApproveLeave.status === 200 && resApproveLeave.data.leave?.status === 'approved',
      'Test 6.5: Department Head of member\'s department approves the leave request (200 OK)'
    );

    // Test 6.6: Leave history records reviewer name and review notes
    const resCheckLeaveHist = await makeRequest({
      method: 'GET',
      path: `/api/hr/leaves/${memberLeaveId}`,
      headers: authHeaders(tokenMember),
    });
    const leaveHistory = resCheckLeaveHist.data.leave?.history || [];
    assert(
      resCheckLeaveHist.status === 200 &&
        leaveHistory.length >= 2 &&
        resCheckLeaveHist.data.leave?.reviewedByName === litHead.name,
      'Test 6.6: Leave history records reviewer name, timestamp, and review notes'
    );

    // =========================================================================
    // GROUP 7: CROSS-DEPARTMENT LEAVE PROTECTION
    // =========================================================================
    console.log('\n>>> [GROUP 7]: Cross-Department Leave Protection');

    // Create a new leave request for Media department
    const mediaMember = {
      _id: 'usr_med_mem_01',
      id: 'usr_med_mem_01',
      name: 'Tariq Media (Media Member)',
      email: 'tariq_media@rekhta.org',
      password: hash,
      role: 'member',
      department: 'Media',
      departmentCode: 'MED',
      status: 'active',
      tokenVersion: 0,
    };
    setMemoryUser(mediaMember);
    const tokenMediaMember = generateToken({
      id: mediaMember.id,
      role: mediaMember.role,
      name: mediaMember.name,
      email: mediaMember.email,
      department: mediaMember.department,
      tokenVersion: 0,
    });

    const resMediaLeave = await makeRequest({
      method: 'POST',
      path: '/api/hr/leaves',
      headers: authHeaders(tokenMediaMember),
      body: {
        leaveType: 'Personal',
        startDate: leaveStart,
        endDate: leaveEnd,
        reason: 'Family event in Islamabad.',
      },
    });
    const mediaLeaveId = resMediaLeave.data.leave?._id || resMediaLeave.data.leave?.id;

    // Test 7.1: Literature Head queries department leaves and sees only Literature leaves
    const resLitDeptLeaves = await makeRequest({
      method: 'GET',
      path: '/api/hr/leaves/department',
      headers: authHeaders(tokenLitHead),
    });
    const containsMediaLeave = resLitDeptLeaves.data.leaves?.some((l) => l.department === 'Media');
    assert(
      resLitDeptLeaves.status === 200 && !containsMediaLeave,
      'Test 7.1: Literature Head queries /api/hr/leaves/department and sees only Literature leaves'
    );

    // Test 7.2: Literature Head attempting to review Media member's leave blocked with 403
    const resCrossDeptLeaveReview = await makeRequest({
      method: 'PATCH',
      path: `/api/hr/leaves/${mediaLeaveId}/review`,
      headers: authHeaders(tokenLitHead),
      body: { action: 'approve', notes: 'Literature lead cross-approving media leave' },
    });
    assert(
      resCrossDeptLeaveReview.status === 403,
      'Test 7.2: Literature Head attempting to review Media member\'s leave is blocked with 403 Forbidden'
    );

    // Test 7.3: HR or Super Admin can review any department's leave
    const resHROverrideLeave = await makeRequest({
      method: 'PATCH',
      path: `/api/hr/leaves/${mediaLeaveId}/review`,
      headers: authHeaders(tokenHR),
      body: { action: 'approve', notes: 'HR central approved leave.' },
    });
    assert(
      resHROverrideLeave.status === 200 && resHROverrideLeave.data.leave?.status === 'approved',
      'Test 7.3: Super Admin or HR can review any department\'s leave request (200 OK)'
    );

    // =========================================================================
    // GROUP 8: FINANCE ISOLATION & HR OVERVIEW METRICS
    // =========================================================================
    console.log('\n>>> [GROUP 8]: Finance Isolation & HR Overview Metrics');

    // Test 8.1: Finance lead attempting to query /api/hr/leaves blocked with 403
    const resFinLeaves = await makeRequest({
      method: 'GET',
      path: '/api/hr/leaves',
      headers: authHeaders(tokenFin),
    });
    assert(
      resFinLeaves.status === 403,
      'Test 8.1: Finance lead attempting to query /api/hr/leaves is blocked with 403 Forbidden'
    );

    // Test 8.2: Finance lead attempting to query /api/hr/overview blocked with 403
    const resFinOverview = await makeRequest({
      method: 'GET',
      path: '/api/hr/overview',
      headers: authHeaders(tokenFin),
    });
    assert(
      resFinOverview.status === 403,
      'Test 8.2: Finance lead attempting to query /api/hr/overview is blocked with 403 Forbidden'
    );

    // Test 8.3: HR successfully accesses /api/hr/overview
    const resHROverview = await makeRequest({
      method: 'GET',
      path: '/api/hr/overview',
      headers: authHeaders(tokenHR),
    });
    assert(
      resHROverview.status === 200 &&
        resHROverview.data.success &&
        resHROverview.data.metrics?.totalEmployees >= 5 &&
        Array.isArray(resHROverview.data.departmentDistribution),
      'Test 8.3: HR successfully accesses /api/hr/overview with aggregate workforce metrics (200 OK)'
    );
  } catch (err) {
    console.error('[Phase 6A Test Error]:', err);
    failed++;
  }

  console.log('\n======================================================================');
  console.log(`  PHASE 6A TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('======================================================================\n');

  server.close(() => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

server = http.createServer(app);
server.listen(TEST_PORT, () => {
  console.log(`[Phase 6A Test Runner] Server listening on port ${TEST_PORT}...`);
  runTestSuite();
});
