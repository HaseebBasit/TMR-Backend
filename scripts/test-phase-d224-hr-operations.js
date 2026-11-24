/**
 * Phase D.2.2.4 — HR Operations, Volunteer Application Intake, Departmental
 * Announcements & Export Management Offline Test Suite
 * 
 * Mode: Strictly Offline Mock Isolation — Zero Live Database Connections
 * Active Staging Test Run ID: TR_20261124_1EA2B4
 * 
 * Comprehensive Test Coverage:
 *   Section 1: Model Schema Verification (Announcement, Application, Campaign, LeaveRequest)
 *   Section 2: Capability Architecture & RBAC Evaluation
 *   Section 3: Volunteer Intake & Deduplication Engine
 *   Section 4: HR Authorization Middleware Gates (Recruitment, Export, Coordination In-charge)
 *   Section 5: Advanced Recruitment Lifecycle (Interviewer Assignment, Feedback, Final Decision)
 *   Section 6: Excel (.xlsx) & CSV Data Export Engine
 *   Section 7: Departmental Announcements & Multi-Tenant Isolation
 *   Section 8: Leave Approval Boundaries & Anti-Self-Approval Protection
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_for_offline_suite_d224_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_d224_2026';

const jwt = require('jsonwebtoken');
const XLSX = require('xlsx');
const {
  CAPABILITIES,
  hasCapability,
  DEPT_ROLE_MAP,
  TECHNICAL_ROLES,
  HR_DESIGNATIONS,
  OPERATIONAL_DESIGNATIONS,
  normalizeDesignation,
} = require('../src/constants/roles');

const {
  requireHRRecruitmentManage,
  requireHRExport,
  requireHRCoordinationIncharge,
  setMemoryUser,
} = require('../src/middleware/auth');

const {
  Announcement,
  Application,
  Campaign,
  LeaveRequest,
  User,
} = require('../src/models');

const {
  router: hrRouter,
  setMemoryApplication,
  getMemoryApplicationsList,
  setMemoryCampaign,
  getMemoryCampaignsList,
  setMemoryLeave,
  getMemoryLeavesList,
  setMemoryAnnouncement,
  getMemoryAnnouncementsList,
} = require('../src/routes/hr.routes');

const volunteerRouter = require('../src/routes/volunteer.routes');
const portalRouter = require('../src/routes/portal.routes');

let passedTests = 0;
let failedTests = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passedTests++;
  } else {
    console.error(`  [FAIL] ${testName} ${details ? '- ' + details : ''}`);
    failedTests++;
  }
}

function mockReq(user, body = {}, params = {}, query = {}, method = 'GET', url = '/') {
  const headers = { 'x-requested-with': 'XMLHttpRequest' };
  if (user) {
    const payload = {
      id: user.id || user._id || 'usr_test',
      name: user.name || 'Test User',
      email: user.email || `${user.role || 'user'}@tameer.org`,
      role: user.role,
      designation: user.designation,
      department: user.department,
      status: user.status || 'active',
      tokenVersion: 0,
    };
    const token = jwt.sign(payload, process.env.JWT_SECRET);
    headers.authorization = `Bearer ${token}`;
    setMemoryUser({ ...payload, _id: payload.id });
  }
  return {
    method,
    url,
    originalUrl: url,
    user,
    body,
    params,
    query,
    headers,
    cookies: {},
  };
}

function mockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    data: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(obj) {
      this.data = obj;
      return this;
    },
    send(buf) {
      this.data = buf;
      return this;
    },
    setHeader(key, val) {
      this.headers[key.toLowerCase()] = val;
      return this;
    },
  };
  return res;
}

// Router execution helper
function invokeRouter(router, req, res) {
  return new Promise((resolve) => {
    router.handle(req, res, (err) => {
      if (err) {
        res.status(500).json({ error: err.message });
      }
      resolve();
    });
  });
}

async function runTests() {
  console.log('='.repeat(80));
  console.log('TA\'MEER-E-REKHTA MANAGEMENT PORTAL — PHASE D.2.2.4 OFFLINE TEST SUITE');
  console.log('HR Operations, Volunteer Intake, Department Announcements & Export Engine');
  console.log('Mode: Controlled Isolation | Zero DB Connections | Offline Fallbacks Active');
  console.log('='.repeat(80));

  // ---------------------------------------------------------------------------
  // SECTION 1: MODEL SCHEMAS
  // ---------------------------------------------------------------------------
  console.log('\n--- Section 1: Model Schema Verification ---');

  const annPaths = Announcement.schema.paths;
  assert(annPaths.announcementId, 'Announcement schema includes announcementId');
  assert(annPaths.title, 'Announcement schema includes title');
  assert(annPaths.message, 'Announcement schema includes message');
  assert(annPaths.targetDepartment, 'Announcement schema includes targetDepartment');
  assert(annPaths.senderName, 'Announcement schema includes senderName');
  assert(annPaths.recipientCount, 'Announcement schema includes recipientCount');

  const appPaths = Application.schema.paths;
  assert(appPaths['interviewDetails.interviewerId'], 'Application schema includes interviewDetails.interviewerId');
  assert(appPaths['interviewDetails.recommendation'], 'Application schema includes interviewDetails.recommendation');
  assert(appPaths['decisionDetails.decision'], 'Application schema includes decisionDetails.decision');
  assert(appPaths['decisionDetails.decidedByName'], 'Application schema includes decisionDetails.decidedByName');

  const appSourceEnum = appPaths.source.enumValues || [];
  assert(
    appSourceEnum.includes('official_website') || appSourceEnum.includes('website_volunteer_form'),
    'Application source enum supports official website volunteer intakes'
  );

  // ---------------------------------------------------------------------------
  // SECTION 2: CAPABILITY ARCHITECTURE & RBAC EVALUATION
  // ---------------------------------------------------------------------------
  console.log('\n--- Section 2: Capability Architecture & RBAC Evaluation ---');

  const superAdmin = { role: 'super_admin', name: 'Super Admin', id: 'usr_sa_01' };
  const hrHead = { role: 'hr', designation: 'hr_head', name: 'HR Head', id: 'usr_hr_head' };
  const hrDirector = { role: 'hr', designation: 'hr_director', name: 'HR Director', id: 'usr_hr_dir' };
  const hrIncharge = { role: 'hr', designation: 'hr_coordination_incharge', name: 'HR In-charge', id: 'usr_hr_inc' };
  const hrMember = { role: 'hr', designation: 'hr_member', name: 'HR Member', id: 'usr_hr_mem' };
  const litHead = { role: 'dept_literature', designation: 'head', department: 'Literature', id: 'usr_lit_head' };
  const mediaMember = { role: 'dept_media', designation: 'member', department: 'Media', id: 'usr_med_mem' };

  // HR_RECRUITMENT_MANAGE
  assert(hasCapability(superAdmin, CAPABILITIES.HR_RECRUITMENT_MANAGE), 'Super Admin has HR_RECRUITMENT_MANAGE');
  assert(hasCapability(hrHead, CAPABILITIES.HR_RECRUITMENT_MANAGE), 'HR Head has HR_RECRUITMENT_MANAGE');
  assert(hasCapability(hrDirector, CAPABILITIES.HR_RECRUITMENT_MANAGE), 'HR Director has HR_RECRUITMENT_MANAGE');
  assert(hasCapability(hrIncharge, CAPABILITIES.HR_RECRUITMENT_MANAGE), 'HR Coordination In-charge has HR_RECRUITMENT_MANAGE');
  assert(!hasCapability(hrMember, CAPABILITIES.HR_RECRUITMENT_MANAGE), 'HR Member DENIED HR_RECRUITMENT_MANAGE (View-Only)');
  assert(!hasCapability(litHead, CAPABILITIES.HR_RECRUITMENT_MANAGE), 'Operational Department Head DENIED HR_RECRUITMENT_MANAGE');

  // HR_DATA_EXPORT
  assert(hasCapability(superAdmin, CAPABILITIES.HR_DATA_EXPORT), 'Super Admin has HR_DATA_EXPORT');
  assert(hasCapability(hrHead, CAPABILITIES.HR_DATA_EXPORT), 'HR Head has HR_DATA_EXPORT');
  assert(hasCapability(hrDirector, CAPABILITIES.HR_DATA_EXPORT), 'HR Director has HR_DATA_EXPORT');
  assert(hasCapability(hrIncharge, CAPABILITIES.HR_DATA_EXPORT), 'HR Coordination In-charge has HR_DATA_EXPORT');
  assert(!hasCapability(hrMember, CAPABILITIES.HR_DATA_EXPORT), 'HR Member DENIED HR_DATA_EXPORT');
  assert(!hasCapability(mediaMember, CAPABILITIES.HR_DATA_EXPORT), 'Operational Member DENIED HR_DATA_EXPORT');

  // HR_DEPARTMENT_ANNOUNCEMENT
  assert(hasCapability(superAdmin, CAPABILITIES.HR_DEPARTMENT_ANNOUNCEMENT), 'Super Admin has HR_DEPARTMENT_ANNOUNCEMENT');
  assert(hasCapability(hrIncharge, CAPABILITIES.HR_DEPARTMENT_ANNOUNCEMENT), 'HR Coordination In-charge has HR_DEPARTMENT_ANNOUNCEMENT (Exclusive)');
  assert(!hasCapability(hrHead, CAPABILITIES.HR_DEPARTMENT_ANNOUNCEMENT), 'HR Head STRICTLY DENIED HR_DEPARTMENT_ANNOUNCEMENT');
  assert(!hasCapability(hrDirector, CAPABILITIES.HR_DEPARTMENT_ANNOUNCEMENT), 'HR Director STRICTLY DENIED HR_DEPARTMENT_ANNOUNCEMENT');
  assert(!hasCapability(hrMember, CAPABILITIES.HR_DEPARTMENT_ANNOUNCEMENT), 'HR Member STRICTLY DENIED HR_DEPARTMENT_ANNOUNCEMENT');

  // ---------------------------------------------------------------------------
  // SECTION 3: VOLUNTEER INTAKE & DEDUPLICATION ENGINE
  // ---------------------------------------------------------------------------
  console.log('\n--- Section 3: Volunteer Intake & Deduplication Engine ---');

  const volSubmission1 = {
    fullName: 'Zainab Qureshi',
    email: 'zainab.q@example.com',
    phone: '+92 300 1234567',
    city: 'Lahore',
    areaOfInterest: 'Literature',
    motivation: 'Passionate about classic Urdu poetry and Nazms.',
    submissionId: 'SUB_VOL_2026_001',
  };

  const reqVol1 = mockReq(null, volSubmission1, {}, {}, 'POST', '/');
  const resVol1 = mockRes();
  await invokeRouter(volunteerRouter, reqVol1, resVol1);

  assert(resVol1.statusCode === 200, 'Volunteer endpoint accepts valid application submission');
  assert(resVol1.data && resVol1.data.success === true, 'Volunteer intake returns success');
  assert(resVol1.data && resVol1.data.submissionId === 'SUB_VOL_2026_001', 'Volunteer intake preserves submissionId');

  // Duplicate Submission with identical submissionId
  const reqVolDup = mockReq(null, volSubmission1, {}, {}, 'POST', '/');
  const resVolDup = mockRes();
  await invokeRouter(volunteerRouter, reqVolDup, resVolDup);

  assert(resVolDup.statusCode === 200, 'Duplicate submission handled gracefully');
  assert(resVolDup.data && resVolDup.data.duplicate === true, 'Duplicate submission correctly flagged duplicate=true without error');

  // Verify application registered in memoryApplications
  const registered = getMemoryApplicationsList().find((a) => a.submissionId === 'SUB_VOL_2026_001');
  assert(Boolean(registered), 'Volunteer application registered in HR Portal application storage');
  assert(registered && registered.source === 'website_volunteer_form', 'Registered application source is website_volunteer_form');

  // ---------------------------------------------------------------------------
  // SECTION 4: HR AUTHORIZATION MIDDLEWARE GATES
  // ---------------------------------------------------------------------------
  console.log('\n--- Section 4: HR Authorization Middleware Gates ---');

  // Test requireHRRecruitmentManage
  let calledNext = false;
  requireHRRecruitmentManage(mockReq(hrHead), mockRes(), () => { calledNext = true; });
  assert(calledNext, 'requireHRRecruitmentManage permits HR Head');

  calledNext = false;
  requireHRRecruitmentManage(mockReq(hrIncharge), mockRes(), () => { calledNext = true; });
  assert(calledNext, 'requireHRRecruitmentManage permits HR Coordination In-charge');

  calledNext = false;
  const resGateMem = mockRes();
  requireHRRecruitmentManage(mockReq(hrMember), resGateMem, () => { calledNext = true; });
  assert(!calledNext && resGateMem.statusCode === 403, 'requireHRRecruitmentManage blocks HR Member with HTTP 403');

  // Test requireHRExport
  calledNext = false;
  requireHRExport(mockReq(hrDirector), mockRes(), () => { calledNext = true; });
  assert(calledNext, 'requireHRExport permits HR Director');

  calledNext = false;
  const resExpMem = mockRes();
  requireHRExport(mockReq(hrMember), resExpMem, () => { calledNext = true; });
  assert(!calledNext && resExpMem.statusCode === 403, 'requireHRExport blocks HR Member with HTTP 403');

  // Test requireHRCoordinationIncharge
  calledNext = false;
  requireHRCoordinationIncharge(mockReq(hrIncharge), mockRes(), () => { calledNext = true; });
  assert(calledNext, 'requireHRCoordinationIncharge permits HR Coordination In-charge');

  calledNext = false;
  const resIncHead = mockRes();
  requireHRCoordinationIncharge(mockReq(hrHead), resIncHead, () => { calledNext = true; });
  assert(!calledNext && resIncHead.statusCode === 403, 'requireHRCoordinationIncharge blocks HR Head with HTTP 403');

  // ---------------------------------------------------------------------------
  // SECTION 5: ADVANCED RECRUITMENT LIFECYCLE
  // ---------------------------------------------------------------------------
  console.log('\n--- Section 5: Advanced Recruitment Lifecycle ---');

  // Seed a candidate application
  const testCandidate = {
    _id: 'app_cand_901',
    id: 'app_cand_901',
    fullName: 'Mirza Asadullah Baig',
    email: 'mirza.asad@example.com',
    phoneNumber: '+92 321 9876543',
    department: 'Literature',
    areaOfInterest: 'Literature',
    source: 'website_volunteer_form',
    status: 'submitted',
    createdAt: new Date(),
  };
  setMemoryApplication(testCandidate);

  // 5a. Assign Interviewer: HR Member tries to assign interviewer -> Rejected with 403
  const reqAssignMem = mockReq(
    hrMember,
    { interviewerId: 'usr_lit_head', interviewerName: 'Noor-ul-Huda' },
    { id: 'app_cand_901' },
    {},
    'POST',
    '/applications/app_cand_901/assign-interviewer'
  );
  const resAssignMem = mockRes();
  await invokeRouter(hrRouter, reqAssignMem, resAssignMem);
  assert(resAssignMem.statusCode === 403, 'HR Member rejected with HTTP 403 when assigning interviewer');

  // HR In-charge assigns interviewer
  const reqAssignInc = mockReq(
    hrIncharge,
    {
      interviewerId: 'usr_lit_head',
      interviewerName: 'Noor-ul-Huda',
      scheduledAt: new Date(Date.now() + 86400000).toISOString(),
      mode: 'Online',
      meetingLink: 'https://meet.google.com/xyz-test',
    },
    { id: 'app_cand_901' },
    {},
    'POST',
    '/applications/app_cand_901/assign-interviewer'
  );
  const resAssignInc = mockRes();
  await invokeRouter(hrRouter, reqAssignInc, resAssignInc);

  assert(resAssignInc.statusCode === 200, 'HR Coordination In-charge successfully assigns interviewer');
  assert(testCandidate.assignedInterviewer === 'usr_lit_head', 'Candidate record updated with assignedInterviewer');
  assert(testCandidate.status === 'interview_scheduled', 'Candidate status updated to interview_scheduled');

  // 5b. Interviewer Feedback & Recommendation
  const interviewerUser = {
    id: 'usr_lit_head',
    _id: 'usr_lit_head',
    role: 'dept_literature',
    name: 'Noor-ul-Huda',
  };
  const reqFeedback = mockReq(
    interviewerUser,
    {
      rating: 5,
      recommendation: 'strong_hire',
      feedbackNotes: 'Exceptional command of classical Urdu meter and Dastaan narration.',
    },
    { id: 'app_cand_901' },
    {},
    'POST',
    '/applications/app_cand_901/interview-feedback'
  );
  const resFeedback = mockRes();
  await invokeRouter(hrRouter, reqFeedback, resFeedback);

  assert(resFeedback.statusCode === 200, 'Assigned interviewer successfully submits feedback');
  assert(testCandidate.interviewDetails.recommendation === 'strong_hire', 'Candidate interview recommendation recorded');
  assert(testCandidate.interviewDetails.rating === 5, 'Candidate interview rating recorded');
  assert(testCandidate.status === 'interview_completed', 'Application status moved to interview_completed without premature decision');

  // 5c. Final Recruitment Decision
  const reqDecision = mockReq(
    hrHead,
    { decision: 'selected', notes: 'Approved for onboarding based on outstanding literary audition.' },
    { id: 'app_cand_901' },
    {},
    'POST',
    '/applications/app_cand_901/decision'
  );
  const resDecision = mockRes();
  await invokeRouter(hrRouter, reqDecision, resDecision);

  assert(resDecision.statusCode === 200, 'HR Head records final recruitment decision');
  assert(testCandidate.status === 'selected', 'Candidate application status moved to selected');
  assert(testCandidate.decisionDetails.decision === 'selected', 'Decision details recorded with decider identity');

  // ---------------------------------------------------------------------------
  // SECTION 6: EXCEL (.xlsx) & CSV DATA EXPORT ENGINE
  // ---------------------------------------------------------------------------
  console.log('\n--- Section 6: Excel (.xlsx) & CSV Data Export Engine ---');

  // Export applications as Excel (.xlsx)
  const reqExpXlsx = mockReq(hrHead, {}, {}, { format: 'xlsx' }, 'GET', '/export/applications');
  const resExpXlsx = mockRes();
  await invokeRouter(hrRouter, reqExpXlsx, resExpXlsx);

  assert(resExpXlsx.statusCode === 200, 'GET /export/applications returns HTTP 200');
  assert(
    resExpXlsx.headers['content-type']?.includes('openxmlformats-officedocument.spreadsheetml.sheet'),
    'Excel export includes openxmlformats spreadsheet content type header'
  );
  assert(Buffer.isBuffer(resExpXlsx.data), 'Excel export returns binary buffer');

  // Parse Excel buffer using xlsx reader
  const parsedWb = XLSX.read(resExpXlsx.data, { type: 'buffer' });
  assert(parsedWb.SheetNames.includes('Applications'), 'Excel workbook contains "Applications" worksheet');
  const sheetData = XLSX.utils.sheet_to_json(parsedWb.Sheets['Applications']);
  assert(sheetData.length >= 1, `Excel worksheet parsed cleanly with ${sheetData.length} data rows`);

  // Export applications as CSV
  const reqExpCsv = mockReq(hrDirector, {}, {}, { format: 'csv' }, 'GET', '/export/applications');
  const resExpCsv = mockRes();
  await invokeRouter(hrRouter, reqExpCsv, resExpCsv);

  assert(resExpCsv.statusCode === 200, 'GET /export/applications returns HTTP 200 for CSV');
  assert(resExpCsv.headers['content-type']?.includes('text/csv'), 'CSV export includes text/csv content type');
  assert(Buffer.isBuffer(resExpCsv.data), 'CSV export returns buffer with BOM');
  assert(resExpCsv.data[0] === 0xef && resExpCsv.data[1] === 0xbb && resExpCsv.data[2] === 0xbf, 'CSV export includes UTF-8 Byte Order Mark (BOM)');

  // Verify HR Member blocked from export
  const reqExpMem = mockReq(hrMember, {}, {}, { format: 'xlsx' }, 'GET', '/export/applications');
  const resExpMemRoute = mockRes();
  await invokeRouter(hrRouter, reqExpMem, resExpMemRoute);
  assert(resExpMemRoute.statusCode === 403, 'HR Member rejected with HTTP 403 on export endpoint');

  // ---------------------------------------------------------------------------
  // SECTION 7: DEPARTMENT ANNOUNCEMENTS & MULTI-TENANT ISOLATION
  // ---------------------------------------------------------------------------
  console.log('\n--- Section 7: Department Announcements & Multi-Tenant Isolation ---');

  // Seed sample users for Department Targeting
  setMemoryUser({
    _id: 'usr_lit_member_01',
    id: 'usr_lit_member_01',
    name: 'Hamza Farooqi',
    role: 'member',
    department: 'Literature',
    status: 'active',
  });
  setMemoryUser({
    _id: 'usr_med_member_01',
    id: 'usr_med_member_01',
    name: 'Sara Khan',
    role: 'member',
    department: 'Media',
    status: 'active',
  });

  // 7a. Non-authorized sender rejected
  const reqAnnHead = mockReq(
    hrHead,
    { title: 'Invalid Announcement', message: 'Should be rejected', targetDepartment: 'Literature' },
    {},
    {},
    'POST',
    '/announcements'
  );
  const resAnnHead = mockRes();
  await invokeRouter(hrRouter, reqAnnHead, resAnnHead);
  assert(resAnnHead.statusCode === 403, 'HR Head rejected with HTTP 403 when dispatching announcement');

  // 7b. HR Coordination In-charge dispatches announcement targeted to Literature
  const reqAnnInc = mockReq(
    hrIncharge,
    {
      title: 'Annual Mushaira Volunteer Briefing',
      message: 'All Literature volunteers must assemble in Room 4B at 3:00 PM for program review.',
      targetDepartment: 'Literature',
    },
    {},
    {},
    'POST',
    '/announcements'
  );
  const resAnnInc = mockRes();
  await invokeRouter(hrRouter, reqAnnInc, resAnnInc);

  assert(resAnnInc.statusCode === 201, 'HR Coordination In-charge successfully dispatches department announcement (HTTP 201)');
  assert(resAnnInc.data?.announcement?.targetDepartment === 'Literature', 'Announcement targetDepartment is Literature');

  // 7c. Literature member views announcement via /api/announcements/my
  const litMember = { id: 'usr_lit_member_01', role: 'member', department: 'Literature' };
  const reqLitMy = mockReq(litMember, {}, {}, {}, 'GET', '/announcements/my');
  const resLitMy = mockRes();
  await invokeRouter(portalRouter, reqLitMy, resLitMy);

  assert(resLitMy.statusCode === 200, 'Literature member fetches announcements via /announcements/my');
  const litAnnouncements = resLitMy.data?.announcements || [];
  const foundLitAnn = litAnnouncements.find((a) => a.title === 'Annual Mushaira Volunteer Briefing');
  assert(Boolean(foundLitAnn), 'Literature member successfully receives Literature announcement');

  // 7d. Media member checks /api/announcements/my -> Must NOT see Literature-specific announcement
  const mediaMemberUser = { id: 'usr_med_member_01', role: 'member', department: 'Media' };
  const reqMedMy = mockReq(mediaMemberUser, {}, {}, {}, 'GET', '/announcements/my');
  const resMedMy = mockRes();
  await invokeRouter(portalRouter, reqMedMy, resMedMy);

  assert(resMedMy.statusCode === 200, 'Media member fetches announcements via /announcements/my');
  const medAnnouncements = resMedMy.data?.announcements || [];
  const leakedLitAnn = medAnnouncements.find((a) => a.title === 'Annual Mushaira Volunteer Briefing');
  assert(!leakedLitAnn, 'Department Isolation Verified: Media member CANNOT view Literature announcement');

  // ---------------------------------------------------------------------------
  // SECTION 8: LEAVE APPROVAL BOUNDARIES & ANTI-SELF-APPROVAL
  // ---------------------------------------------------------------------------
  console.log('\n--- Section 8: Leave Approval Boundaries & Anti-Self-Approval ---');

  // Seed operational leave request for a Literature member
  const litLeave = {
    _id: 'leave_lit_001',
    id: 'leave_lit_001',
    memberId: 'usr_lit_member_01',
    memberName: 'Hamza Farooqi',
    memberEmail: 'hamza.f@example.com',
    department: 'Literature',
    leaveType: 'Exam',
    startDate: new Date('2026-12-01'),
    endDate: new Date('2026-12-05'),
    reason: 'University semester final exams.',
    status: 'pending',
  };
  setMemoryLeave(litLeave);

  // 8a. Anti-self-approval rule: Member cannot approve their own leave
  const reqSelfLeave = mockReq(litMember, { action: 'approve' }, { id: 'leave_lit_001' }, {}, 'PATCH', '/leaves/leave_lit_001/review');
  const resSelfLeave = mockRes();
  await invokeRouter(hrRouter, reqSelfLeave, resSelfLeave);
  assert(resSelfLeave.statusCode === 403, 'Anti-self-approval: Member rejected with HTTP 403 approving own leave');

  // 8b. HR Member view-only: HR Member cannot review leave
  const reqMemLeave = mockReq(hrMember, { action: 'approve' }, { id: 'leave_lit_001' }, {}, 'PATCH', '/leaves/leave_lit_001/review');
  const resMemLeave = mockRes();
  await invokeRouter(hrRouter, reqMemLeave, resMemLeave);
  assert(resMemLeave.statusCode === 403, 'HR Member rejected with HTTP 403 reviewing leave request');

  // 8c. Departmental Boundary: HR Head CANNOT approve operational (Literature) leave
  const reqHrApproveLit = mockReq(hrHead, { action: 'approve' }, { id: 'leave_lit_001' }, {}, 'PATCH', '/leaves/leave_lit_001/review');
  const resHrApproveLit = mockRes();
  await invokeRouter(hrRouter, reqHrApproveLit, resHrApproveLit);
  assert(resHrApproveLit.statusCode === 403, 'Department Boundary: HR Head rejected with HTTP 403 approving Literature leave');

  // 8d. Literature Department Head approves Literature leave
  const litHeadUser = {
    id: 'usr_lit_head',
    role: 'dept_literature',
    designation: 'head',
    department: 'Literature',
    name: 'Noor-ul-Huda',
  };
  const reqLitHeadApprove = mockReq(
    litHeadUser,
    { action: 'approve', notes: 'Best of luck for exams.' },
    { id: 'leave_lit_001' },
    {},
    'PATCH',
    '/leaves/leave_lit_001/review'
  );
  const resLitHeadApprove = mockRes();
  await invokeRouter(hrRouter, reqLitHeadApprove, resLitHeadApprove);
  assert(resLitHeadApprove.statusCode === 200, 'Literature Department Head successfully approves Literature leave');
  assert(litLeave.status === 'approved', 'Literature leave status updated to approved');

  // 8e. HR department leave can be approved by HR Head
  const hrLeave = {
    _id: 'leave_hr_002',
    id: 'leave_hr_002',
    memberId: 'usr_hr_mem',
    memberName: 'HR Member Persona',
    department: 'HR',
    leaveType: 'Sick',
    startDate: new Date('2026-12-10'),
    endDate: new Date('2026-12-11'),
    reason: 'Flu recovery.',
    status: 'pending',
  };
  setMemoryLeave(hrLeave);

  const reqHrLeaveApprove = mockReq(hrHead, { action: 'approve' }, { id: 'leave_hr_002' }, {}, 'PATCH', '/leaves/leave_hr_002/review');
  const resHrLeaveApprove = mockRes();
  await invokeRouter(hrRouter, reqHrLeaveApprove, resHrLeaveApprove);
  assert(resHrLeaveApprove.statusCode === 200, 'HR Head successfully approves HR department leave');
  assert(hrLeave.status === 'approved', 'HR leave status updated to approved');

  // ---------------------------------------------------------------------------
  // SUMMARY
  // ---------------------------------------------------------------------------
  console.log('\n' + '='.repeat(80));
  console.log(`PHASE D.2.2.4 TEST RESULTS: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log('='.repeat(80));

  if (failedTests > 0) {
    console.error(`\nFAILED: ${failedTests} test(s) failed in Phase D.2.2.4 suite.`);
    process.exit(1);
  } else {
    console.log('\nSUCCESS: All Phase D.2.2.4 tests passed cleanly.');
    process.exit(0);
  }
}

runTests().catch((err) => {
  console.error('Fatal test execution error:', err);
  process.exit(1);
});
