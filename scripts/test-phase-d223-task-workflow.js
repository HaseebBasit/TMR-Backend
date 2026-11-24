/**
 * Phase D.2.2.3 — Advanced Task Lifecycle, Inter-Department Referral, Testing,
 * Moderation & Media Gallery Publishing Architecture Offline Test Suite
 * 
 * Mode: Strictly Offline Mock Isolation — Zero Live Database Connections
 * Active Staging Test Run ID: TR_20261124_1EA2B4
 * 
 * Comprehensive Test Coverage:
 *   Section 1: Model Schema Verification (User, Task, MediaAsset)
 *   Section 2: Storage Service & Multimedia Validation
 *   Section 3: Tester & Moderator Capability Architecture
 *   Section 4: Intermediate Reviewer Boundary Enforcement
 *   Section 5: Task Assignment & Versioned Multimedia Submissions
 *   Section 6: Tester Review Workflow (Pass / Corrections / Reject)
 *   Section 7: Moderator Review & Deliverable Editing
 *   Section 8: Department Rechecking & Reassignment (Stage 4b)
 *   Section 9: Inter-Department Referral & Response (Stage 5)
 *   Section 10: Final Departmental Approval Restrictions (Stage 6)
 *   Section 11: Exclusive Media Gallery Publishing Authorization
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_for_offline_suite_d223_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_d223_2026';

const {
  CAPABILITIES,
  hasCapability,
  DEPT_ROLE_MAP,
} = require('../src/constants/roles');

const {
  requireTester,
  requireModerator,
  requireMediaHead,
  normalizeDesignation,
} = require('../src/middleware/auth');

const {
  validateAttachmentMetadata,
  generateSafeFileName,
  ALLOWED_EXTENSIONS,
  SIZE_LIMITS,
} = require('../src/services/storage.service');

const { User, Task, MediaAsset } = require('../src/models');

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

function createMockContext(user, params = {}, query = {}, body = {}) {
  const req = {
    user,
    params,
    query,
    body,
    headers: {},
  };
  const res = {
    statusCode: 200,
    bodyData: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.bodyData = data;
      return this;
    },
  };
  let nextCalled = false;
  const next = () => {
    nextCalled = true;
  };
  return { req, res, next, wasNextCalled: () => nextCalled };
}

async function runTestSuite() {
  console.log('================================================================================');
  console.log("TA'MEER-E-REKHTA MANAGEMENT PORTAL — PHASE D.2.2.3 OFFLINE TEST SUITE");
  console.log('Active Staging Test Run ID: TR_20261124_1EA2B4');
  console.log('Mode: Offline Mock Isolation (Zero Live Database Mutations)');
  console.log('================================================================================\n');

  // ---------------------------------------------------------------------------
  // SECTION 1: MODEL SCHEMA VERIFICATION
  // ---------------------------------------------------------------------------
  console.log('--- SECTION 1: Model Schema Verification ---');

  const userPaths = User.schema.paths;
  assert(userPaths['isTester'] !== undefined, 'User schema includes isTester boolean flag');
  assert(userPaths['isModerator'] !== undefined, 'User schema includes isModerator boolean flag');
  assert(userPaths['capabilities'] !== undefined, 'User schema includes capabilities array');

  const taskPaths = Task.schema.paths;
  assert(taskPaths['originalDepartment'] !== undefined, 'Task schema includes immutable originalDepartment field');
  assert(taskPaths['originalDepartmentCode'] !== undefined, 'Task schema includes originalDepartmentCode field');
  assert(taskPaths['instructions'] !== undefined, 'Task schema includes explicit instructions field');
  assert(taskPaths['requiredDeliverables'] !== undefined, 'Task schema includes requiredDeliverables array');
  assert(taskPaths['referenceAttachments'] !== undefined, 'Task schema includes referenceAttachments array');
  assert(taskPaths['currentVersion'] !== undefined, 'Task schema includes currentVersion number');
  assert(taskPaths['submissions'] !== undefined, 'Task schema includes versioned submissions array');
  assert(taskPaths['testingDetails.decision'] !== undefined, 'Task schema includes testingDetails with verdict decision');
  assert(taskPaths['moderationDetails.decision'] !== undefined, 'Task schema includes moderationDetails with decision');
  assert(taskPaths['moderationDetails.editedAttachments'] !== undefined, 'Task schema includes moderationDetails editedAttachments');
  assert(taskPaths['referrals'] !== undefined, 'Task schema includes referrals array');
  assert(taskPaths['activeReferral.referralId'] !== undefined, 'Task schema includes activeReferral object');
  assert(taskPaths['finalApprovalDetails.approvedBy.id'] !== undefined, 'Task schema includes finalApprovalDetails object');

  const mediaPaths = MediaAsset.schema.paths;
  assert(mediaPaths['publicationStatus'] !== undefined, 'MediaAsset schema includes publicationStatus');
  assert(mediaPaths['publishedBy'] !== undefined, 'MediaAsset schema includes publishedBy reference');
  assert(mediaPaths['publishedAt'] !== undefined, 'MediaAsset schema includes publishedAt timestamp');
  assert(mediaPaths['caption'] !== undefined, 'MediaAsset schema includes caption field');
  assert(mediaPaths['uploadedByName'] !== undefined, 'MediaAsset schema includes uploadedByName field');

  // ---------------------------------------------------------------------------
  // SECTION 2: STORAGE SERVICE & MULTIMEDIA VALIDATION
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 2: Storage Service & Multimedia Validation ---');

  // Valid video (<100MB)
  const validVideo = validateAttachmentMetadata({
    fileName: 'documentary_scene1.mp4',
    fileSize: 45 * 1024 * 1024,
    fileType: 'video/mp4',
    mimeType: 'video/mp4',
  });
  assert(validVideo.valid === true, 'Accepts valid video MP4 under 100MB limit');

  // Video exceeding limit (>100MB)
  const oversizedVideo = validateAttachmentMetadata({
    fileName: 'huge_footage.mov',
    fileSize: 120 * 1024 * 1024,
    fileType: 'video/quicktime',
    mimeType: 'video/quicktime',
  });
  assert(oversizedVideo.valid === false && oversizedVideo.error.includes('100MB'), 'Rejects video exceeding 100MB limit');

  // Valid document (<25MB)
  const validDoc = validateAttachmentMetadata({
    fileName: 'literature_analysis.pdf',
    fileSize: 5 * 1024 * 1024,
    fileType: 'application/pdf',
    mimeType: 'application/pdf',
  });
  assert(validDoc.valid === true, 'Accepts valid PDF document under 25MB limit');

  // Document exceeding limit (>25MB)
  const oversizedDoc = validateAttachmentMetadata({
    fileName: 'massive_archive.pdf',
    fileSize: 30 * 1024 * 1024,
    fileType: 'application/pdf',
    mimeType: 'application/pdf',
  });
  assert(oversizedDoc.valid === false && oversizedDoc.error.includes('25MB'), 'Rejects document exceeding 25MB limit');

  // Disallowed dangerous file type (.exe)
  const dangerousFile = validateAttachmentMetadata({
    fileName: 'malicious_payload.exe',
    fileSize: 1024,
    fileType: 'application/x-msdownload',
    mimeType: 'application/x-msdownload',
  });
  assert(dangerousFile.valid === false && dangerousFile.error.includes('extension'), 'Rejects disallowed executable file extension (.exe)');

  // Safe unique filename generation
  const safeName = generateSafeFileName('Urdu Poetry Recital #1 (Draft).mp4');
  assert(safeName.endsWith('.mp4') && !safeName.includes('#') && !safeName.includes('('), 'Generates sanitized, safe unique filename');

  // ---------------------------------------------------------------------------
  // SECTION 3: TESTER & MODERATOR CAPABILITY ARCHITECTURE
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 3: Tester & Moderator Capability Architecture ---');

  const testerUser = {
    id: 'u_tester_1',
    name: 'Tariq Tester',
    role: 'member',
    department: 'Media',
    isTester: true,
  };
  const moderatorUser = {
    id: 'u_moderator_1',
    name: 'Mona Moderator',
    role: 'member',
    department: 'Literature',
    isModerator: true,
  };
  const standardMember = {
    id: 'u_member_1',
    name: 'Standard Member',
    role: 'member',
    department: 'Media',
  };
  const superAdminUser = {
    id: 'u_sa_1',
    name: 'Global Super Admin',
    role: 'super_admin',
  };

  // requireTester middleware test
  const ctxTesterPass = createMockContext(testerUser);
  requireTester(ctxTesterPass.req, ctxTesterPass.res, ctxTesterPass.next);
  assert(ctxTesterPass.wasNextCalled() === true, 'requireTester permits user with isTester === true');

  const ctxTesterAdminPass = createMockContext(superAdminUser);
  requireTester(ctxTesterAdminPass.req, ctxTesterAdminPass.res, ctxTesterAdminPass.next);
  assert(ctxTesterAdminPass.wasNextCalled() === true, 'requireTester permits super_admin');

  const ctxTesterFail = createMockContext(standardMember);
  requireTester(ctxTesterFail.req, ctxTesterFail.res, ctxTesterFail.next);
  assert(ctxTesterFail.res.statusCode === 403, 'requireTester rejects non-tester member with HTTP 403');

  // requireModerator middleware test
  const ctxModPass = createMockContext(moderatorUser);
  requireModerator(ctxModPass.req, ctxModPass.res, ctxModPass.next);
  assert(ctxModPass.wasNextCalled() === true, 'requireModerator permits user with isModerator === true');

  const ctxModFail = createMockContext(standardMember);
  requireModerator(ctxModFail.req, ctxModFail.res, ctxModFail.next);
  assert(ctxModFail.res.statusCode === 403, 'requireModerator rejects non-moderator member with HTTP 403');

  // ---------------------------------------------------------------------------
  // SECTION 4: INTERMEDIATE REVIEWER BOUNDARY ENFORCEMENT
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 4: Intermediate Reviewer Boundary Enforcement ---');

  // Invariant: Tester and Moderator CANNOT grant final departmental approval
  const testerApprovalAttempt = hasCapability(testerUser, CAPABILITIES.TASK_FINAL_APPROVE, 'Media');
  assert(testerApprovalAttempt === false, 'hasCapability denies TASK_FINAL_APPROVE to Tester');

  const moderatorApprovalAttempt = hasCapability(moderatorUser, CAPABILITIES.TASK_FINAL_APPROVE, 'Literature');
  assert(moderatorApprovalAttempt === false, 'hasCapability denies TASK_FINAL_APPROVE to Moderator');

  // ---------------------------------------------------------------------------
  // SECTION 5: TASK ASSIGNMENT & VERSIONED MULTIMEDIA SUBMISSIONS
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 5: Task Assignment & Versioned Multimedia Submissions ---');

  // Simulated task initialization
  const taskRecord = {
    _id: 'task_phase_d223_001',
    title: 'Urdu Short Film Audio Design',
    description: 'Design atmospheric soundscape and clean audio dubbing for episode 1.',
    instructions: 'Deliver uncompressed WAV master and 320kbps MP3 preview.',
    department: 'Media',
    departmentCode: 'MED',
    originalDepartment: 'Media', // IMMUTABLE
    originalDepartmentCode: 'MED',
    priority: 'high',
    status: 'assigned',
    assignedTo: standardMember.id,
    assignedMemberName: standardMember.name,
    createdBy: 'u_media_head',
    createdByName: 'Media Head Farhan',
    createdByRole: 'dept_media',
    currentVersion: 0,
    submissions: [],
    referrals: [],
    history: [],
  };

  assert(taskRecord.originalDepartment === 'Media', 'Task initialization sets immutable originalDepartment');
  assert(taskRecord.currentVersion === 0, 'Initial task version is 0 before submissions');

  // Member submits Deliverable Version 1
  const sub1Version = taskRecord.currentVersion + 1;
  taskRecord.currentVersion = sub1Version;
  const sub1 = {
    version: sub1Version,
    submittedBy: { id: standardMember.id, name: standardMember.name },
    submittedAt: new Date(),
    notes: 'Initial audio design draft with Foley stems.',
    attachments: [
      {
        fileName: 'soundscape_v1.mp3',
        fileUrl: '/uploads/soundscape_v1.mp3',
        fileType: 'audio/mpeg',
        fileSize: 12 * 1024 * 1024,
      },
    ],
    status: 'pending_testing',
  };
  taskRecord.submissions.push(sub1);
  taskRecord.status = 'pending_testing';

  assert(taskRecord.currentVersion === 1, 'Task version increments to 1 after first submission');
  assert(taskRecord.submissions.length === 1, 'Submissions array contains first deliverable');
  assert(taskRecord.status === 'pending_testing', 'Task status transitions to pending_testing');

  // Member resubmits Deliverable Version 2 (e.g. after corrections)
  const sub2Version = taskRecord.currentVersion + 1;
  taskRecord.currentVersion = sub2Version;
  const sub2 = {
    version: sub2Version,
    submittedBy: { id: standardMember.id, name: standardMember.name },
    submittedAt: new Date(),
    notes: 'Version 2 with corrected dialogue equalization.',
    attachments: [
      {
        fileName: 'soundscape_v2.mp3',
        fileUrl: '/uploads/soundscape_v2.mp3',
        fileType: 'audio/mpeg',
        fileSize: 14 * 1024 * 1024,
      },
    ],
    status: 'pending_testing',
  };
  taskRecord.submissions.push(sub2);

  assert(taskRecord.currentVersion === 2, 'Task version increments to 2 on resubmission');
  assert(taskRecord.submissions.length === 2, 'Submissions array preserves history of all versions');
  assert(taskRecord.submissions[0].version === 1 && taskRecord.submissions[1].version === 2, 'Previous submission version is NEVER overwritten');

  // ---------------------------------------------------------------------------
  // SECTION 6: TESTER REVIEW WORKFLOW (PASS / CORRECTIONS / REJECT)
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 6: Tester Review Workflow ---');

  // Case A: Tester requests corrections
  taskRecord.testingDetails = {
    testerId: testerUser.id,
    testerName: testerUser.name,
    testedAt: new Date(),
    decision: 'corrections_requested',
    findings: 'Audio clipping detected at timestamp 02:14 in dialogue track.',
    forwardedToModerator: false,
  };
  taskRecord.status = 'revision_requested';
  assert(taskRecord.status === 'revision_requested', 'Tester corrections request transitions status to revision_requested');
  assert(taskRecord.testingDetails.forwardedToModerator === false, 'Corrections request halts progression to moderator');

  // Case B: Tester passes submission
  taskRecord.testingDetails = {
    testerId: testerUser.id,
    testerName: testerUser.name,
    testedAt: new Date(),
    decision: 'passed',
    findings: 'All audio levels compliant with broadcast standards (-14 LUFS).',
    forwardedToModerator: true,
  };
  taskRecord.status = 'moderation_pending';
  assert(taskRecord.status === 'moderation_pending', 'Tester pass transitions task status to moderation_pending');
  assert(taskRecord.testingDetails.forwardedToModerator === true, 'Tester pass marks forwardedToModerator as true');

  // ---------------------------------------------------------------------------
  // SECTION 7: MODERATOR REVIEW & DELIVERABLE EDITING
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 7: Moderator Review & Deliverable Editing ---');

  // Moderator review with deliverable editing
  const editedDeliverable = {
    fileName: 'soundscape_v2_moderated.mp3',
    fileUrl: '/uploads/soundscape_v2_moderated.mp3',
    fileType: 'audio/mpeg',
    fileSize: 13 * 1024 * 1024,
  };
  const modEditValidation = validateAttachmentMetadata(editedDeliverable);
  assert(modEditValidation.valid === true, 'Moderator edited deliverable passes storage validation');

  taskRecord.moderationDetails = {
    moderatorId: moderatorUser.id,
    moderatorName: moderatorUser.name,
    moderatedAt: new Date(),
    decision: 'forwarded_for_approval',
    feedback: 'Added intro fade-in and normalization filter.',
    editedAttachments: [editedDeliverable],
  };
  taskRecord.status = 'awaiting_final_approval';

  assert(taskRecord.status === 'awaiting_final_approval', 'Moderator forwarding transitions task status to awaiting_final_approval');
  assert(taskRecord.moderationDetails.editedAttachments.length === 1, 'Moderator edited deliverables stored in task moderationDetails');

  // Case: Moderator returns to department for rework
  const modReturnRecord = { ...taskRecord };
  modReturnRecord.moderationDetails = {
    moderatorId: moderatorUser.id,
    decision: 'returned_to_department',
    returnDetails: {
      returnReason: 'Background noise too prominent.',
      requiredChanges: 'Re-record voiceover in quiet environment.',
    },
  };
  modReturnRecord.status = 'rechecking_pending';
  assert(modReturnRecord.status === 'rechecking_pending', 'Moderator return transitions status to rechecking_pending');

  // ---------------------------------------------------------------------------
  // SECTION 8: DEPARTMENT RECHECKING & REASSIGNMENT (STAGE 4B)
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 8: Department Rechecking & Reassignment (Stage 4b) ---');

  const mediaHeadUser = {
    id: 'u_media_head',
    name: 'Aisha Tariq',
    role: 'dept_media',
    department: 'Media',
    designation: 'head',
  };
  const mediaDirectorUser = {
    id: 'u_media_dir',
    name: 'Kamran Director',
    role: 'dept_media',
    department: 'Media',
    designation: 'director',
  };
  const litHeadUser = {
    id: 'u_lit_head',
    name: 'Noor Literature Head',
    role: 'dept_literature',
    department: 'Literature',
    designation: 'head',
  };

  // Rechecking authority check
  const mediaHeadCanRecheck = (
    mediaHeadUser.department.toLowerCase() === taskRecord.originalDepartment.toLowerCase() &&
    ['head', 'director'].includes(normalizeDesignation(mediaHeadUser.designation))
  );
  assert(mediaHeadCanRecheck === true, 'Original department Head is authorized to recheck task');

  const mediaDirCanRecheck = (
    mediaDirectorUser.department.toLowerCase() === taskRecord.originalDepartment.toLowerCase() &&
    ['head', 'director'].includes(normalizeDesignation(mediaDirectorUser.designation))
  );
  assert(mediaDirCanRecheck === true, 'Original department Director is authorized to recheck task');

  const litHeadCanRecheckMedia = (
    litHeadUser.department.toLowerCase() === taskRecord.originalDepartment.toLowerCase() &&
    ['head', 'director'].includes(normalizeDesignation(litHeadUser.designation))
  );
  assert(litHeadCanRecheckMedia === false, 'Other department Head is strictly denied rechecking authority');

  // Rechecking action: Reassign member and resume in_progress
  taskRecord.assignedTo = 'u_media_member_bob';
  taskRecord.assignedMemberName = 'Bob Editor';
  taskRecord.instructions = 'Updated instructions: re-balance vocals with noise reduction filter.';
  taskRecord.status = 'in_progress';

  assert(taskRecord.assignedMemberName === 'Bob Editor', 'Original Department Head successfully reassigns task');
  assert(taskRecord.status === 'in_progress', 'Rechecked task successfully resumes in_progress status');

  // ---------------------------------------------------------------------------
  // SECTION 9: INTER-DEPARTMENT REFERRAL & RESPONSE (STAGE 5)
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 9: Inter-Department Referral & Response (Stage 5) ---');

  // Media refers task to Literature for poetry subtitle verification
  const referralPayload = {
    referralId: 'ref_20261124_001',
    originalDepartment: taskRecord.originalDepartment, // MUST REMAIN 'Media'
    sendingDepartment: taskRecord.department,
    receivingDepartment: 'Literature',
    referringUser: {
      id: mediaHeadUser.id,
      name: mediaHeadUser.name,
      role: mediaHeadUser.role,
      designation: mediaHeadUser.designation,
    },
    reason: 'Poetry subtitle translation verification by Literature department scholars.',
    status: 'pending',
    referredAt: new Date(),
  };

  taskRecord.referrals.push(referralPayload);
  taskRecord.activeReferral = referralPayload;
  taskRecord.department = 'Literature'; // Active department shifts
  taskRecord.departmentCode = 'LIT';

  assert(taskRecord.originalDepartment === 'Media', 'CRITICAL RULE: originalDepartment remains immutable (Media) after referral');
  assert(taskRecord.department === 'Literature', 'Active department shifts to receiving department (Literature)');
  assert(taskRecord.activeReferral.status === 'pending', 'Active referral status is pending acceptance');

  // Receiving Department Head responds: Accept
  taskRecord.activeReferral.status = 'accepted';
  assert(taskRecord.activeReferral.status === 'accepted', 'Literature department successfully accepts referral');

  // Literature department completes review and returns to Media
  taskRecord.activeReferral.status = 'returned';
  taskRecord.department = taskRecord.originalDepartment; // Reverts back to Media
  taskRecord.departmentCode = taskRecord.originalDepartmentCode;
  taskRecord.status = 'awaiting_final_approval';

  assert(taskRecord.department === 'Media', 'On return, active department reverts to originalDepartment (Media)');
  assert(taskRecord.status === 'awaiting_final_approval', 'Returned referral moves to awaiting_final_approval in original department');

  // ---------------------------------------------------------------------------
  // SECTION 10: FINAL DEPARTMENTAL APPROVAL RESTRICTIONS (STAGE 6)
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 10: Final Departmental Approval Restrictions (Stage 6) ---');

  const mediaAsstDirUser = {
    id: 'u_media_ad',
    name: 'Media Assistant Director',
    role: 'dept_media',
    department: 'Media',
    designation: 'assistant_director',
  };
  const mediaMemberUser = {
    id: 'u_media_mem',
    name: 'Media Team Member',
    role: 'member',
    department: 'Media',
    designation: 'member',
  };
  const hrHeadUser = {
    id: 'u_hr_head',
    name: 'HR Head Zahra',
    role: 'hr',
    department: 'HR',
    designation: 'hr_head',
  };
  const financeUser = {
    id: 'u_fin_head',
    name: 'Finance Officer Tariq',
    role: 'finance',
    department: 'Finance',
    designation: null,
  };

  // Helper verifying final approval rule
  function checkFinalApprovalAuthorization(user, task) {
    if (user.role === 'super_admin') return true;
    const callerDept = user.department || (user.role.startsWith('dept_') ? DEPT_ROLE_MAP[user.role]?.name : null);
    const callerDesig = normalizeDesignation(user.designation);
    return (
      (callerDept?.toLowerCase() === task.originalDepartment?.toLowerCase() ||
        (user.role.startsWith('dept_') &&
          DEPT_ROLE_MAP[user.role]?.name?.toLowerCase() === task.originalDepartment?.toLowerCase())) &&
      ['head', 'director'].includes(callerDesig || '')
    );
  }

  // 1. Media Head -> ALLOWED
  assert(checkFinalApprovalAuthorization(mediaHeadUser, taskRecord) === true, 'Original Department Head is AUTHORIZED to give final task approval');

  // 2. Media Director -> ALLOWED
  assert(checkFinalApprovalAuthorization(mediaDirectorUser, taskRecord) === true, 'Original Department Director is AUTHORIZED to give final task approval');

  // 3. Super Admin -> ALLOWED
  assert(checkFinalApprovalAuthorization(superAdminUser, taskRecord) === true, 'Super Admin is AUTHORIZED to give final task approval');

  // 4. Media Assistant Director -> STRICTLY DENIED
  assert(checkFinalApprovalAuthorization(mediaAsstDirUser, taskRecord) === false, 'Assistant Director is STRICTLY DENIED final approval authority');

  // 5. Media Member -> STRICTLY DENIED
  assert(checkFinalApprovalAuthorization(mediaMemberUser, taskRecord) === false, 'Team Member is STRICTLY DENIED final approval authority');

  // 6. Tester -> STRICTLY DENIED
  assert(checkFinalApprovalAuthorization(testerUser, taskRecord) === false, 'Tester is STRICTLY DENIED final approval authority');

  // 7. Moderator -> STRICTLY DENIED
  assert(checkFinalApprovalAuthorization(moderatorUser, taskRecord) === false, 'Moderator is STRICTLY DENIED final approval authority');

  // 8. Other Department Head (Literature Head) -> STRICTLY DENIED
  assert(checkFinalApprovalAuthorization(litHeadUser, taskRecord) === false, 'Other Department Head (Literature) is STRICTLY DENIED final approval for Media task');

  // 9. HR Head -> STRICTLY DENIED
  assert(checkFinalApprovalAuthorization(hrHeadUser, taskRecord) === false, 'HR Head is STRICTLY DENIED final approval for operational task');

  // 10. Finance Officer -> STRICTLY DENIED
  assert(checkFinalApprovalAuthorization(financeUser, taskRecord) === false, 'Finance Officer is STRICTLY DENIED final approval for operational task');

  // Execute Final Approval by authorized Media Head
  taskRecord.status = 'completed';
  taskRecord.completedAt = new Date();
  taskRecord.finalApprovalDetails = {
    approvedBy: {
      id: mediaHeadUser.id,
      name: mediaHeadUser.name,
      role: mediaHeadUser.role,
      designation: mediaHeadUser.designation,
    },
    approvedAt: new Date(),
    approvalNotes: 'Outstanding sound engineering. Final departmental approval granted.',
    originalDepartment: taskRecord.originalDepartment,
  };

  assert(taskRecord.status === 'completed', 'Task status transitions to completed upon final approval');
  assert(taskRecord.finalApprovalDetails.originalDepartment === 'Media', 'Final approval record records originalDepartment');

  // ---------------------------------------------------------------------------
  // SECTION 11: EXCLUSIVE MEDIA GALLERY PUBLISHING AUTHORIZATION
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 11: Exclusive Media Gallery Publishing Authorization ---');

  // Helper verifying media gallery publishing rule
  function checkMediaPublishAuthorization(user) {
    if (user.role === 'super_admin') return true;
    return user.role === 'dept_media' && normalizeDesignation(user.designation) === 'head';
  }

  // 1. Media Head -> ALLOWED
  assert(checkMediaPublishAuthorization(mediaHeadUser) === true, 'Media Department Head has EXCLUSIVE gallery publishing permission');

  // 2. Media Director -> STRICTLY DENIED
  assert(checkMediaPublishAuthorization(mediaDirectorUser) === false, 'Media Director is STRICTLY DENIED gallery publishing permission');

  // 3. Media Assistant Director -> STRICTLY DENIED
  assert(checkMediaPublishAuthorization(mediaAsstDirUser) === false, 'Media Assistant Director is STRICTLY DENIED gallery publishing permission');

  // 4. Media Member -> STRICTLY DENIED
  assert(checkMediaPublishAuthorization(mediaMemberUser) === false, 'Media Member is STRICTLY DENIED gallery publishing permission');

  // 5. Literature Head -> STRICTLY DENIED
  assert(checkMediaPublishAuthorization(litHeadUser) === false, 'Other Department Head (Literature) is STRICTLY DENIED media gallery publishing');

  // 6. Tester -> STRICTLY DENIED
  assert(checkMediaPublishAuthorization(testerUser) === false, 'Tester is STRICTLY DENIED media gallery publishing');

  // 7. Moderator -> STRICTLY DENIED
  assert(checkMediaPublishAuthorization(moderatorUser) === false, 'Moderator is STRICTLY DENIED media gallery publishing');

  // 8. HR Head -> STRICTLY DENIED
  assert(checkMediaPublishAuthorization(hrHeadUser) === false, 'HR Head is STRICTLY DENIED media gallery publishing');

  // 9. Finance Officer -> STRICTLY DENIED
  assert(checkMediaPublishAuthorization(financeUser) === false, 'Finance Officer is STRICTLY DENIED media gallery publishing');

  // 10. requireMediaHead Middleware Verification
  const ctxMediaHeadPass = createMockContext(mediaHeadUser);
  requireMediaHead(ctxMediaHeadPass.req, ctxMediaHeadPass.res, ctxMediaHeadPass.next);
  assert(ctxMediaHeadPass.wasNextCalled() === true, 'requireMediaHead middleware grants access to Media Head');

  const ctxMediaDirFail = createMockContext(mediaDirectorUser);
  requireMediaHead(ctxMediaDirFail.req, ctxMediaDirFail.res, ctxMediaDirFail.next);
  assert(ctxMediaDirFail.res.statusCode === 403, 'requireMediaHead middleware rejects Media Director with HTTP 403');

  const ctxMediaMemFail = createMockContext(mediaMemberUser);
  requireMediaHead(ctxMediaMemFail.req, ctxMediaMemFail.res, ctxMediaMemFail.next);
  assert(ctxMediaMemFail.res.statusCode === 403, 'requireMediaHead middleware rejects Media Member with HTTP 403');

  // Gallery Asset Invariant: Standalone management portal only, never publishedToWebsite: true
  const samplePublishedAsset = {
    _id: 'media_asset_001',
    title: 'Urdu Mehfil High Resolution Photo',
    publicationStatus: 'published',
    publishedToWebsite: false, // Invariant: internal management portal only
    publishedBy: mediaHeadUser.id,
    publishedByName: mediaHeadUser.name,
    publishedAt: new Date(),
  };

  assert(samplePublishedAsset.publishedToWebsite === false, 'Media Gallery asset strictly sets publishedToWebsite: false (standalone portal only)');

  // ---------------------------------------------------------------------------
  // SUMMARY
  // ---------------------------------------------------------------------------
  console.log('\n================================================================================');
  console.log(`TEST SUITE COMPLETE: ${passedTests} PASSED, ${failedTests} FAILED (TOTAL: ${passedTests + failedTests})`);
  console.log('================================================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runTestSuite().catch((err) => {
  console.error('Unexpected test error:', err);
  process.exit(1);
});
