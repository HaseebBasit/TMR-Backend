/**
 * Centralized Roles, Designations, and Permission Architecture
 * Ta'meer-e-Rekhta Management Portal
 * 
 * Strict separation between:
 * 1. Technical Roles (9 approved User.role values)
 * 2. Organizational Designations (Hierarchical operational & HR titles)
 * 3. Functional Capabilities (Fine-grained access rights)
 */

// ---------------------------------------------------------------------------
// 1. Technical Roles (Core Approved Roles)
// ---------------------------------------------------------------------------
const TECHNICAL_ROLES = Object.freeze({
  SUPER_ADMIN: 'super_admin',
  DEVELOPER: 'developer',
  DEPT_LITERATURE: 'dept_literature',
  DEPT_MEDIA: 'dept_media',
  DEPT_MARKETING: 'dept_marketing',
  DEPT_OUTREACH: 'dept_outreach',
  DEPT_OAM: 'dept_oam',
  DEPT_CONTENT: 'dept_content',
  DEPT_WELFARE: 'dept_welfare',
  HR: 'hr',
  FINANCE: 'finance',
  MEMBER: 'member',
});

const ALLOWED_ROLES = Object.freeze(Object.values(TECHNICAL_ROLES));

const OPERATIONAL_DEPT_ROLES = Object.freeze([
  TECHNICAL_ROLES.DEPT_LITERATURE,
  TECHNICAL_ROLES.DEPT_MEDIA,
  TECHNICAL_ROLES.DEPT_MARKETING,
  TECHNICAL_ROLES.DEPT_OUTREACH,
  TECHNICAL_ROLES.DEPT_OAM,
  TECHNICAL_ROLES.DEPT_CONTENT,
  TECHNICAL_ROLES.DEPT_WELFARE,
]);

// ---------------------------------------------------------------------------
// 2. Organizational Designations
// ---------------------------------------------------------------------------
const OPERATIONAL_DESIGNATIONS = Object.freeze({
  HEAD: 'head',
  HEAD_OF_PUNJAB: 'head_of_punjab',
  HEAD_OF_SINDH: 'head_of_sindh',
  DIRECTOR: 'director',
  DIRECTOR_GRAPHICS: 'director_graphics',
  ASSISTANT_DIRECTOR: 'assistant_director',
  COORDINATION_INCHARGE: 'coordination_incharge',
  MEMBER: 'member',
  VOLUNTEER: 'volunteer',
});

const HR_DESIGNATIONS = Object.freeze({
  HR_HEAD: 'hr_head',
  HR_DIRECTOR: 'hr_director',
  HR_COORDINATION_INCHARGE: 'hr_coordination_incharge',
  HR_MEMBER: 'hr_member',
});

const FINANCE_DESIGNATIONS = Object.freeze({
  HEAD_OF_FINANCE: 'head_of_finance',
  FINANCE_MEMBER: 'finance_member',
});

const DEVELOPER_DESIGNATIONS = Object.freeze({
  DEVELOPER: 'developer',
  SYSTEM_LEAD: 'system_lead',
});

const ALL_APPROVED_DESIGNATIONS = Object.freeze([
  ...Object.values(OPERATIONAL_DESIGNATIONS),
  ...Object.values(HR_DESIGNATIONS),
  ...Object.values(FINANCE_DESIGNATIONS),
  ...Object.values(DEVELOPER_DESIGNATIONS),
]);

// Title-case / display aliases normalized to canonical lowercase snake_case
const DESIGNATION_ALIAS_MAP = Object.freeze({
  head: 'head',
  head_of_punjab: 'head_of_punjab',
  head_of_sindh: 'head_of_sindh',
  director: 'director',
  director_graphics: 'director_graphics',
  assistant_director: 'assistant_director',
  coordination_incharge: 'coordination_incharge',
  member: 'member',
  volunteer: 'volunteer',
  hr_head: 'hr_head',
  hr_director: 'hr_director',
  hr_coordination_incharge: 'hr_coordination_incharge',
  hr_member: 'hr_member',
  head_of_finance: 'head_of_finance',
  finance_head: 'head_of_finance',
  finance_member: 'finance_member',
  developer: 'developer',
  system_lead: 'system_lead',
  // Title-case variants
  'Head': 'head',
  'Head of Punjab': 'head_of_punjab',
  'Head of Sindh': 'head_of_sindh',
  'Director': 'director',
  'Director (Graphics Designing)': 'director_graphics',
  'Director (Graphics)': 'director_graphics',
  'Assistant Director': 'assistant_director',
  'Member': 'member',
  'Volunteer': 'volunteer',
  'Co-ordination Incharge': 'coordination_incharge',
  'Coordination Incharge': 'coordination_incharge',
  'HR Head': 'hr_head',
  'HR Director': 'hr_director',
  'HR Coordination In-charge': 'hr_coordination_incharge',
  'HR Coordination Incharge': 'hr_coordination_incharge',
  'HR Member': 'hr_member',
  'Head of Finance': 'head_of_finance',
  'Finance Head': 'head_of_finance',
  'head of finance': 'head_of_finance',
  'Head Of Finance': 'head_of_finance',
  'Finance Member': 'finance_member',
  'Developer': 'developer',
  'System Lead': 'system_lead',
  'Volunteer / Team Member': 'volunteer',
});

/**
 * Normalizes a designation string to canonical format.
 * Returns null if input is null, undefined, or unrecognized.
 */
function normalizeDesignation(designation) {
  if (!designation || typeof designation !== 'string') return null;
  let trimmed = designation.trim();
  if (trimmed === '' || trimmed.toLowerCase() === 'none' || trimmed.toLowerCase() === 'null') {
    return null;
  }
  // Strip wrapping parentheses if present, e.g. "(Head)" -> "Head"
  if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
    trimmed = trimmed.substring(1, trimmed.length - 1).trim();
  }
  return DESIGNATION_ALIAS_MAP[trimmed] || DESIGNATION_ALIAS_MAP[trimmed.toLowerCase()] || null;
}

// ---------------------------------------------------------------------------
// 3. Role-Designation Compatibility Rules
// ---------------------------------------------------------------------------
const ROLE_DESIGNATION_COMPATIBILITY = Object.freeze({
  [TECHNICAL_ROLES.SUPER_ADMIN]: Object.freeze([null, undefined, 'none']),
  [TECHNICAL_ROLES.DEVELOPER]: Object.freeze([null, undefined, 'none', 'developer', 'system_lead']),
  [TECHNICAL_ROLES.DEPT_LITERATURE]: Object.freeze(Object.values(OPERATIONAL_DESIGNATIONS)),
  [TECHNICAL_ROLES.DEPT_MEDIA]: Object.freeze(Object.values(OPERATIONAL_DESIGNATIONS)),
  [TECHNICAL_ROLES.DEPT_MARKETING]: Object.freeze(Object.values(OPERATIONAL_DESIGNATIONS)),
  [TECHNICAL_ROLES.DEPT_OUTREACH]: Object.freeze(Object.values(OPERATIONAL_DESIGNATIONS)),
  [TECHNICAL_ROLES.DEPT_OAM]: Object.freeze(Object.values(OPERATIONAL_DESIGNATIONS)),
  [TECHNICAL_ROLES.DEPT_CONTENT]: Object.freeze(Object.values(OPERATIONAL_DESIGNATIONS)),
  [TECHNICAL_ROLES.DEPT_WELFARE]: Object.freeze(Object.values(OPERATIONAL_DESIGNATIONS)),
  [TECHNICAL_ROLES.HR]: Object.freeze([
    ...Object.values(HR_DESIGNATIONS),
    OPERATIONAL_DESIGNATIONS.ASSISTANT_DIRECTOR,
    OPERATIONAL_DESIGNATIONS.COORDINATION_INCHARGE,
    OPERATIONAL_DESIGNATIONS.VOLUNTEER,
    OPERATIONAL_DESIGNATIONS.MEMBER,
  ]),
  [TECHNICAL_ROLES.FINANCE]: Object.freeze([
    null,
    undefined,
    'none',
    FINANCE_DESIGNATIONS.HEAD_OF_FINANCE,
    FINANCE_DESIGNATIONS.FINANCE_MEMBER,
    OPERATIONAL_DESIGNATIONS.MEMBER,
  ]),
  [TECHNICAL_ROLES.MEMBER]: Object.freeze([OPERATIONAL_DESIGNATIONS.MEMBER, OPERATIONAL_DESIGNATIONS.VOLUNTEER]),
});

/**
 * Validates whether a given technical role and designation combination is permitted.
 */
function validateRoleDesignation(role, rawDesignation) {
  if (!role || !ALLOWED_ROLES.includes(role)) {
    return {
      valid: false,
      error: `Invalid technical role '${role}'. Must be one of: ${ALLOWED_ROLES.join(', ')}.`,
    };
  }

  const normalized = normalizeDesignation(rawDesignation);

  // If designation is omitted or unassigned (null)
  if (!normalized) {
    // Super Admin and Finance do not use departmental leadership designations
    if (role === TECHNICAL_ROLES.SUPER_ADMIN || role === TECHNICAL_ROLES.FINANCE) {
      return { valid: true, designation: null };
    }
    // For operational and HR roles, unassigned is accepted for legacy compatibility,
    // but grants no elevated permissions (deny-by-default)
    return { valid: true, designation: null, isUnassigned: true };
  }

  // Check if normalized designation is among allowed designations globally
  if (!ALL_APPROVED_DESIGNATIONS.includes(normalized)) {
    return {
      valid: false,
      error: `Unknown designation '${rawDesignation}'. Approved designations: ${ALL_APPROVED_DESIGNATIONS.join(', ')}.`,
    };
  }

  // Super Admin must not receive ordinary departmental or HR designations
  if (role === TECHNICAL_ROLES.SUPER_ADMIN) {
    return {
      valid: false,
      error: 'Super Admin holds global system authority and cannot be assigned an ordinary departmental designation.',
    };
  }

  // Developer is a system-level technical role separate from Super Admin and departmental hierarchy
  if (role === TECHNICAL_ROLES.DEVELOPER) {
    if (normalized && !['developer', 'system_lead'].includes(normalized)) {
      return {
        valid: false,
        error: `Developer role cannot receive departmental or HR leadership designation '${rawDesignation}'.`,
      };
    }
    return { valid: true, designation: normalized || 'developer' };
  }

  // Finance must remain a separate functional governance role without operational or HR authority
  if (role === TECHNICAL_ROLES.FINANCE) {
    if (!['member', 'head_of_finance', 'finance_member'].includes(normalized)) {
      return {
        valid: false,
        error: `Finance role cannot receive operational or HR leadership designation '${rawDesignation}'.`,
      };
    }
    return { valid: true, designation: normalized };
  }

  // Member role cannot claim leadership designations (only member and volunteer are permitted)
  if (role === TECHNICAL_ROLES.MEMBER) {
    if (![OPERATIONAL_DESIGNATIONS.MEMBER, OPERATIONAL_DESIGNATIONS.VOLUNTEER].includes(normalized)) {
      return {
        valid: false,
        error: `Users with technical role 'member' cannot be assigned leadership designation '${rawDesignation}'.`,
      };
    }
    return { valid: true, designation: normalized };
  }

  // Operational department roles (Literature, Media, etc.)
  if (OPERATIONAL_DEPT_ROLES.includes(role)) {
    const allowed = ROLE_DESIGNATION_COMPATIBILITY[role];
    if (!allowed.includes(normalized)) {
      return {
        valid: false,
        error: `Operational department role '${role}' cannot receive HR designation '${rawDesignation}'. Allowed: ${allowed.join(', ')}.`,
      };
    }
    return { valid: true, designation: normalized };
  }

  // HR technical role
  if (role === TECHNICAL_ROLES.HR) {
    let hrNormalized = normalized;
    if (hrNormalized === OPERATIONAL_DESIGNATIONS.HEAD) hrNormalized = HR_DESIGNATIONS.HR_HEAD;
    if (hrNormalized === OPERATIONAL_DESIGNATIONS.DIRECTOR) hrNormalized = HR_DESIGNATIONS.HR_DIRECTOR;
    const allowed = ROLE_DESIGNATION_COMPATIBILITY[role];
    if (!allowed.includes(hrNormalized)) {
      return {
        valid: false,
        error: `HR role cannot receive operational department designation '${rawDesignation}'. Allowed HR designations: ${allowed.join(', ')}.`,
      };
    }
    return { valid: true, designation: hrNormalized };
  }

  return { valid: false, error: 'Unauthorized role-designation combination.' };
}

// ---------------------------------------------------------------------------
// 4. Fine-Grained Capability Definitions
// ---------------------------------------------------------------------------
const CAPABILITIES = Object.freeze({
  ORGANIZATION_ADMINISTRATION: 'organization_administration',
  DEPARTMENT_OPERATIONAL_ACCESS: 'department_operational_access',
  CONFIDENTIAL_GRADING_VIEW: 'confidential_grading_view',
  FINAL_TASK_APPROVAL: 'final_task_approval',
  TASK_RECOMMENDATION: 'task_recommendation',
  FINAL_LEAVE_APPROVAL: 'final_leave_approval',
  LEAVE_RECOMMENDATION: 'leave_recommendation',
  OWN_ASSIGNED_WORK: 'own_assigned_work',
  HR_CROSS_DEPARTMENT_VIEW: 'hr_cross_department_view',
  HR_CROSS_DEPARTMENT_WRITE: 'hr_cross_department_write',
  ADMINISTRATIVE_PASSWORD_RESET: 'administrative_password_reset',
  SUPER_ADMIN_IMMUNITY: 'super_admin_immunity',
  TESTER_REVIEW: 'tester_review',
  MODERATOR_REVIEW: 'moderator_review',
  INTER_DEPARTMENT_REFERRAL: 'inter_department_referral',
  MEDIA_GALLERY_PUBLISH: 'media_gallery_publish',
  MEDIA_GALLERY_UPLOAD: 'media_gallery_upload',
  HR_RECRUITMENT_MANAGE: 'hr_recruitment_manage',
  HR_DATA_EXPORT: 'hr_data_export',
  HR_DEPARTMENT_ANNOUNCEMENT: 'hr_department_announcement',
  FINANCE_DASHBOARD_VIEW: 'finance_dashboard_view',
  FINANCE_BUDGET_MANAGE: 'finance_budget_manage',
  FINANCE_EXPENSE_REVIEW: 'finance_expense_review',
  FINANCE_EXPENSE_DISBURSE: 'finance_expense_disburse',
  FINANCE_DONATION_VERIFY: 'finance_donation_verify',
  FINANCE_DATA_EXPORT: 'finance_data_export',
  ACCOUNT_CREATE_MANAGE: 'account_create_manage',
  DEVELOPER_DIAGNOSTICS_VIEW: 'developer_diagnostics_view',
  DEVELOPER_IMPERSONATE: 'developer_impersonate',
  DEVELOPER_AUDIT_VIEW: 'developer_audit_view',
});

// Approved administrative password reset designations
const APPROVED_ADMIN_RESET_ROLES = Object.freeze([
  TECHNICAL_ROLES.SUPER_ADMIN,
]);
const APPROVED_ADMIN_RESET_DESIGNATIONS = Object.freeze([
  HR_DESIGNATIONS.HR_HEAD,
  HR_DESIGNATIONS.HR_COORDINATION_INCHARGE,
]);

/**
 * Central authorization evaluator enforcing role, designation, department scope,
 * and target user constraints.
 * 
 * @param {Object} user Authenticated user object { role, designation, department, departmentCode }
 * @param {string} capability Capability string from CAPABILITIES
 * @param {Object} context Context object { targetDepartment, targetUserId, targetUserRole }
 * @returns {boolean}
 */
function hasCapability(user, capability, context = {}) {
  if (!user || !user.role) return false;

  const role = user.role;
  const designation = normalizeDesignation(user.designation);

  // Super Admin has global bypass for all administrative and operational capabilities
  if (role === TECHNICAL_ROLES.SUPER_ADMIN) {
    // Super Admin cannot perform HR cross-department write as an ordinary HR user
    if (capability === CAPABILITIES.HR_CROSS_DEPARTMENT_WRITE) return false;
    // Exclusive Media Head authority
    if (capability === CAPABILITIES.MEDIA_GALLERY_PUBLISH) return false;
    // Routine departmental approval belongs to the department's Head or Director
    if (capability === CAPABILITIES.FINAL_TASK_APPROVAL && context.strictDepartmentalApproval) return false;
    return true;
  }

  // 1. Organization-Wide Administration
  if (capability === CAPABILITIES.ORGANIZATION_ADMINISTRATION) {
    return false; // Super Admin only (handled above)
  }

  // 2. Confidential Grading View: STRICT ACCESS GATE
  // Only Super Admin and Department Heads (including Regional Welfare Heads) for their own department
  if (capability === CAPABILITIES.CONFIDENTIAL_GRADING_VIEW) {
    if (!OPERATIONAL_DEPT_ROLES.includes(role)) return false;
    if (!['head', 'head_of_punjab', 'head_of_sindh'].includes(designation)) return false;

    // Must match caller's authenticated department
    if (context.targetDepartment) {
      return isDepartmentMatch(user, context.targetDepartment);
    }
    return true;
  }

  // 3. Department Operational Access
  if (capability === CAPABILITIES.DEPARTMENT_OPERATIONAL_ACCESS) {
    if (OPERATIONAL_DEPT_ROLES.includes(role)) {
      if (['head', 'director', 'director_graphics', 'assistant_director', 'head_of_punjab', 'head_of_sindh', 'coordination_incharge'].includes(designation)) {
        return context.targetDepartment ? isDepartmentMatch(user, context.targetDepartment) : true;
      }
    }
    return false;
  }

  // 4. Final Task Approval: ONLY original owning department's Head, Regional Head, or Director
  if (capability === CAPABILITIES.FINAL_TASK_APPROVAL) {
    if (!OPERATIONAL_DEPT_ROLES.includes(role)) return false;
    if (!['head', 'director', 'director_graphics', 'head_of_punjab', 'head_of_sindh'].includes(designation)) return false;
    const targetDept = context.originalDepartment || context.targetDepartment;
    return targetDept ? isDepartmentMatch(user, targetDept) : true;
  }

  // 5. Task Recommendation
  if (capability === CAPABILITIES.TASK_RECOMMENDATION) {
    if (!OPERATIONAL_DEPT_ROLES.includes(role)) return false;
    if (!['head', 'director', 'director_graphics', 'assistant_director', 'head_of_punjab', 'head_of_sindh'].includes(designation)) return false;
    return context.targetDepartment ? isDepartmentMatch(user, context.targetDepartment) : true;
  }

  // 6. Final Leave Approval
  if (capability === CAPABILITIES.FINAL_LEAVE_APPROVAL) {
    if (OPERATIONAL_DEPT_ROLES.includes(role)) {
      if (!['head', 'director', 'head_of_punjab', 'head_of_sindh'].includes(designation)) return false;
      return context.targetDepartment ? isDepartmentMatch(user, context.targetDepartment) : true;
    }
    // HR Leadership can approve leave ONLY for HR department members
    if (role === TECHNICAL_ROLES.HR) {
      if (!['hr_head', 'hr_director'].includes(designation)) return false;
      return context.targetDepartment ? isDepartmentMatch(user, context.targetDepartment) : true;
    }
    return false;
  }

  // 7. Leave Recommendation
  if (capability === CAPABILITIES.LEAVE_RECOMMENDATION) {
    if (OPERATIONAL_DEPT_ROLES.includes(role)) {
      if (!['head', 'director', 'director_graphics', 'assistant_director', 'head_of_punjab', 'head_of_sindh'].includes(designation)) return false;
      return context.targetDepartment ? isDepartmentMatch(user, context.targetDepartment) : true;
    }
    if (role === TECHNICAL_ROLES.HR) {
      if (!['hr_head', 'hr_director', 'hr_coordination_incharge'].includes(designation)) return false;
      return context.targetDepartment ? isDepartmentMatch(user, context.targetDepartment) : true;
    }
    return false;
  }

  // 8. Own Assigned Work
  if (capability === CAPABILITIES.OWN_ASSIGNED_WORK) {
    return true; // All authenticated users can access own work
  }

  // 9. HR Cross-Department View
  if (capability === CAPABILITIES.HR_CROSS_DEPARTMENT_VIEW) {
    return role === TECHNICAL_ROLES.HR;
  }

  // 10. HR Cross-Department Write: STRICTLY DENIED TO ALL HR USERS
  if (capability === CAPABILITIES.HR_CROSS_DEPARTMENT_WRITE) {
    return false; // HR cannot edit other departments' operational records
  }

  // 11. Administrative Password Reset
  if (capability === CAPABILITIES.ADMINISTRATIVE_PASSWORD_RESET) {
    // Super Admin immunity check
    if (context.targetUserRole === TECHNICAL_ROLES.SUPER_ADMIN && role !== TECHNICAL_ROLES.SUPER_ADMIN) {
      return false; // HR cannot reset Super Admin!
    }
    if (role === TECHNICAL_ROLES.HR && APPROVED_ADMIN_RESET_DESIGNATIONS.includes(designation)) {
      return true;
    }
    return false;
  }

  // 12. Tester Review (Intermediate review only - cannot final approve)
  if (capability === CAPABILITIES.TESTER_REVIEW) {
    return Boolean(user.isTester === true || user.capabilities?.includes('tester_review') || user.capabilities?.includes('tester'));
  }

  // 13. Moderator Review (Intermediate review & editing - cannot final approve)
  if (capability === CAPABILITIES.MODERATOR_REVIEW) {
    return Boolean(user.isModerator === true || user.capabilities?.includes('moderator_review') || user.capabilities?.includes('moderator'));
  }

  // 14. Inter-Department Referral
  if (capability === CAPABILITIES.INTER_DEPARTMENT_REFERRAL) {
    if (OPERATIONAL_DEPT_ROLES.includes(role)) {
      return ['head', 'director', 'assistant_director'].includes(designation);
    }
    return false;
  }

  // 15. Media Gallery Publish: EXCLUSIVE TO MEDIA DEPARTMENT HEAD ONLY!
  if (capability === CAPABILITIES.MEDIA_GALLERY_PUBLISH) {
    return role === TECHNICAL_ROLES.DEPT_MEDIA && designation === OPERATIONAL_DESIGNATIONS.HEAD;
  }

  // 16. Media Gallery Upload
  if (capability === CAPABILITIES.MEDIA_GALLERY_UPLOAD) {
    return role === TECHNICAL_ROLES.DEPT_MEDIA;
  }

  // 17. HR Recruitment Management (Accept, reject, assign interviewer, update status)
  // Super Admin, HR Head, HR Director, HR Coordination In-charge.
  // HR Member / Assistant is STRICTLY DENIED (view-only).
  if (capability === CAPABILITIES.HR_RECRUITMENT_MANAGE) {
    if (role === TECHNICAL_ROLES.SUPER_ADMIN) return true;
    if (role === TECHNICAL_ROLES.HR) {
      return [
        HR_DESIGNATIONS.HR_HEAD,
        HR_DESIGNATIONS.HR_DIRECTOR,
        HR_DESIGNATIONS.HR_COORDINATION_INCHARGE,
      ].includes(designation);
    }
    return false;
  }

  // 18. HR Data Export (Export applications, leaves, recruitment records)
  // Super Admin, HR Head, HR Director, HR Coordination In-charge.
  // HR Member / Assistant is STRICTLY DENIED.
  if (capability === CAPABILITIES.HR_DATA_EXPORT) {
    if (role === TECHNICAL_ROLES.SUPER_ADMIN) return true;
    if (role === TECHNICAL_ROLES.HR) {
      return [
        HR_DESIGNATIONS.HR_HEAD,
        HR_DESIGNATIONS.HR_DIRECTOR,
        HR_DESIGNATIONS.HR_COORDINATION_INCHARGE,
      ].includes(designation);
    }
    return false;
  }

  // 19. HR Department Announcement (Official department announcements)
  // Strictly HR Coordination In-charge ONLY (and Super Admin).
  // HR Head, HR Director, and HR Member are STRICTLY DENIED.
  if (capability === CAPABILITIES.HR_DEPARTMENT_ANNOUNCEMENT) {
    if (role === TECHNICAL_ROLES.SUPER_ADMIN) return true;
    if (role === TECHNICAL_ROLES.HR) {
      return designation === HR_DESIGNATIONS.HR_COORDINATION_INCHARGE;
    }
    return false;
  }

  // 20. Finance Operations & Administration
  // Strictly Finance personnel and Super Admin.
  // HR, operational department leads, and members are STRICTLY DENIED.
  if (
    [
      CAPABILITIES.FINANCE_DASHBOARD_VIEW,
      CAPABILITIES.FINANCE_BUDGET_MANAGE,
      CAPABILITIES.FINANCE_EXPENSE_REVIEW,
      CAPABILITIES.FINANCE_EXPENSE_DISBURSE,
      CAPABILITIES.FINANCE_DONATION_VERIFY,
      CAPABILITIES.FINANCE_DATA_EXPORT,
    ].includes(capability)
  ) {
    if (role === TECHNICAL_ROLES.SUPER_ADMIN || role === TECHNICAL_ROLES.FINANCE) {
      return true;
    }
    return false;
  }

  // 21. Account Creation & Activation Link Management
  // Super Admin, HR Head, HR Director, HR Coordination In-charge.
  // HR Member/Assistant, Department Leads/Members, Finance, Testers, Moderators are STRICTLY DENIED.
  if (capability === CAPABILITIES.ACCOUNT_CREATE_MANAGE) {
    if (role === TECHNICAL_ROLES.SUPER_ADMIN) return true;
    if (role === TECHNICAL_ROLES.HR) {
      return [
        HR_DESIGNATIONS.HR_HEAD,
        HR_DESIGNATIONS.HR_DIRECTOR,
        HR_DESIGNATIONS.HR_COORDINATION_INCHARGE,
      ].includes(designation);
    }
    return false;
  }

  // 22. Developer System Diagnostics & Audited Impersonation
  // Strictly Developer role only.
  if (
    [
      CAPABILITIES.DEVELOPER_DIAGNOSTICS_VIEW,
      CAPABILITIES.DEVELOPER_IMPERSONATE,
      CAPABILITIES.DEVELOPER_AUDIT_VIEW,
    ].includes(capability)
  ) {
    return role === TECHNICAL_ROLES.DEVELOPER;
  }

  return false;
}

/**
 * Helper to test if a target department matches the user's assigned department.
 * Checks active context, primary department, and multi-department memberships.
 */
function isDepartmentMatch(user, targetDepartment) {
  if (!user || !targetDepartment) return false;
  if (user.role === TECHNICAL_ROLES.SUPER_ADMIN) return true;

  const target = targetDepartment.toLowerCase().trim();

  // 1. Active department context match
  if (user.activeDepartment && user.activeDepartment.toLowerCase().trim() === target) return true;
  if (user.activeDepartmentCode && user.activeDepartmentCode.toLowerCase().trim() === target) return true;

  // 2. Primary department match
  const userDept = (user.department || '').toLowerCase().trim();
  const userCode = (user.departmentCode || '').toLowerCase().trim();
  if (target === userDept || target === userCode) return true;

  // 3. Multi-department memberships match
  if (Array.isArray(user.memberships) && user.memberships.length > 0) {
    return user.memberships.some((m) => {
      const mDept = (m.department || '').toLowerCase().trim();
      const mCode = (m.departmentCode || '').toLowerCase().trim();
      return target === mDept || target === mCode;
    });
  }

  return false;
}

/**
 * Helper to determine a user's Welfare regional scope ('Punjab', 'Sindh', 'National', or 'ALL' for super admin)
 */
function getWelfareRegionalScope(user) {
  if (!user) return null;
  if (user.role === TECHNICAL_ROLES.SUPER_ADMIN || user.activeRole === TECHNICAL_ROLES.SUPER_ADMIN) {
    return 'ALL';
  }
  const desig = normalizeDesignation(user.activeDesignation || user.designation);
  const region = user.activeRegion || user.region;

  if (desig === 'head_of_punjab' || region === 'Punjab') {
    return 'Punjab';
  }
  if (desig === 'head_of_sindh' || region === 'Sindh') {
    return 'Sindh';
  }
  if (region === 'National') {
    return 'National';
  }
  // Check memberships
  if (Array.isArray(user.memberships)) {
    const welfareMem = user.memberships.find((m) => m.department?.toLowerCase() === 'welfare');
    if (welfareMem) {
      const mDesig = normalizeDesignation(welfareMem.designation);
      if (mDesig === 'head_of_punjab' || welfareMem.region === 'Punjab') return 'Punjab';
      if (mDesig === 'head_of_sindh' || welfareMem.region === 'Sindh') return 'Sindh';
      if (welfareMem.region === 'National') return 'National';
    }
  }
  return null;
}

const DEPT_ROLE_MAP = Object.freeze({
  dept_literature: { name: 'Literature', code: 'LIT' },
  dept_media: { name: 'Media', code: 'MED' },
  dept_marketing: { name: 'Marketing', code: 'MKT' },
  dept_outreach: { name: 'Outreach', code: 'OUT' },
  dept_oam: { name: 'Outreach and Marketing', code: 'OAM' },
  dept_content: { name: 'Content Creation', code: 'CON' },
  dept_welfare: { name: 'Welfare', code: 'WEL' },
});

module.exports = {
  TECHNICAL_ROLES,
  ALLOWED_ROLES,
  OPERATIONAL_DEPT_ROLES,
  OPERATIONAL_DESIGNATIONS,
  HR_DESIGNATIONS,
  FINANCE_DESIGNATIONS,
  DEVELOPER_DESIGNATIONS,
  ALL_APPROVED_DESIGNATIONS,
  DESIGNATION_ALIAS_MAP,
  ROLE_DESIGNATION_COMPATIBILITY,
  CAPABILITIES,
  DEPT_ROLE_MAP,
  APPROVED_ADMIN_RESET_ROLES,
  APPROVED_ADMIN_RESET_DESIGNATIONS,
  normalizeDesignation,
  validateRoleDesignation,
  hasCapability,
  isDepartmentMatch,
  getWelfareRegionalScope,
};
