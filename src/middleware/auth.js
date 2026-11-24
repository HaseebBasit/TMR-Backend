const jwt = require('jsonwebtoken');
const { User } = require('../models');
const {
  TECHNICAL_ROLES,
  ALLOWED_ROLES,
  OPERATIONAL_DEPT_ROLES,
  OPERATIONAL_DESIGNATIONS,
  HR_DESIGNATIONS,
  ALL_APPROVED_DESIGNATIONS,
  CAPABILITIES,
  normalizeDesignation,
  validateRoleDesignation,
  hasCapability,
  isDepartmentMatch,
} = require('../constants/roles');

// Validate production secrets: never allow production to run on hardcoded defaults
if (process.env.NODE_ENV === 'production') {
  const defaultInsecureSecrets = [
    'rekhta_access_secret_2026_super_secure',
    'rekhta_refresh_secret_2026_super_secure',
    'rekhta_super_secret_jwt_key_2026',
    'rekhta_refresh_super_secret_2026',
  ];
  if (!process.env.JWT_SECRET || defaultInsecureSecrets.includes(process.env.JWT_SECRET)) {
    throw new Error('[FATAL SECURITY EXCEPTION]: Production JWT_SECRET is missing or using default fallback.');
  }
  if (!process.env.JWT_REFRESH_SECRET || defaultInsecureSecrets.includes(process.env.JWT_REFRESH_SECRET)) {
    throw new Error('[FATAL SECURITY EXCEPTION]: Production JWT_REFRESH_SECRET is missing or using default fallback.');
  }
}

const JWT_SECRET = process.env.JWT_SECRET || 'rekhta_access_secret_2026_super_secure';

// In-memory user store fallback for testing/offline controlled mode
const memoryUsers = new Map();

const setMemoryUser = (user) => {
  if (user._id) memoryUsers.set(user._id.toString(), user);
  if (user.id) memoryUsers.set(user.id.toString(), user);
  if (user.email) memoryUsers.set(user.email.toLowerCase().trim(), user);
};

const getMemoryUser = (identifier) => {
  if (!identifier) return null;
  return memoryUsers.get(identifier.toString()) || memoryUsers.get(identifier.toString().toLowerCase().trim()) || null;
};

const getMemoryUsersList = () => {
  return Array.from(memoryUsers.values());
};

// Department mapping dictionary
const DEPT_ROLE_MAP = {
  dept_literature: { name: 'Literature', code: 'LIT' },
  dept_media: { name: 'Media', code: 'MED' },
  dept_marketing: { name: 'Marketing', code: 'MKT' },
  dept_outreach: { name: 'Outreach', code: 'OUT' },
  dept_content: { name: 'Content Creation', code: 'CON' },
};

/**
 * Protect middleware: Verifies JWT access token and active account status
 */
const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.rekhta_access_token) {
    token = req.cookies.rekhta_access_token;
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. No session token provided.',
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Fetch user from DB or offline memory store
    let user = null;
    try {
      user = await User.findById(decoded.id).select('-password');
    } catch {
      // In offline/test mode
    }

    if (!user) {
      user = getMemoryUser(decoded.id) || getMemoryUser(decoded.email);
    }

    if (!user) {
      // Use decoded token payload if user record is unavailable in offline mock mode
      user = {
        _id: decoded.id,
        id: decoded.id,
        name: decoded.name || 'Portal User',
        email: decoded.email,
        role: decoded.role,
        department: decoded.department,
        departmentCode: decoded.departmentCode,
        status: decoded.status || 'active',
        isPrivilegedHR: Boolean(decoded.isPrivilegedHR),
        tokenVersion: decoded.tokenVersion || 0,
        designation: normalizeDesignation(decoded.designation) || null,
      };
    } else {
      user.designation = normalizeDesignation(user.designation || decoded.designation) || null;
    }

    // Account Status Gate: Suspended or inactive accounts are immediately blocked
    if (user.status !== 'active') {
      return res.status(403).json({
        success: false,
        error: `Account ${user.status}. Access has been suspended. Please contact Super Admin.`,
        accountStatus: user.status,
      });
    }

    // Token Version Gate: Invalidate tokens if sessions were revoked
    if (decoded.tokenVersion !== undefined && user.tokenVersion !== undefined) {
      if (decoded.tokenVersion < user.tokenVersion) {
        return res.status(401).json({
          success: false,
          error: 'Session has been revoked. Please sign in again.',
        });
      }
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Session expired. Please refresh your token.',
        code: 'TOKEN_EXPIRED',
      });
    }
    return res.status(401).json({
      success: false,
      error: 'Invalid session token. Access denied.',
    });
  }
};

/**
 * Authorize middleware: Checks if authenticated user has one of the allowed roles
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Unauthorized.' });
    }

    // Super Admin has global bypass
    if (req.user.role === 'super_admin') {
      return next();
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Role '${req.user.role}' is not authorized for this resource.`,
      });
    }

    next();
  };
};

/**
 * Department Scope Gate: Ensures Department Heads can only access their own department
 */
const requireDepartmentScope = (paramName = 'department') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Unauthorized.' });
    }

    // Super Admin has organization-wide access
    if (req.user.role === 'super_admin') {
      return next();
    }

    // If user is a Department Head
    if (req.user.role && req.user.role.startsWith('dept_')) {
      const assignedDept = DEPT_ROLE_MAP[req.user.role];
      const targetDept =
        req.params[paramName] ||
        req.query[paramName] ||
        req.body[paramName] ||
        req.headers['x-department'];

      if (!targetDept) {
        return next();
      }

      const normalizedTarget = targetDept.toLowerCase().trim();
      const matchByName = assignedDept?.name.toLowerCase() === normalizedTarget;
      const matchByCode = assignedDept?.code.toLowerCase() === normalizedTarget;

      if (!matchByName && !matchByCode) {
        return res.status(403).json({
          success: false,
          error: `Department Isolation Violation: You are authorized for '${assignedDept?.name}' only. Access to '${targetDept}' is forbidden.`,
        });
      }

      return next();
    }

    // Role is neither super_admin nor an authorized department head
    return res.status(403).json({
      success: false,
      error: `Access denied: Role '${req.user.role}' is not authorized for department workspace resources.`,
    });
  };
};

/**
 * Member Ownership Gate: Members cannot access other members' records
 */
const requireOwnershipOrPrivilege = (userIdField = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Unauthorized.' });
    }

    // Super Admin & HR have privileged oversight
    if (['super_admin', 'hr'].includes(req.user.role)) {
      return next();
    }

    // Department heads can access their own department's members
    if (req.user.role.startsWith('dept_')) {
      return next();
    }

    // Members are strictly restricted to their own ID
    if (req.user.role === 'member') {
      const targetUserId =
        req.params[userIdField] ||
        req.params.id ||
        req.query[userIdField] ||
        req.body[userIdField];

      const currentUserId = req.user._id?.toString() || req.user.id?.toString();

      if (targetUserId && targetUserId.toString() !== currentUserId) {
        return res.status(403).json({
          success: false,
          error: 'Access denied: You are only authorized to access your own personal records.',
        });
      }
    }

    next();
  };
};

/**
 * Privileged HR Gate: Only Super Admin or HR users specifically granted privileged status
 */
const requirePrivilegedHR = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Unauthorized.' });
  }

  if (req.user.role === 'super_admin') {
    return next();
  }

  if (req.user.role === 'hr' && req.user.isPrivilegedHR === true) {
    return next();
  }

  return res.status(403).json({
    success: false,
    error: 'Access denied: This action requires Privileged HR authorization granted by Super Admin.',
  });
};

/**
 * Designation Gate: Verifies that authenticated user holds one of the specified designations.
 * Super Admin bypasses designation gates by default.
 */
const requireDesignation = (...allowedDesignations) => {
  const normalizedAllowed = allowedDesignations
    .map(normalizeDesignation)
    .filter(Boolean);

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Unauthorized.' });
    }

    // Super Admin global bypass
    if (req.user.role === TECHNICAL_ROLES.SUPER_ADMIN) {
      return next();
    }

    const userDesig = normalizeDesignation(req.user.designation);

    // Deny by default if designation is missing or unassigned
    if (!userDesig) {
      return res.status(403).json({
        success: false,
        error: 'Access denied: No organizational designation assigned. Privileged action rejected by default.',
      });
    }

    if (!normalizedAllowed.includes(userDesig)) {
      return res.status(403).json({
        success: false,
        error: `Access denied: Designation '${userDesig}' is not authorized for this resource. Required: ${normalizedAllowed.join(', ')}.`,
      });
    }

    next();
  };
};

/**
 * Capability-based Authorization Middleware: Evaluates fine-grained permissions.
 */
const requireCapability = (capability, getContextFn = null) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Unauthorized.' });
    }

    const context = getContextFn
      ? getContextFn(req)
      : {
          targetDepartment: req.params.department || req.query.department || req.body?.department,
          targetUserId: req.params.id || req.params.userId || req.body?.userId,
          targetUserRole: req.body?.role || req.targetUser?.role,
        };

    if (!hasCapability(req.user, capability, context)) {
      return res.status(403).json({
        success: false,
        error: `Access denied: You do not possess the '${capability}' capability for this resource.`,
      });
    }

    next();
  };
};

/**
 * Strict Confidential Grading Security:
 * - Super Admin: Organization-wide access.
 * - Department Head: Access ONLY to confidential grading records for their assigned department.
 * - Director, Assistant Director, Member, HR, Finance: Strictly DENIED.
 * 
 * Note: Department ownership is strictly derived from authenticated server-side user data.
 * Client-supplied department parameters CANNOT escalate or broaden access.
 */
const requireGradingConfidentiality = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Unauthorized.' });
  }

  // 1. Super Admin has organization-wide access
  if (req.user.role === TECHNICAL_ROLES.SUPER_ADMIN) {
    return next();
  }

  // 2. Department Head for assigned operational department ONLY
  const designation = normalizeDesignation(req.user.designation);
  const isOperationalRole = OPERATIONAL_DEPT_ROLES.includes(req.user.role);

  if (isOperationalRole && designation === OPERATIONAL_DESIGNATIONS.HEAD) {
    const userDept = req.user.department || DEPT_ROLE_MAP[req.user.role]?.name;
    const userCode = req.user.departmentCode || DEPT_ROLE_MAP[req.user.role]?.code;

    // Check if client explicitly requested another department via query/params
    const targetDept = req.query.department || req.params.department || req.body?.department;
    if (targetDept) {
      const matchName = targetDept.toLowerCase().trim() === userDept?.toLowerCase().trim();
      const matchCode = targetDept.toLowerCase().trim() === userCode?.toLowerCase().trim();
      if (!matchName && !matchCode) {
        return res.status(403).json({
          success: false,
          error: `Department Isolation Violation: You are authorized for '${userDept}' only. Access to '${targetDept}' confidential grading reports is forbidden.`,
        });
      }
    }

    // Server-side lockdown: Force query filter to match user's authorized department
    req.query.department = userDept;
    return next();
  }

  // 3. Directors, Assistant Directors, Members, HR, Finance, and unassigned users are strictly denied
  const roleTitle = req.user.role;
  const desigTitle = designation || 'unassigned';
  return res.status(403).json({
    success: false,
    error: `Confidentiality Gate: Access to confidential grading reports is restricted to Super Admin and Department Heads for their assigned department only (Current: role '${roleTitle}', designation '${desigTitle}').`,
  });
};

/**
 * Tester Review Gate: Verifies that caller holds explicit Tester capability.
 * A Tester possesses intermediate review authority ONLY and cannot final-approve tasks.
 */
const requireTester = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Unauthorized.' });
  }
  if (!hasCapability(req.user, CAPABILITIES.TESTER_REVIEW)) {
    return res.status(403).json({
      success: false,
      error: 'Access denied: This action requires Tester review capability.',
    });
  }
  next();
};

/**
 * Moderator Review Gate: Verifies that caller holds explicit Moderator capability.
 * A Moderator possesses intermediate review and editing authority ONLY and cannot final-approve tasks.
 */
const requireModerator = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Unauthorized.' });
  }
  if (!hasCapability(req.user, CAPABILITIES.MODERATOR_REVIEW)) {
    return res.status(403).json({
      success: false,
      error: 'Access denied: This action requires Moderator review capability.',
    });
  }
  next();
};

/**
 * Exclusive Media Gallery Publishing Gate: Strictly Media Department Head ONLY.
 * Media Director, Assistant Director, Members, Tester, Moderator, HR, Finance strictly denied.
 */
const requireMediaHead = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Unauthorized.' });
  }
  const isMediaHead =
    req.user.role === TECHNICAL_ROLES.DEPT_MEDIA &&
    normalizeDesignation(req.user.designation) === OPERATIONAL_DESIGNATIONS.HEAD;

  if (!isMediaHead) {
    return res.status(403).json({
      success: false,
      error: 'Exclusive Publishing Authority: Only the Media Department Head is authorized to publish or manage internal gallery assets.',
    });
  }
  next();
};

/**
 * Require HR Recruitment Management authority.
 * Permits Super Admin, HR Head, HR Director, and HR Coordination In-charge.
 * Blocks HR Member/Assistant with HTTP 403 Forbidden.
 */
const requireHRRecruitmentManage = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required.' });
  }
  if (req.user.role === TECHNICAL_ROLES.SUPER_ADMIN) {
    return next();
  }
  if (req.user.role === TECHNICAL_ROLES.HR) {
    const desig = normalizeDesignation(req.user.designation);
    if (
      [
        HR_DESIGNATIONS.HR_HEAD,
        HR_DESIGNATIONS.HR_DIRECTOR,
        HR_DESIGNATIONS.HR_COORDINATION_INCHARGE,
      ].includes(desig)
    ) {
      return next();
    }
    return res.status(403).json({
      success: false,
      error: 'Forbidden: HR Members/Assistants have view-only access and cannot modify recruitment or applicant records.',
    });
  }
  return res.status(403).json({
    success: false,
    error: 'Access Denied: Only authorized HR Leadership or Super Admin can manage recruitment.',
  });
};

/**
 * Require HR Data Export authority.
 * Permits Super Admin, HR Head, HR Director, and HR Coordination In-charge.
 * Blocks HR Member/Assistant with HTTP 403 Forbidden.
 */
const requireHRExport = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required.' });
  }
  if (req.user.role === TECHNICAL_ROLES.SUPER_ADMIN) {
    return next();
  }
  if (req.user.role === TECHNICAL_ROLES.HR) {
    const desig = normalizeDesignation(req.user.designation);
    if (
      [
        HR_DESIGNATIONS.HR_HEAD,
        HR_DESIGNATIONS.HR_DIRECTOR,
        HR_DESIGNATIONS.HR_COORDINATION_INCHARGE,
      ].includes(desig)
    ) {
      return next();
    }
    return res.status(403).json({
      success: false,
      error: 'Forbidden: HR Members/Assistants do not have permission to export HR records.',
    });
  }
  return res.status(403).json({
    success: false,
    error: 'Access Denied: Only authorized HR Leadership or Super Admin can export HR data.',
  });
};

/**
 * Require HR Coordination In-charge authority for Department Announcements.
 * Permits Super Admin and HR Coordination In-charge ONLY.
 * Blocks HR Head, HR Director, HR Members, and all other roles with HTTP 403 Forbidden.
 */
const requireHRCoordinationIncharge = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required.' });
  }
  if (req.user.role === TECHNICAL_ROLES.SUPER_ADMIN) {
    return next();
  }
  if (req.user.role === TECHNICAL_ROLES.HR) {
    const desig = normalizeDesignation(req.user.designation);
    if (desig === HR_DESIGNATIONS.HR_COORDINATION_INCHARGE) {
      return next();
    }
    return res.status(403).json({
      success: false,
      error: 'Access Denied: Only the HR Coordination In-charge is authorized to send official department announcements.',
    });
  }
  return res.status(403).json({
    success: false,
    error: 'Access Denied: Only the HR Coordination In-charge is authorized to send official department announcements.',
  });
};

/**
 * Require Finance authority.
 * Permits Super Admin and Finance role.
 * Blocks HR, operational department leads, and regular members with HTTP 403 Forbidden.
 */
const requireFinance = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required.' });
  }
  if (req.user.role === TECHNICAL_ROLES.SUPER_ADMIN || req.user.role === TECHNICAL_ROLES.FINANCE) {
    return next();
  }
  return res.status(403).json({
    success: false,
    error: `Access Denied: Role '${req.user.role}' is not authorized for Finance operations. Access is restricted to Finance personnel and Super Admin.`,
  });
};

/**
 * Require Finance Export authority.
 * Permits Super Admin and Finance role.
 * Blocks HR, operational department leads, and regular members with HTTP 403 Forbidden.
 */
const requireFinanceExport = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required.' });
  }
  if (req.user.role === TECHNICAL_ROLES.SUPER_ADMIN || req.user.role === TECHNICAL_ROLES.FINANCE) {
    return next();
  }
  return res.status(403).json({
    success: false,
    error: 'Access Denied: Only authorized Finance personnel or Super Admin can export financial records.',
  });
};

/**
 * Require Account Creation & Activation Link Management authority.
 * Permits Super Admin, HR Head, HR Director, and HR Coordination In-charge.
 * Blocks HR Member/Assistant, Department Leads/Members, Finance, Testers, Moderators with HTTP 403 Forbidden.
 */
const requireAccountCreateAuthority = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required.' });
  }
  if (hasCapability(req.user, CAPABILITIES.ACCOUNT_CREATE_MANAGE)) {
    return next();
  }
  return res.status(403).json({
    success: false,
    error: 'Access Denied: Only authorized HR Leadership or Super Admin can create accounts and manage activation links.',
  });
};

module.exports = {
  protect,
  authorize,
  requireDepartmentScope,
  requireOwnershipOrPrivilege,
  requirePrivilegedHR,
  requireDesignation,
  requireCapability,
  requireTester,
  requireModerator,
  requireMediaHead,
  requireHRRecruitmentManage,
  requireHRExport,
  requireHRCoordinationIncharge,
  requireFinance,
  requireFinanceExport,
  requireAccountCreateAuthority,
  requireGradingConfidentiality,
  requireConfidentialAssessmentAccess: requireGradingConfidentiality, // Alias for clarity
  setMemoryUser,
  getMemoryUser,
  getMemoryUsersList,
  DEPT_ROLE_MAP,
  ALLOWED_ROLES,
  TECHNICAL_ROLES,
  OPERATIONAL_DEPT_ROLES,
  OPERATIONAL_DESIGNATIONS,
  HR_DESIGNATIONS,
  ALL_APPROVED_DESIGNATIONS,
  CAPABILITIES,
  normalizeDesignation,
  validateRoleDesignation,
  hasCapability,
  isDepartmentMatch,
};
