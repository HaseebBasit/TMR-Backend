const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const {
  Department,
  Task,
  Notification,
  Donation,
  AuditLog,
  Application,
  Assessment,
  User,
  Announcement,
  LeaveRequest,
} = require('../models');
const {
  protect,
  authorize,
  requireDepartmentScope,
  requireOwnershipOrPrivilege,
  requireTester,
  requireModerator,
  requireMediaHead,
  DEPT_ROLE_MAP,
  ALLOWED_ROLES,
  getMemoryUsersList,
  getMemoryUser,
  setMemoryUser,
  validateRoleDesignation,
  normalizeDesignation,
} = require('../middleware/auth');
const { validateAttachmentMetadata } = require('../services/storage.service');
const { hasCapability, CAPABILITIES } = require('../constants/roles');
const {
  getMemoryApplicationsList,
  setMemoryApplication,
  getMemoryAnnouncementsList,
  getMemoryLeavesList,
  setMemoryLeave,
} = require('./hr.routes');
const {
  sendNotification,
  getNotificationsForUser,
  markNotificationRead,
  markAllNotificationsRead,
  deleteNotification,
} = require('../services/notification.service');

// ---------------------------------------------------------------------------
// In-Memory Task & Department Stores for Offline/Controlled Config Mode
// ---------------------------------------------------------------------------
const memoryTasks = new Map();
const memoryDepartments = [
  {
    name: 'Literature',
    code: 'LIT',
    description: 'Reviving Urdu poetry, prose, and literary discourse.',
    leadName: 'Noor-ul-Huda',
    status: 'active',
    iconName: 'BookOpen',
  },
  {
    name: 'Media',
    code: 'MED',
    description: 'Photography, videography, graphic design, and video production.',
    leadName: 'Aisha Tariq',
    status: 'active',
    iconName: 'Camera',
  },
  {
    name: 'Marketing',
    code: 'MKT',
    description: 'Digital campaigns, social media growth, and branding.',
    leadName: 'Ahmad Raza Waseem',
    status: 'active',
    iconName: 'TrendingUp',
  },
  {
    name: 'Outreach',
    code: 'OUT',
    description: 'Community welfare, youth events, and relief distribution.',
    leadName: 'Asfand Yar Karimi',
    status: 'active',
    iconName: 'HeartHandshake',
  },
  {
    name: 'Content Creation',
    code: 'CON',
    description: 'Urdu scripting, editorial copywriting, and Gen-Z series.',
    leadName: 'Salman Mallana',
    status: 'active',
    iconName: 'PenTool',
  },
];

const getMemoryTasksList = () => Array.from(memoryTasks.values());
const setMemoryTask = (task) => {
  if (task._id) memoryTasks.set(task._id.toString(), task);
  if (task.id) memoryTasks.set(task.id.toString(), task);
};

// Seed an initial task in memory store for offline mode
const memoryAuditLogs = [];
const getMemoryAuditLogsList = () => [...memoryAuditLogs];
const recordMemoryAuditLog = (entry) => {
  memoryAuditLogs.unshift({
    _id: 'audit_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
    createdAt: new Date(),
    ...entry,
  });
  if (memoryAuditLogs.length > 200) memoryAuditLogs.pop();
};

if (memoryAuditLogs.length === 0) {
  recordMemoryAuditLog({
    actorName: 'System Kernel',
    actorRole: 'system',
    action: 'SYSTEM_BOOT',
    module: 'CORE',
    description: 'Portal engine initialized in controlled configuration-check mode.',
  });
}

if (memoryTasks.size === 0) {
  const initialTask = {
    _id: '507f191e810c19729de860f1',
    id: '507f191e810c19729de860f1',
    title: 'Urdu Gen-Z Video Series Episode 1',
    description: 'Script and record the initial episode focusing on classical Urdu idioms in modern contexts.',
    instructions: 'Prepare complete screenplay draft with timestamped scene breakdown and recorded audio rehearsal.',
    department: 'Media',
    departmentCode: 'MED',
    originalDepartment: 'Media',
    originalDepartmentCode: 'MED',
    priority: 'high',
    status: 'assigned',
    assignedTo: '507f191e810c19729de860e6',
    assignedMemberName: 'Member Alice',
    createdByName: 'Aisha Tariq',
    createdByRole: 'dept_media',
    dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    currentVersion: 0,
    submissions: [],
    referrals: [],
    requiredDeliverables: ['video', 'audio', 'document'],
    referenceAttachments: [],
    history: [
      {
        status: 'assigned',
        updatedBy: 'Aisha Tariq',
        role: 'dept_media',
        notes: 'Task initialized and assigned to Media team.',
        timestamp: new Date(),
      },
    ],
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  setMemoryTask(initialTask);
}

// ---------------------------------------------------------------------------
// 1. PUBLIC / GENERAL PORTAL ROUTES
// ---------------------------------------------------------------------------

// Public or Protected Departments Directory
router.get('/departments', async (req, res) => {
  let departments = [];
  try {
    departments = await Department.find({ status: 'active' }).sort({ name: 1 });
  } catch {}

  if (!departments || departments.length === 0) {
    departments = memoryDepartments;
  }
  return res.json({ success: true, departments });
});

// Notifications - Personal User Notifications & Management
router.get('/notifications', protect, async (req, res) => {
  const result = await getNotificationsForUser(req.user.id || req.user._id, req.query);
  return res.json(result);
});

router.patch('/notifications/:id/read', protect, async (req, res) => {
  const result = await markNotificationRead(req.params.id, req.user.id || req.user._id);
  if (!result.success) {
    return res.status(result.statusCode || 400).json(result);
  }
  return res.json(result);
});

router.patch('/notifications/read-all', protect, async (req, res) => {
  const result = await markAllNotificationsRead(req.user.id || req.user._id);
  return res.json(result);
});

router.delete('/notifications/:id', protect, async (req, res) => {
  const result = await deleteNotification(req.params.id, req.user.id || req.user._id);
  if (!result.success) {
    return res.status(result.statusCode || 400).json(result);
  }
  return res.json(result);
});

// ---------------------------------------------------------------------------
// 2. SUPER ADMIN SPECIFIC ROUTES (Global Organization Control)
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/super-admin/overview
 * @desc    Fetch organization-wide metrics, department stats, and recent activities
 * @access  Protected (Super Admin Only)
 */
router.get('/super-admin/overview', protect, authorize('super_admin'), async (req, res) => {
  try {
    // 1. Members Statistics
    let users = [];
    try {
      users = await User.find().select('-password');
    } catch {}
    if (!users || users.length === 0) {
      users = getMemoryUsersList();
    }

    const totalMembers = users.length;
    const activeMembers = users.filter((u) => u.status === 'active').length;
    const inactiveMembers = users.filter((u) => u.status !== 'active').length;

    // 2. Tasks Statistics
    let tasks = [];
    try {
      tasks = await Task.find();
    } catch {}
    if (!tasks || tasks.length === 0) {
      tasks = getMemoryTasksList();
    }

    const activeTasksCount = tasks.filter((t) => ['assigned', 'in_progress', 'todo'].includes(t.status)).length;
    const pendingReviewCount = tasks.filter((t) => ['submitted', 'under_review', 'review'].includes(t.status)).length;
    const revisionCount = tasks.filter((t) => t.status === 'revision_requested').length;
    const completedTasksCount = tasks.filter((t) => ['approved', 'completed'].includes(t.status)).length;

    // 3. Department Breakdown
    const departmentDistribution = memoryDepartments.map((dept) => {
      const deptMembers = users.filter(
        (u) =>
          u.department?.toLowerCase() === dept.name.toLowerCase() ||
          u.departmentCode?.toUpperCase() === dept.code.toUpperCase()
      );
      const deptTasks = tasks.filter(
        (t) =>
          t.department?.toLowerCase() === dept.name.toLowerCase() ||
          t.departmentCode?.toUpperCase() === dept.code.toUpperCase()
      );
      return {
        name: dept.name,
        code: dept.code,
        leadName: dept.leadName,
        iconName: dept.iconName,
        memberCount: deptMembers.length,
        activeTasks: deptTasks.filter((t) => !['completed', 'approved'].includes(t.status)).length,
        completedTasks: deptTasks.filter((t) => ['completed', 'approved'].includes(t.status)).length,
      };
    });

    // 4. Pending Applications
    let applicationsCount = 0;
    try {
      applicationsCount = await Application.countDocuments({ status: 'pending' });
    } catch {}

    // 5. Assessments Count
    let assessmentsCount = 0;
    try {
      assessmentsCount = await Assessment.countDocuments();
    } catch {}

    // 6. Recent Audit Logs
    let recentAuditLogs = [];
    try {
      recentAuditLogs = await AuditLog.find().sort({ createdAt: -1 }).limit(10);
    } catch {}

    return res.json({
      success: true,
      stats: {
        totalMembers,
        activeMembers,
        inactiveMembers,
        activeTasksCount,
        pendingReviewCount,
        revisionCount,
        completedTasksCount,
        pendingApplicationsCount: applicationsCount,
        assessmentsCount,
      },
      departmentDistribution,
      recentAuditLogs,
    });
  } catch (err) {
    console.error('[Super Admin Overview Error]:', err);
    return res.status(500).json({ success: false, error: 'Failed to retrieve super admin overview.' });
  }
});

/**
 * @route   GET /api/super-admin/users
 * @desc    Paginated/filtered user management list
 * @access  Protected (Super Admin Only)
 */
router.get('/super-admin/users', protect, authorize('super_admin'), async (req, res) => {
  try {
    const { role, department, status, search } = req.query;
    let users = [];
    try {
      const filter = {};
      if (role) filter.role = role;
      if (department) filter.department = department;
      if (status) filter.status = status;
      if (search) {
        filter.$or = [
          { name: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
        ];
      }
      users = await User.find(filter).select('-password').sort({ createdAt: -1 });
    } catch {}

    if (!users || users.length === 0) {
      users = getMemoryUsersList().map((u) => {
        const { password, ...safeUser } = u;
        return safeUser;
      });
      if (role) users = users.filter((u) => u.role === role);
      if (department) users = users.filter((u) => u.department === department);
      if (status) users = users.filter((u) => u.status === status);
      if (search) {
        const s = search.toLowerCase();
        users = users.filter((u) => u.name?.toLowerCase().includes(s) || u.email?.toLowerCase().includes(s));
      }
    }

    return res.json({ success: true, count: users.length, users });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch users.' });
  }
});

/**
 * @route   POST /api/super-admin/users
 * @desc    Super Admin invites or registers a new staff/member directly
 * @access  Protected (Super Admin Only)
 */
router.post('/super-admin/users', protect, authorize('super_admin'), async (req, res) => {
  try {
    const { name, email, role, department, designation, phoneNumber, password } = req.body;

    if (!name || !email || !role) {
      return res.status(400).json({ success: false, error: 'Name, email, and role are required.' });
    }

    // Role architecture verification: strictly allow only the approved 9 roles
    if (!ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({
        success: false,
        error: `Invalid role '${role}'. Role must be one of the 9 approved roles: ${ALLOWED_ROLES.join(', ')}.`,
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check duplicate
    let existing = null;
    try {
      existing = await User.findOne({ email: normalizedEmail });
    } catch {}
    if (!existing) existing = getMemoryUser(normalizedEmail);

    if (existing) {
      return res.status(400).json({ success: false, error: 'A user with this email address already exists.' });
    }

    // Server-side department assignment enforcement based on role
    let resolvedDept = department || null;
    let resolvedDeptCode = null;

    if (role.startsWith('dept_')) {
      const mapped = DEPT_ROLE_MAP[role];
      resolvedDept = mapped?.name || null;
      resolvedDeptCode = mapped?.code || null;
    } else if (role === 'hr') {
      resolvedDept = 'HR';
      resolvedDeptCode = 'HR';
    } else if (role === 'finance') {
      resolvedDept = 'Finance';
      resolvedDeptCode = 'FIN';
    } else if (role === 'super_admin') {
      resolvedDept = department || 'Administration';
      resolvedDeptCode = 'ADM';
    } else {
      const deptEntry = Object.values(DEPT_ROLE_MAP).find(
        (d) => d.name.toLowerCase() === (department || '').toLowerCase()
      );
      resolvedDeptCode = deptEntry ? deptEntry.code : null;
    }

    // Validate role-designation compatibility
    let resolvedDesignation = null;
    if (designation) {
      const validation = validateRoleDesignation(role, designation);
      if (!validation.valid) {
        return res.status(400).json({ success: false, error: validation.error });
      }
      resolvedDesignation = validation.designation;
    }

    const initialPassword = password || crypto.randomBytes(8).toString('hex');
    const hashedPassword = await bcrypt.hash(initialPassword, 10);

    // Cryptographic activation token for new accounts
    const rawActivationToken = crypto.randomBytes(32).toString('hex');
    const hashedActivationToken = crypto.createHash('sha256').update(rawActivationToken).digest('hex');
    const activationExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const newUser = {
      _id: 'usr_' + Date.now(),
      id: 'usr_' + Date.now(),
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      role,
      department: resolvedDept,
      departmentCode: resolvedDeptCode,
      designation: resolvedDesignation || null,
      phoneNumber: phoneNumber || '',
      status: password ? 'active' : 'inactive',
      activationToken: hashedActivationToken,
      activationExpires,
      isPrivilegedHR: role === 'super_admin' ? true : false,
      tokenVersion: 0,
      createdAt: new Date(),
    };

    try {
      await User.create(newUser);
    } catch {
      setMemoryUser(newUser);
    }

    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const activationUrl = `${baseUrl}/portal/activate?token=${rawActivationToken}`;

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'USER_CREATED_BY_ADMIN',
      module: 'SUPER_ADMIN',
      targetId: newUser.id,
      targetModel: 'User',
      description: `Super Admin created user ${name} (${normalizedEmail}) with role ${role}. Activation link generated.`,
    }).catch(() => null);

    const { password: _, activationToken: __, ...safeUser } = newUser;
    return res.status(201).json({
      success: true,
      message: 'User created successfully.',
      user: safeUser,
      initialPassword: password ? undefined : initialPassword,
      activation: {
        token: rawActivationToken,
        url: activationUrl,
        expiresAt: activationExpires,
      },
      activationUrl,
      activationToken: rawActivationToken,
      expiresAt: activationExpires,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to create user.' });
  }
});

/**
 * @route   POST /api/super-admin/users/:id/regenerate-activation
 * @desc    Super Admin regenerates activation link for an account
 * @access  Protected (Super Admin Only)
 */
router.post('/super-admin/users/:id/regenerate-activation', protect, authorize('super_admin'), async (req, res) => {
  try {
    const { id } = req.params;
    let user = null;
    try {
      user = await User.findById(id);
    } catch {}
    if (!user) {
      user = getMemoryUsersList().find((u) => (u._id || u.id)?.toString() === id.toString());
    }

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    // Super Admin accounts cannot have activation links regenerated and cannot be deactivated
    if (user.role === 'super_admin') {
      return res.status(400).json({
        success: false,
        error: 'Cannot regenerate activation link for Super Admin account. Use password reset if credentials are required.',
      });
    }

    // Active accounts cannot be forced into inactive status via activation regeneration
    if (user.status === 'active' && !user.activationToken) {
      return res.status(400).json({
        success: false,
        error: 'Cannot regenerate activation link: Account is already active. Use password reset if credentials are required.',
      });
    }

    const rawActivationToken = crypto.randomBytes(32).toString('hex');
    const hashedActivationToken = crypto.createHash('sha256').update(rawActivationToken).digest('hex');
    const activationExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    user.activationToken = hashedActivationToken;
    user.activationExpires = activationExpires;
    user.status = 'inactive';

    try {
      if (user.save) await user.save();
      else setMemoryUser(user);
    } catch {
      setMemoryUser(user);
    }

    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const activationUrl = `${baseUrl}/portal/activate?token=${rawActivationToken}`;

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'ADMIN_REGENERATED_ACTIVATION',
      module: 'SUPER_ADMIN',
      targetId: (user._id || user.id)?.toString(),
      targetModel: 'User',
      description: `Super Admin regenerated activation link for ${user.name} (${user.email}).`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Activation link regenerated successfully.',
      activation: {
        token: rawActivationToken,
        url: activationUrl,
        expiresAt: activationExpires,
      },
      activationUrl,
      activationToken: rawActivationToken,
      expiresAt: activationExpires,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to regenerate activation link.' });
  }
});

/**
 * @route   PATCH /api/super-admin/users/:id
 * @desc    Super Admin updates user details (role, department, designation, status)
 * @access  Protected (Super Admin Only)
 */
router.patch('/super-admin/users/:id', protect, authorize('super_admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { role, department, designation, status, isPrivilegedHR } = req.body;

    let user = null;
    try {
      user = await User.findById(id);
    } catch {}
    if (!user) user = getMemoryUser(id);

    if (!user) {
      return res.status(404).json({ success: false, error: 'User record not found.' });
    }

    if (role) {
      if (!ALLOWED_ROLES.includes(role)) {
        return res.status(400).json({
          success: false,
          error: `Invalid role '${role}'. Role must be one of the 9 approved roles: ${ALLOWED_ROLES.join(', ')}.`,
        });
      }
      user.role = role;
      if (role.startsWith('dept_')) {
        const mapped = DEPT_ROLE_MAP[role];
        user.department = mapped?.name || user.department;
        user.departmentCode = mapped?.code || user.departmentCode;
      } else if (role === 'hr') {
        user.department = 'HR';
        user.departmentCode = 'HR';
      } else if (role === 'finance') {
        user.department = 'Finance';
        user.departmentCode = 'FIN';
      }
    }
    if (department !== undefined && !user.role?.startsWith('dept_') && !['hr', 'finance'].includes(user.role)) {
      user.department = department;
      const deptEntry = Object.values(DEPT_ROLE_MAP).find(
        (d) => d.name.toLowerCase() === (department || '').toLowerCase()
      );
      user.departmentCode = deptEntry ? deptEntry.code : null;
    }
    if (designation !== undefined) {
      const targetRole = role || user.role;
      const validation = validateRoleDesignation(targetRole, designation);
      if (!validation.valid) {
        return res.status(400).json({ success: false, error: validation.error });
      }
      user.designation = validation.designation;
    }
    if (status) {
      if (user.role === 'super_admin' && (status === 'suspended' || status === 'inactive')) {
        return res.status(400).json({
          success: false,
          error: 'Cannot suspend or deactivate Super Admin account.',
        });
      }
      user.status = status;
    }
    if (isPrivilegedHR !== undefined) user.isPrivilegedHR = Boolean(isPrivilegedHR);

    try {
      await user.save();
    } catch {
      setMemoryUser(user);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'USER_UPDATED_BY_ADMIN',
      module: 'SUPER_ADMIN',
      targetId: id,
      targetModel: 'User',
      description: `Super Admin updated profile and role for user ${user.name} (${user.email}).`,
    }).catch(() => null);

    const safeUser = {
      id: user._id || user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      department: user.department,
      departmentCode: user.departmentCode,
      designation: user.designation,
      status: user.status,
      isPrivilegedHR: user.isPrivilegedHR,
    };

    return res.json({ success: true, message: 'User updated successfully.', user: safeUser });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to update user.' });
  }
});

/**
 * @route   GET /api/super-admin/leaves
 * @desc    Get all organization leave requests with summary metrics and filters
 * @access  Protected (Super Admin Only)
 */
router.get('/super-admin/leaves', protect, authorize('super_admin'), async (req, res) => {
  try {
    const { status, department, leaveType, search } = req.query;
    let leaves = [];
    try {
      const filter = {};
      if (department && department !== 'all') filter.department = department;
      if (status && status !== 'all') filter.status = status;
      if (leaveType && leaveType !== 'all') filter.leaveType = leaveType;
      leaves = await LeaveRequest.find(filter).sort({ createdAt: -1 });
    } catch {}

    if (!leaves || leaves.length === 0) {
      leaves = getMemoryLeavesList();
      if (department && department !== 'all') {
        leaves = leaves.filter((l) => (l.department || '').toLowerCase() === department.toLowerCase());
      }
      if (status && status !== 'all') {
        leaves = leaves.filter((l) => l.status === status);
      }
      if (leaveType && leaveType !== 'all') {
        leaves = leaves.filter((l) => l.leaveType === leaveType);
      }
      if (search) {
        const q = search.toLowerCase();
        leaves = leaves.filter(
          (l) =>
            (l.memberName && l.memberName.toLowerCase().includes(q)) ||
            (l.reason && l.reason.toLowerCase().includes(q)) ||
            (l.department && l.department.toLowerCase().includes(q))
        );
      }
    }

    // Calculate metrics across all leaves
    let allLeaves = [];
    try {
      allLeaves = await LeaveRequest.find();
    } catch {}
    if (!allLeaves || allLeaves.length === 0) {
      allLeaves = getMemoryLeavesList();
    }

    const total = allLeaves.length;
    const pending = allLeaves.filter((l) => ['pending', 'submitted', 'dept_approved'].includes(l.status)).length;
    const approved = allLeaves.filter((l) => ['approved', 'hr_approved'].includes(l.status)).length;
    const rejected = allLeaves.filter((l) => ['rejected', 'dept_rejected', 'hr_rejected'].includes(l.status)).length;

    return res.json({
      success: true,
      count: leaves.length,
      stats: {
        total,
        pending,
        approved,
        rejected,
      },
      leaves,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch leave requests.' });
  }
});

/**
 * @route   PATCH /api/super-admin/leaves/:id/review
 * @desc    Super Admin reviews (approves or rejects) any organizational leave request
 * @access  Protected (Super Admin Only)
 */
router.patch('/super-admin/leaves/:id/review', protect, authorize('super_admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { action, notes } = req.body;

    if (!action || !['approve', 'reject'].includes(action)) {
      return res.status(400).json({
        success: false,
        error: "Action must be either 'approve' or 'reject'.",
      });
    }

    let leave = null;
    try {
      leave = await LeaveRequest.findById(id);
    } catch {}
    if (!leave) {
      const memoryList = getMemoryLeavesList();
      leave = memoryList.find((l) => l._id?.toString() === id || l.id?.toString() === id);
    }

    if (!leave) {
      return res.status(404).json({ success: false, error: 'Leave request not found.' });
    }

    const reviewerId = (req.user.id || req.user._id)?.toString();
    const reviewerName = req.user.name || 'Super Admin';
    const isOwner = (leave.memberId || leave.userId)?.toString() === reviewerId;

    // Anti-self-approval rule: Super Admin cannot approve or reject their own leave request
    if (isOwner) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: Anti-self-approval rule prevents approving or rejecting your own leave request.',
      });
    }

    const newStatus = action === 'approve' ? 'approved' : 'rejected';

    if (leave.save) {
      leave.status = newStatus;
      leave.reviewerId = reviewerId;
      leave.reviewerName = reviewerName;
      leave.reviewNotes = notes || (action === 'approve' ? 'Approved by Executive Command' : 'Rejected by Executive Command');
      leave.reviewedAt = new Date();
      await leave.save();
    } else {
      leave.status = newStatus;
      leave.reviewerId = reviewerId;
      leave.reviewerName = reviewerName;
      leave.reviewNotes = notes || (action === 'approve' ? 'Approved by Executive Command' : 'Rejected by Executive Command');
      leave.reviewedAt = new Date();
      setMemoryLeave(leave);
    }

    await AuditLog.create({
      actorId: reviewerId,
      actorName: reviewerName,
      actorRole: req.user.role,
      action: action === 'approve' ? 'SUPER_ADMIN_LEAVE_APPROVED' : 'SUPER_ADMIN_LEAVE_REJECTED',
      module: 'SUPER_ADMIN',
      targetId: (leave._id || leave.id)?.toString(),
      targetModel: 'LeaveRequest',
      description: `Executive Command ${newStatus} leave request for ${leave.memberName || 'Member'} (${leave.department}). Note: ${notes || 'None'}`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Leave request successfully ${newStatus}.`,
      leave,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to process leave review.' });
  }
});

/**
 * @route   GET /api/super-admin/departments
 * @desc    Super Admin department management listing
 * @access  Protected (Super Admin Only)
 */
router.get('/super-admin/departments', protect, authorize('super_admin'), async (req, res) => {
  let users = [];
  try {
    users = await User.find().select('-password');
  } catch {}
  if (!users || users.length === 0) users = getMemoryUsersList();

  let tasks = [];
  try {
    tasks = await Task.find();
  } catch {}
  if (!tasks || tasks.length === 0) tasks = getMemoryTasksList();

  const departmentsWithMetrics = memoryDepartments.map((dept) => {
    const deptMembers = users.filter(
      (u) =>
        u.department?.toLowerCase() === dept.name.toLowerCase() ||
        u.departmentCode?.toUpperCase() === dept.code.toUpperCase()
    );
    const deptTasks = tasks.filter(
      (t) =>
        t.department?.toLowerCase() === dept.name.toLowerCase() ||
        t.departmentCode?.toUpperCase() === dept.code.toUpperCase()
    );
    return {
      ...dept,
      memberCount: deptMembers.length,
      activeTasksCount: deptTasks.filter((t) => !['completed', 'approved'].includes(t.status)).length,
      completedTasksCount: deptTasks.filter((t) => ['completed', 'approved'].includes(t.status)).length,
    };
  });

  return res.json({ success: true, departments: departmentsWithMetrics });
});

/**
 * @route   GET /api/super-admin/audit-logs
 * @desc    Super Admin Audit Logs - Strictly Super Admin Only
 * @access  Protected (Super Admin Only)
 */
router.get('/super-admin/audit-logs', protect, authorize('super_admin'), async (req, res) => {
  let logs = [];
  try {
    logs = await AuditLog.find().sort({ createdAt: -1 }).limit(100);
  } catch {}
  if (!logs || logs.length === 0) {
    logs = getMemoryAuditLogsList();
  }
  return res.json({ success: true, count: logs.length, logs });
});

// ---------------------------------------------------------------------------
// 3. DEPARTMENT HEAD SPECIFIC ROUTES (Scoped per department)
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/department/:department/overview
 * @desc    Fetch department workspace overview, metrics, and active tasks
 * @access  Protected (Department Head matching scope or Super Admin)
 */
router.get(
  '/department/:department/overview',
  protect,
  requireDepartmentScope('department'),
  async (req, res) => {
    try {
      const { department } = req.params;

      // Determine authoritative department name
      let authoritativeDept = department;
      if (req.user.role.startsWith('dept_')) {
        authoritativeDept = DEPT_ROLE_MAP[req.user.role]?.name || department;
      }

      // 1. Fetch Department Tasks
      let tasks = [];
      try {
        tasks = await Task.find({
          $or: [
            { department: authoritativeDept },
            { departmentCode: authoritativeDept.toUpperCase() },
          ],
        }).sort({ createdAt: -1 });
      } catch {}

      if (!tasks || tasks.length === 0) {
        tasks = getMemoryTasksList().filter(
          (t) =>
            t.department?.toLowerCase() === authoritativeDept.toLowerCase() ||
            t.departmentCode?.toUpperCase() === authoritativeDept.toUpperCase()
        );
      }

      // 2. Fetch Department Members
      let members = [];
      try {
        members = await User.find({
          $or: [
            { department: authoritativeDept },
            { departmentCode: authoritativeDept.toUpperCase() },
          ],
        }).select('-password');
      } catch {}

      if (!members || members.length === 0) {
        members = getMemoryUsersList().filter(
          (u) =>
            u.department?.toLowerCase() === authoritativeDept.toLowerCase() ||
            u.departmentCode?.toUpperCase() === authoritativeDept.toUpperCase()
        );
      }

      const activeTasks = tasks.filter((t) => ['assigned', 'in_progress', 'todo'].includes(t.status)).length;
      const awaitingReview = tasks.filter((t) => ['submitted', 'under_review', 'review'].includes(t.status)).length;
      const revisionRequested = tasks.filter((t) => t.status === 'revision_requested').length;
      const completedTasks = tasks.filter((t) => ['approved', 'completed'].includes(t.status)).length;

      return res.json({
        success: true,
        department: authoritativeDept,
        metrics: {
          memberCount: members.length,
          activeTasks,
          awaitingReview,
          revisionRequested,
          completedTasks,
          totalTasks: tasks.length,
        },
        members: members.map((m) => ({
          id: m._id || m.id,
          name: m.name,
          email: m.email,
          role: m.role,
          designation: m.designation,
          status: m.status,
        })),
        tasks,
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Failed to fetch department overview.' });
    }
  }
);

/**
 * @route   GET /api/department/:department/members
 * @desc    Fetch members of a specific department
 * @access  Protected (Department Head matching scope or Super Admin)
 */
router.get(
  '/department/:department/members',
  protect,
  requireDepartmentScope('department'),
  async (req, res) => {
    try {
      const { department } = req.params;
      let authoritativeDept = department;
      if (req.user.role.startsWith('dept_')) {
        authoritativeDept = DEPT_ROLE_MAP[req.user.role]?.name || department;
      }

      let members = [];
      try {
        members = await User.find({
          $or: [
            { department: authoritativeDept },
            { departmentCode: authoritativeDept.toUpperCase() },
          ],
        }).select('-password');
      } catch {}

      if (!members || members.length === 0) {
        members = getMemoryUsersList().filter(
          (u) =>
            u.department?.toLowerCase() === authoritativeDept.toLowerCase() ||
            u.departmentCode?.toUpperCase() === authoritativeDept.toUpperCase()
        );
      }

      const safeMembers = members.map((m) => ({
        id: m._id || m.id,
        name: m.name,
        email: m.email,
        role: m.role,
        designation: m.designation,
        status: m.status,
      }));

      return res.json({ success: true, count: safeMembers.length, members: safeMembers });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Failed to fetch department members.' });
    }
  }
);

/**
 * @route   GET /api/department/:department/tasks
 * @desc    Fetch department tasks with filters
 * @access  Protected (Department Head matching scope or Super Admin)
 */
router.get(
  '/department/:department/tasks',
  protect,
  requireDepartmentScope('department'),
  async (req, res) => {
    try {
      const { department } = req.params;
      let authoritativeDept = department;
      if (req.user.role.startsWith('dept_')) {
        authoritativeDept = DEPT_ROLE_MAP[req.user.role]?.name || department;
      }

      const filter = {
        $or: [
          { department: authoritativeDept },
          { departmentCode: authoritativeDept.toUpperCase() },
        ],
      };

      if (req.query.status) filter.status = req.query.status;
      if (req.query.priority) filter.priority = req.query.priority;

      let tasks = [];
      try {
        tasks = await Task.find(filter).sort({ createdAt: -1 });
      } catch {}

      if (!tasks || tasks.length === 0) {
        tasks = getMemoryTasksList().filter(
          (t) =>
            t.department?.toLowerCase() === authoritativeDept.toLowerCase() ||
            t.departmentCode?.toUpperCase() === authoritativeDept.toUpperCase()
        );
        if (req.query.status) tasks = tasks.filter((t) => t.status === req.query.status);
        if (req.query.priority) tasks = tasks.filter((t) => t.priority === req.query.priority);
      }

      return res.json({ success: true, count: tasks.length, tasks });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Failed to fetch department tasks.' });
    }
  }
);

// ---------------------------------------------------------------------------
// 4. TASK LIFECYCLE & WORKFLOW ROUTES (Complete Lifecycle)
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/tasks/tester-queue
 * @desc    Fetch tasks awaiting tester verification
 * @access  Protected (Testers and Super Admin)
 */
router.get('/tasks/tester-queue', protect, requireTester, async (req, res) => {
  try {
    let tasks = [];
    try {
      tasks = await Task.find({
        status: { $in: ['pending_testing', 'under_testing'] },
      }).sort({ updatedAt: -1 });
    } catch {}

    if (!tasks || tasks.length === 0) {
      tasks = getMemoryTasksList().filter((t) =>
        ['pending_testing', 'under_testing'].includes(t.status)
      );
    }
    return res.json({ success: true, count: tasks.length, tasks });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch tester queue.' });
  }
});

/**
 * @route   GET /api/tasks/moderator-queue
 * @desc    Fetch tasks awaiting moderator review & content editing
 * @access  Protected (Moderators and Super Admin)
 */
router.get('/tasks/moderator-queue', protect, requireModerator, async (req, res) => {
  try {
    let tasks = [];
    try {
      tasks = await Task.find({
        status: { $in: ['moderation_pending', 'under_moderation'] },
      }).sort({ updatedAt: -1 });
    } catch {}

    if (!tasks || tasks.length === 0) {
      tasks = getMemoryTasksList().filter((t) =>
        ['moderation_pending', 'under_moderation'].includes(t.status)
      );
    }
    return res.json({ success: true, count: tasks.length, tasks });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch moderator queue.' });
  }
});

/**
 * @route   GET /api/tasks/referrals/incoming
 * @desc    Fetch incoming inter-department task referrals
 * @access  Protected (Department Heads, Directors, Super Admin)
 */
router.get('/tasks/referrals/incoming', protect, async (req, res) => {
  try {
    let userDept = req.user.department;
    if (req.user.role.startsWith('dept_')) {
      userDept = DEPT_ROLE_MAP[req.user.role]?.name || userDept;
    }

    let tasks = [];
    try {
      const q = { 'activeReferral.status': 'pending' };
      if (req.user.role !== 'super_admin') {
        q['activeReferral.receivingDepartment'] = userDept;
      }
      tasks = await Task.find(q).sort({ updatedAt: -1 });
    } catch {}

    if (!tasks || tasks.length === 0) {
      tasks = getMemoryTasksList().filter((t) => {
        if (!t.activeReferral || t.activeReferral.status !== 'pending') return false;
        if (req.user.role === 'super_admin') return true;
        return t.activeReferral.receivingDepartment?.toLowerCase() === userDept?.toLowerCase();
      });
    }
    return res.json({ success: true, count: tasks.length, tasks });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch incoming referrals.' });
  }
});

/**
 * @route   GET /api/tasks
 * @desc    Fetch role-scoped tasks list
 * @access  Protected
 */
router.get('/tasks', protect, async (req, res) => {
  try {
    const q = {};

    // 1. Super Admin sees all or filters by department
    if (req.user.role === 'super_admin') {
      if (req.query.department) q.department = req.query.department;
      if (req.query.departmentCode) q.departmentCode = req.query.departmentCode;
    }
    // 2. Department Heads are strictly scoped to their assigned department
    else if (req.user.role.startsWith('dept_')) {
      const assignedDept = DEPT_ROLE_MAP[req.user.role];
      q.department = assignedDept?.name;
      delete q.departmentId;
    }
    // 3. Members only see tasks assigned to them
    else if (req.user.role === 'member') {
      q.assignedTo = (req.user.id || req.user._id).toString();
    } else if (!['hr', 'finance'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Access denied.' });
    }

    if (req.query.status) q.status = req.query.status;

    let tasks = [];
    try {
      tasks = await Task.find(q).sort({ createdAt: -1 });
    } catch {}

    if (!tasks || tasks.length === 0) {
      tasks = getMemoryTasksList();
      if (q.department) tasks = tasks.filter((t) => t.department === q.department);
      if (q.assignedTo) tasks = tasks.filter((t) => t.assignedTo?.toString() === q.assignedTo.toString());
      if (q.status) tasks = tasks.filter((t) => t.status === q.status);
    }

    return res.json({ success: true, count: tasks.length, tasks });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch tasks.' });
  }
});

/**
 * @route   POST /api/tasks
 * @desc    Create and assign a task (Super Admin or Department Head/Director)
 * @access  Protected
 */
router.post(
  '/tasks',
  protect,
  authorize('super_admin', 'dept_literature', 'dept_media', 'dept_marketing', 'dept_outreach', 'dept_content', 'hr'),
  async (req, res) => {
    try {
      const {
        title,
        description,
        instructions,
        priority,
        dueDate,
        deadline,
        assignedTo,
        assignedMemberName,
        assignedMemberEmail,
        requiredDeliverables,
        referenceAttachments,
      } = req.body;

      if (!title) {
        return res.status(400).json({ success: false, error: 'Task title is required.' });
      }

      let department = req.body.department;
      let departmentCode = req.body.departmentCode;

      // Department Heads/Directors are strictly locked to their own department
      if (req.user.role.startsWith('dept_')) {
        const assignedDept = DEPT_ROLE_MAP[req.user.role];
        department = assignedDept?.name;
        departmentCode = assignedDept?.code;

        // Department isolation: Validate target member belongs to the same department
        if (assignedTo) {
          let targetMember = null;
          try {
            targetMember = await User.findById(assignedTo);
          } catch {}
          if (!targetMember) targetMember = getMemoryUser(assignedTo);
          if (targetMember && targetMember.department && targetMember.department.toLowerCase() !== department.toLowerCase()) {
            return res.status(400).json({
              success: false,
              error: `Cross-Department Assignment Violation: You can only assign tasks to members in ${department}.`,
            });
          }
        }
      } else if (!department && req.user.role === 'super_admin') {
        department = 'Administration';
        departmentCode = 'ADM';
      }

      const initialStatus = 'assigned';
      const newTask = {
        _id: 'tsk_' + Date.now(),
        id: 'tsk_' + Date.now(),
        title: title.trim(),
        description: description?.trim() || '',
        instructions: instructions?.trim() || description?.trim() || '',
        department,
        departmentCode,
        originalDepartment: department, // IMMUTABLE
        originalDepartmentCode: departmentCode,
        assignedTo: assignedTo || null,
        assignedMemberName: assignedMemberName || '',
        assignedMemberEmail: assignedMemberEmail || '',
        createdBy: req.user.id || req.user._id,
        createdByName: req.user.name,
        createdByRole: req.user.role,
        priority: priority || 'medium',
        status: initialStatus,
        dueDate: dueDate ? new Date(dueDate) : deadline ? new Date(deadline) : null,
        deadline: deadline ? new Date(deadline) : dueDate ? new Date(dueDate) : null,
        requiredDeliverables: Array.isArray(requiredDeliverables)
          ? requiredDeliverables
          : requiredDeliverables
          ? [requiredDeliverables]
          : [],
        referenceAttachments: Array.isArray(referenceAttachments) ? referenceAttachments : [],
        currentVersion: 0,
        submissions: [],
        referrals: [],
        history: [
          {
            status: initialStatus,
            updatedBy: req.user.name,
            role: req.user.role,
            notes: 'Task created and assigned.',
            timestamp: new Date(),
          },
        ],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      let task = null;
      try {
        task = await Task.create(newTask);
      } catch {
        setMemoryTask(newTask);
        task = newTask;
      }

      await AuditLog.create({
        actorId: req.user.id || req.user._id,
        actorName: req.user.name,
        actorRole: req.user.role,
        action: 'TASK_CREATED',
        module: 'TASK_MANAGEMENT',
        targetId: task.id || task._id,
        targetModel: 'Task',
        description: `Task '${title}' created for ${department} assigned to ${assignedMemberName || assignedTo || 'unassigned'}.`,
      }).catch(() => null);

      if (task.assignedTo) {
        await sendNotification({
          userId: task.assignedTo,
          title: 'New Task Assignment',
          message: `You have been assigned to task '${title}' in ${department}.`,
          type: 'info',
          category: 'task',
          link: '/portal/member?tab=tasks',
          dedupKey: `task:assign:${task.id || task._id}:${task.assignedTo}`,
        }).catch(() => null);
      }

      return res.status(201).json({ success: true, task });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Failed to create task.' });
    }
  }
);

/**
 * @route   PATCH /api/tasks/:id/status
 * @desc    Advance task status (e.g. assigned -> in_progress)
 * @access  Protected (Assigned Member, Department Head, or Super Admin)
 */
router.patch('/tasks/:id/status', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;

    if (!status) {
      return res.status(400).json({ success: false, error: 'New status is required.' });
    }

    const ALLOWED_TASK_STATUSES = [
      'assigned',
      'in_progress',
      'submitted',
      'under_review',
      'revision_requested',
      'approved',
      'completed',
    ];

    if (!ALLOWED_TASK_STATUSES.includes(status)) {
      return res.status(400).json({
        success: false,
        error: `Invalid task status '${status}'. Must be one of: ${ALLOWED_TASK_STATUSES.join(', ')}.`,
      });
    }

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    // Authorization check
    const currentUserId = (req.user.id || req.user._id)?.toString();
    const isAssigned = task.assignedTo?.toString() === currentUserId;
    const isDeptHead = req.user.role.startsWith('dept_') && DEPT_ROLE_MAP[req.user.role]?.name === task.department;
    const isSuperAdmin = req.user.role === 'super_admin';

    if (!isAssigned && !isDeptHead && !isSuperAdmin) {
      return res.status(403).json({ success: false, error: 'You are not authorized to update this task.' });
    }

    // Role-specific transition rules:
    // Members can ONLY transition tasks from 'assigned' or 'revision_requested' -> 'in_progress'.
    // Members CANNOT self-approve, complete, mark under_review, or request revision.
    if (req.user.role === 'member') {
      if (status !== 'in_progress') {
        return res.status(403).json({
          success: false,
          error: `Unauthorized status transition: Members cannot set task status to '${status}'. Submit deliverables via POST /api/tasks/:id/submit.`,
        });
      }
      if (!['assigned', 'revision_requested'].includes(task.status)) {
        return res.status(400).json({
          success: false,
          error: `Invalid transition: Task cannot transition to 'in_progress' from current status '${task.status}'.`,
        });
      }
    }

    task.status = status;
    if (status === 'completed' || status === 'approved') {
      task.completedAt = new Date();
    }

    if (!task.history) task.history = [];
    task.history.push({
      status,
      updatedBy: req.user.name,
      role: req.user.role,
      notes: notes || `Status updated to ${status}.`,
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    return res.json({ success: true, message: `Task status updated to ${status}.`, task });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to update task status.' });
  }
});

/**
 * @route   PATCH /api/tasks/:id/reassign
 * @desc    Reassign a task to another department member
 * @access  Protected (Department Head of Department or Super Admin)
 */
router.patch('/tasks/:id/reassign', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { assignedTo, assignedMemberName, assignedMemberEmail } = req.body;

    if (!assignedTo) {
      return res.status(400).json({ success: false, error: 'Target assignedTo user ID is required.' });
    }

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    const isDeptHead = req.user.role.startsWith('dept_') && DEPT_ROLE_MAP[req.user.role]?.name === task.department;
    const isSuperAdmin = req.user.role === 'super_admin';

    if (!isDeptHead && !isSuperAdmin) {
      return res.status(403).json({
        success: false,
        error: 'Access denied: Only the Department Head or Super Admin is authorized to reassign tasks.',
      });
    }

    let targetMember = null;
    try {
      targetMember = await User.findById(assignedTo);
    } catch {}
    if (!targetMember) targetMember = getMemoryUser(assignedTo);

    if (isDeptHead && targetMember && targetMember.department && targetMember.department.toLowerCase() !== task.department.toLowerCase()) {
      return res.status(400).json({
        success: false,
        error: `Department Isolation Violation: You can only reassign tasks to members within ${task.department}.`,
      });
    }

    const prevAssignee = task.assignedMemberName || task.assignedTo || 'unassigned';
    task.assignedTo = assignedTo;
    task.assignedMemberName = assignedMemberName || targetMember?.name || '';
    task.assignedMemberEmail = assignedMemberEmail || targetMember?.email || '';

    if (!task.history) task.history = [];
    task.history.push({
      status: task.status,
      updatedBy: req.user.name,
      role: req.user.role,
      notes: `Task reassigned from ${prevAssignee} to ${task.assignedMemberName || assignedTo} by ${req.user.name}.`,
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'TASK_REASSIGNED',
      module: 'TASK_MANAGEMENT',
      targetId: id,
      targetModel: 'Task',
      description: `Task '${task.title}' reassigned from ${prevAssignee} to ${task.assignedMemberName || assignedTo}.`,
    }).catch(() => null);

    if (task.assignedTo) {
      await sendNotification({
        userId: task.assignedTo,
        title: 'Task Reassigned',
        message: `Task '${task.title}' has been reassigned to you in ${task.department}.`,
        type: 'info',
        category: 'task',
        link: '/portal/member?tab=tasks',
        dedupKey: `task:reassign:${task.id || task._id}:${task.assignedTo}`,
      }).catch(() => null);
    }

    return res.json({ success: true, message: 'Task reassigned successfully.', task });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to reassign task.' });
  }
});

/**
 * @route   POST /api/tasks/:id/submit
 * @desc    Member submits completed multimedia deliverables with versioning (Stage 2)
 * @access  Protected (Assigned Member or Super Admin)
 */
router.post('/tasks/:id/submit', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { notes, links, attachments } = req.body;

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    const currentUserId = (req.user.id || req.user._id)?.toString();
    const isAssigned = task.assignedTo?.toString() === currentUserId;
    const isSuperAdmin = req.user.role === 'super_admin';

    if (!isAssigned && !isSuperAdmin) {
      return res.status(403).json({ success: false, error: 'Only the assigned member can submit work for this task.' });
    }

    if (['approved', 'completed'].includes(task.status)) {
      return res.status(400).json({
        success: false,
        error: 'Task has already been approved and completed. Submissions are closed.',
      });
    }

    // Validate multimedia attachments if provided
    const attachmentsList = Array.isArray(attachments) ? attachments : attachments ? [attachments] : [];
    for (const att of attachmentsList) {
      const val = validateAttachmentMetadata({
        fileName: att.fileName || att.originalName || att.name || 'deliverable',
        fileSize: att.fileSize || att.size || 0,
        fileType: att.fileType || att.mimeType || 'application/octet-stream',
        mimeType: att.mimeType || att.fileType || 'application/octet-stream',
      });
      if (!val.valid) {
        return res.status(400).json({ success: false, error: `Invalid attachment '${att.fileName || 'deliverable'}': ${val.error}` });
      }
    }

    // Versioning: increment currentVersion (previous versions never overwritten)
    const nextVersion = (task.currentVersion || 0) + 1;
    task.currentVersion = nextVersion;

    const formattedAttachments = attachmentsList.map((att) => ({
      fileName: att.fileName || att.originalName || att.name || 'deliverable',
      fileUrl: att.fileUrl || att.url || '',
      fileType: att.fileType || att.mimeType || 'application/octet-stream',
      fileSize: att.fileSize || att.size || 0,
      mimeType: att.mimeType || att.fileType || 'application/octet-stream',
      uploadedAt: new Date(),
    }));

    const submissionEntry = {
      version: nextVersion,
      submittedBy: {
        id: req.user.id || req.user._id,
        name: req.user.name,
        email: req.user.email,
      },
      submittedAt: new Date(),
      notes: notes || '',
      attachments: formattedAttachments,
      status: 'pending_testing',
    };

    if (!task.submissions) task.submissions = [];
    task.submissions.push(submissionEntry);

    // Status advances to pending_testing for tester review
    task.status = 'pending_testing';

    // Legacy fields for backward compatibility
    task.submissionDetails = {
      notes: notes || '',
      links: Array.isArray(links) ? links : links ? [links] : [],
      submittedAt: new Date(),
    };

    if (!task.history) task.history = [];
    task.history.push({
      status: 'pending_testing',
      updatedBy: req.user.name,
      role: req.user.role,
      notes: notes || `Deliverable v${nextVersion} submitted with ${formattedAttachments.length} attachment(s) for tester review.`,
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'TASK_WORK_SUBMITTED',
      module: 'TASK_MANAGEMENT',
      targetId: id,
      targetModel: 'Task',
      description: `Member ${req.user.name} submitted v${nextVersion} deliverable with ${formattedAttachments.length} attachment(s) for task '${task.title}'.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Deliverable v${nextVersion} submitted successfully and queued for tester review.`,
      task,
      version: nextVersion,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to submit work.' });
  }
});

/**
 * @route   POST /api/tasks/:id/test-review
 * @desc    Tester reviews submitted deliverables (Stage 3: pass / corrections_requested / reject)
 * @access  Protected (Testers and Super Admin)
 */
router.post('/tasks/:id/test-review', protect, requireTester, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, comments, findings, notes } = req.body;

    // Strict boundary: Tester cannot final-approve or complete tasks
    if (['approve', 'complete', 'final_approval'].includes(action)) {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Testers are intermediate reviewers and cannot final-approve or complete tasks. Final approval is strictly reserved for the original department Head or Director.',
      });
    }

    if (!action || !['pass', 'passed', 'corrections_requested', 'reject', 'rejected'].includes(action)) {
      return res.status(400).json({
        success: false,
        error: "Action must be 'pass', 'corrections_requested', or 'reject'.",
      });
    }

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    const isPass = action === 'pass' || action === 'passed';
    const verdict = isPass ? 'passed' : action === 'corrections_requested' ? 'corrections_requested' : 'rejected';
    const newStatus = isPass ? 'moderation_pending' : 'revision_requested';

    task.status = newStatus;
    task.testingDetails = {
      testerId: req.user.id || req.user._id,
      testerName: req.user.name,
      testedAt: new Date(),
      comments: comments || notes || '',
      findings: findings || '',
      decision: verdict,
      forwardedToModerator: isPass,
    };

    if (task.submissions && task.submissions.length > 0) {
      task.submissions[task.submissions.length - 1].status = isPass ? 'tested_passed' : verdict;
    }

    if (!task.history) task.history = [];
    task.history.push({
      status: newStatus,
      updatedBy: req.user.name,
      role: req.user.role,
      notes: `Tester review verdict: ${verdict}. ${comments || notes || ''}`.trim(),
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: isPass ? 'TASK_TEST_PASSED' : 'TASK_TEST_DEFECT_FOUND',
      module: 'TASK_MANAGEMENT',
      targetId: id,
      targetModel: 'Task',
      description: `Tester ${req.user.name} reviewed task '${task.title}': ${verdict}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Tester review recorded: ${verdict}. Next stage: ${newStatus}.`,
      task,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to record tester review.' });
  }
});

/**
 * @route   POST /api/tasks/:id/moderate
 * @desc    Moderator reviews and edits deliverables (Stage 4: forward for approval / return to department)
 * @access  Protected (Moderators and Super Admin)
 */
router.post('/tasks/:id/moderate', protect, requireModerator, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      action,
      feedback,
      notes,
      editedDeliverables,
      editedAttachments,
      returnReason,
      requiredChanges,
      recheckingDeadline,
      recommendedMember,
    } = req.body;

    // Strict boundary: Moderator cannot final-approve
    if (['approve', 'complete', 'final_approval'].includes(action)) {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Moderators are intermediate reviewers and cannot final-approve or complete tasks. Final approval is strictly reserved for the original department Head or Director.',
      });
    }

    const ALLOWED_MOD_ACTIONS = [
      'forward_for_approval',
      'forward',
      'pass',
      'return_to_department',
      'return',
      'request_revision',
    ];
    if (!action || !ALLOWED_MOD_ACTIONS.includes(action)) {
      return res.status(400).json({
        success: false,
        error: "Action must be 'forward_for_approval' or 'return_to_department'.",
      });
    }

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    const isForward = ['forward_for_approval', 'forward', 'pass'].includes(action);
    const decision = isForward ? 'forwarded_for_approval' : 'returned_to_department';
    const newStatus = isForward ? 'awaiting_final_approval' : 'rechecking_pending';

    // Validate any edited attachments provided by moderator
    const rawAttachments = editedAttachments || editedDeliverables || [];
    const attachmentsList = Array.isArray(rawAttachments) ? rawAttachments : [rawAttachments];
    for (const att of attachmentsList) {
      const val = validateAttachmentMetadata({
        fileName: att.fileName || att.originalName || att.name || 'edited_deliverable',
        fileSize: att.fileSize || att.size || 0,
        fileType: att.fileType || att.mimeType || 'application/octet-stream',
        mimeType: att.mimeType || att.fileType || 'application/octet-stream',
      });
      if (!val.valid) {
        return res.status(400).json({ success: false, error: `Invalid edited attachment: ${val.error}` });
      }
    }

    const formattedEditedAttachments = attachmentsList.map((att) => ({
      fileName: att.fileName || att.originalName || att.name || 'edited_deliverable',
      fileUrl: att.fileUrl || att.url || '',
      fileType: att.fileType || att.mimeType || 'application/octet-stream',
      fileSize: att.fileSize || att.size || 0,
      uploadedAt: new Date(),
    }));

    task.status = newStatus;
    task.moderationDetails = {
      moderatorId: req.user.id || req.user._id,
      moderatorName: req.user.name,
      moderatedAt: new Date(),
      feedback: feedback || notes || '',
      editedAttachments: formattedEditedAttachments,
      decision,
      returnDetails: !isForward
        ? {
            returnReason: returnReason || feedback || 'Moderator requested rechecking.',
            requiredChanges: requiredChanges || '',
            recheckingDeadline: recheckingDeadline ? new Date(recheckingDeadline) : null,
            recommendedMember: recommendedMember || '',
          }
        : undefined,
    };

    if (!task.history) task.history = [];
    task.history.push({
      status: newStatus,
      updatedBy: req.user.name,
      role: req.user.role,
      notes: `Moderator decision: ${decision}. ${feedback || notes || ''}`.trim(),
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: isForward ? 'TASK_MODERATED_FORWARDED' : 'TASK_MODERATED_RETURNED',
      module: 'TASK_MANAGEMENT',
      targetId: id,
      targetModel: 'Task',
      description: `Moderator ${req.user.name} reviewed task '${task.title}': ${decision}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Moderation review completed: ${decision}. Next stage: ${newStatus}.`,
      task,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to record moderation review.' });
  }
});

/**
 * @route   POST /api/tasks/:id/recheck
 * @desc    Department Head/Director rechecks and reassigns returned task (Stage 4b)
 * @access  Protected (Original Department Head/Director or Super Admin ONLY)
 */
router.post('/tasks/:id/recheck', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, assignedTo, assignedMemberName, instructions, notes } = req.body;

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    const isSuperAdmin = req.user.role === 'super_admin';
    const callerDept = req.user.department || (req.user.role.startsWith('dept_') ? DEPT_ROLE_MAP[req.user.role]?.name : null);
    const callerDesig = normalizeDesignation(req.user.designation);
    const isOriginalDeptLead =
      (callerDept?.toLowerCase() === task.originalDepartment?.toLowerCase() ||
        (req.user.role.startsWith('dept_') &&
          DEPT_ROLE_MAP[req.user.role]?.name?.toLowerCase() === task.originalDepartment?.toLowerCase())) &&
      ['head', 'director'].includes(callerDesig || '');

    if (!isSuperAdmin && !isOriginalDeptLead) {
      return res.status(403).json({
        success: false,
        error: `Access Denied: Only the Head or Director of the original department (${task.originalDepartment}) is authorized to recheck and reassign this task.`,
      });
    }

    if (assignedTo) {
      task.assignedTo = assignedTo;
      if (assignedMemberName) task.assignedMemberName = assignedMemberName;
    }
    if (instructions) {
      task.instructions = instructions;
    }

    let newStatus = 'in_progress';
    if (action === 'resubmit_to_testing') {
      newStatus = 'pending_testing';
    } else if (action === 'cancel') {
      newStatus = 'cancelled';
    } else {
      newStatus = 'in_progress';
    }

    task.status = newStatus;

    if (!task.history) task.history = [];
    task.history.push({
      status: newStatus,
      updatedBy: req.user.name,
      role: req.user.role,
      notes: `Rechecked by ${req.user.name} (${callerDesig || req.user.role}): ${notes || 'Reassigned and resumed in_progress.'}`,
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'TASK_RECHECKED_REASSIGNED',
      module: 'TASK_MANAGEMENT',
      targetId: id,
      targetModel: 'Task',
      description: `${req.user.name} rechecked task '${task.title}' and transitioned to ${newStatus}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Task successfully rechecked and transitioned to ${newStatus}.`,
      task,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to recheck task.' });
  }
});

/**
 * @route   POST /api/tasks/:id/refer
 * @desc    Inter-department task referral (Stage 5)
 * @access  Protected (Department Head, Director, or Super Admin)
 */
router.post('/tasks/:id/refer', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { targetDepartment, targetDepartmentCode, reason, instructions, specificAssignee, specificAssigneeName } = req.body;

    if (!targetDepartment) {
      return res.status(400).json({ success: false, error: 'targetDepartment is required for referral.' });
    }

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    const isSuperAdmin = req.user.role === 'super_admin';
    const callerDept = req.user.department || (req.user.role.startsWith('dept_') ? DEPT_ROLE_MAP[req.user.role]?.name : null);
    const callerDesig = normalizeDesignation(req.user.designation);
    const isDeptLead =
      (callerDept?.toLowerCase() === task.department?.toLowerCase() ||
        (req.user.role.startsWith('dept_') &&
          DEPT_ROLE_MAP[req.user.role]?.name?.toLowerCase() === task.department?.toLowerCase())) &&
      ['head', 'director'].includes(callerDesig || '');

    if (!isSuperAdmin && !isDeptLead) {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Department Heads or Directors can refer tasks to other departments.',
      });
    }

    // Invariant: originalDepartment is NEVER modified
    const referralId = 'ref_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);
    const referralEntry = {
      referralId,
      originalDepartment: task.originalDepartment || task.department,
      sendingDepartment: task.department,
      receivingDepartment: targetDepartment,
      referringUser: {
        id: req.user.id || req.user._id,
        name: req.user.name,
        role: req.user.role,
        designation: req.user.designation,
      },
      receivingUser: specificAssignee
        ? {
            id: specificAssignee,
            name: specificAssigneeName || '',
          }
        : undefined,
      reason: reason || '',
      instructions: instructions || '',
      status: 'pending',
      referredAt: new Date(),
    };

    if (!task.referrals) task.referrals = [];
    task.referrals.push(referralEntry);

    task.activeReferral = {
      referralId,
      originalDepartment: task.originalDepartment || task.department,
      sendingDepartment: task.department,
      receivingDepartment: targetDepartment,
      referringUserName: req.user.name,
      reason: reason || '',
      status: 'pending',
      referredAt: new Date(),
    };

    // Update active department while keeping originalDepartment immutable
    task.department = targetDepartment;
    if (targetDepartmentCode) task.departmentCode = targetDepartmentCode;
    if (specificAssignee) {
      task.assignedTo = specificAssignee;
      task.assignedMemberName = specificAssigneeName || '';
    }

    if (!task.history) task.history = [];
    task.history.push({
      status: task.status,
      updatedBy: req.user.name,
      role: req.user.role,
      notes: `Task referred from ${referralEntry.sendingDepartment} to ${targetDepartment}. Reason: ${reason || 'Inter-department collaboration.'}`,
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'TASK_REFERRED_CROSS_DEPARTMENT',
      module: 'TASK_MANAGEMENT',
      targetId: id,
      targetModel: 'Task',
      description: `${req.user.name} referred task '${task.title}' to ${targetDepartment}. Original department: ${task.originalDepartment}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Task referred successfully to ${targetDepartment}. Original department preserved as ${task.originalDepartment}.`,
      task,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to refer task.' });
  }
});

/**
 * @route   POST /api/tasks/:id/referral-respond
 * @desc    Receiving department responds to referral (Stage 5 response: accept / reject / return)
 * @access  Protected (Receiving Department Head/Director or Super Admin)
 */
router.post('/tasks/:id/referral-respond', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, notes, assignedTo, assignedMemberName } = req.body;

    if (!action || !['accept', 'reject', 'return'].includes(action)) {
      return res.status(400).json({ success: false, error: "Action must be 'accept', 'reject', or 'return'." });
    }

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    if (!task.activeReferral) {
      return res.status(400).json({ success: false, error: 'No active referral found on this task.' });
    }

    const isSuperAdmin = req.user.role === 'super_admin';
    const callerDept = req.user.department || (req.user.role.startsWith('dept_') ? DEPT_ROLE_MAP[req.user.role]?.name : null);
    const callerDesig = normalizeDesignation(req.user.designation);
    const isReceivingLead =
      (callerDept?.toLowerCase() === task.activeReferral.receivingDepartment?.toLowerCase() ||
        (req.user.role.startsWith('dept_') &&
          DEPT_ROLE_MAP[req.user.role]?.name?.toLowerCase() === task.activeReferral.receivingDepartment?.toLowerCase())) &&
      ['head', 'director'].includes(callerDesig || '');

    if (!isSuperAdmin && !isReceivingLead) {
      return res.status(403).json({
        success: false,
        error: `Access Denied: Only the Head or Director of the receiving department (${task.activeReferral.receivingDepartment}) can respond to this referral.`,
      });
    }

    task.activeReferral.status = action === 'accept' ? 'accepted' : action === 'reject' ? 'rejected' : 'returned';
    task.activeReferral.respondedAt = new Date();

    if (task.referrals && task.referrals.length > 0) {
      const lastRef = task.referrals[task.referrals.length - 1];
      lastRef.status = task.activeReferral.status;
      lastRef.respondedAt = new Date();
      lastRef.responseNotes = notes || '';
    }

    if (action === 'accept') {
      if (assignedTo) {
        task.assignedTo = assignedTo;
        if (assignedMemberName) task.assignedMemberName = assignedMemberName;
      }
    } else if (action === 'reject') {
      // Revert to original department
      task.department = task.originalDepartment;
      task.departmentCode = task.originalDepartmentCode;
      task.status = 'rechecking_pending';
    } else if (action === 'return') {
      // Return completed work back to original department for final approval
      task.department = task.originalDepartment;
      task.departmentCode = task.originalDepartmentCode;
      task.status = 'awaiting_final_approval';
    }

    if (!task.history) task.history = [];
    task.history.push({
      status: task.status,
      updatedBy: req.user.name,
      role: req.user.role,
      notes: `Referral response '${action}' by ${req.user.name}. ${notes || ''}`.trim(),
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: `TASK_REFERRAL_${action.toUpperCase()}`,
      module: 'TASK_MANAGEMENT',
      targetId: id,
      targetModel: 'Task',
      description: `${req.user.name} responded '${action}' to referral on task '${task.title}'.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Referral response '${action}' processed successfully.`,
      task,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to process referral response.' });
  }
});

/**
 * @route   POST /api/tasks/:id/final-approval
 * @desc    Final Departmental Task Approval (Stage 6)
 * @access  Protected (ONLY Original Owning Department Head or Director, or Super Admin)
 */
router.post('/tasks/:id/final-approval', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, notes, feedback, rating } = req.body;

    if (!action || !['approve', 'request_revision', 'reject'].includes(action)) {
      return res.status(400).json({ success: false, error: "Action must be 'approve', 'request_revision', or 'reject'." });
    }

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    // MANDATORY CRITICAL RESTRICTION:
    // ONLY the original owning department Head or Director (or Super Admin) can grant final approval!
    const isSuperAdmin = req.user.role === 'super_admin';
    const callerDept = req.user.department || (req.user.role.startsWith('dept_') ? DEPT_ROLE_MAP[req.user.role]?.name : null);
    const callerDesig = normalizeDesignation(req.user.designation);
    const isOriginalDeptLead =
      (callerDept?.toLowerCase() === task.originalDepartment?.toLowerCase() ||
        (req.user.role.startsWith('dept_') &&
          DEPT_ROLE_MAP[req.user.role]?.name?.toLowerCase() === task.originalDepartment?.toLowerCase())) &&
      ['head', 'director'].includes(callerDesig || '');

    if (!isSuperAdmin && !isOriginalDeptLead) {
      return res.status(403).json({
        success: false,
        error: `Final Approval Forbidden: Only the Head or Director of the original owning department (${task.originalDepartment}) is authorized to give final approval. Testers, moderators, assistant directors, members, HR, Finance, and other department leadership are strictly prohibited.`,
      });
    }

    const isApprove = action === 'approve';
    const newStatus = isApprove ? 'completed' : 'rechecking_pending';

    task.status = newStatus;
    if (isApprove) {
      task.completedAt = new Date();
      task.finalApprovalDetails = {
        approvedBy: {
          id: req.user.id || req.user._id,
          name: req.user.name,
          role: req.user.role,
          designation: req.user.designation,
        },
        approvedAt: new Date(),
        approvalNotes: notes || feedback || 'Final departmental approval granted.',
        originalDepartment: task.originalDepartment,
      };
    }

    if (!task.history) task.history = [];
    task.history.push({
      status: newStatus,
      updatedBy: req.user.name,
      role: req.user.role,
      notes: isApprove
        ? `Final approval granted by ${req.user.name} (${callerDesig || req.user.role}). ${notes || ''}`.trim()
        : `Final approval rejected / returned for recheck by ${req.user.name}: ${notes || feedback || ''}`.trim(),
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: isApprove ? 'TASK_FINAL_APPROVED' : 'TASK_FINAL_APPROVAL_REJECTED',
      module: 'TASK_MANAGEMENT',
      targetId: id,
      targetModel: 'Task',
      description: `${req.user.name} (${callerDesig || req.user.role}) processed final approval for task '${task.title}': ${action.toUpperCase()}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: isApprove ? 'Task approved and marked completed.' : 'Task returned to original department for rechecking.',
      task,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to process final approval.' });
  }
});

/**
 * @route   PATCH /api/tasks/:id/review
 * @desc    Backward-compatible review route with original department leadership restriction
 * @access  Protected (Original Department Head/Director or Super Admin ONLY)
 */
router.patch('/tasks/:id/review', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, feedback, revisionNotes } = req.body;

    if (!action || !['approve', 'request_revision', 'under_review', 'complete'].includes(action)) {
      return res.status(400).json({
        success: false,
        error: "Action must be 'approve', 'request_revision', 'under_review', or 'complete'.",
      });
    }

    let task = null;
    try {
      task = await Task.findById(id);
    } catch {}
    if (!task) task = memoryTasks.get(id);

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found.' });
    }

    // Verify reviewer authority: ONLY original department Head/Director or Super Admin can approve/complete
    const isSuperAdmin = req.user.role === 'super_admin';
    const callerDept = req.user.department || (req.user.role.startsWith('dept_') ? DEPT_ROLE_MAP[req.user.role]?.name : null);
    const callerDesig = normalizeDesignation(req.user.designation);
    const isOriginalDeptLead =
      (callerDept?.toLowerCase() === task.originalDepartment?.toLowerCase() ||
        (req.user.role.startsWith('dept_') &&
          DEPT_ROLE_MAP[req.user.role]?.name?.toLowerCase() === task.originalDepartment?.toLowerCase())) &&
      ['head', 'director'].includes(callerDesig || '');

    if (!isSuperAdmin && !isOriginalDeptLead) {
      return res.status(403).json({
        success: false,
        error: `Only the original department Head or Director (${task.originalDepartment}) or Super Admin is authorized to review or approve this submission.`,
      });
    }

    let newStatus = 'under_review';
    if (action === 'approve') {
      newStatus = 'approved';
      task.completedAt = new Date();
    } else if (action === 'complete') {
      newStatus = 'completed';
      task.completedAt = new Date();
    } else if (action === 'request_revision') {
      newStatus = 'revision_requested';
    } else if (action === 'under_review') {
      newStatus = 'under_review';
    }

    task.status = newStatus;
    task.reviewDetails = {
      reviewerId: req.user.id || req.user._id,
      reviewerName: req.user.name,
      feedback: feedback || '',
      revisionNotes: revisionNotes || '',
      reviewedAt: new Date(),
    };

    if (!task.history) task.history = [];
    task.history.push({
      status: newStatus,
      updatedBy: req.user.name,
      role: req.user.role,
      notes:
        action === 'approve'
          ? feedback || 'Work approved.'
          : action === 'complete'
          ? feedback || 'Task completed and archived.'
          : revisionNotes || 'Revision requested.',
      timestamp: new Date(),
    });

    try {
      await task.save();
    } catch {
      setMemoryTask(task);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: action === 'approve' ? 'TASK_APPROVED' : action === 'complete' ? 'TASK_COMPLETED' : 'TASK_REVISION_REQUESTED',
      module: 'TASK_MANAGEMENT',
      targetId: id,
      targetModel: 'Task',
      description: `${req.user.name} reviewed task '${task.title}': ${action.toUpperCase()}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Task submission review completed: ${newStatus.replace('_', ' ')}.`,
      task,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to process task review.' });
  }
});

// Member Personal Tasks
router.get('/members/:userId/tasks', protect, requireOwnershipOrPrivilege('userId'), async (req, res) => {
  try {
    const { userId } = req.params;
    let tasks = [];
    try {
      tasks = await Task.find({ assignedTo: userId }).sort({ createdAt: -1 });
    } catch {}

    if (!tasks || tasks.length === 0) {
      tasks = getMemoryTasksList().filter((t) => t.assignedTo?.toString() === userId.toString());
    }

    return res.json({ success: true, count: tasks.length, tasks });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch member tasks.' });
  }
});

// ---------------------------------------------------------------------------
// 5. FINANCE OPERATIONS: Delegated to routes/finance.routes.js
// ---------------------------------------------------------------------------

// HR 1: List all recruitment applications
router.get('/recruitment/applications', protect, authorize('super_admin', 'hr'), async (req, res) => {
  let applications = [];
  try {
    applications = await Application.find().sort({ createdAt: -1 });
  } catch {}
  if (!applications || applications.length === 0) {
    applications = getMemoryApplicationsList();
  }
  return res.json({ success: true, count: applications.length, applications });
});

// HR 2: Single application record lookup
router.get('/recruitment/applications/:id', protect, authorize('super_admin', 'hr'), async (req, res) => {
  let application = null;
  try {
    application = await Application.findById(req.params.id);
  } catch {}
  if (!application) {
    application = getMemoryApplicationsList().find((a) => (a._id || a.id)?.toString() === req.params.id);
  }
  if (!application) {
    return res.status(404).json({ success: false, error: 'Recruitment application not found.' });
  }
  return res.json({ success: true, application });
});

// HR 3: Update application status (reviewing, interview, accepted, rejected)
router.patch('/recruitment/applications/:id/status', protect, authorize('super_admin', 'hr'), async (req, res) => {
  const { status, notes } = req.body;
  if (!status) {
    return res.status(400).json({ success: false, error: 'Application status is required.' });
  }
  let application = null;
  try {
    application = await Application.findByIdAndUpdate(
      req.params.id,
      {
        status,
        reviewNotes: notes,
        reviewedBy: req.user.id || req.user._id,
        reviewedAt: new Date(),
      },
      { new: true }
    );
  } catch {}
  if (!application) {
    application = getMemoryApplicationsList().find((a) => (a._id || a.id)?.toString() === req.params.id);
    if (application) {
      application.status = status;
      application.reviewNotes = notes;
      application.reviewedBy = req.user.id || req.user._id;
      application.reviewedAt = new Date();
      setMemoryApplication(application);
    }
  }
  return res.json({ success: Boolean(application), application });
});

// HR 4: Recruitment summary statistics
router.get('/recruitment/stats', protect, authorize('super_admin', 'hr'), async (req, res) => {
  let applications = [];
  try {
    applications = await Application.find();
  } catch {}
  if (!applications || applications.length === 0) {
    applications = getMemoryApplicationsList();
  }
  return res.json({
    success: true,
    stats: {
      totalApplications: applications.length,
      pendingCount: applications.filter((a) => a.status === 'pending' || a.status === 'submitted').length,
      reviewingCount: applications.filter((a) => a.status === 'reviewing' || a.status === 'under_review').length,
      acceptedCount: applications.filter((a) => a.status === 'accepted' || a.status === 'selected').length,
      rejectedCount: applications.filter((a) => a.status === 'rejected').length,
    },
  });
});

// ---------------------------------------------------------------------------
// Department Announcements Access for All Members
// ---------------------------------------------------------------------------
/**
 * @route   GET /api/announcements/my
 * @desc    Get announcements targeting the authenticated user's department or 'All'
 * @access  Protected (All authenticated staff & members)
 */
router.get('/announcements/my', protect, async (req, res) => {
  try {
    const isSuperAdmin = req.user.role === 'super_admin';
    const isHR = req.user.role === 'hr';
    const userDept = req.user.department || (req.user.role.startsWith('dept_') ? DEPT_ROLE_MAP[req.user.role]?.name : null) || 'General';

    let announcements = [];
    try {
      const filter = isSuperAdmin || isHR
        ? {}
        : { $or: [{ targetDepartment: userDept }, { targetDepartment: 'All' }] };
      announcements = await Announcement.find(filter).sort({ createdAt: -1 });
    } catch {}

    if (!announcements || announcements.length === 0) {
      const memList = getMemoryAnnouncementsList();
      announcements = isSuperAdmin || isHR
        ? memList
        : memList.filter(
            (a) => a.targetDepartment === 'All' || a.targetDepartment?.toLowerCase() === userDept.toLowerCase()
          );
    }

    return res.json({ success: true, count: announcements.length, department: userDept, announcements });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to retrieve announcements.' });
  }
});

module.exports = router;
