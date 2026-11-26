const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { User, AuditLog, Department, Task } = require('../models');
const { protect, authorize, getMemoryUsersList, getMemoryUser } = require('../middleware/auth');
const { getConnectionStatus } = require('../config/db');

const JWT_SECRET = process.env.JWT_SECRET || 'rekhta_jwt_secret_2026';

/**
 * @route   POST /api/developer/impersonate
 * @desc    Time-limited (15-min), reason-required, audited user impersonation (RFC 8693)
 * @access  Protected (Developer Only)
 */
router.post('/impersonate', protect, authorize('developer'), async (req, res) => {
  try {
    const { targetUserId, targetEmail, reason } = req.body || {};

    // 1. Mandatory Reason Requirement (Must be meaningful, min 10 chars)
    if (!reason || typeof reason !== 'string' || reason.trim().length < 10) {
      return res.status(400).json({
        success: false,
        error: 'Reason requirement: Impersonation requires an explicit, audited reason of at least 10 characters.',
        code: 'IMPERSONATION_REASON_REQUIRED',
      });
    }

    // 2. Resolve Target User
    let targetUser = null;
    if (targetUserId) {
      try {
        targetUser = await User.findById(targetUserId);
      } catch {}
      if (!targetUser) {
        targetUser = getMemoryUsersList().find(
          (u) => (u._id || u.id)?.toString() === targetUserId.toString()
        );
      }
    } else if (targetEmail) {
      const normalizedEmail = targetEmail.trim().toLowerCase();
      try {
        targetUser = await User.findOne({ email: normalizedEmail });
      } catch {}
      if (!targetUser) {
        targetUser = getMemoryUser(normalizedEmail);
      }
    }

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        error: 'Target user not found for impersonation.',
      });
    }

    // 3. HARD BARRIER: Super Admin Impersonation Lockout
    if (targetUser.role === 'super_admin' || targetUser.activeRole === 'super_admin') {
      await AuditLog.create({
        actorId: req.user._id || req.user.id,
        actorName: req.user.name,
        actorRole: req.user.role,
        action: 'SECURITY_ALERT_SUPER_ADMIN_IMPERSONATION_ATTEMPT',
        module: 'DEVELOPER',
        targetId: (targetUser._id || targetUser.id)?.toString(),
        targetModel: 'User',
        description: `CRITICAL: Developer ${req.user.name} (${req.user.email}) attempted to impersonate protected Super Admin (${targetUser.email}). Hard block triggered.`,
        ipAddress: req.ip,
      }).catch(() => null);

      return res.status(403).json({
        success: false,
        error: 'Security Violation: Impersonation of Super Administrator accounts is strictly prohibited.',
        code: 'SUPER_ADMIN_IMPERSONATION_PROHIBITED',
      });
    }

    // 4. Hard Barrier: Cannot impersonate other Developers or Self
    if (targetUser.role === 'developer' || (targetUser._id || targetUser.id)?.toString() === (req.user._id || req.user.id)?.toString()) {
      return res.status(400).json({
        success: false,
        error: 'Developer cannot impersonate another developer or self.',
      });
    }

    // 5. Account Status Gate: Cannot impersonate inactive or suspended users
    if (targetUser.status !== 'active') {
      return res.status(400).json({
        success: false,
        error: `Cannot impersonate user with status '${targetUser.status}'. Target must be active.`,
      });
    }

    // 6. Token Exchange Structure (RFC 8693) with 15-Minute Expiration
    const targetIdStr = (targetUser._id || targetUser.id)?.toString();
    const developerIdStr = (req.user._id || req.user.id)?.toString();

    const impersonationPayload = {
      id: targetIdStr,
      sub: targetIdStr,
      name: targetUser.name,
      email: targetUser.email,
      role: targetUser.role,
      department: targetUser.department,
      departmentCode: targetUser.departmentCode,
      designation: targetUser.designation,
      isImpersonated: true,
      actor: {
        id: developerIdStr,
        name: req.user.name,
        email: req.user.email,
        role: 'developer',
      },
      impersonationReason: reason.trim(),
      tokenVersion: targetUser.tokenVersion || 0,
    };

    const impersonationToken = jwt.sign(impersonationPayload, JWT_SECRET, {
      expiresIn: '15m',
    });

    // 7. Audit Log Recording (Dual-Identity Auditing)
    await AuditLog.create({
      actorId: developerIdStr,
      actorName: req.user.name,
      actorRole: 'developer',
      action: 'DEVELOPER_IMPERSONATION_STARTED',
      module: 'DEVELOPER',
      targetId: targetIdStr,
      targetModel: 'User',
      description: `Developer ${req.user.name} (${req.user.email}) initiated audited impersonation of ${targetUser.name} (${targetUser.email}). Reason: "${reason.trim()}". Max duration: 15 minutes.`,
      ipAddress: req.ip,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Impersonation session established for ${targetUser.name}. Valid for 15 minutes.`,
      impersonationToken,
      expiresIn: '15m',
      targetUser: {
        id: targetIdStr,
        name: targetUser.name,
        email: targetUser.email,
        role: targetUser.role,
        department: targetUser.department,
        designation: targetUser.designation,
      },
      actor: {
        id: developerIdStr,
        email: req.user.email,
        role: 'developer',
      },
    });
  } catch (err) {
    console.error('[Developer Impersonation Error]:', err);
    return res.status(500).json({ success: false, error: 'Failed to process impersonation request.' });
  }
});

/**
 * @route   GET /api/developer/diagnostics
 * @desc    System technical observability, health metrics, and database stats
 * @access  Protected (Developer Only)
 */
router.get('/diagnostics', protect, authorize('developer'), async (req, res) => {
  try {
    const dbStatus = getConnectionStatus();
    let totalUsers = 0;
    let totalDepts = 0;
    let totalTasks = 0;

    try {
      totalUsers = await User.countDocuments();
      totalDepts = await Department.countDocuments();
      totalTasks = await Task.countDocuments();
    } catch {}

    const memoryUsage = process.memoryUsage();

    await AuditLog.create({
      actorId: req.user._id || req.user.id,
      actorName: req.user.name,
      actorRole: 'developer',
      action: 'DEVELOPER_DIAGNOSTICS_VIEW',
      module: 'DEVELOPER',
      description: `Developer ${req.user.name} viewed system diagnostics telemetry.`,
      ipAddress: req.ip,
    }).catch(() => null);

    return res.json({
      success: true,
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        uptimeSeconds: Math.floor(process.uptime()),
        memory: {
          rssMb: Math.round(memoryUsage.rss / 1024 / 1024),
          heapTotalMb: Math.round(memoryUsage.heapTotal / 1024 / 1024),
          heapUsedMb: Math.round(memoryUsage.heapUsed / 1024 / 1024),
        },
      },
      database: {
        status: dbStatus.isConnected ? 'connected' : 'offline',
        host: dbStatus.host,
        name: dbStatus.dbName,
        metrics: {
          users: totalUsers,
          departments: totalDepts,
          tasks: totalTasks,
        },
      },
      environment: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to retrieve diagnostics.' });
  }
});

module.exports = router;
