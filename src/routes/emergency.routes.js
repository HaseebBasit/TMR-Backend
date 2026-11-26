const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { User, AuditLog, EmergencyCredential } = require('../models');
const { emergencyAccessRateLimiter } = require('../middleware/rateLimiter');
const { verifyTotp, findMatchingRecoveryCode } = require('../services/mfa.service');
const { normalizeDesignation } = require('../constants/roles');
const { validateProductionSecrets } = require('../config/secrets');

const validatedSecrets = validateProductionSecrets();
const JWT_SECRET = validatedSecrets.accessSecret;

/**
 * Helper to retrieve active emergency credential from DB or memory fallback
 */
async function getActiveEmergencyCredential() {
  let cred = null;
  try {
    cred = await EmergencyCredential.findOne({ status: 'active' });
  } catch {}
  if (!cred) {
    cred = EmergencyCredential.getMemoryEmergencyCredential?.();
  }
  return cred;
}

/**
 * Helper to retrieve emergency credential by keyId or any status
 */
async function getAnyEmergencyCredential() {
  let cred = null;
  try {
    cred = await EmergencyCredential.findOne().sort({ createdAt: -1 });
  } catch {}
  if (!cred) {
    cred = EmergencyCredential.getMemoryEmergencyCredential?.();
  }
  return cred;
}

/**
 * @route   GET /api/emergency/status
 * @desc    Check whether Emergency Access System is configured and active
 * @access  Public (No secrets disclosed)
 */
router.get('/status', async (req, res) => {
  try {
    const cred = await getActiveEmergencyCredential();
    return res.json({
      success: true,
      configured: Boolean(cred),
      active: Boolean(cred && cred.status === 'active'),
      keyId: cred ? cred.keyId : null,
      operatorEmail: cred ? cred.operatorEmail : null,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to retrieve emergency status.' });
  }
});

/**
 * @route   POST /api/emergency/verify-key
 * @desc    Step 1: Authenticate Emergency Operator Key and validate target organizational user
 * @access  Public (Rate-limited, audited)
 */
router.post('/verify-key', emergencyAccessRateLimiter, async (req, res) => {
  try {
    const { targetEmail, accessKey, reason } = req.body || {};

    // 1. Mandatory Input Validation
    if (!targetEmail || typeof targetEmail !== 'string') {
      return res.status(400).json({ success: false, error: 'Target organizational email is required.' });
    }
    if (!accessKey || typeof accessKey !== 'string' || accessKey.length < 12) {
      return res.status(400).json({ success: false, error: 'Emergency Access Key is required and must meet complexity requirements.' });
    }
    if (!reason || typeof reason !== 'string' || reason.trim().length < 10) {
      return res.status(400).json({
        success: false,
        error: 'Mandatory technical reason of at least 10 characters is required for emergency access.',
        code: 'EMERGENCY_REASON_REQUIRED',
      });
    }

    // 2. Resolve Active Emergency Credential
    const cred = await getActiveEmergencyCredential();
    if (!cred || cred.status !== 'active') {
      return res.status(403).json({
        success: false,
        error: 'Emergency Access System is inactive or the emergency key has been revoked.',
        code: 'EMERGENCY_SYSTEM_INACTIVE',
      });
    }

    // Check account lockout
    if (cred.lockUntil && cred.lockUntil > new Date()) {
      return res.status(429).json({
        success: false,
        error: 'Emergency access is temporarily locked due to excessive failed attempts. Please retry later.',
      });
    }

    // 3. Cryptographic Verification of Emergency Access Key
    const keyMatch = await bcrypt.compare(accessKey, cred.keyHash);
    if (!keyMatch) {
      cred.failedAttempts = (cred.failedAttempts || 0) + 1;
      if (cred.failedAttempts >= 5) {
        cred.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
      }
      try {
        await cred.save?.();
      } catch {}

      await AuditLog.create({
        actorId: 'emergency_operator',
        actorName: 'Emergency Access System',
        actorRole: 'emergency_operator',
        action: 'SECURITY_ALERT_EMERGENCY_KEY_REJECTED',
        module: 'EMERGENCY_ACCESS',
        description: `Failed emergency access key attempt for target ${targetEmail}. IP: ${req.ip}`,
        ipAddress: req.ip,
      }).catch(() => null);

      return res.status(401).json({
        success: false,
        error: 'Invalid Emergency Access Key. Please check the credential and retry.',
      });
    }

    // Reset failed attempts on success
    cred.failedAttempts = 0;
    try {
      await cred.save?.();
    } catch {}

    // 4. Resolve Target Organizational User
    const normalizedTarget = targetEmail.trim().toLowerCase();
    let targetUser = null;
    try {
      targetUser = await User.findOne({ email: normalizedTarget });
    } catch {}
    if (!targetUser && typeof User.getMemoryUser === 'function') {
      targetUser = User.getMemoryUser(normalizedTarget);
    }
    // Also check memory users list if present
    if (!targetUser) {
      const { getMemoryUsersList } = require('../middleware/auth');
      targetUser = getMemoryUsersList?.().find((u) => u.email?.toLowerCase() === normalizedTarget);
    }

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        error: `Target account '${targetEmail}' does not exist in the organizational roster.`,
      });
    }

    // 5. Account Eligibility Gates
    if (targetUser.status !== 'active') {
      return res.status(400).json({
        success: false,
        error: `Cannot establish emergency access for account with status '${targetUser.status}'. Target must be active.`,
      });
    }

    // 6. HARD BARRIER: Super Admin & System Developer Lockout
    if (targetUser.role === 'super_admin' || targetUser.activeRole === 'super_admin') {
      await AuditLog.create({
        actorId: 'emergency_operator',
        actorName: cred.operatorName,
        actorRole: 'emergency_operator',
        action: 'SECURITY_ALERT_EMERGENCY_SUPER_ADMIN_BLOCKED',
        module: 'EMERGENCY_ACCESS',
        targetId: (targetUser._id || targetUser.id)?.toString(),
        targetModel: 'User',
        description: `CRITICAL: Attempted emergency access to protected Super Admin (${targetUser.email}). Hard barrier triggered.`,
        ipAddress: req.ip,
      }).catch(() => null);

      return res.status(403).json({
        success: false,
        error: 'Security Barrier: Emergency access to Super Administrator accounts is strictly prohibited.',
        code: 'SUPER_ADMIN_EMERGENCY_PROHIBITED',
      });
    }

    if (targetUser.role === 'developer' || targetUser.activeRole === 'developer') {
      await AuditLog.create({
        actorId: 'emergency_operator',
        actorName: cred.operatorName,
        actorRole: 'emergency_operator',
        action: 'SECURITY_ALERT_EMERGENCY_DEVELOPER_BLOCKED',
        module: 'EMERGENCY_ACCESS',
        targetId: (targetUser._id || targetUser.id)?.toString(),
        targetModel: 'User',
        description: `CRITICAL: Attempted emergency access to System Developer (${targetUser.email}). Hard barrier triggered.`,
        ipAddress: req.ip,
      }).catch(() => null);

      return res.status(403).json({
        success: false,
        error: 'Security Barrier: Emergency access to System Developer accounts is strictly prohibited.',
        code: 'DEVELOPER_EMERGENCY_PROHIBITED',
      });
    }

    // 7. Issue Short-Lived MFA Verification Token (5 Minutes)
    const targetIdStr = (targetUser._id || targetUser.id)?.toString();
    const emergencyToken = jwt.sign(
      {
        type: 'emergency_mfa_pending',
        keyId: cred.keyId,
        operatorEmail: cred.operatorEmail,
        operatorName: cred.operatorName,
        targetUserId: targetIdStr,
        targetEmail: targetUser.email,
        reason: reason.trim(),
        jti: crypto.randomBytes(16).toString('hex'),
      },
      JWT_SECRET,
      { expiresIn: '5m' }
    );

    return res.json({
      success: true,
      requireMfa: true,
      emergencyToken,
      targetUser: {
        id: targetIdStr,
        name: targetUser.name,
        email: targetUser.email,
        role: targetUser.role,
        department: targetUser.department,
        departmentCode: targetUser.departmentCode,
        designation: targetUser.designation,
        memberships: targetUser.memberships || [],
      },
      message: 'Emergency Access Key accepted. Please supply the operator MFA verification code.',
    });
  } catch (err) {
    console.error('[Emergency Verify-Key Error]:', err);
    return res.status(500).json({ success: false, error: 'Internal error processing emergency access request.' });
  }
});

/**
 * @route   POST /api/emergency/verify-mfa
 * @desc    Step 2: Verify Emergency Operator MFA TOTP and issue 15-minute emergency session token
 * @access  Public (Token-governed, audited)
 */
router.post('/verify-mfa', emergencyAccessRateLimiter, async (req, res) => {
  try {
    const { emergencyToken, code, recoveryCode } = req.body || {};

    if (!emergencyToken) {
      return res.status(400).json({ success: false, error: 'Emergency session token is required.' });
    }
    if (!code && !recoveryCode) {
      return res.status(400).json({ success: false, error: 'MFA TOTP code or recovery code is required.' });
    }

    // 1. Verify Emergency Session Token
    let decoded;
    try {
      decoded = jwt.verify(emergencyToken, JWT_SECRET);
    } catch {
      return res.status(401).json({
        success: false,
        error: 'Emergency session has expired or is invalid. Please restart emergency authentication.',
      });
    }

    if (decoded.type !== 'emergency_mfa_pending' || !decoded.targetUserId) {
      return res.status(401).json({ success: false, error: 'Invalid emergency session token structure.' });
    }

    // 2. Resolve Emergency Credential for MFA
    const cred = await getActiveEmergencyCredential();
    if (!cred || cred.status !== 'active') {
      return res.status(403).json({ success: false, error: 'Emergency credential is no longer active.' });
    }

    // 3. Verify MFA TOTP or Backup Recovery Code
    let mfaValid = false;
    const plainMfaSecret = typeof cred.getDecryptedMfaSecret === 'function'
      ? cred.getDecryptedMfaSecret()
      : (EmergencyCredential.decryptSecret ? EmergencyCredential.decryptSecret(cred.mfaSecret) : cred.mfaSecret);

    if (code) {
      mfaValid = verifyTotp(code.toString().trim(), plainMfaSecret);
    } else if (recoveryCode) {
      const matchIndex = findMatchingRecoveryCode(recoveryCode.trim(), cred.mfaRecoveryCodes || []);
      if (matchIndex !== -1) {
        mfaValid = true;
        // Single-use: consume recovery code
        cred.mfaRecoveryCodes.splice(matchIndex, 1);
        try {
          await cred.save?.();
        } catch {}
      }
    }

    if (!mfaValid) {
      await AuditLog.create({
        actorId: 'emergency_operator',
        actorName: cred.operatorName,
        actorRole: 'emergency_operator',
        action: 'SECURITY_ALERT_EMERGENCY_MFA_FAILED',
        module: 'EMERGENCY_ACCESS',
        targetId: decoded.targetUserId,
        targetModel: 'User',
        description: `Failed emergency MFA code attempt for target ${decoded.targetEmail}. IP: ${req.ip}`,
        ipAddress: req.ip,
      }).catch(() => null);

      return res.status(401).json({
        success: false,
        error: 'Invalid MFA verification code. Please check your authenticator app or backup code.',
      });
    }

    // 4. Resolve Target User
    let targetUser = null;
    try {
      targetUser = await User.findById(decoded.targetUserId);
    } catch {}
    if (!targetUser && typeof User.getMemoryUser === 'function') {
      targetUser = User.getMemoryUser(decoded.targetUserId) || User.getMemoryUser(decoded.targetEmail);
    }
    if (!targetUser) {
      const { getMemoryUsersList } = require('../middleware/auth');
      targetUser = getMemoryUsersList?.().find(
        (u) => (u._id || u.id)?.toString() === decoded.targetUserId
      );
    }

    if (!targetUser || targetUser.status !== 'active') {
      return res.status(400).json({ success: false, error: 'Target user is no longer available or active.' });
    }

    // Double-check Super Admin & Developer Hard Barrier
    if (targetUser.role === 'super_admin' || targetUser.role === 'developer') {
      return res.status(403).json({ success: false, error: 'Emergency access to privileged core accounts is prohibited.' });
    }

    // 5. Generate Target-Scoped RFC 8693 Emergency Access Token (Strict 15 Minutes)
    const primaryMembership = Array.isArray(targetUser.memberships) && targetUser.memberships.find((m) => m.isPrimary);
    const activeDept = targetUser.activeDepartment || targetUser.department || primaryMembership?.department || null;
    const activeCode = targetUser.activeDepartmentCode || targetUser.departmentCode || primaryMembership?.departmentCode || null;
    const activeRole = targetUser.activeRole || targetUser.role;
    const activeDesig = normalizeDesignation(targetUser.activeDesignation || targetUser.designation || primaryMembership?.designation) || null;

    const payload = {
      id: (targetUser._id || targetUser.id)?.toString(),
      email: targetUser.email,
      name: targetUser.name,
      role: activeRole,
      department: activeDept,
      departmentCode: activeCode,
      designation: activeDesig,
      status: targetUser.status,
      memberships: targetUser.memberships || [],
      emailAliases: targetUser.emailAliases || [],
      city: targetUser.city || null,
      region: targetUser.region || null,
      activeDepartment: activeDept,
      activeDepartmentCode: activeCode,
      activeRole: activeRole,
      activeDesignation: activeDesig,
      tokenVersion: targetUser.tokenVersion || 0,
      isEmergencyAccess: true,
      act: {
        sub: 'emergency_operator',
        keyId: decoded.keyId,
        name: decoded.operatorName || 'Authorized Emergency Operator',
        email: decoded.operatorEmail || 'emergency-operator@system.rekhta.org',
        reason: decoded.reason,
        initiatedAt: new Date().toISOString(),
      },
    };

    // Strict 15-minute token (900 seconds)
    const emergencyAccessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });

    // 6. Set HTTP-Only Cookie (15 Minutes) and OMIT Refresh Token
    const isProd = process.env.NODE_ENV === 'production' || Boolean(process.env.RENDER);
    res.cookie('rekhta_access_token', emergencyAccessToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      path: '/',
      maxAge: 15 * 60 * 1000,
    });
    // Set explicit emergency flag cookie for UI hydration
    res.cookie('rekhta_emergency_mode', 'true', {
      httpOnly: false,
      secure: isProd,
      sameSite: 'lax',
      path: '/',
      maxAge: 15 * 60 * 1000,
    });
    // Clear any existing refresh token so this session CANNOT be rotated or refreshed
    res.clearCookie('rekhta_refresh_token', { path: '/' });

    // 7. Comprehensive Audit Logging
    await AuditLog.create({
      actorId: 'emergency_operator',
      actorName: decoded.operatorName || 'Authorized Emergency Operator',
      actorRole: 'emergency_operator',
      action: 'EMERGENCY_ACCESS_SESSION_CREATED',
      module: 'EMERGENCY_ACCESS',
      targetId: (targetUser._id || targetUser.id)?.toString(),
      targetModel: 'User',
      description: `EMERGENCY ACCESS ESTABLISHED: Operator initiated 15-minute temporary session for target ${targetUser.email} (${targetUser.name}). Reason: "${decoded.reason}". Key: ${decoded.keyId}.`,
      ipAddress: req.ip,
    }).catch(() => null);

    // Update credential usage statistics
    cred.lastUsedAt = new Date();
    cred.usageCount = (cred.usageCount || 0) + 1;
    try {
      await cred.save?.();
    } catch {}

    // NOTICE: Target user's password, mfaSecret, tokenVersion, and status are 100% UNTOUCHED!
    return res.json({
      success: true,
      token: emergencyAccessToken,
      user: payload,
      sessionExpiresIn: 900, // 15 minutes in seconds
      message: 'Emergency access session established successfully for 15 minutes.',
    });
  } catch (err) {
    console.error('[Emergency Verify-MFA Error]:', err);
    return res.status(500).json({ success: false, error: 'Internal error finalizing emergency session.' });
  }
});

/**
 * @route   POST /api/emergency/end-session
 * @desc    Terminate active emergency access session immediately
 * @access  Public (Revokes session cookies)
 */
router.post('/end-session', async (req, res) => {
  try {
    const token = req.cookies?.rekhta_access_token || req.headers?.authorization?.replace('Bearer ', '');
    let targetEmail = 'unknown';

    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        targetEmail = decoded.email || 'unknown';
        if (decoded.isEmergencyAccess) {
          await AuditLog.create({
            actorId: 'emergency_operator',
            actorName: decoded.act?.name || 'Authorized Emergency Operator',
            actorRole: 'emergency_operator',
            action: 'EMERGENCY_ACCESS_SESSION_TERMINATED',
            module: 'EMERGENCY_ACCESS',
            targetId: decoded.id,
            targetModel: 'User',
            description: `EMERGENCY ACCESS TERMINATED: Operator manually ended emergency session for ${targetEmail}.`,
            ipAddress: req.ip,
          }).catch(() => null);
        }
      } catch {}
    }

    res.clearCookie('rekhta_access_token', { path: '/' });
    res.clearCookie('rekhta_refresh_token', { path: '/' });
    res.clearCookie('rekhta_emergency_mode', { path: '/' });

    return res.json({
      success: true,
      message: 'Emergency access session terminated successfully.',
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to terminate emergency session.' });
  }
});

/**
 * @route   POST /api/emergency/revoke
 * @desc    Immediately revoke active Emergency Credential
 * @access  Protected (Requires Emergency Access Key or Super Admin token)
 */
router.post('/revoke', async (req, res) => {
  try {
    const { accessKey, reason } = req.body || {};
    const cred = await getAnyEmergencyCredential();

    if (!cred) {
      return res.status(404).json({ success: false, error: 'No emergency credential found to revoke.' });
    }

    if (cred.status === 'revoked') {
      return res.status(400).json({ success: false, error: 'Emergency credential is already revoked.' });
    }

    // Require either matching access key or valid Super Admin session
    let authorized = false;
    if (accessKey) {
      authorized = await bcrypt.compare(accessKey, cred.keyHash);
    } else if (req.headers.authorization) {
      try {
        const decoded = jwt.verify(req.headers.authorization.replace('Bearer ', ''), JWT_SECRET);
        if (decoded.role === 'super_admin') {
          authorized = true;
        }
      } catch {}
    }

    if (!authorized) {
      return res.status(401).json({ success: false, error: 'Authorization required to revoke emergency credential.' });
    }

    cred.status = 'revoked';
    cred.revokedAt = new Date();
    cred.revokedReason = reason || 'Emergency credential revoked by authorized operator.';
    cred.revokedBy = 'Emergency Operator / Super Admin';

    try {
      await cred.save?.();
    } catch {
      EmergencyCredential.setMemoryEmergencyCredential?.(cred);
    }

    await AuditLog.create({
      actorId: 'emergency_operator',
      actorName: 'Security Administration',
      actorRole: 'emergency_operator',
      action: 'EMERGENCY_CREDENTIAL_REVOKED',
      module: 'EMERGENCY_ACCESS',
      description: `CRITICAL: Emergency Access Key (${cred.keyId}) was permanently revoked. Reason: "${cred.revokedReason}".`,
      ipAddress: req.ip,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Emergency Access Key (${cred.keyId}) successfully revoked.`,
    });
  } catch (err) {
    console.error('[Emergency Revoke Error]:', err);
    return res.status(500).json({ success: false, error: 'Failed to revoke emergency credential.' });
  }
});

module.exports = router;
