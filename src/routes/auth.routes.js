const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { User, AuditLog } = require('../models');
const { normalizeDesignation } = require('../constants/roles');
const {
  protect,
  setAuthService,
  authorize,
  setMemoryUser,
  getMemoryUser,
  getMemoryUsersList,
  DEPT_ROLE_MAP,
} = require('../middleware/auth');
const { sendEmail } = require('../services/email.service');
const { verifyTotp, findMatchingRecoveryCode } = require('../services/mfa.service');
const { validateProductionSecrets } = require('../config/secrets');
const { loginRateLimiter, passwordResetRateLimiter } = require('../middleware/rateLimiter');

// Validate production secrets: never allow production to run on hardcoded, missing, weak, or identical defaults
const validatedSecrets = validateProductionSecrets();
const JWT_SECRET = validatedSecrets.accessSecret;
const REFRESH_SECRET = validatedSecrets.refreshSecret;

// Helper to generate access & refresh tokens
function generateTokens(user) {
  const primaryMembership = Array.isArray(user.memberships) && user.memberships.find((m) => m.isPrimary);
  const activeDept = user.activeDepartment || user.department || primaryMembership?.department || DEPT_ROLE_MAP[user.role]?.name || null;
  const activeCode = user.activeDepartmentCode || user.departmentCode || primaryMembership?.departmentCode || DEPT_ROLE_MAP[user.role]?.code || null;
  const activeRole = user.activeRole || user.role;
  const activeDesig = normalizeDesignation(user.activeDesignation || user.designation || primaryMembership?.designation) || null;

  const payload = {
    id: user._id?.toString() || user.id?.toString(),
    email: user.email,
    name: user.name,
    role: activeRole,
    department: activeDept,
    departmentCode: activeCode,
    status: user.status,
    isPrivilegedHR: Boolean(user.isPrivilegedHR),
    tokenVersion: user.tokenVersion || 0,
    designation: activeDesig,
    memberships: user.memberships || [],
    emailAliases: user.emailAliases || [],
    city: user.city || null,
    region: user.region || null,
    activeDepartment: activeDept,
    activeDepartmentCode: activeCode,
    activeRole: activeRole,
    activeDesignation: activeDesig,
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
  const refreshToken = jwt.sign(
    {
      id: payload.id,
      email: payload.email,
      tokenVersion: payload.tokenVersion,
      jti: crypto.randomBytes(16).toString('hex'), // Cryptographically unique ID ensuring no collision within same second
    },
    REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken, payload };
}

// In-process lock to serialize concurrent refresh requests per user and prevent race conditions
const userRefreshLocks = new Map();

async function withUserLock(userId, fn) {
  const currentPromise = userRefreshLocks.get(userId) || Promise.resolve();
  let release;
  const newPromise = new Promise((resolve) => {
    release = resolve;
  });
  userRefreshLocks.set(userId, newPromise);

  try {
    await currentPromise;
    return await fn();
  } finally {
    release();
    if (userRefreshLocks.get(userId) === newPromise) {
      userRefreshLocks.delete(userId);
    }
  }
}

// Cookie helper with first-party same-site support for Vercel <-> Render
function getCookieOptions(maxAge) {
  const isProd = process.env.NODE_ENV === 'production';
  const isRender = Boolean(process.env.RENDER || process.env.RENDER_SERVICE_ID);
  const useSecure = isProd || isRender || process.env.COOKIE_SECURE === 'true';

  return {
    httpOnly: true,
    secure: useSecure,
    sameSite: 'lax',
    path: '/',
    ...(maxAge ? { maxAge } : {}),
  };
}

function setAuthCookies(res, accessToken, refreshToken) {
  res.cookie('rekhta_access_token', accessToken, getCookieOptions(1 * 60 * 60 * 1000)); // 1 hour
  res.cookie('rekhta_refresh_token', refreshToken, getCookieOptions(7 * 24 * 60 * 60 * 1000)); // 7 days
}

// Register token & cookie service with auth middleware for seamless session recovery
if (typeof setAuthService === 'function') {
  setAuthService({ generateTokens, setAuthCookies, getCookieOptions });
}

router.generateTokens = generateTokens;
router.setAuthCookies = setAuthCookies;
router.getCookieOptions = getCookieOptions;

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user, issue JWT access & refresh tokens
 * @access  Public
 */
router.post('/login', loginRateLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required.' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // 1. Search database or in-memory store
    let user = null;
    try {
      user = await User.findOne({
        $or: [{ email: normalizedEmail }, { emailAliases: normalizedEmail }],
      });
    } catch {
      // In offline/controlled config mode
    }

    if (!user) {
      user = getMemoryUser(normalizedEmail);
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials. Please verify your email and password.',
      });
    }

    // 2. Validate password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await AuditLog.create({
        actorName: normalizedEmail,
        actorRole: 'unauthenticated',
        action: 'LOGIN_FAILED',
        module: 'AUTH',
        description: `Failed login attempt for email: ${normalizedEmail}`,
        ipAddress: req.ip,
      }).catch(() => null);

      return res.status(401).json({
        success: false,
        error: 'Invalid credentials. Please verify your email and password.',
      });
    }

    // 3. Status Check: Reject suspended or inactive accounts immediately
    if (user.status !== 'active') {
      return res.status(403).json({
        success: false,
        error: `Account ${user.status}. Access has been suspended. Please contact Super Admin.`,
        accountStatus: user.status,
      });
    }

    // 3a. MFA Gate: If user has MFA enabled, require TOTP verification before issuing session
    if (user.mfaEnabled) {
      const mfaTempToken = jwt.sign(
        { id: (user._id || user.id)?.toString(), email: user.email, mfaPending: true },
        JWT_SECRET,
        { expiresIn: '5m' }
      );
      return res.json({
        success: true,
        requireMfa: true,
        mfaToken: mfaTempToken,
        message: 'Two-factor authentication code required.',
      });
    }

    // 3b. Force Password Change Gate: If user must change password on initial login
    if (user.mustChangePassword) {
      const changePasswordTempToken = jwt.sign(
        { id: (user._id || user.id)?.toString(), email: user.email, passwordChangePending: true },
        JWT_SECRET,
        { expiresIn: '10m' }
      );
      return res.json({
        success: true,
        requirePasswordChange: true,
        tempToken: changePasswordTempToken,
        message: 'Password change is required on initial login before access is granted.',
      });
    }

    // 4. Generate Tokens
    const { accessToken, refreshToken, payload } = generateTokens(user);

    // 5. Update user state
    user.refreshToken = refreshToken;
    user.lastLogin = new Date();
    try {
      await user.save();
    } catch {
      setMemoryUser(user);
    }

    // 6. Set HTTP-only secure cookies
    setAuthCookies(res, accessToken, refreshToken);

    // 7. Audit Log
    await AuditLog.create({
      actorId: user._id || user.id,
      actorName: user.name,
      actorRole: user.role,
      action: 'USER_LOGIN',
      module: 'AUTH',
      targetId: (user._id || user.id)?.toString(),
      targetModel: 'User',
      description: `User ${user.name} (${user.email}) logged in successfully as ${user.role}.`,
      ipAddress: req.ip,
    }).catch(() => null);

    // For web portal browser requests, authenticate strictly via HTTP-only cookies
    // AND provide the JWT access token in the response body so clients can use
    // Bearer Authorization headers reliably across same-origin proxies and cross-origin environments.
    return res.json({
      success: true,
      message: 'Login successful.',
      user: {
        id: payload.id,
        name: user.name,
        email: user.email,
        role: payload.role || user.role,
        department: payload.department,
        departmentCode: payload.departmentCode,
        designation: payload.designation,
        memberships: user.memberships || [],
        emailAliases: user.emailAliases || [],
        city: user.city || null,
        region: user.region || null,
        activeDepartment: payload.activeDepartment || payload.department,
        activeDepartmentCode: payload.activeDepartmentCode || payload.departmentCode,
        activeRole: payload.activeRole || user.role,
        activeDesignation: payload.activeDesignation || payload.designation,
        isPrivilegedHR: Boolean(user.isPrivilegedHR),
        status: user.status,
      },
      token: accessToken,
    });
  } catch (err) {
    console.error('[Auth Error]:', err);
    return res.status(500).json({ success: false, error: 'Authentication service failure.' });
  }
});

/**
 * @route   POST /api/auth/refresh
 * @desc    Rotate refresh token and issue new access token (Single-use with Replay Detection)
 * @access  Public (via refresh token)
 */
router.post('/refresh', async (req, res) => {
  try {
    const token = req.cookies?.rekhta_refresh_token || req.body?.refreshToken;

    if (!token) {
      return res.status(401).json({ success: false, error: 'Refresh token required.' });
    }

    const decoded = jwt.verify(token, REFRESH_SECRET);

    return await withUserLock(decoded.id, async () => {
      let user = null;
      try {
        user = await User.findById(decoded.id);
      } catch {
        // Offline fallback
      }

      if (!user) {
        user = getMemoryUser(decoded.id) || getMemoryUser(decoded.email);
      }

      if (!user) {
        return res.status(401).json({ success: false, error: 'User session not found.' });
      }

      // 1. Account Status Gate: Suspended or deactivated accounts cannot refresh tokens
      if (user.status !== 'active') {
        return res.status(403).json({ success: false, error: `Account is ${user.status}. Access denied.` });
      }

      // 2. Token Version Gate: Invalidate tokens if sessions were revoked
      if (decoded.tokenVersion !== undefined && decoded.tokenVersion < (user.tokenVersion || 0)) {
        return res.status(401).json({ success: false, error: 'Session token invalidated.' });
      }

      // 3. Null Session Gate: If refresh token was purged server-side (e.g. after logout)
      if (!user.refreshToken) {
        return res.status(401).json({
          success: false,
          error: 'Session was logged out or revoked. Please sign in again.',
        });
      }

      // 4. CRITICAL REPLAY ATTACK DETECTION (Single-use enforcement):
      // If an incoming token does NOT match the stored active refresh token, an old/stolen token is being reused!
      if (user.refreshToken !== token) {
        // Automatic session kill-switch: Immediately revoke ALL sessions for this user
        user.tokenVersion = (user.tokenVersion || 0) + 1;
        user.refreshToken = null;
        try {
          await user.save();
        } catch {
          setMemoryUser(user);
        }

        await AuditLog.create({
          actorId: user._id || user.id,
          actorName: user.name,
          actorRole: user.role,
          action: 'SECURITY_ALERT_TOKEN_REUSE',
          module: 'AUTH',
          targetId: (user._id || user.id)?.toString(),
          targetModel: 'User',
          description: `Stolen or previously-rotated refresh token reuse detected for ${user.email}. All sessions terminated.`,
          ipAddress: req.ip,
        }).catch(() => null);

        res.clearCookie('rekhta_access_token', getCookieOptions());
        res.clearCookie('rekhta_refresh_token', getCookieOptions());

        return res.status(401).json({
          success: false,
          error: 'Security alert: Refresh token reuse detected. All active sessions have been revoked.',
          code: 'TOKEN_REUSE_DETECTED',
        });
      }

      // 5. Single-Use Rotation: Issue new tokens and invalidate the previous refresh token
      const { accessToken: newAccessToken, refreshToken: newRefreshToken, payload } = generateTokens(user);

      user.refreshToken = newRefreshToken;
      try {
        await user.save();
      } catch {
        setMemoryUser(user);
      }

      setAuthCookies(res, newAccessToken, newRefreshToken);

      return res.json({
        success: true,
        message: 'Session refreshed successfully.',
        token: newAccessToken,
        user: {
          id: payload.id,
          name: user.name,
          email: user.email,
          role: user.role,
          department: payload.department,
          departmentCode: payload.departmentCode,
          designation: normalizeDesignation(user.designation) || null,
        },
      });
    });
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Invalid or expired refresh token.' });
  }
});

/**
 * @route   POST /api/auth/mfa/verify
 * @desc    Verify TOTP or recovery code during login
 * @access  Public (Requires mfaToken)
 */
router.post('/mfa/verify', async (req, res) => {
  try {
    const { mfaToken, code, recoveryCode } = req.body || {};
    if (!mfaToken) {
      return res.status(400).json({ success: false, error: 'MFA session token is required.' });
    }
    if (!code && !recoveryCode) {
      return res.status(400).json({ success: false, error: 'TOTP code or recovery code is required.' });
    }

    let decoded;
    try {
      decoded = jwt.verify(mfaToken, JWT_SECRET);
    } catch {
      return res.status(401).json({ success: false, error: 'MFA session expired or invalid. Please sign in again.' });
    }

    if (!decoded.mfaPending || !decoded.id) {
      return res.status(401).json({ success: false, error: 'Invalid MFA verification token.' });
    }

    let user = null;
    try {
      user = await User.findById(decoded.id);
    } catch {}
    if (!user) {
      user = getMemoryUser(decoded.id) || getMemoryUser(decoded.email);
    }
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    let isValid = false;
    let usedRecoveryIndex = -1;

    if (code) {
      isValid = verifyTotp(code.toString().trim(), user.mfaSecret);
    } else if (recoveryCode) {
      usedRecoveryIndex = await findMatchingRecoveryCode(recoveryCode, user.mfaRecoveryCodes);
      if (usedRecoveryIndex !== -1) {
        isValid = true;
        // Invalidate single-use recovery code
        user.mfaRecoveryCodes.splice(usedRecoveryIndex, 1);
        try {
          await user.save();
        } catch {
          setMemoryUser(user);
        }
      }
    }

    if (!isValid) {
      await AuditLog.create({
        actorId: user._id || user.id,
        actorName: user.name,
        actorRole: user.role,
        action: 'MFA_VERIFICATION_FAILED',
        module: 'AUTH',
        targetId: (user._id || user.id)?.toString(),
        targetModel: 'User',
        description: `Failed MFA verification attempt for ${user.email}.`,
        ipAddress: req.ip,
      }).catch(() => null);

      return res.status(401).json({
        success: false,
        error: 'Invalid authentication code. Please check your authenticator app.',
      });
    }

    // Audit successful MFA
    await AuditLog.create({
      actorId: user._id || user.id,
      actorName: user.name,
      actorRole: user.role,
      action: 'MFA_VERIFIED',
      module: 'AUTH',
      targetId: (user._id || user.id)?.toString(),
      targetModel: 'User',
      description: `MFA verified successfully for ${user.email} (${usedRecoveryIndex !== -1 ? 'Used Backup Recovery Code' : 'TOTP App'}).`,
      ipAddress: req.ip,
    }).catch(() => null);

    // If password change is still pending on first login:
    if (user.mustChangePassword) {
      const changePasswordTempToken = jwt.sign(
        { id: (user._id || user.id)?.toString(), email: user.email, passwordChangePending: true },
        JWT_SECRET,
        { expiresIn: '10m' }
      );
      return res.json({
        success: true,
        mfaVerified: true,
        requirePasswordChange: true,
        tempToken: changePasswordTempToken,
        message: 'MFA verified. Password change is required on initial login.',
      });
    }

    // Complete login: generate session tokens
    const { accessToken, refreshToken, payload } = generateTokens(user);
    user.refreshToken = refreshToken;
    user.lastLogin = new Date();
    try {
      await user.save();
    } catch {
      setMemoryUser(user);
    }

    setAuthCookies(res, accessToken, refreshToken);

    await AuditLog.create({
      actorId: user._id || user.id,
      actorName: user.name,
      actorRole: user.role,
      action: 'USER_LOGIN',
      module: 'AUTH',
      targetId: (user._id || user.id)?.toString(),
      targetModel: 'User',
      description: `User ${user.name} (${user.email}) logged in successfully with MFA as ${user.role}.`,
      ipAddress: req.ip,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'MFA authentication successful. Login complete.',
      user: {
        id: payload.id,
        name: user.name,
        email: user.email,
        role: payload.role || user.role,
        department: payload.department,
        designation: payload.designation,
        status: user.status,
      },
      token: accessToken,
    });
  } catch (err) {
    console.error('[MFA Verify Error]:', err);
    return res.status(500).json({ success: false, error: 'MFA verification service failure.' });
  }
});

/**
 * @route   POST /api/auth/change-initial-password
 * @desc    Enforce password change on initial login (Developer & provisioned accounts)
 * @access  Public (Requires tempToken) or Authenticated
 */
router.post('/change-initial-password', async (req, res) => {
  try {
    const { tempToken, newPassword } = req.body || {};
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 10) {
      return res.status(400).json({
        success: false,
        error: 'New password must be at least 10 characters long with sufficient complexity.',
      });
    }

    let userId = null;
    if (tempToken) {
      try {
        const decoded = jwt.verify(tempToken, JWT_SECRET);
        userId = decoded.id;
      } catch {
        return res.status(401).json({ success: false, error: 'Password change session expired. Please sign in again.' });
      }
    } else if (req.headers.authorization) {
      const token = req.headers.authorization.replace('Bearer ', '');
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.id;
      } catch {}
    }

    if (!userId) {
      return res.status(401).json({ success: false, error: 'Authentication token required to change password.' });
    }

    let user = null;
    try {
      user = await User.findById(userId);
    } catch {}
    if (!user) {
      user = getMemoryUser(userId);
    }
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    // Enforce password update
    user.password = await bcrypt.hash(newPassword, 10);
    user.mustChangePassword = false;
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    user.refreshToken = null;

    try {
      await user.save();
    } catch {
      setMemoryUser(user);
    }

    await AuditLog.create({
      actorId: user._id || user.id,
      actorName: user.name,
      actorRole: user.role,
      action: 'INITIAL_PASSWORD_CHANGED',
      module: 'AUTH',
      targetId: (user._id || user.id)?.toString(),
      targetModel: 'User',
      description: `Initial password change completed for ${user.email}.`,
      ipAddress: req.ip,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Password changed successfully. Please log in with your new password.',
    });
  } catch (err) {
    console.error('[Change Password Error]:', err);
    return res.status(500).json({ success: false, error: 'Failed to change password.' });
  }
});

/**
 * @route   GET /api/auth/me
 * @desc    Fetch current authenticated user profile
 * @access  Protected
 */
router.get('/me', protect, (req, res) => {
  return res.json({
    success: true,
    user: req.user,
    token: req.token,
  });
});

/**
 * @route   POST /api/auth/switch-department
 * @desc    Validate and switch user's active department context
 * @access  Protected
 */
router.post('/switch-department', protect, async (req, res) => {
  try {
    const { department } = req.body;
    if (!department) {
      return res.status(400).json({ success: false, error: 'Department name or code is required.' });
    }

    const requested = department.trim().toLowerCase();

    // 1. Super Admin has unrestricted context switching
    if (req.user.role === 'super_admin') {
      req.user.activeDepartment = department.trim();
      req.user.activeDepartmentCode = department.trim().substring(0, 3).toUpperCase();
      req.user.activeRole = 'super_admin';
      req.user.activeDesignation = null;

      const { accessToken, refreshToken, payload } = generateTokens(req.user);
      setAuthCookies(res, accessToken, refreshToken);

      return res.json({
        success: true,
        activeDepartment: req.user.activeDepartment,
        activeDepartmentCode: req.user.activeDepartmentCode,
        activeRole: 'super_admin',
        activeDesignation: null,
        user: payload,
      });
    }

    // 2. Check multi-department memberships
    let matchedMembership = null;
    if (Array.isArray(req.user.memberships) && req.user.memberships.length > 0) {
      matchedMembership = req.user.memberships.find(
        (m) =>
          m.department?.toLowerCase() === requested ||
          m.departmentCode?.toLowerCase() === requested
      );
    }

    // 3. Fallback: check primary department and code
    if (!matchedMembership) {
      const primaryName = (req.user.department || DEPT_ROLE_MAP[req.user.role]?.name || '').toLowerCase();
      const primaryCode = (req.user.departmentCode || DEPT_ROLE_MAP[req.user.role]?.code || '').toLowerCase();
      if (primaryName === requested || primaryCode === requested) {
        matchedMembership = {
          department: req.user.department || DEPT_ROLE_MAP[req.user.role]?.name,
          departmentCode: req.user.departmentCode || DEPT_ROLE_MAP[req.user.role]?.code,
          role: req.user.role,
          designation: req.user.designation,
          region: req.user.region || null,
        };
      }
    }

    // 4. Server-Side Security Gate: Reject if not authorized
    if (!matchedMembership) {
      return res.status(403).json({
        success: false,
        error: `Unauthorized department context: You do not hold an authorized membership in '${department}'.`,
      });
    }

    req.user.activeDepartment = matchedMembership.department;
    req.user.activeDepartmentCode = matchedMembership.departmentCode;
    req.user.activeRole = matchedMembership.role;
    req.user.activeDesignation = matchedMembership.designation;
    req.user.activeRegion = matchedMembership.region || null;

    const { accessToken, refreshToken, payload } = generateTokens(req.user);
    setAuthCookies(res, accessToken, refreshToken);

    return res.json({
      success: true,
      activeDepartment: matchedMembership.department,
      activeDepartmentCode: matchedMembership.departmentCode,
      activeRole: matchedMembership.role,
      activeDesignation: matchedMembership.designation,
      activeRegion: matchedMembership.region || null,
      user: payload,
      token: accessToken,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to switch department context.' });
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Clear session cookies and revoke refresh token server-side
 * @access  Public / Protected
 */
router.post('/logout', async (req, res) => {
  // Clear browser session cookies
  res.clearCookie('rekhta_access_token', getCookieOptions());
  res.clearCookie('rekhta_refresh_token', getCookieOptions());

  // Extract user identity from token cookie, Authorization header, or body
  let userId = req.user?.id || req.user?._id;

  if (!userId) {
    const rawToken =
      req.cookies?.rekhta_access_token ||
      (req.headers.authorization && req.headers.authorization.split(' ')[1]) ||
      req.cookies?.rekhta_refresh_token;

    if (rawToken) {
      try {
        const decoded = jwt.decode(rawToken);
        if (decoded?.id) userId = decoded.id;
      } catch {
        // Ignore decode errors
      }
    }
  }

  // Server-side session invalidation: Nullify refresh token and increment tokenVersion
  if (userId) {
    let user = null;
    try {
      user = await User.findById(userId);
    } catch {}

    if (!user) user = getMemoryUser(userId);

    if (user) {
      user.refreshToken = null;
      user.tokenVersion = (user.tokenVersion || 0) + 1;
      try {
        await user.save();
      } catch {
        setMemoryUser(user);
      }

      await AuditLog.create({
        actorId: user._id || user.id,
        actorName: user.name,
        actorRole: user.role,
        action: 'USER_LOGOUT',
        module: 'AUTH',
        description: `User ${user.name} logged out. Server session revoked and refresh token cleared.`,
      }).catch(() => null);
    }
  }

  return res.json({ success: true, message: 'Logged out successfully. Server session revoked.' });
});

/**
 * @route   POST /api/auth/revoke-sessions
 * @desc    Revoke all active sessions for a user (increments tokenVersion)
 * @access  Protected (Super Admin or Self)
 */
router.post('/revoke-sessions', protect, async (req, res) => {
  try {
    const targetUserId = req.body.userId || req.user.id || req.user._id;

    // Only Super Admin can revoke sessions for other users
    if (targetUserId.toString() !== (req.user.id || req.user._id).toString() && req.user.role !== 'super_admin') {
      return res.status(403).json({ success: false, error: 'Access denied.' });
    }

    let user = null;
    try {
      user = await User.findById(targetUserId);
    } catch {}

    if (!user) user = getMemoryUser(targetUserId);

    if (user) {
      user.tokenVersion = (user.tokenVersion || 0) + 1;
      user.refreshToken = null;
      try {
        await user.save();
      } catch {
        setMemoryUser(user);
      }
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'SESSIONS_REVOKED',
      module: 'AUTH',
      targetId: targetUserId.toString(),
      targetModel: 'User',
      description: `All active sessions revoked for user ${user?.name || targetUserId}.`,
    }).catch(() => null);

    return res.json({ success: true, message: 'Sessions revoked successfully.' });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to revoke sessions.' });
  }
});

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Generate password reset token and dispatch email
 * @access  Public
 */
router.post('/forgot-password', passwordResetRateLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: 'Email is required.' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    let user = null;
    try {
      user = await User.findOne({ email: normalizedEmail });
    } catch {}

    if (!user) user = getMemoryUser(normalizedEmail);

    // Safe response: Do not leak whether user exists
    if (!user) {
      return res.json({
        success: true,
        message: 'If the email is registered, password reset instructions have been sent.',
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // 1 hour

    try {
      await user.save();
    } catch {
      setMemoryUser(user);
    }

    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/portal/reset-password?token=${resetToken}`;

    sendEmail({
      to: user.email,
      subject: "Password Reset Request — Ta'meer-e-Rekhta Portal",
      text: `Hello ${user.name},\n\nA password reset was requested for your account. Visit the following link to set a new password:\n\n${resetUrl}\n\nThis link expires in 1 hour. If you did not request this, please ignore this email.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'If the email is registered, password reset instructions have been sent.',
      devResetToken: process.env.NODE_ENV !== 'production' ? resetToken : undefined,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to process forgot password request.' });
  }
});

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password using reset token
 * @access  Public
 */
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      return res.status(400).json({ success: false, error: 'Token and new password are required.' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters long.' });
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    let user = null;
    try {
      user = await User.findOne({
        resetPasswordToken: hashedToken,
        resetPasswordExpires: { $gt: Date.now() },
      });
    } catch {}

    if (!user) {
      for (const u of getMemoryUsersList()) {
        if (u.resetPasswordToken === hashedToken && u.resetPasswordExpires > Date.now()) {
          user = u;
          break;
        }
      }
    }

    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired password reset token.',
      });
    }

    // Hash new password and invalidate previous sessions
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    user.tokenVersion = (user.tokenVersion || 0) + 1;

    try {
      await user.save();
    } catch {
      setMemoryUser(user);
    }

    await AuditLog.create({
      actorId: user._id || user.id,
      actorName: user.name,
      actorRole: user.role,
      action: 'PASSWORD_RESET',
      module: 'AUTH',
      targetId: (user._id || user.id)?.toString(),
      targetModel: 'User',
      description: `Password was reset successfully for ${user.email}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Password reset successful. You may now log in with your new password.',
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to reset password.' });
  }
});

/**
 * @route   POST /api/auth/verify-activation-token
 * @desc    Verify activation token validity for frontend activation screen
 * @access  Public
 */
router.post('/verify-activation-token', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, valid: false, error: 'Activation token is required.' });
    }

    const hashedToken = crypto.createHash('sha256').update(token.trim()).digest('hex');

    let user = null;
    try {
      user = await User.findOne({ activationToken: hashedToken });
    } catch {}

    if (!user) {
      for (const u of getMemoryUsersList()) {
        if (u.activationToken === hashedToken) {
          user = u;
          break;
        }
      }
    }

    if (!user) {
      return res.status(400).json({
        success: false,
        valid: false,
        error: 'Invalid or unrecognized activation token. Please request a new link from the Super Admin.',
      });
    }

    if (user.status === 'suspended') {
      return res.status(403).json({
        success: false,
        valid: false,
        error: 'This account has been suspended. Account activation is strictly prohibited.',
      });
    }

    if (user.status === 'active') {
      return res.status(400).json({
        success: false,
        valid: false,
        error: 'This account has already been activated. Please proceed to the portal login page.',
      });
    }

    if (user.activationExpires && new Date(user.activationExpires) < new Date()) {
      return res.status(400).json({
        success: false,
        valid: false,
        error: 'This activation link has expired. Please contact the Super Admin for a fresh link.',
      });
    }

    return res.json({
      success: true,
      valid: true,
      name: user.name,
      email: user.email,
      department: user.department,
      departmentCode: user.departmentCode,
      role: user.role,
      designation: user.designation,
      memberships: user.memberships || [],
    });
  } catch (err) {
    return res.status(500).json({ success: false, valid: false, error: 'Failed to verify activation token.' });
  }
});

/**
 * @route   POST /api/auth/activate
 * @desc    Activate a new account created by HR / Admin
 * @access  Public
 */
router.post('/activate', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) {
      return res.status(400).json({ success: false, error: 'Activation token and password are required.' });
    }

    // Security: Block any client privilege escalation or role/department tampering
    if (req.body.role || req.body.department || req.body.departmentCode || req.body.isPrivilegedHR || req.body.designation) {
      return res.status(400).json({
        success: false,
        error: 'Privilege tampering detected: Role, department, designation, and permissions cannot be altered during activation.',
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters long.' });
    }

    const hashedToken = crypto.createHash('sha256').update(token.trim()).digest('hex');

    let user = null;
    try {
      user = await User.findOne({
        activationToken: hashedToken,
      });
    } catch {}

    if (!user) {
      for (const u of getMemoryUsersList()) {
        if (u.activationToken === hashedToken) {
          user = u;
          break;
        }
      }
    }

    if (!user) {
      await AuditLog.create({
        actorId: null,
        actorName: 'Anonymous Candidate',
        actorRole: 'anonymous',
        action: 'ACTIVATION_FAILED',
        module: 'AUTH',
        targetId: null,
        targetModel: 'User',
        description: 'Account activation attempt failed: Invalid token.',
      }).catch(() => null);

      return res.status(400).json({ success: false, error: 'Invalid or expired activation token.' });
    }

    if (user.status === 'suspended') {
      await AuditLog.create({
        actorId: user._id || user.id,
        actorName: user.name,
        actorRole: user.role,
        action: 'ACTIVATION_FAILED',
        module: 'AUTH',
        targetId: (user._id || user.id)?.toString(),
        targetModel: 'User',
        description: `Account activation attempt blocked for suspended user: ${user.name} (${user.email}).`,
      }).catch(() => null);

      return res.status(403).json({
        success: false,
        error: 'This account has been suspended. Account activation is strictly prohibited.',
      });
    }

    if (user.activationExpires && new Date(user.activationExpires) < new Date()) {
      await AuditLog.create({
        actorId: user._id || user.id,
        actorName: user.name,
        actorRole: user.role,
        action: 'ACTIVATION_FAILED',
        module: 'AUTH',
        targetId: (user._id || user.id)?.toString(),
        targetModel: 'User',
        description: `Account activation attempt failed: Expired token for ${user.name} (${user.email}).`,
      }).catch(() => null);

      return res.status(400).json({ success: false, error: 'Invalid or expired activation token.' });
    }

    user.password = await bcrypt.hash(password, 10);
    user.status = 'active';
    user.activationToken = undefined;
    user.activationExpires = undefined;
    user.activationRevokedAt = undefined;
    user.tokenVersion = (user.tokenVersion || 0) + 1;

    try {
      await user.save();
    } catch {
      setMemoryUser(user);
    }

    await AuditLog.create({
      actorId: user._id || user.id,
      actorName: user.name,
      actorRole: user.role,
      action: 'ACCOUNT_ACTIVATED',
      module: 'AUTH',
      targetId: (user._id || user.id)?.toString(),
      targetModel: 'User',
      description: `Account activated for ${user.name} (${user.email}).`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Account activated successfully. Please sign in to the portal.',
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to activate account.' });
  }
});

/**
 * @route   PATCH /api/auth/users/:id/status
 * @desc    Super Admin can activate, deactivate, or suspend any user account
 * @access  Protected (Super Admin Only)
 */
router.patch('/users/:id/status', protect, authorize('super_admin'), async (req, res) => {
  try {
    const { status } = req.body;
    if (!['active', 'inactive', 'suspended'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status. Must be active, inactive, or suspended.' });
    }

    let user = null;
    try {
      user = await User.findById(req.params.id);
    } catch {}

    if (!user) user = getMemoryUser(req.params.id);

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    user.status = status;
    // If suspended or inactive, revoke active tokens
    if (status !== 'active') {
      user.tokenVersion = (user.tokenVersion || 0) + 1;
      user.refreshToken = null;
    }

    try {
      await user.save();
    } catch {
      setMemoryUser(user);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'USER_STATUS_UPDATED',
      module: 'SUPER_ADMIN',
      targetId: req.params.id,
      targetModel: 'User',
      description: `Account status for ${user.name} changed to '${status}' by Super Admin.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Account status updated to '${status}'.`,
      user: { id: user._id || user.id, name: user.name, email: user.email, status: user.status },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to update account status.' });
  }
});

/**
 * @route   PATCH /api/auth/users/:id/hr-privilege
 * @desc    Super Admin grants or revokes privileged HR authorization
 * @access  Protected (Super Admin Only)
 */
router.patch('/users/:id/hr-privilege', protect, authorize('super_admin'), async (req, res) => {
  try {
    const { isPrivilegedHR } = req.body;
    if (typeof isPrivilegedHR !== 'boolean') {
      return res.status(400).json({ success: false, error: 'isPrivilegedHR boolean field required.' });
    }

    let user = null;
    try {
      user = await User.findById(req.params.id);
    } catch {}

    if (!user) user = getMemoryUser(req.params.id);

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    if (user.role !== 'hr') {
      return res.status(400).json({ success: false, error: 'Privileged HR status can only be granted to HR accounts.' });
    }

    user.isPrivilegedHR = isPrivilegedHR;
    try {
      await user.save();
    } catch {
      setMemoryUser(user);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: isPrivilegedHR ? 'HR_PRIVILEGE_GRANTED' : 'HR_PRIVILEGE_REVOKED',
      module: 'SUPER_ADMIN',
      targetId: req.params.id,
      targetModel: 'User',
      description: `Privileged HR status ${isPrivilegedHR ? 'GRANTED' : 'REVOKED'} for ${user.name} by Super Admin.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Privileged HR authorization ${isPrivilegedHR ? 'granted' : 'revoked'}.`,
      user: { id: user._id || user.id, name: user.name, isPrivilegedHR: user.isPrivilegedHR },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to update HR privilege.' });
  }
});

module.exports = router;
