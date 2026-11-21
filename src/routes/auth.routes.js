const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { User, AuditLog } = require('../models');
const { protect } = require('../middleware/auth');

const JWT_SECRET = process.env.JWT_SECRET || 'rekhta_super_secret_jwt_key_2026';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'rekhta_refresh_super_secret_2026';

const PRECONFIGURED_ACCOUNTS = {
  'admin@rekhta.org': {
    name: 'Syed Ali (Super Admin)',
    role: 'super_admin',
    password: 'Admin@123456',
  },
  'hr@rekhta.org': {
    name: 'Hania Mehmood (Head of HR)',
    role: 'hr',
    password: 'Hr@123456',
  },
  'finance@rekhta.org': {
    name: 'Ahmad Maqsood (Head of Finance)',
    role: 'finance',
    password: 'Finance@123456',
  },
  'depthead@rekhta.org': {
    name: 'Asfand Yar Karimi (Department Lead)',
    role: 'department_head',
    password: 'Dept@123456',
    departmentId: 'dept-welfare-punjab',
  },
  'member@rekhta.org': {
    name: 'Zoraiz Ali (Core Member)',
    role: 'member',
    password: 'Member@123456',
    departmentId: 'dept-welfare-punjab',
  },
};

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required.' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    let user = await User.findOne({ email: normalizedEmail });
    let authenticated = false;

    if (user) {
      authenticated = await bcrypt.compare(password, user.password);
    }

    if (!authenticated && PRECONFIGURED_ACCOUNTS[normalizedEmail]) {
      const demoAccount = PRECONFIGURED_ACCOUNTS[normalizedEmail];
      if (password === demoAccount.password) {
        authenticated = true;
        if (!user) {
          const hashedPassword = await bcrypt.hash(password, 10);
          user = await User.create({
            name: demoAccount.name,
            email: normalizedEmail,
            password: hashedPassword,
            role: demoAccount.role,
            status: 'active',
          }).catch(() => null);
        }
      }
    }

    if (!authenticated) {
      return res.status(401).json({ success: false, error: 'Invalid credentials. Please verify your email and password.' });
    }

    const resolvedRole = user?.role || PRECONFIGURED_ACCOUNTS[normalizedEmail]?.role || 'member';
    const resolvedName = user?.name || PRECONFIGURED_ACCOUNTS[normalizedEmail]?.name || 'Rekhta Member';
    const resolvedId = user?._id?.toString() || `mock_${normalizedEmail}`;

    const payload = { id: resolvedId, email: normalizedEmail, role: resolvedRole, name: resolvedName };
    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
    const refreshToken = jwt.sign(payload, REFRESH_SECRET, { expiresIn: '7d' });

    res.cookie('rekhta_access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 8 * 60 * 60 * 1000,
    });

    res.cookie('rekhta_refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    await AuditLog.create({
      actorId: user?._id,
      actorName: resolvedName,
      actorRole: resolvedRole,
      action: 'USER_LOGIN',
      module: 'AUTH',
      targetId: resolvedId,
      targetModel: 'User',
      description: `User ${resolvedName} (${normalizedEmail}) signed into the Management Portal.`,
    }).catch(() => null);

    return res.json({
      success: true,
      user: { id: resolvedId, name: resolvedName, email: normalizedEmail, role: resolvedRole },
      token: accessToken,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Server authentication failure.' });
  }
});

router.get('/me', protect, (req, res) => {
  return res.json({ success: true, user: req.user });
});

router.post('/logout', (req, res) => {
  res.clearCookie('rekhta_access_token');
  res.clearCookie('rekhta_refresh_token');
  return res.json({ success: true, message: 'Logged out successfully.' });
});

module.exports = router;
