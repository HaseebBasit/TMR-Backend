/**
 * Phase D.2.2.6 — Account Creation & Activation Management Offline Test Suite
 * 
 * Mode: Strictly Offline Mock Isolation — Zero Live Database Connections
 * Active Staging Test Run ID: TR_20261124_1EA2B4
 * 
 * Comprehensive Test Coverage:
 *   Section 1: Capability Architecture (CAPABILITIES.ACCOUNT_CREATE_MANAGE)
 *   Section 2: Middleware Access Gate (requireAccountCreateAuthority)
 *   Section 3: Authorized Account Provisioning & Cryptographic Token Generation (POST /api/hr/accounts)
 *   Section 4: Privilege Escalation & Unauthorized Creation Defense
 *   Section 5: Account Listing & Strict Token Secrecy (GET /api/hr/accounts)
 *   Section 6: Account Activation Flow (POST /api/auth/activate)
 *   Section 7: Token Single-Use, Expiry & Tamper Resistance
 *   Section 8: Activation Link Regeneration Lifecycle (POST /api/hr/accounts/:id/regenerate-activation)
 *   Section 9: Super Admin User Creation & Activation URL Generation (POST /api/super-admin/users)
 */

process.env.NODE_ENV = 'test';
const JWT_SECRET = process.env.JWT_SECRET || 'rekhta_access_secret_2026_super_secure';
process.env.JWT_SECRET = JWT_SECRET;
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'rekhta_refresh_super_secret_2026';
process.env.FRONTEND_URL = 'http://localhost:3000';

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const {
  CAPABILITIES,
  hasCapability,
  TECHNICAL_ROLES,
  HR_DESIGNATIONS,
  OPERATIONAL_DESIGNATIONS,
  ALLOWED_ROLES,
  validateRoleDesignation,
} = require('../src/constants/roles');

const {
  requireAccountCreateAuthority,
  setMemoryUser,
  getMemoryUser,
  getMemoryUsersList,
} = require('../src/middleware/auth');

const { router: hrRouter } = require('../src/routes/hr.routes');
const authRouter = require('../src/routes/auth.routes');
const portalRouter = require('../src/routes/portal.routes');

// ---------------------------------------------------------------------------
// 1. Synthetic Test Personas
// ---------------------------------------------------------------------------
const PERSONAS = {
  superAdmin: {
    id: 'usr_sa_d226',
    _id: 'usr_sa_d226',
    name: 'President / Super Admin',
    email: 'admin.d226@tameer-rekhta.org',
    role: TECHNICAL_ROLES.SUPER_ADMIN,
    designation: null,
    department: 'Administration',
    status: 'active',
  },
  hrHead: {
    id: 'usr_hr_head_d226',
    _id: 'usr_hr_head_d226',
    name: 'Farhan Zaidi (HR Head)',
    email: 'hr.head.d226@tameer-rekhta.org',
    role: TECHNICAL_ROLES.HR,
    designation: HR_DESIGNATIONS.HR_HEAD,
    department: 'HR',
    status: 'active',
  },
  hrDirector: {
    id: 'usr_hr_dir_d226',
    _id: 'usr_hr_dir_d226',
    name: 'Zainab Qazi (HR Director)',
    email: 'hr.dir.d226@tameer-rekhta.org',
    role: TECHNICAL_ROLES.HR,
    designation: HR_DESIGNATIONS.HR_DIRECTOR,
    department: 'HR',
    status: 'active',
  },
  hrCoordIncharge: {
    id: 'usr_hr_coord_d226',
    _id: 'usr_hr_coord_d226',
    name: 'Bilal Farooqi (HR Coordination In-charge)',
    email: 'hr.coord.d226@tameer-rekhta.org',
    role: TECHNICAL_ROLES.HR,
    designation: HR_DESIGNATIONS.HR_COORDINATION_INCHARGE,
    department: 'HR',
    status: 'active',
  },
  hrMember: {
    id: 'usr_hr_mem_d226',
    _id: 'usr_hr_mem_d226',
    name: 'Ayesha Siddiqui (HR Member)',
    email: 'hr.mem.d226@tameer-rekhta.org',
    role: TECHNICAL_ROLES.HR,
    designation: HR_DESIGNATIONS.HR_MEMBER,
    department: 'HR',
    status: 'active',
  },
  deptHeadLit: {
    id: 'usr_lit_head_d226',
    _id: 'usr_lit_head_d226',
    name: 'Faiz Ahmed (Literature Head)',
    email: 'lit.head.d226@tameer-rekhta.org',
    role: TECHNICAL_ROLES.DEPT_LITERATURE,
    designation: OPERATIONAL_DESIGNATIONS.HEAD,
    department: 'Literature',
    status: 'active',
  },
  financeOfficer: {
    id: 'usr_fin_d226',
    _id: 'usr_fin_d226',
    name: 'Kamran Akmal (Finance)',
    email: 'finance.d226@tameer-rekhta.org',
    role: TECHNICAL_ROLES.FINANCE,
    designation: null,
    department: 'Finance',
    status: 'active',
  },
  regularMember: {
    id: 'usr_mem_d226',
    _id: 'usr_mem_d226',
    name: 'Hamza Tariq (Member)',
    email: 'member.d226@tameer-rekhta.org',
    role: TECHNICAL_ROLES.MEMBER,
    designation: OPERATIONAL_DESIGNATIONS.MEMBER,
    department: 'Literature',
    status: 'active',
  },
};

// Seed personas into auth memory store
Object.values(PERSONAS).forEach((p) => setMemoryUser(p));

function makeToken(user) {
  if (!user) return null;
  return jwt.sign(
    {
      id: user.id || user._id,
      email: user.email,
      name: user.name,
      role: user.role,
      designation: user.designation,
      department: user.department,
      status: user.status || 'active',
      tokenVersion: 0,
    },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// ---------------------------------------------------------------------------
// 2. Test Express App Server
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use('/api/hr', hrRouter);
app.use('/api/auth', authRouter);
app.use('/api', portalRouter);

let server;
let port;
let baseUrl;

function startServer() {
  return new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}/api`;
      resolve();
    });
  });
}

function stopServer() {
  return new Promise((resolve) => {
    if (server) server.close(resolve);
    else resolve();
  });
}

async function request(method, path, body = null, token = null) {
  const url = `${baseUrl}${path}`;
  const parsed = new URL(url);

  return new Promise((resolve, reject) => {
    const headers = { 'x-requested-with': 'XMLHttpRequest' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (body) headers['Content-Type'] = 'application/json';

    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          let json = null;
          const text = buffer.toString('utf8');
          try {
            json = JSON.parse(text);
          } catch {}
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: json,
            text,
            buffer,
          });
        });
      }
    );

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ---------------------------------------------------------------------------
// 3. Test Runner & Assertion Harness
// ---------------------------------------------------------------------------
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

async function runTests() {
  console.log('\n================================================================');
  console.log('TA\'MEER-E-REKHTA MANAGEMENT PORTAL');
  console.log('Phase D.2.2.6 — Account Creation & Activation Management Suite');
  console.log('Test Run ID: TR_20261124_1EA2B4');
  console.log('================================================================\n');

  await startServer();

  try {
    // -----------------------------------------------------------------------
    // SECTION 1: Capability Architecture
    // -----------------------------------------------------------------------
    console.log('--- SECTION 1: Capability Architecture (CAPABILITIES.ACCOUNT_CREATE_MANAGE) ---');

    assert(
      hasCapability(PERSONAS.superAdmin, CAPABILITIES.ACCOUNT_CREATE_MANAGE) === true,
      'Super Admin possesses ACCOUNT_CREATE_MANAGE capability'
    );
    assert(
      hasCapability(PERSONAS.hrHead, CAPABILITIES.ACCOUNT_CREATE_MANAGE) === true,
      'HR Head possesses ACCOUNT_CREATE_MANAGE capability'
    );
    assert(
      hasCapability(PERSONAS.hrDirector, CAPABILITIES.ACCOUNT_CREATE_MANAGE) === true,
      'HR Director possesses ACCOUNT_CREATE_MANAGE capability'
    );
    assert(
      hasCapability(PERSONAS.hrCoordIncharge, CAPABILITIES.ACCOUNT_CREATE_MANAGE) === true,
      'HR Coordination In-charge possesses ACCOUNT_CREATE_MANAGE capability'
    );
    assert(
      hasCapability(PERSONAS.hrMember, CAPABILITIES.ACCOUNT_CREATE_MANAGE) === false,
      'HR Member is DENIED ACCOUNT_CREATE_MANAGE capability'
    );
    assert(
      hasCapability(PERSONAS.deptHeadLit, CAPABILITIES.ACCOUNT_CREATE_MANAGE) === false,
      'Operational Department Head is DENIED ACCOUNT_CREATE_MANAGE capability'
    );
    assert(
      hasCapability(PERSONAS.financeOfficer, CAPABILITIES.ACCOUNT_CREATE_MANAGE) === false,
      'Finance Officer is DENIED ACCOUNT_CREATE_MANAGE capability'
    );
    assert(
      hasCapability(PERSONAS.regularMember, CAPABILITIES.ACCOUNT_CREATE_MANAGE) === false,
      'Regular Member is DENIED ACCOUNT_CREATE_MANAGE capability'
    );

    // -----------------------------------------------------------------------
    // SECTION 2: Middleware Access Gate (requireAccountCreateAuthority)
    // -----------------------------------------------------------------------
    console.log('\n--- SECTION 2: Middleware Access Gate (requireAccountCreateAuthority) ---');

    const testMiddleware = (user) => {
      const req = { user };
      let resData = null;
      let resCode = 200;
      const res = {
        status(c) { resCode = c; return this; },
        json(d) { resData = d; return this; },
      };
      let nextCalled = false;
      const next = () => { nextCalled = true; };
      requireAccountCreateAuthority(req, res, next);
      return { nextCalled, statusCode: resCode, error: resData?.error };
    };

    assert(testMiddleware(PERSONAS.superAdmin).nextCalled === true, 'Middleware allows Super Admin');
    assert(testMiddleware(PERSONAS.hrHead).nextCalled === true, 'Middleware allows HR Head');
    assert(testMiddleware(PERSONAS.hrDirector).nextCalled === true, 'Middleware allows HR Director');
    assert(testMiddleware(PERSONAS.hrCoordIncharge).nextCalled === true, 'Middleware allows HR Coordination In-charge');

    const hrMemResult = testMiddleware(PERSONAS.hrMember);
    assert(
      hrMemResult.nextCalled === false && hrMemResult.statusCode === 403,
      'Middleware blocks HR Member with HTTP 403 Forbidden'
    );

    const deptHeadResult = testMiddleware(PERSONAS.deptHeadLit);
    assert(
      deptHeadResult.nextCalled === false && deptHeadResult.statusCode === 403,
      'Middleware blocks Operational Department Head with HTTP 403 Forbidden'
    );

    const finResult = testMiddleware(PERSONAS.financeOfficer);
    assert(
      finResult.nextCalled === false && finResult.statusCode === 403,
      'Middleware blocks Finance Officer with HTTP 403 Forbidden'
    );

    const anonResult = testMiddleware(null);
    assert(
      anonResult.nextCalled === false && anonResult.statusCode === 401,
      'Middleware blocks Unauthenticated user with HTTP 401'
    );

    // -----------------------------------------------------------------------
    // SECTION 3: Authorized Account Provisioning & Cryptographic Token Generation
    // -----------------------------------------------------------------------
    console.log('\n--- SECTION 3: Account Provisioning (POST /api/hr/accounts) ---');

    const newAccountEmail = `contributor_${Date.now()}@tameer.org`;
    const hrHeadToken = makeToken(PERSONAS.hrHead);

    const createRes = await request('POST', '/hr/accounts', {
      name: 'Mirza Ghalib Contributor',
      email: newAccountEmail,
      role: 'dept_literature',
      department: 'Literature',
      designation: 'member',
      phoneNumber: '+92 300 9876543',
    }, hrHeadToken);

    assert(createRes.status === 201, 'HR Head successfully provisions new member account (HTTP 201)');
    assert(Boolean(createRes.body?.account), 'Response includes safe account payload');
    assert(Boolean(createRes.body?.activationUrl), 'Response includes activation URL');
    assert(Boolean(createRes.body?.activationToken), 'Response includes raw single-use activation token');
    assert(Boolean(createRes.body?.expiresAt), 'Response includes 7-day expiresAt timestamp');

    const provisionedToken = createRes.body?.activationToken;
    const provisionedUserId = createRes.body?.account?.id || createRes.body?.account?._id;

    assert(
      typeof provisionedToken === 'string' && provisionedToken.length === 64,
      'Raw activation token is a 32-byte cryptographic hex string (64 characters)'
    );

    assert(
      createRes.body.activationUrl.includes(`/portal/activate?token=${provisionedToken}`),
      'Activation URL correctly contains raw single-use token in query parameter'
    );

    // Verify stored user record in storage
    const storedUser = getMemoryUser(provisionedUserId) || getMemoryUser(newAccountEmail);
    assert(Boolean(storedUser), 'Account successfully persisted in storage');
    assert(storedUser?.status === 'inactive', 'Newly provisioned account has status: inactive');
    assert(
      storedUser?.activationToken !== provisionedToken,
      'Raw activation token is NEVER stored plaintext in the database'
    );

    const expectedHash = crypto.createHash('sha256').update(provisionedToken).digest('hex');
    assert(
      storedUser?.activationToken === expectedHash,
      'Activation token is securely stored as a SHA-256 hash'
    );

    const diffDays = Math.round((new Date(storedUser.activationExpires) - Date.now()) / (1000 * 60 * 60 * 24));
    assert(diffDays === 7, 'Activation expiration is set to exactly 7 days in the future');

    // -----------------------------------------------------------------------
    // SECTION 4: Privilege Escalation & Unauthorized Creation Defense
    // -----------------------------------------------------------------------
    console.log('\n--- SECTION 4: Privilege Escalation & Unauthorized Defense ---');

    // 1. HR attempts to create Super Admin account
    const superAdminRes = await request('POST', '/hr/accounts', {
      name: 'Rogue Admin',
      email: `rogue_${Date.now()}@tameer.org`,
      role: 'super_admin',
    }, hrHeadToken);

    assert(
      superAdminRes.status === 403,
      'HR attempting to create Super Admin account is REJECTED with HTTP 403 Forbidden'
    );

    // 2. HR attempts to appoint Operational Department Head
    const deptHeadRes = await request('POST', '/hr/accounts', {
      name: 'Rogue Dept Head',
      email: `rogue_head_${Date.now()}@tameer.org`,
      role: 'dept_literature',
      designation: 'head',
    }, hrHeadToken);

    assert(
      deptHeadRes.status === 403,
      'HR attempting to appoint operational Department Head is REJECTED with HTTP 403 Forbidden'
    );

    // 3. HR Member attempting to create account
    const hrMemToken = makeToken(PERSONAS.hrMember);
    const hrMemRes = await request('POST', '/hr/accounts', {
      name: 'Another User',
      email: `user_${Date.now()}@tameer.org`,
      role: 'dept_literature',
    }, hrMemToken);

    assert(
      hrMemRes.status === 403,
      'HR Member (view-only) attempting to create account is REJECTED with HTTP 403 Forbidden'
    );

    // 4. Duplicate email rejection
    const duplicateRes = await request('POST', '/hr/accounts', {
      name: 'Duplicate Contributor',
      email: newAccountEmail,
      role: 'dept_literature',
    }, hrHeadToken);

    assert(
      duplicateRes.status === 400,
      'Duplicate account creation with existing email is REJECTED with HTTP 400'
    );

    // 5. OBS-PERM-01: HR Head attempting to appoint another HR Head is REJECTED
    const hrHeadSelfAppointRes = await request('POST', '/hr/accounts', {
      name: 'Rival HR Head',
      email: `rival_hr_head_${Date.now()}@tameer.org`,
      role: 'hr',
      designation: 'hr_head',
    }, hrHeadToken);

    assert(
      hrHeadSelfAppointRes.status === 403,
      'HR Head attempting to appoint another HR Head is REJECTED with HTTP 403 Forbidden (OBS-PERM-01)'
    );

    // 6. OBS-PERM-01: HR Director attempting to appoint an HR Head is REJECTED
    const hrDirectorToken = makeToken(PERSONAS.hrDirector);
    const hrDirAppointHrHeadRes = await request('POST', '/hr/accounts', {
      name: 'Unauthorized HR Head Appointment',
      email: `unauth_hr_head_${Date.now()}@tameer.org`,
      role: 'hr',
      designation: 'hr_head',
    }, hrDirectorToken);

    assert(
      hrDirAppointHrHeadRes.status === 403,
      'HR Director attempting to appoint an HR Head is REJECTED with HTTP 403 Forbidden (OBS-PERM-01)'
    );

    // 7. OBS-PERM-01: HR Coordination In-charge attempting to appoint an HR Head is REJECTED
    const hrCoordTokenForPerm = makeToken(PERSONAS.hrCoordIncharge);
    const hrCoordAppointHrHeadRes = await request('POST', '/hr/accounts', {
      name: 'Coord Appointing HR Head',
      email: `coord_hr_head_${Date.now()}@tameer.org`,
      role: 'hr',
      designation: 'hr_head',
    }, hrCoordTokenForPerm);

    assert(
      hrCoordAppointHrHeadRes.status === 403,
      'HR Coordination In-charge attempting to appoint an HR Head is REJECTED with HTTP 403 Forbidden (OBS-PERM-01)'
    );

    // 8. HR Head appointing authorized HR designation (hr_coordination_incharge) succeeds
    const hrValidRes = await request('POST', '/hr/accounts', {
      name: 'New HR Coordinator',
      email: `new_hr_coord_${Date.now()}@tameer.org`,
      role: 'hr',
      designation: 'hr_coordination_incharge',
    }, hrHeadToken);

    assert(
      hrValidRes.status === 201,
      'HR Head appointing authorized HR role & designation (hr_coordination_incharge) succeeds with HTTP 201'
    );

    // -----------------------------------------------------------------------
    // SECTION 5: Account Listing & Sanitization (GET /api/hr/accounts)
    // -----------------------------------------------------------------------
    console.log('\n--- SECTION 5: Account Listing & Sanitization (GET /api/hr/accounts) ---');

    const hrDirToken = makeToken(PERSONAS.hrDirector);
    const listRes = await request('GET', '/hr/accounts', null, hrDirToken);

    assert(listRes.status === 200, 'HR Director can list all accounts (HTTP 200)');
    assert(Array.isArray(listRes.body?.accounts), 'Accounts list is returned as array');

    const accounts = listRes.body?.accounts || [];
    const provAcc = accounts.find((a) => a.email === newAccountEmail);

    assert(Boolean(provAcc), 'Provisioned account appears in accounts list');
    assert(
      provAcc?.activationStatus === 'Pending Activation',
      'Inactive account with active expiration displays activationStatus: "Pending Activation"'
    );
    assert(
      provAcc?.activationToken === undefined,
      'Raw or hashed activation token is STRICTLY OMITTED from account listing'
    );
    assert(
      provAcc?.password === undefined,
      'Password hash is STRICTLY OMITTED from account listing'
    );

    // -----------------------------------------------------------------------
    // SECTION 6: Account Activation Flow (POST /api/auth/activate)
    // -----------------------------------------------------------------------
    console.log('\n--- SECTION 6: Account Activation Flow (POST /api/auth/activate) ---');

    const activateRes = await request('POST', '/auth/activate', {
      token: provisionedToken,
      password: 'StrongSecretPassword123!',
    });

    assert(activateRes.status === 200, 'Valid activation token activates account (HTTP 200)');
    assert(activateRes.body?.success === true, 'Activation response indicates success');

    const activatedUser = getMemoryUser(provisionedUserId) || getMemoryUser(newAccountEmail);
    assert(activatedUser?.status === 'active', 'User status transitioned to "active"');
    assert(
      activatedUser?.activationToken === undefined,
      'Activation token hash is cleared from storage upon successful activation'
    );
    assert(
      activatedUser?.activationExpires === undefined,
      'Activation expiration is cleared from storage upon successful activation'
    );

    const passwordValid = await bcrypt.compare('StrongSecretPassword123!', activatedUser.password);
    assert(passwordValid === true, 'New password is encrypted with bcrypt and verifies correctly');

    // -----------------------------------------------------------------------
    // SECTION 7: Token Single-Use, Expiry & Tamper Resistance
    // -----------------------------------------------------------------------
    console.log('\n--- SECTION 7: Single-Use, Expiry & Tamper Resistance ---');

    // 1. Single-use: Reusing already activated token
    const reuseRes = await request('POST', '/auth/activate', {
      token: provisionedToken,
      password: 'AnotherPassword456!',
    });

    assert(
      reuseRes.status === 400,
      'Reusing an already activated token is REJECTED with HTTP 400'
    );

    // 2. Privilege tampering during activation
    const tamperRes = await request('POST', '/auth/activate', {
      token: 'some_random_token_123',
      password: 'StrongSecretPassword123!',
      role: 'super_admin', // Tamper attempt!
    });

    assert(
      tamperRes.status === 400 && tamperRes.body?.error?.includes('Privilege tampering detected'),
      'Privilege tampering during activation (role override attempt) is REJECTED with HTTP 400'
    );

    // 3. Expired token rejection
    const expiredToken = crypto.randomBytes(32).toString('hex');
    const expiredHash = crypto.createHash('sha256').update(expiredToken).digest('hex');
    const expiredUser = {
      _id: 'usr_expired_001',
      id: 'usr_expired_001',
      name: 'Expired User',
      email: 'expired@tameer.org',
      password: 'temp_hashed_pass',
      role: 'member',
      status: 'inactive',
      activationToken: expiredHash,
      activationExpires: new Date(Date.now() - 1000 * 60 * 60), // Expired 1 hour ago
    };
    setMemoryUser(expiredUser);

    const expiredRes = await request('POST', '/auth/activate', {
      token: expiredToken,
      password: 'StrongSecretPassword123!',
    });

    assert(
      expiredRes.status === 400,
      'Activating with an expired activation token is REJECTED with HTTP 400'
    );

    // -----------------------------------------------------------------------
    // SECTION 8: Activation Link Regeneration Lifecycle
    // -----------------------------------------------------------------------
    console.log('\n--- SECTION 8: Activation Link Regeneration (POST /api/hr/accounts/:id/regenerate-activation) ---');

    const hrCoordToken = makeToken(PERSONAS.hrCoordIncharge);

    // 1. Regenerate link for expired account
    const regenRes = await request('POST', `/hr/accounts/usr_expired_001/regenerate-activation`, {}, hrCoordToken);

    assert(regenRes.status === 200, 'HR Coordination In-charge successfully regenerates link (HTTP 200)');
    assert(Boolean(regenRes.body?.activationUrl), 'Regenerated link includes new activation URL');
    assert(Boolean(regenRes.body?.activationToken), 'Regenerated link includes new raw activation token');

    const newToken = regenRes.body?.activationToken;
    const recheckedUser = getMemoryUser('usr_expired_001');

    assert(
      recheckedUser.activationToken === crypto.createHash('sha256').update(newToken).digest('hex'),
      'New activation token hash is stored in user record'
    );
    assert(
      new Date(recheckedUser.activationExpires) > new Date(Date.now() + 6 * 24 * 3600 * 1000),
      'New activation expiration is refreshed to 7 days in future'
    );

    // 2. Reject regenerating for already active account
    const activeRegenRes = await request('POST', `/hr/accounts/${provisionedUserId}/regenerate-activation`, {}, hrCoordToken);

    assert(
      activeRegenRes.status === 400,
      'Attempting to regenerate activation link for an already ACTIVE account is REJECTED with HTTP 400'
    );

    // 3. HR forbidden from regenerating Super Admin activation
    const saRegenRes = await request('POST', `/hr/accounts/${PERSONAS.superAdmin.id}/regenerate-activation`, {}, hrHeadToken);

    assert(
      saRegenRes.status === 403,
      'HR attempting to regenerate activation for Super Admin account is FORBIDDEN (HTTP 403)'
    );

    // -----------------------------------------------------------------------
    // SECTION 9: Super Admin User Creation & Activation URL Generation
    // -----------------------------------------------------------------------
    console.log('\n--- SECTION 9: Super Admin User Creation (POST /api/super-admin/users) ---');

    const saToken = makeToken(PERSONAS.superAdmin);
    const newAdminEmail = `created_by_sa_${Date.now()}@tameer.org`;

    const saRes = await request('POST', '/super-admin/users', {
      name: 'Allama Iqbal Scholar',
      email: newAdminEmail,
      role: 'dept_literature',
      department: 'Literature',
      designation: 'head',
    }, saToken);

    assert(saRes.status === 201, 'Super Admin creates new member with activation link (HTTP 201)');
    assert(Boolean(saRes.body?.activationUrl), 'Super Admin response includes activationUrl');
    assert(Boolean(saRes.body?.activationToken), 'Super Admin response includes activationToken');

    const saCreatedUser = getMemoryUser(newAdminEmail);
    assert(saCreatedUser?.status === 'inactive', 'User created without explicit password has status: inactive');
    assert(
      saCreatedUser?.activationToken === crypto.createHash('sha256').update(saRes.body.activationToken).digest('hex'),
      'Super Admin created user activation token is securely hashed'
    );

    // 9.2 OBS-PERM-01: Super Admin appointing an HR Head succeeds with HTTP 201
    const saAppointHrHeadEmail = `sa_appointed_hr_head_${Date.now()}@tameer.org`;
    const saHrHeadRes = await request('POST', '/super-admin/users', {
      name: 'Super Admin Appointed HR Head',
      email: saAppointHrHeadEmail,
      role: 'hr',
      department: 'HR',
      designation: 'hr_head',
    }, saToken);

    assert(
      saHrHeadRes.status === 201,
      'Super Admin appointing an HR Head succeeds with HTTP 201 (OBS-PERM-01)'
    );
    const saHrHeadUser = getMemoryUser(saAppointHrHeadEmail);
    assert(
      saHrHeadUser?.designation === 'hr_head',
      'Super Admin appointed user has designation: hr_head'
    );

    // -----------------------------------------------------------------------
    // SECTION 10: Super Admin Leave Management & Executive Review Governance
    // -----------------------------------------------------------------------
    console.log('\n--- SECTION 10: Super Admin Leave Governance (GET/PATCH /api/super-admin/leaves) ---');

    const { setMemoryLeave } = require('../src/routes/hr.routes');
    const memberToken = makeToken(PERSONAS.regularMember);

    const testLeaveId = 'leave_d226_test_001';
    setMemoryLeave({
      id: testLeaveId,
      _id: testLeaveId,
      memberId: PERSONAS.regularMember.id,
      memberName: PERSONAS.regularMember.name,
      memberEmail: PERSONAS.regularMember.email,
      department: 'Literature',
      leaveType: 'Sick',
      startDate: new Date(),
      endDate: new Date(Date.now() + 3 * 86400000),
      reason: 'Medical recovery leave',
      status: 'pending',
      createdAt: new Date(),
    });

    // 10.1 Super Admin lists leaves
    const leavesListRes = await request('GET', '/super-admin/leaves', null, saToken);
    assert(leavesListRes.status === 200, 'Super Admin successfully fetches organization leaves (HTTP 200)');
    assert(Array.isArray(leavesListRes.body?.leaves), 'Super Admin response includes leaves array');
    assert(Boolean(leavesListRes.body?.stats), 'Super Admin response includes summary stats');
    assert(typeof leavesListRes.body?.stats?.total === 'number', 'Summary stats include total count');
    assert(typeof leavesListRes.body?.stats?.pending === 'number', 'Summary stats include pending count');

    // 10.2 Non-Super Admin access is forbidden
    const memberLeaveRes = await request('GET', '/super-admin/leaves', null, memberToken);
    assert(memberLeaveRes.status === 403, 'Regular member access to /super-admin/leaves is FORBIDDEN (HTTP 403)');

    // 10.3 Super Admin Executive Review: Approve
    const approveRes = await request('PATCH', `/super-admin/leaves/${testLeaveId}/review`, {
      action: 'approve',
      notes: 'Approved under executive command.',
    }, saToken);
    assert(approveRes.status === 200, 'Super Admin successfully approves leave request (HTTP 200)');
    assert(approveRes.body?.leave?.status === 'approved', 'Leave status updated to approved');

    // 10.4 Super Admin Executive Review: Reject
    const testLeave2Id = 'leave_d226_test_002';
    setMemoryLeave({
      id: testLeave2Id,
      _id: testLeave2Id,
      memberId: PERSONAS.regularMember.id,
      memberName: PERSONAS.regularMember.name,
      memberEmail: PERSONAS.regularMember.email,
      department: 'Media',
      leaveType: 'Personal',
      startDate: new Date(),
      endDate: new Date(Date.now() + 2 * 86400000),
      reason: 'Personal travel',
      status: 'pending',
      createdAt: new Date(),
    });

    const rejectRes = await request('PATCH', `/super-admin/leaves/${testLeave2Id}/review`, {
      action: 'reject',
      notes: 'Conflicting departmental deadlines.',
    }, saToken);
    assert(rejectRes.status === 200, 'Super Admin successfully rejects leave request (HTTP 200)');
    assert(rejectRes.body?.leave?.status === 'rejected', 'Leave status updated to rejected');

    // 10.5 Non-Super Admin cannot call Super Admin review
    const unauthReviewRes = await request('PATCH', `/super-admin/leaves/${testLeave2Id}/review`, {
      action: 'approve',
    }, memberToken);
    assert(unauthReviewRes.status === 403, 'Regular member cannot execute super admin leave review (HTTP 403)');

    // 10.6 OBS-PERM-03: Anti-Self-Approval Rule for Super Admin
    const saOwnLeaveId = 'leave_sa_self_001';
    setMemoryLeave({
      id: saOwnLeaveId,
      _id: saOwnLeaveId,
      memberId: PERSONAS.superAdmin.id,
      memberName: PERSONAS.superAdmin.name,
      memberEmail: PERSONAS.superAdmin.email,
      department: 'Administration',
      leaveType: 'Annual',
      startDate: new Date(),
      endDate: new Date(Date.now() + 5 * 86400000),
      reason: 'Executive personal leave',
      status: 'pending',
      createdAt: new Date(),
    });

    // Super Admin attempts to self-approve own leave
    const selfApproveRes = await request('PATCH', `/super-admin/leaves/${saOwnLeaveId}/review`, {
      action: 'approve',
      notes: 'Attempting self-approval',
    }, saToken);

    assert(
      selfApproveRes.status === 403,
      'Super Admin attempting to self-approve own leave is REJECTED with HTTP 403 Forbidden (OBS-PERM-03)'
    );
    assert(
      selfApproveRes.body?.error?.includes('Anti-self-approval rule'),
      'Error message explicitly specifies anti-self-approval rule'
    );

    // Super Admin attempts to self-reject own leave
    const selfRejectRes = await request('PATCH', `/super-admin/leaves/${saOwnLeaveId}/review`, {
      action: 'reject',
      notes: 'Attempting self-rejection',
    }, saToken);

    assert(
      selfRejectRes.status === 403,
      'Super Admin attempting to self-reject own leave is REJECTED with HTTP 403 Forbidden (OBS-PERM-03)'
    );

    // Verify leave status remained pending
    const saOwnLeaveAfter = (require('../src/routes/hr.routes').getMemoryLeavesList() || []).find(
      (l) => (l._id || l.id)?.toString() === saOwnLeaveId
    );
    assert(
      saOwnLeaveAfter?.status === 'pending',
      'Leave status remains pending after blocked self-approval/rejection attempts'
    );

  } finally {
    await stopServer();
  }

  // -------------------------------------------------------------------------
  // FINAL SCORECARD
  // -------------------------------------------------------------------------
  console.log('\n================================================================');
  console.log(`TEST SUITE RESULTS: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log('================================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal Test Exception:', err);
  process.exit(1);
});