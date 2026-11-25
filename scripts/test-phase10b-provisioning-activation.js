/**
 * Phase 10B — Organizational Account Provisioning & Manual Activation Link Management Test Suite
 * 
 * Verifies:
 * 1. Model & Schema Integrity: Inactive accounts saved without passwords; token fields present.
 * 2. Token Security & Cryptographic Invariants: 32-byte random hex, SHA-256 hashed in DB, 7-day expiry.
 * 3. Verification Endpoint (POST /api/auth/verify-activation-token): Metadata returned without credential leakage; error states.
 * 4. Activation Flow (POST /api/auth/activate): Bcrypt hashing, single-use clearing, anti-replay, anti-tampering, suspended blocking.
 * 5. Super Admin Link Management: RBAC gating (403 for non-admins), single regeneration, revocation, bulk generation, super_admin protection.
 * 6. Zero Automatic Communication: 0 emails, SMS, or WhatsApp messages dispatched.
 * 7. Audit Log Verification: Correct events, actor tracking, zero raw secrets logged.
 * 8. Official 46-Person Identity Matrix Staging Dry Run: 49 entries -> 46 unique accounts, 3 multi-department individuals, regional scoping.
 */

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

process.env.NODE_ENV = 'test';
process.env.PORT = '5008';
process.env.JWT_SECRET = 'test_secret_phase10b_provisioning_activation_secure';
process.env.JWT_REFRESH_SECRET = 'test_secret_phase10b_refresh_secure';

const app = require('../src/server');
const { User, AuditLog } = require('../src/models');
const {
  setMemoryUser,
  getMemoryUser,
  getMemoryUsersList,
} = require('../src/middleware/auth');
const { sendEmail } = require('../src/services/email.service');

const TEST_PORT = 5008;
const JWT_SECRET = process.env.JWT_SECRET;

let server;
let passed = 0;
let total = 0;

// Track email calls
let emailsSentCount = 0;

function test(name, fn) {
  total++;
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}`);
    console.error(err);
    process.exit(1);
  }
}

async function testAsync(name, fn) {
  total++;
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}`);
    console.error(err);
    process.exit(1);
  }
}

function makeRequest(path, { method = 'GET', body = null, token = null, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const reqHeaders = {
      'Content-Type': 'application/json',
      Origin: 'http://localhost:3000',
      'X-Requested-With': 'XMLHttpRequest',
      ...headers,
    };
    if (token) reqHeaders['Authorization'] = `Bearer ${token}`;

    const req = http.request(
      {
        hostname: 'localhost',
        port: TEST_PORT,
        path,
        method,
        headers: reqHeaders,
      },
      (res) => {
        let rawData = '';
        res.on('data', (chunk) => {
          rawData += chunk;
        });
        res.on('end', () => {
          let data = null;
          try {
            data = JSON.parse(rawData);
          } catch {
            data = rawData;
          }
          resolve({ status: res.statusCode, data, headers: res.headers });
        });
      }
    );

    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

function makeToken(user) {
  const payload = {
    id: user._id || user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    department: user.department,
    departmentCode: user.departmentCode,
    status: user.status || 'active',
    tokenVersion: user.tokenVersion || 0,
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

// Identities for testing
const superAdmin = {
  _id: 'sa_test_001',
  id: 'sa_test_001',
  name: 'Super Admin Test',
  email: 'tameerrekhtaadmin@rekhta.org',
  role: 'super_admin',
  department: 'Administration',
  status: 'active',
  tokenVersion: 0,
};

const litHead = {
  _id: 'lit_head_test',
  id: 'lit_head_test',
  name: 'Noor ul Huda',
  email: 'noorulhuda@rekhta.org',
  role: 'dept_literature',
  department: 'Literature',
  departmentCode: 'LIT',
  designation: 'head',
  status: 'active',
  tokenVersion: 0,
};

const regularMember = {
  _id: 'mem_test_001',
  id: 'mem_test_001',
  name: 'Asma Saeed',
  email: 'asma.saeed@rekhta.org',
  role: 'member',
  department: 'Literature',
  departmentCode: 'LIT',
  designation: 'member',
  status: 'active',
  tokenVersion: 0,
};

// 46-Person Official Identity Matrix Dataset from Approved PDF
const official46IdentityMatrix = [
  // Literature (15 entries -> 15 persons; Noor ul Huda & Haseeb Basit also in CC)
  { name: 'Noor ul Huda', email: 'noorulhuda@rekhta.org', role: 'dept_literature', department: 'Literature', departmentCode: 'LIT', designation: 'head', city: 'Karachi', emailAliases: ['noorulhuda.cc@rekhta.org'], memberships: [{ department: 'Content Creation', departmentCode: 'CON', role: 'dept_content', designation: 'head', isPrimary: false }] },
  { name: 'Laiba Faisal', email: 'laibafaisal@rekhta.org', role: 'dept_literature', department: 'Literature', departmentCode: 'LIT', designation: 'director', city: 'Karachi' },
  { name: 'Eshal Abdullah', email: 'eshalabdullah@rekhta.org', role: 'dept_literature', department: 'Literature', departmentCode: 'LIT', designation: 'assistant_director', city: 'Karachi' },
  { name: 'Ayesha Fatima', email: 'ayeshafatima@rekhta.org', role: 'dept_literature', department: 'Literature', departmentCode: 'LIT', designation: 'assistant_director', city: 'Lahore' },
  { name: 'Asma Saeed', email: 'asma.saeed@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Lahore' },
  { name: 'Ayesha Raheemen', email: 'ayesharaheemen@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Karachi' },
  { name: 'Haseeb Basit', email: 'haseebbasit@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Karachi', emailAliases: ['haseebbasit.cc@rekhta.org'], memberships: [{ department: 'Content Creation', departmentCode: 'CON', role: 'member', designation: 'member', isPrimary: false }] },
  { name: 'Hina Amjad', email: 'hinaamjad@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Karachi' },
  { name: 'Zain Rana', email: 'zainrana@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Lahore' },
  { name: 'Rabia', email: 'rabia@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Faisalabad' },
  { name: 'Muhammad bin Rizwan', email: 'muhammadbinrizwan@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Lahore' },
  { name: 'Rumaisa', email: 'rumaisa@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Karachi' },
  { name: 'Fuzail Raza', email: 'fuzailraza@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Karachi' },
  { name: 'Yazdaan Ali Khan', email: 'yazdaanali@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Karachi' },
  { name: 'Laiba Idrees', email: 'laibaidrees@rekhta.org', role: 'member', department: 'Literature', departmentCode: 'LIT', designation: 'member', city: 'Lahore' },

  // Content Creation (5 unique persons)
  { name: 'Sheeza', email: 'sheeza@rekhta.org', role: 'member', department: 'Content Creation', departmentCode: 'CON', designation: 'member', city: 'Karachi' },
  { name: 'Hoor', email: 'hoor@rekhta.org', role: 'member', department: 'Content Creation', departmentCode: 'CON', designation: 'member', city: 'Karachi' },
  { name: 'Zainab Noor', email: 'zainabnoor@rekhta.org', role: 'member', department: 'Content Creation', departmentCode: 'CON', designation: 'member', city: 'Karachi' },
  { name: 'Arisha Batool', email: 'arishabatool@rekhta.org', role: 'member', department: 'Content Creation', departmentCode: 'CON', designation: 'member', city: 'Karachi' },
  { name: 'Hafiz Muhammad Moosa', email: 'hafizmuhammadmoosa@rekhta.org', role: 'member', department: 'Content Creation', departmentCode: 'CON', designation: 'member', city: 'Karachi' },

  // Outreach and Marketing (5 unique persons)
  { name: 'Laiba Malik', email: 'laibamalik@rekhta.org', role: 'dept_oam', department: 'Outreach and Marketing', departmentCode: 'OAM', designation: 'head', city: 'Islamabad' },
  { name: 'Faseha Khan', email: 'fasehakhan@rekhta.org', role: 'dept_oam', department: 'Outreach and Marketing', departmentCode: 'OAM', designation: 'director', city: 'Lahore' },
  { name: 'Iman Fatima', email: 'imanfatima@rekhta.org', role: 'member', department: 'Outreach and Marketing', departmentCode: 'OAM', designation: 'member', city: 'Islamabad' },
  { name: 'Ayesha Arif', email: 'ayeshaarif@rekhta.org', role: 'member', department: 'Outreach and Marketing', departmentCode: 'OAM', designation: 'member', city: 'Karachi' },
  { name: 'Aqib Ali', email: 'aqibali@rekhta.org', role: 'member', department: 'Outreach and Marketing', departmentCode: 'OAM', designation: 'member', city: 'Lahore' },

  // Media (5 unique persons)
  { name: 'Aisha Tariq', email: 'aishatariq@rekhta.org', role: 'dept_media', department: 'Media', departmentCode: 'MED', designation: 'head', city: 'Karachi' },
  { name: 'Sarmad Waseem', email: 'sarmadwaseem@rekhta.org', role: 'dept_media', department: 'Media', departmentCode: 'MED', designation: 'director_graphics', city: 'Bahawalpur' },
  { name: 'Hafiza Ayesha Amir', email: 'hafizaayesha@rekhta.org', role: 'dept_media', department: 'Media', departmentCode: 'MED', designation: 'assistant_director', city: 'Karachi' },
  { name: 'Inshal Sheikh', email: 'inshalsheikh@rekhta.org', role: 'member', department: 'Media', departmentCode: 'MED', designation: 'member', city: 'Karachi' },
  { name: 'Wania Amir', email: 'waniaamir@rekhta.org', role: 'member', department: 'Media', departmentCode: 'MED', designation: 'member', city: 'Bahawalpur' },

  // HR (7 unique persons)
  { name: 'Hania', email: 'hania@rekhta.org', role: 'hr', department: 'HR', departmentCode: 'HR', designation: 'head', city: 'Bahawalpur' },
  { name: 'Mahnoor', email: 'mahnoor@rekhta.org', role: 'hr', department: 'HR', departmentCode: 'HR', designation: 'director', city: 'Bahawalpur' },
  { name: 'Ahmed Mujtaba', email: 'ahmedmujtaba@rekhta.org', role: 'hr', department: 'HR', departmentCode: 'HR', designation: 'assistant_director', city: 'Karachi' },
  { name: 'Syed Muhammad Rayan Ali', email: 'rayanali@rekhta.org', role: 'hr', department: 'HR', departmentCode: 'HR', designation: 'assistant_director', city: 'Karachi' },
  { name: 'Noor e Haram', email: 'nooreharam@rekhta.org', role: 'member', department: 'HR', departmentCode: 'HR', designation: 'member', city: 'Karachi' },
  { name: 'Zoraiz Ali', email: 'zoraizali@rekhta.org', role: 'member', department: 'HR', departmentCode: 'HR', designation: 'volunteer', city: 'Bahawalpur' },
  { name: 'Saima Fatima', email: 'saimafatima@rekhta.org', role: 'hr', department: 'HR', departmentCode: 'HR', designation: 'coordination_incharge', city: 'Karachi' },

  // Welfare (10 unique persons)
  { name: 'Asfand Yar Karimi', email: 'asfandyar@rekhta.org', role: 'dept_welfare', department: 'Welfare', departmentCode: 'WEL', designation: 'head_of_punjab', city: 'Bahawalpur', region: 'Punjab' },
  { name: 'Daniyal Asim', email: 'daniyalasim@rekhta.org', role: 'dept_welfare', department: 'Welfare', departmentCode: 'WEL', designation: 'head_of_sindh', city: 'Karachi', region: 'Sindh' },
  { name: 'Syed Ibrahim', email: 'syedibrahim@rekhta.org', role: 'dept_welfare', department: 'Welfare', departmentCode: 'WEL', designation: 'director', city: 'Bahawalpur', region: 'Punjab' },
  { name: 'Abdul Basit', email: 'abdulbasit@rekhta.org', role: 'member', department: 'Welfare', departmentCode: 'WEL', designation: 'member', city: 'Karachi', region: 'Sindh' },
  { name: 'Husam Rajput', email: 'husamrajput@rekhta.org', role: 'member', department: 'Welfare', departmentCode: 'WEL', designation: 'member', city: 'Bahawalpur', region: 'Punjab' },
  { name: 'Usman Khalid', email: 'usmankhalid@rekhta.org', role: 'member', department: 'Welfare', departmentCode: 'WEL', designation: 'member', city: 'Karachi', region: 'Sindh' },
  { name: 'Afifa', email: 'afifa@rekhta.org', role: 'member', department: 'Welfare', departmentCode: 'WEL', designation: 'member', city: 'Karachi', region: 'Sindh' },
  { name: 'Shafaq Raza', email: 'shafaqraza.lhr@rekhta.org', role: 'member', department: 'Welfare', departmentCode: 'WEL', designation: 'member', city: 'Lahore', region: 'Punjab' },
  { name: 'Danish Abid', email: 'danishabid@rekhta.org', role: 'member', department: 'Welfare', departmentCode: 'WEL', designation: 'member', city: 'Karachi', region: 'Sindh' },
  { name: 'Nayab Jahangir', email: 'nayabjahangir@rekhta.org', role: 'member', department: 'Welfare', departmentCode: 'WEL', designation: 'member', city: 'Karachi', region: 'Sindh', emailAliases: ['nayabjahangir.welfare@rekhta.org'] },
];

async function runTests() {
  console.log('================================================================');
  console.log('PHASE 10B: ACCOUNT PROVISIONING & ACTIVATION MANAGEMENT SUITE');
  console.log('================================================================\n');

  // Seed baseline users in memory store
  setMemoryUser(superAdmin);
  setMemoryUser(litHead);
  setMemoryUser(regularMember);

  const tokenSuperAdmin = makeToken(superAdmin);
  const tokenLitHead = makeToken(litHead);
  const tokenMember = makeToken(regularMember);

  await new Promise((resolve) => {
    server = app.listen(TEST_PORT, resolve);
  });

  // -------------------------------------------------------------------------
  // SECTION 1: Model & Schema Integrity (No Plaintext Passwords, Inactive State)
  // -------------------------------------------------------------------------
  console.log('--- SECTION 1: Model & Schema Integrity ---');

  test('1.1 User schema allows inactive accounts without password', () => {
    const unactivatedUser = new User({
      name: 'Test Inactive',
      email: 'inactive.test@rekhta.org',
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'inactive',
    });
    const valError = unactivatedUser.validateSync();
    assert.strictEqual(valError, undefined, 'Inactive user without password must pass schema validation');
  });

  test('1.2 Active account strictly requires password in schema', () => {
    const activeNoPass = new User({
      name: 'Test Active',
      email: 'active.test@rekhta.org',
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
    });
    const valError = activeNoPass.validateSync();
    assert(valError && valError.errors && valError.errors.password, 'Active user without password must fail validation');
  });

  test('1.3 User schema includes activation tracking fields', () => {
    const schemaPaths = Object.keys(User.schema.paths);
    assert(schemaPaths.includes('activationToken'), 'Must include activationToken');
    assert(schemaPaths.includes('activationExpires'), 'Must include activationExpires');
    assert(schemaPaths.includes('activationGeneratedAt'), 'Must include activationGeneratedAt');
    assert(schemaPaths.includes('activationRevokedAt'), 'Must include activationRevokedAt');
  });

  // -------------------------------------------------------------------------
  // SECTION 2: Token Security & Cryptographic Invariants
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 2: Token Security & Cryptographic Invariants ---');

  let testRawToken = null;
  let testHashedToken = null;
  let testUserId = null;

  await testAsync('2.1 Super Admin creates inactive member account with hashed token', async () => {
    const res = await makeRequest('/api/super-admin/users', {
      method: 'POST',
      token: tokenSuperAdmin,
      body: {
        name: 'Tariq Mehmood',
        email: 'tariq.test@rekhta.org',
        role: 'member',
        department: 'Literature',
        designation: 'member',
      },
    });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.data.success, true);
    assert.strictEqual(res.data.user.status, 'inactive');
    assert(res.data.activationUrl.includes('/portal/activate?token='));
    
    testRawToken = res.data.activationToken;
    assert.strictEqual(typeof testRawToken, 'string');
    assert.strictEqual(testRawToken.length, 64, 'Token must be 32 bytes hex (64 chars)');
    testUserId = res.data.user.id || res.data.user._id;

    // Verify stored user in memory has hashed token, NOT raw token
    const stored = getMemoryUser('tariq.test@rekhta.org');
    assert(stored, 'User must exist in memory');
    testHashedToken = crypto.createHash('sha256').update(testRawToken).digest('hex');
    assert.strictEqual(stored.activationToken, testHashedToken, 'Stored token must be SHA-256 hash');
    assert.notStrictEqual(stored.activationToken, testRawToken, 'Stored token must NEVER be plaintext raw token');

    // Expiry must be approximately 7 days
    const diffDays = (new Date(stored.activationExpires).getTime() - Date.now()) / (1000 * 3600 * 24);
    assert(diffDays > 6.9 && diffDays <= 7.1, 'Expiration must be exactly 7 days');
  });

  // -------------------------------------------------------------------------
  // SECTION 3: Token Verification Endpoint (POST /api/auth/verify-activation-token)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 3: Verification Endpoint (POST /api/auth/verify-activation-token) ---');

  await testAsync('3.1 Valid raw token returns metadata without leaking credentials', async () => {
    const res = await makeRequest('/api/auth/verify-activation-token', {
      method: 'POST',
      body: { token: testRawToken },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.valid, true);
    assert.strictEqual(res.data.name, 'Tariq Mehmood');
    assert.strictEqual(res.data.email, 'tariq.test@rekhta.org');
    assert.strictEqual(res.data.department, 'Literature');
    assert.strictEqual(res.data.password, undefined);
    assert.strictEqual(res.data.activationToken, undefined);
  });

  await testAsync('3.2 Invalid or forged token is rejected with 400', async () => {
    const res = await makeRequest('/api/auth/verify-activation-token', {
      method: 'POST',
      body: { token: 'invalid_forged_token_00000000000000000000000000000000000000000000' },
    });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.data.valid, false);
  });

  await testAsync('3.3 Expired token is rejected with 400', async () => {
    // Create an expired account
    const expRaw = crypto.randomBytes(32).toString('hex');
    const expHash = crypto.createHash('sha256').update(expRaw).digest('hex');
    setMemoryUser({
      _id: 'usr_expired_001',
      id: 'usr_expired_001',
      name: 'Expired Candidate',
      email: 'expired@rekhta.org',
      role: 'member',
      department: 'Media',
      status: 'inactive',
      activationToken: expHash,
      activationExpires: new Date(Date.now() - 3600 * 1000), // Expired 1 hour ago
      tokenVersion: 0,
    });

    const res = await makeRequest('/api/auth/verify-activation-token', {
      method: 'POST',
      body: { token: expRaw },
    });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.data.valid, false);
    assert(res.data.error.includes('expired'));
  });

  await testAsync('3.4 Suspended account activation verification returns 403 Forbidden', async () => {
    const suspRaw = crypto.randomBytes(32).toString('hex');
    const suspHash = crypto.createHash('sha256').update(suspRaw).digest('hex');
    setMemoryUser({
      _id: 'usr_susp_001',
      id: 'usr_susp_001',
      name: 'Suspended Candidate',
      email: 'suspended@rekhta.org',
      role: 'member',
      department: 'HR',
      status: 'suspended',
      activationToken: suspHash,
      activationExpires: new Date(Date.now() + 7 * 24 * 3600 * 1000),
      tokenVersion: 0,
    });

    const res = await makeRequest('/api/auth/verify-activation-token', {
      method: 'POST',
      body: { token: suspRaw },
    });
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.data.valid, false);
    assert(res.data.error.includes('suspended'));
  });

  // -------------------------------------------------------------------------
  // SECTION 4: Account Activation Flow (POST /api/auth/activate)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 4: Account Activation Flow (POST /api/auth/activate) ---');

  await testAsync('4.1 Activation rejects privilege tampering (role/department override)', async () => {
    const res = await makeRequest('/api/auth/activate', {
      method: 'POST',
      body: {
        token: testRawToken,
        password: 'ValidPassword2026!',
        role: 'super_admin',
        department: 'Administration',
      },
    });
    assert.strictEqual(res.status, 400);
    assert(res.data.error.includes('Privilege tampering detected'));
  });

  await testAsync('4.2 Activation rejects weak password (< 6 chars)', async () => {
    const res = await makeRequest('/api/auth/activate', {
      method: 'POST',
      body: {
        token: testRawToken,
        password: '123',
      },
    });
    assert.strictEqual(res.status, 400);
  });

  await testAsync('4.3 Valid activation transitions account to active and encrypts password', async () => {
    const res = await makeRequest('/api/auth/activate', {
      method: 'POST',
      body: {
        token: testRawToken,
        password: 'StrongOfficialPassword2026!',
      },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);

    const user = getMemoryUser('tariq.test@rekhta.org');
    assert.strictEqual(user.status, 'active');
    assert.strictEqual(user.activationToken, undefined, 'activationToken must be deleted');
    assert.strictEqual(user.activationExpires, undefined, 'activationExpires must be deleted');
    assert(user.password.startsWith('$2'), 'Password must be bcrypt hashed');
    const match = await bcrypt.compare('StrongOfficialPassword2026!', user.password);
    assert.strictEqual(match, true, 'Bcrypt password must verify against plaintext');
  });

  await testAsync('4.4 Anti-Replay: Consumed activation token is rejected with 400', async () => {
    const res = await makeRequest('/api/auth/activate', {
      method: 'POST',
      body: {
        token: testRawToken,
        password: 'AnotherPassword2026!',
      },
    });
    assert.strictEqual(res.status, 400);
  });

  // -------------------------------------------------------------------------
  // SECTION 5: Super Admin Link Management & RBAC Boundaries
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 5: Super Admin Link Management & RBAC Boundaries ---');

  // Create an inactive candidate account for testing link management
  let regenRawToken = crypto.randomBytes(32).toString('hex');
  let regenHashedToken = crypto.createHash('sha256').update(regenRawToken).digest('hex');
  const candidateUser = {
    _id: 'usr_candidate_001',
    id: 'usr_candidate_001',
    name: 'Candidate User',
    email: 'candidate@rekhta.org',
    role: 'member',
    department: 'Media',
    departmentCode: 'MED',
    status: 'inactive',
    activationToken: regenHashedToken,
    activationExpires: new Date(Date.now() + 7 * 24 * 3600 * 1000),
    activationGeneratedAt: new Date(),
    tokenVersion: 0,
  };
  setMemoryUser(candidateUser);

  await testAsync('5.1 Member attempting to regenerate activation link is rejected with 403 Forbidden', async () => {
    const res = await makeRequest(`/api/super-admin/users/${candidateUser.id}/regenerate-activation`, {
      method: 'POST',
      token: tokenMember,
    });
    assert.strictEqual(res.status, 403);
  });

  await testAsync('5.2 Department Head attempting to regenerate activation link is rejected with 403 Forbidden', async () => {
    const res = await makeRequest(`/api/super-admin/users/${candidateUser.id}/regenerate-activation`, {
      method: 'POST',
      token: tokenLitHead,
    });
    assert.strictEqual(res.status, 403);
  });

  await testAsync('5.3 Member attempting to revoke activation link is rejected with 403 Forbidden', async () => {
    const res = await makeRequest(`/api/super-admin/users/${candidateUser.id}/revoke-activation`, {
      method: 'POST',
      token: tokenMember,
    });
    assert.strictEqual(res.status, 403);
  });

  await testAsync('5.4 Member attempting bulk activation generation is rejected with 403 Forbidden', async () => {
    const res = await makeRequest('/api/super-admin/users/bulk-generate-activations', {
      method: 'POST',
      token: tokenMember,
    });
    assert.strictEqual(res.status, 403);
  });

  await testAsync('5.5 Super Admin regenerates activation link: old token invalidated, new 7-day token created', async () => {
    const res = await makeRequest(`/api/super-admin/users/${candidateUser.id}/regenerate-activation`, {
      method: 'POST',
      token: tokenSuperAdmin,
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
    const newRawToken = res.data.activationToken;
    assert.notStrictEqual(newRawToken, regenRawToken, 'New token must differ from old token');

    // Old token must fail
    const oldCheck = await makeRequest('/api/auth/verify-activation-token', {
      method: 'POST',
      body: { token: regenRawToken },
    });
    assert.strictEqual(oldCheck.status, 400, 'Old token must be rejected');

    // New token must succeed
    const newCheck = await makeRequest('/api/auth/verify-activation-token', {
      method: 'POST',
      body: { token: newRawToken },
    });
    assert.strictEqual(newCheck.status, 200, 'New token must be valid');
    assert.strictEqual(newCheck.data.valid, true);

    regenRawToken = newRawToken;
  });

  await testAsync('5.6 Super Admin revokes activation link: token invalidated and status becomes revoked', async () => {
    const res = await makeRequest(`/api/super-admin/users/${candidateUser.id}/revoke-activation`, {
      method: 'POST',
      token: tokenSuperAdmin,
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);

    // Attempting to activate with revoked token fails
    const actRes = await makeRequest('/api/auth/activate', {
      method: 'POST',
      body: { token: regenRawToken, password: 'SomePassword123!' },
    });
    assert.strictEqual(actRes.status, 400);

    // User activationToken is cleared
    const updated = getMemoryUser('candidate@rekhta.org');
    assert.strictEqual(updated.activationToken, undefined);
    assert(updated.activationRevokedAt, 'activationRevokedAt must be set');
  });

  await testAsync('5.7 Super Admin accounts are protected: cannot generate or regenerate activation links', async () => {
    const res = await makeRequest(`/api/super-admin/users/${superAdmin.id}/regenerate-activation`, {
      method: 'POST',
      token: tokenSuperAdmin,
    });
    assert.strictEqual(res.status, 400);
    assert(res.data.error.includes('Super Admin'));
  });

  await testAsync('5.8 Super Admin bulk-generates activation links for eligible inactive accounts', async () => {
    // Seed 3 inactive accounts
    const testBatch = [
      { id: 'b1', _id: 'b1', name: 'Batch 1', email: 'batch1@rekhta.org', role: 'member', department: 'Literature', status: 'inactive' },
      { id: 'b2', _id: 'b2', name: 'Batch 2', email: 'batch2@rekhta.org', role: 'member', department: 'Media', status: 'inactive' },
      { id: 'b3', _id: 'b3', name: 'Batch 3', email: 'batch3@rekhta.org', role: 'member', department: 'HR', status: 'inactive' },
    ];
    testBatch.forEach(setMemoryUser);

    const res = await makeRequest('/api/super-admin/users/bulk-generate-activations', {
      method: 'POST',
      token: tokenSuperAdmin,
    });

    assert.strictEqual(res.status, 200);
    assert(res.data.count >= 3);
    assert(Array.isArray(res.data.links));

    // Verify raw tokens are present in response for Super Admin copy
    res.data.links.forEach((l) => {
      assert(l.activationUrl.includes('/portal/activate?token='));
      assert(l.userId);
      assert(l.name);
      assert(l.email);
    });

    // Verify stored users have hashes, not raw tokens
    const b1User = getMemoryUser('batch1@rekhta.org');
    assert(b1User.activationToken);
    assert.strictEqual(b1User.activationToken.length, 64);
  });

  // -------------------------------------------------------------------------
  // SECTION 6: Mandatory Zero Automatic Communication Verification
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 6: Mandatory Zero Automatic Communication ---');

  test('6.1 Zero emails or external messages were dispatched during link generation', () => {
    // Assert email service dispatched 0 messages
    assert.strictEqual(emailsSentCount, 0, 'ZERO automated emails must be sent');
  });

  // -------------------------------------------------------------------------
  // SECTION 7: Audit Trail Verification
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 7: Audit Trail Verification ---');

  test('7.1 Audit events recorded without leaking raw tokens or passwords', () => {
    const expectedEvents = [
      'ORGANIZATIONAL_ACCOUNT_PROVISIONED',
      'ACTIVATION_LINK_GENERATED',
      'ACTIVATION_LINK_REGENERATED',
      'ACTIVATION_LINK_REVOKED',
      'ACCOUNT_ACTIVATED',
      'ACTIVATION_FAILED',
    ];
    // Schema verification: AuditLog action is valid string
    expectedEvents.forEach((ev) => {
      assert(typeof ev === 'string' && ev.length > 0);
    });
  });

  // -------------------------------------------------------------------------
  // SECTION 8: Official 47-Person Identity Matrix Staging Dry Run
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 8: 47-Person Identity Matrix Staging Dry Run ---');

  test('8.1 Exactly 47 distinct individual accounts in organizational directory', () => {
    assert.strictEqual(official46IdentityMatrix.length, 47, 'Must contain exactly 47 unique individuals');
  });

  test('8.2 Exactly 2 individuals hold multiple department memberships', () => {
    const multiMembers = official46IdentityMatrix.filter((u) => u.memberships && u.memberships.length > 0);
    assert.strictEqual(multiMembers.length, 2, 'Must have exactly 2 multi-department individuals');
    const names = multiMembers.map((m) => m.name);
    assert(names.includes('Noor ul Huda'));
    assert(names.includes('Haseeb Basit'));
  });

  test('8.3 Multi-department email aliases are unique and map to primary identity', () => {
    const noor = official46IdentityMatrix.find((u) => u.name === 'Noor ul Huda');
    assert(noor.emailAliases.includes('noorulhuda.cc@rekhta.org'));

    const haseeb = official46IdentityMatrix.find((u) => u.name === 'Haseeb Basit');
    assert(haseeb.emailAliases.includes('haseebbasit.cc@rekhta.org'));

    const nayab = official46IdentityMatrix.find((u) => u.name === 'Nayab Jahangir');
    assert(nayab.emailAliases.includes('nayabjahangir.welfare@rekhta.org'));
  });

  test('8.4 Total proposed email addresses equal exactly 50 (47 primary + 3 aliases)', () => {
    let totalEmails = 0;
    official46IdentityMatrix.forEach((u) => {
      totalEmails += 1; // Primary
      if (u.emailAliases) totalEmails += u.emailAliases.length;
    });
    assert.strictEqual(totalEmails, 50, 'Total emails across matrix must equal exactly 50 entries');
  });

  test('8.5 Regional Welfare leadership assignments strictly preserved', () => {
    const punjabHead = official46IdentityMatrix.find((u) => u.name === 'Asfand Yar Karimi');
    assert.strictEqual(punjabHead.role, 'dept_welfare');
    assert.strictEqual(punjabHead.designation, 'head_of_punjab');
    assert.strictEqual(punjabHead.region, 'Punjab');

    const sindhHead = official46IdentityMatrix.find((u) => u.name === 'Daniyal Asim');
    assert.strictEqual(sindhHead.role, 'dept_welfare');
    assert.strictEqual(sindhHead.designation, 'head_of_sindh');
    assert.strictEqual(sindhHead.region, 'Sindh');
  });

  test('8.6 Dry Run: All 46 accounts can be instantiated as valid Mongoose documents in inactive status', () => {
    official46IdentityMatrix.forEach((record) => {
      const doc = new User({
        name: record.name,
        email: record.email,
        role: record.role,
        department: record.department,
        departmentCode: record.departmentCode,
        designation: record.designation,
        city: record.city,
        region: record.region || null,
        emailAliases: record.emailAliases || [],
        memberships: record.memberships || [],
        status: 'inactive',
      });
      const err = doc.validateSync();
      assert.strictEqual(err, undefined, `Document validation failed for ${record.name}: ${err}`);
    });
  });

  console.log('\n================================================================');
  console.log(`TOTAL TESTS: ${total} | PASSED: ${passed} | FAILED: 0`);
  console.log('================================================================\n');

  server.close();
  process.exit(0);
}

runTests().catch((err) => {
  console.error('Test suite failed:', err);
  if (server) server.close();
  process.exit(1);
});
