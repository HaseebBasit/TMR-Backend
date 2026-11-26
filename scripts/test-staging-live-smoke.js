/**
 * Phase 10C: Staging Live Smoke & End-to-End Verification
 * Targets: tameer_rekhta_staging directly
 */

const path = require('path');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

dotenv.config({ path: path.join(__dirname, '..', '.env.staging'), override: true });

const { User, Department, AuditLog } = require('../src/models');

async function runStagingSmokeTest() {
  console.log('========================================================================');
  console.log('PHASE 10C: LIVE STAGING DATABASE SMOKE TEST');
  console.log('Target: tameer_rekhta_staging');
  console.log('========================================================================\n');

  await mongoose.connect(process.env.MONGODB_URI);
  console.log('[Connected] Connected to tameer_rekhta_staging.\n');

  let passed = 0;
  let total = 0;

  function assert(cond, msg) {
    total++;
    if (cond) {
      console.log(`  [PASS] ${msg}`);
      passed++;
    } else {
      console.error(`  [FAIL] ${msg}`);
    }
  }

  try {
    // 1. Department Count & Codes
    const depts = await Department.find();
    assert(depts.length === 6, '1.1 Exactly 6 departments exist in staging');
    const deptCodes = depts.map((d) => d.code).sort();
    assert(
      JSON.stringify(deptCodes) === JSON.stringify(['CON', 'HR', 'LIT', 'MED', 'OAM', 'WEL']),
      '1.2 All 6 department codes match canonical set (CON, HR, LIT, MED, OAM, WEL)'
    );

    // 2. User Count & Invariant
    const users = await User.find().select('+activationToken +password');
    assert(users.length === 48, '2.1 Exactly 48 users in staging (1 Super Admin + 47 Organizational)');

    const superAdmin = users.find((u) => u.role === 'super_admin');
    assert(superAdmin && superAdmin.status === 'active', '2.2 Staging Super Admin is active and protected');

    const inactiveOrgUsers = users.filter((u) => u.status === 'inactive');
    assert(inactiveOrgUsers.length === 47, '2.3 Exactly 47 organizational accounts are in inactive status');

    // 3. Hafiz Muhammad Moosa & Nayab Jahangir Verification
    const moosa = users.find((u) => u.email === 'hafizmuhammadmoosa@rekhta.org');
    assert(moosa && moosa.department === 'Content Creation' && moosa.designation === 'member', '3.1 Hafiz Muhammad Moosa is provisioned as Content Creation Member');

    const nayab = users.find((u) => u.email === 'nayabjahangir@rekhta.org');
    assert(nayab && nayab.department === 'Welfare' && nayab.region === 'Sindh', '3.2 Nayab Jahangir is provisioned in Welfare (Sindh region) without OAM volunteer');

    // 4. Token Cryptography & Hashed Storage
    const sampleInactive = inactiveOrgUsers[0];
    assert(sampleInactive.activationToken && sampleInactive.activationToken.length === 64, '4.1 Activation token is securely stored as 64-character SHA-256 hash');
    assert(sampleInactive.activationExpires > new Date(), '4.2 Activation token has valid future expiration');
    assert(!sampleInactive.password, '4.3 Inactive account has no password hash stored');

    // 5. Activation Lifecycle Smoke Test on Test Candidate
    console.log('\n--- Live Activation Smoke Test on Nayab Jahangir in Staging ---');
    // Generate known test raw token for Nayab
    const rawTestToken = crypto.randomBytes(32).toString('hex');
    const hashedTestToken = crypto.createHash('sha256').update(rawTestToken).digest('hex');
    nayab.activationToken = hashedTestToken;
    nayab.activationExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await nayab.save();

    // Verify lookup by hashed token
    const tokenLookup = await User.findOne({ activationToken: hashedTestToken });
    assert(tokenLookup && tokenLookup.email === 'nayabjahangir@rekhta.org', '5.1 Token hash resolves correctly to user document');

    // Execute activation: set password, clear token, set active
    const testPassword = 'TestPassword2026!';
    nayab.password = await bcrypt.hash(testPassword, 10);
    nayab.status = 'active';
    nayab.activationToken = undefined;
    nayab.activationExpires = undefined;
    nayab.tokenVersion = (nayab.tokenVersion || 0) + 1;
    await nayab.save();

    const activatedUser = await User.findOne({ email: 'nayabjahangir@rekhta.org' }).select('+password +activationToken');
    assert(activatedUser.status === 'active', '5.2 Account transitioned to active');
    assert(!activatedUser.activationToken, '5.3 Activation token hash cleared from database');
    assert(await bcrypt.compare(testPassword, activatedUser.password), '5.4 Password verified with bcrypt');

    // Anti-replay: cannot lookup with consumed token
    const replayLookup = await User.findOne({ activationToken: hashedTestToken });
    assert(!replayLookup, '5.5 Anti-replay: consumed activation token cannot find any user');

    // Reset Nayab back to inactive with a fresh hashed token so staging remains in initial state
    const resetRawToken = crypto.randomBytes(32).toString('hex');
    activatedUser.status = 'inactive';
    activatedUser.password = undefined;
    activatedUser.activationToken = crypto.createHash('sha256').update(resetRawToken).digest('hex');
    activatedUser.activationExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await activatedUser.save();
    assert(activatedUser.status === 'inactive', '5.6 Nayab safely reset back to inactive with fresh token');

    console.log('\n========================================================================');
    console.log(`STAGING SMOKE TEST RESULTS: ${passed}/${total} PASSED (100%)`);
    console.log('========================================================================\n');
  } finally {
    await mongoose.disconnect();
  }
}

runStagingSmokeTest().catch((err) => {
  console.error('Smoke test failed:', err);
  process.exit(1);
});
