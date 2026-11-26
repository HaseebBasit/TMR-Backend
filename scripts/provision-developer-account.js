/**
 * Phase 10H Production Provisioning: Dedicated Developer Master Access
 * 
 * Target: Production Database (tameer_rekhta)
 * Account: rekhtadeveloper@rekhta.org
 * Role: developer (Dedicated Developer Master Access)
 * Designation: system_lead (System Lead)
 * Department: Engineering (ENG)
 * Account Type: Confidential system-level developer account
 * 
 * Security Invariants Enforced:
 * 1. Exactly ONE Developer account provisioned.
 * 2. Strong unique password generated via CSPRNG (24 chars, high entropy).
 * 3. Only bcrypt hash stored in database.
 * 4. Plaintext password NEVER printed in logs, git, or reports.
 * 5. One-time Super Admin credential handoff file written to private brain directory.
 * 6. mustChangePassword: true (Enforced on initial login).
 * 7. mfaEnabled: true (TOTP Base32 secret generated, 8 backup recovery codes hashed).
 * 8. Audited in production AuditLog.
 * 9. Super Admin protected from impersonation; zero universal password.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const {
  generateSecret,
  generateOtpAuthUri,
  generateRecoveryCodes,
  hashRecoveryCode,
} = require('../src/services/mfa.service');

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('[ERROR] MONGODB_URI not found in environment.');
  process.exit(1);
}

// Private handoff path outside repository in brain directory
const BRAIN_DIR = 'C:\\Users\\hasee\\.gemini\\antigravity-cli\\brain\\83e545b1-f4df-4dc2-b9b4-f6bb6718c4bf';
const HANDOFF_FILE_PATH = path.join(BRAIN_DIR, 'DEVELOPER_CREDENTIAL_HANDOFF_ONE_TIME.txt');

function generateSecurePassword(length = 24) {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const special = '!@#$%^&*()_+~=';
  const all = upper + lower + digits + special;

  const bytes = crypto.randomBytes(length);
  let pwd = '';
  // Ensure at least one from each required class
  pwd += upper[crypto.randomInt(upper.length)];
  pwd += lower[crypto.randomInt(lower.length)];
  pwd += digits[crypto.randomInt(digits.length)];
  pwd += special[crypto.randomInt(special.length)];

  for (let i = 4; i < length; i++) {
    pwd += all[bytes[i] % all.length];
  }

  // Shuffle using Fisher-Yates with CSPRNG
  const arr = pwd.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

async function provisionDeveloperAccount() {
  console.log('========================================================================');
  console.log('PHASE 10H: DEDICATED DEVELOPER ACCOUNT PRODUCTION PROVISIONING');
  console.log('========================================================================\n');

  console.log('[1/7] Connecting to MongoDB Atlas Production Cluster...');
  const conn = await mongoose.connect(MONGODB_URI);
  const db = conn.connection.db;

  const dbName = conn.connection.name;
  console.log(`      Target Database: ${dbName}`);
  if (dbName !== 'tameer_rekhta') {
    throw new Error(`Safety Gate Failed: Connected database '${dbName}' is NOT 'tameer_rekhta'.`);
  }

  const usersCollection = db.collection('users');
  const auditCollection = db.collection('auditlogs');

  console.log('[2/7] Pre-flight Roster & Safety Verification...');
  const targetEmail = 'rekhtadeveloper@rekhta.org';
  const existingDev = await usersCollection.findOne({ email: targetEmail.toLowerCase() });
  if (existingDev) {
    throw new Error(`Safety Gate Failed: Account for '${targetEmail}' already exists (ID: ${existingDev._id}).`);
  }

  const existingDevCount = await usersCollection.countDocuments({ role: 'developer' });
  if (existingDevCount > 0) {
    throw new Error(`Safety Gate Failed: Found ${existingDevCount} existing developer account(s). Exactly ONE permitted.`);
  }

  const initialUserCount = await usersCollection.countDocuments();
  console.log(`      Current Total Users: ${initialUserCount}`);

  console.log('[3/7] Generating Cryptographic Credentials & MFA Keys...');
  // 1. Password Generation & Hashing
  const rawPassword = generateSecurePassword(24);
  const hashedPassword = await bcrypt.hash(rawPassword, 10);

  // 2. MFA TOTP Secret & Recovery Codes
  const mfaSecret = generateSecret();
  const rawRecoveryCodes = generateRecoveryCodes(8);
  const hashedRecoveryCodes = await Promise.all(rawRecoveryCodes.map(hashRecoveryCode));
  const otpAuthUri = generateOtpAuthUri({
    secret: mfaSecret,
    email: targetEmail,
    issuer: "Ta'meer-e-Rekhta",
  });

  const now = new Date();

  console.log('[4/7] Constructing Developer User Document...');
  const developerDoc = {
    name: 'System Developer',
    email: targetEmail.toLowerCase(),
    role: 'developer',
    department: 'Engineering',
    departmentCode: 'ENG',
    designation: 'system_lead',
    status: 'active',
    password: hashedPassword,
    mustChangePassword: true,
    mfaEnabled: true,
    mfaSecret: mfaSecret,
    mfaRecoveryCodes: hashedRecoveryCodes,
    tokenVersion: 0,
    isPrivilegedHR: false,
    createdAt: now,
    updatedAt: now,
  };

  console.log('[5/7] Inserting Developer Document into Production Database...');
  const insertResult = await usersCollection.insertOne(developerDoc);
  const provisionedId = insertResult.insertedId;
  console.log(`      Provisioned MongoDB _id: ${provisionedId}`);

  // Create Super Admin Audit Log
  const superAdmin = await usersCollection.findOne({ role: 'super_admin' });
  await auditCollection.insertOne({
    actorId: superAdmin?._id || 'usr_super_admin',
    actorName: superAdmin?.name || 'Super Administrator',
    actorRole: 'super_admin',
    action: 'DEVELOPER_ACCOUNT_PROVISIONED',
    module: 'SUPER_ADMIN',
    targetId: provisionedId.toString(),
    targetModel: 'User',
    description: `Phase 10H: Provisioned single dedicated Developer master access account for ${targetEmail}. MFA enabled, password change required on initial login.`,
    timestamp: now,
  });
  console.log('      Audit Log Created: Action=DEVELOPER_ACCOUNT_PROVISIONED, Module=SUPER_ADMIN');

  console.log('[6/7] Writing Confidential One-Time Credential Handoff File...');
  const handoffContent = [
    '========================================================================',
    "TA'MEER-E-REKHTA — CONFIDENTIAL DEVELOPER INITIAL CREDENTIAL HANDOFF",
    '========================================================================',
    `Timestamp:           ${now.toISOString()}`,
    `Account:             rekhtadeveloper@rekhta.org`,
    `Role:                developer (Dedicated Developer Master Access)`,
    `Official Designation: System Lead (system_lead)`,
    `Department:          Engineering (ENG)`,
    `Status:              ACTIVE (Password Change Required on Initial Login)`,
    `User ID:             ${provisionedId}`,
    '------------------------------------------------------------------------',
    'INITIAL ONE-TIME CREDENTIALS (SUPER ADMIN HANDOFF ONLY):',
    '------------------------------------------------------------------------',
    `Initial Password:    ${rawPassword}`,
    `Must Change Password: TRUE (Enforced on first login attempt)`,
    '',
    'MFA / TWO-FACTOR AUTHENTICATION CREDENTIALS:',
    `MFA Enabled:         TRUE (Mandatory RFC 6238 TOTP)`,
    `TOTP Secret (Base32): ${mfaSecret}`,
    `TOTP Authenticator URI:`,
    `${otpAuthUri}`,
    '',
    'BACKUP RECOVERY CODES (SINGLE-USE ONLY):',
    ...rawRecoveryCodes.map((c, i) => `  Code ${i + 1}: ${c}`),
    '------------------------------------------------------------------------',
    'HANDOFF INSTRUCTIONS:',
    '1. Super Admin securely copies and delivers these credentials out-of-band',
    '   to the authorized system developer.',
    '2. Developer scans the TOTP URI into Google Authenticator or Authy.',
    '3. On first login, Developer enters initial password, then TOTP code.',
    '4. System immediately requires Developer to establish a new permanent password.',
    '5. This file should be securely deleted after delivery.',
    '========================================================================',
  ].join('\n');

  fs.writeFileSync(HANDOFF_FILE_PATH, handoffContent, 'utf8');
  console.log(`      Handoff file securely written to: ${HANDOFF_FILE_PATH}`);

  // Verification of stored database record
  const liveRecord = await usersCollection.findOne({ _id: provisionedId });
  if (!liveRecord) throw new Error('Verification Failed: Record could not be retrieved after insert.');
  if (liveRecord.role !== 'developer') throw new Error('Verification Failed: Role is not developer.');
  if (liveRecord.status !== 'active') throw new Error('Verification Failed: Status is not active.');
  if (liveRecord.mustChangePassword !== true) throw new Error('Verification Failed: mustChangePassword must be true.');
  if (liveRecord.mfaEnabled !== true) throw new Error('Verification Failed: mfaEnabled must be true.');
  if (!liveRecord.mfaSecret) throw new Error('Verification Failed: mfaSecret missing.');
  if (liveRecord.mfaRecoveryCodes?.length !== 8) throw new Error('Verification Failed: Expected 8 hashed recovery codes.');

  // Verify bcrypt password verification against stored hash
  const match = await bcrypt.compare(rawPassword, liveRecord.password);
  if (!match) throw new Error('Verification Failed: Password hash mismatch.');

  const finalUserCount = await usersCollection.countDocuments();
  console.log(`      Final Total Users in DB: ${finalUserCount} (Initial: ${initialUserCount})`);

  console.log('\n========================================================================');
  console.log('DEVELOPER MASTER ACCESS PROVISIONING COMPLETE & VERIFIED');
  console.log('========================================================================\n');
  console.log(`  Account Email:       ${liveRecord.email}`);
  console.log(`  Role:                ${liveRecord.role}`);
  console.log(`  Designation:         System Lead (${liveRecord.designation})`);
  console.log(`  Department:          ${liveRecord.department} (${liveRecord.departmentCode})`);
  console.log(`  Status:              ${liveRecord.status.toUpperCase()}`);
  console.log(`  Password Change Req: ${liveRecord.mustChangePassword}`);
  console.log(`  MFA Protected:       ${liveRecord.mfaEnabled}`);
  console.log(`  Recovery Codes:      8 Single-Use Hashed Codes in Database`);
  console.log(`  Handoff Deliverable: [DEVELOPER_CREDENTIAL_HANDOFF_ONE_TIME.txt](file:///${HANDOFF_FILE_PATH.replace(/\\/g, '/')})`);
  console.log('  Plaintext Password:  [CONCEALED — WRITTEN ONLY TO PRIVATE HANDOFF FILE]');

  await mongoose.disconnect();
  console.log('\n[7/7] Database disconnected cleanly.');

  return {
    userId: liveRecord._id.toString(),
    email: liveRecord.email,
    role: liveRecord.role,
    department: liveRecord.department,
    designation: liveRecord.designation,
    status: liveRecord.status,
    mustChangePassword: liveRecord.mustChangePassword,
    mfaEnabled: liveRecord.mfaEnabled,
    handoffFilePath: HANDOFF_FILE_PATH,
  };
}

if (require.main === module) {
  provisionDeveloperAccount()
    .then((res) => {
      console.log('Provisioning execution succeeded.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('[PROVISIONING ERROR]:', err);
      process.exit(1);
    });
}

module.exports = { provisionDeveloperAccount };
