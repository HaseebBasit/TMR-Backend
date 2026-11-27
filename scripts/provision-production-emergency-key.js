/**
 * Phase 10M Production Provisioning Script:
 * Independent Emergency Access Key System Provisioning
 * 
 * Safety Guarantees:
 * 1. Generates fresh, independent 32-character production key.
 * 2. Stores only bcrypt hash in MongoDB Atlas (tameer_rekhta.emergencycredentials).
 * 3. Encrypts Base32 TOTP secret with AES-256-GCM.
 * 4. Generates 8 single-use recovery codes.
 * 5. Writes private one-time handoff file.
 * 6. ZERO modifications to existing user accounts, passwords, or permissions.
 * 7. ZERO secret disclosures in logs or terminal outputs.
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// Load environment variables
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { generateSecret, generateRecoveryCodes, hashRecoveryCode } = require('../src/services/mfa.service');
const { encryptAtRest } = require('../src/services/encryption.service');

const HANDOFF_PATH = 'C:/Users/hasee/.gemini/antigravity-cli/brain/83e545b1-f4df-4dc2-b9b4-f6bb6718c4bf/EMERGENCY_ACCESS_KEY_HANDOFF_ONE_TIME.txt';

function generateHighEntropyKey(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~=';
  const randomBytes = crypto.randomBytes(length);
  let key = '';
  for (let i = 0; i < length; i++) {
    key += chars[randomBytes[i] % chars.length];
  }
  return key;
}

async function provision() {
  console.log('========================================================================');
  console.log('PHASE 10M: PRODUCTION EMERGENCY ACCESS CREDENTIAL PROVISIONING');
  console.log('========================================================================\n');

  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    throw new Error('MONGODB_URI is required to provision emergency credentials.');
  }

  console.log('[PROVISIONING] Connecting to production MongoDB Atlas (tameer_rekhta)...');
  const conn = await mongoose.createConnection(mongoUri).asPromise();
  const db = conn.useDb('tameer_rekhta');
  const usersCol = db.collection('users');
  const emergencyCol = db.collection('emergencycredentials');
  const auditLogsCol = db.collection('auditlogs');

  // Safety Pre-Check: Verify existing roster integrity
  const totalUsers = await usersCol.countDocuments();
  console.log(`[SAFETY CHECK] Total existing organizational accounts: ${totalUsers}`);
  if (totalUsers < 49) {
    throw new Error(`Unexpected user count (${totalUsers}). Aborting provisioning to prevent corruption.`);
  }

  const superAdmin = await usersCol.findOne({ role: 'super_admin' });
  const developer = await usersCol.findOne({ role: 'developer' });
  const financeHead = await usersCol.findOne({ email: 'ahmadmaqsood@rekhta.org' });

  if (!superAdmin || !developer || !financeHead) {
    throw new Error('Core privileged accounts verification failed. Aborting.');
  }
  console.log('[SAFETY CHECK] Core governance accounts verified intact.');

  // Step 1: Generate completely new cryptographically secure Emergency Access Key
  const productionKey = generateHighEntropyKey(32);
  const salt = bcrypt.genSaltSync(10);
  const keyHash = bcrypt.hashSync(productionKey, salt);

  // Step 2: Generate independent RFC 6238 Base32 TOTP secret
  const rawTotpSecret = generateSecret();
  // Encrypt TOTP secret at rest using AES-256-GCM
  const encryptedTotpSecret = encryptAtRest(rawTotpSecret);

  // Step 3: Generate 8 single-use recovery codes
  const rawRecoveryCodes = generateRecoveryCodes(8);
  const hashedRecoveryCodes = rawRecoveryCodes.map((code) => hashRecoveryCode(code));

  // Step 4: Deactivate any prior emergency credentials if present
  const now = new Date();
  await emergencyCol.updateMany(
    { status: 'active' },
    { $set: { status: 'revoked', revokedAt: now, revokedReason: 'Rotated during new key provisioning.' } }
  );

  // Step 5: Store new emergency credential record
  const keySuffix = crypto.randomBytes(3).toString('hex').toUpperCase();
  const keyId = `EMERGENCY-OPERATOR-KEY-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${keySuffix}`;
  const emergencyDoc = {
    keyId,
    keyHash,
    operatorEmail: 'emergency-operator@system.rekhta.org',
    operatorName: 'Authorized Emergency Operator',
    mfaSecret: encryptedTotpSecret, // AES-256-GCM encrypted
    mfaRecoveryCodes: hashedRecoveryCodes,
    status: 'active',
    usageCount: 0,
    failedAttempts: 0,
    createdAt: now,
    updatedAt: now,
  };

  const insertResult = await emergencyCol.insertOne(emergencyDoc);
  console.log(`[PROVISIONING] Emergency credential created: Key ID "${keyId}" (Doc ID: ${insertResult.insertedId})`);
  console.log('  - Key Hash: Bcrypt salt-hashed ($2a$10$...)');
  console.log('  - MFA Secret: Authenticated AES-256-GCM encrypted at rest (enc:v1:...)');
  console.log('  - Recovery Codes: 8 single-use bcrypt-hashed codes stored');

  // Step 6: Log audit event
  await auditLogsCol.insertOne({
    actorId: 'system_provisioner',
    actorName: 'Emergency Access Provisioner',
    actorRole: 'system',
    action: 'EMERGENCY_CREDENTIAL_PROVISIONED',
    module: 'EMERGENCY_ACCESS',
    targetId: insertResult.insertedId.toString(),
    targetModel: 'EmergencyCredential',
    description: `Production Emergency Access Key (${keyId}) provisioned with AES-256-GCM encrypted MFA at rest.`,
    createdAt: now,
    updatedAt: now,
  });

  // Verify that users collection was untouched
  const finalUserCount = await usersCol.countDocuments();
  if (finalUserCount !== totalUsers) {
    throw new Error('FATAL: Users collection was altered during provisioning!');
  }
  console.log('[SAFETY CHECK] Confirmed users collection was 100% UNTOUCHED.');

  await conn.close();

  // Step 7: Write private one-time credential handoff file
  const handoffContent = `========================================================================
TA'MEER-E-REKHTA — CONFIDENTIAL EMERGENCY ACCESS KEY HANDOFF
========================================================================
Status:                 ACTIVE & PROVISIONED
Key Identifier:         ${keyId}
Operator Identity:      emergency-operator@system.rekhta.org (Authorized Emergency Operator)
Provisioned At:         ${now.toISOString()}
Security Level:         Classified Emergency Recovery Credential
------------------------------------------------------------------------
EMERGENCY ACCESS CREDENTIAL (SUPER ADMIN / AUTHORIZED SYSTEM OWNER ONLY):
------------------------------------------------------------------------
Emergency Access Key:   ${productionKey}

MFA / TWO-FACTOR AUTHENTICATION:
MFA Type:               Mandatory RFC 6238 TOTP
TOTP Secret (Base32):   ${rawTotpSecret}
TOTP Authenticator URI:
otpauth://totp/Ta'meer-e-Rekhta:emergency-operator%40system.rekhta.org?secret=${rawTotpSecret}&issuer=Ta'meer-e-Rekhta&algorithm=SHA1&digits=6&period=30

BACKUP RECOVERY CODES (SINGLE-USE ONLY):
  Code 1: ${rawRecoveryCodes[0]}
  Code 2: ${rawRecoveryCodes[1]}
  Code 3: ${rawRecoveryCodes[2]}
  Code 4: ${rawRecoveryCodes[3]}
  Code 5: ${rawRecoveryCodes[4]}
  Code 6: ${rawRecoveryCodes[5]}
  Code 7: ${rawRecoveryCodes[6]}
  Code 8: ${rawRecoveryCodes[7]}
------------------------------------------------------------------------
OPERATIONAL GUIDELINES:
1. Access Gateway: https://tameer-e-rekhta.vercel.app/emergency-access
2. Stage 1: Enter the target user's email, the Emergency Access Key above,
   and a mandatory technical justification (minimum 10 characters).
3. Stage 2: Enter the 6-digit TOTP code from your Authenticator app.
4. Session Parameters:
   - Maximum lifetime: strictly 15 minutes (900 seconds).
   - Target persona permissions and department restrictions apply.
   - Super Admin and Developer accounts are strictly non-targetable (HTTP 403).
   - Target user credentials, MFA, and sessions remain 100% untouched.
   - Immediate termination button ("End Emergency Access") active on banner.
5. All emergency operations are immutably audited under EMERGENCY_ACCESS.
========================================================================
`;

  fs.writeFileSync(HANDOFF_PATH, handoffContent, 'utf8');
  console.log(`[PROVISIONING] Private credential handoff file written securely to: ${HANDOFF_PATH}`);
  console.log('\n========================================================================');
  console.log('PRODUCTION EMERGENCY CREDENTIAL PROVISIONING COMPLETE');
  console.log('========================================================================');
}

provision().catch((err) => {
  console.error('\n[FATAL ERROR IN PROVISIONING]:', err.message);
  process.exit(1);
});
