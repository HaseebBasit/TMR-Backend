/**
 * Phase 10G Production Provisioning: Finance Head Account
 * 
 * Target: Production Database (tameer_rekhta)
 * Account: Ahmad Maqsood (ahmadmaqsood@rekhta.org)
 * Role: finance
 * Designation: head_of_finance (Head of Finance)
 * Department: Finance (FIN)
 * Account Type: Dedicated Finance Governance Account
 * 
 * Invariants Enforced:
 * 1. Exactly ONE account provisioned.
 * 2. Status set to 'inactive' awaiting single-use cryptographic activation.
 * 3. 7-day expiration on activation token.
 * 4. Only SHA-256 hash stored in database.
 * 5. ZERO automatic communications (no email, SMS, WhatsApp).
 * 6. Super Admin audit log recorded.
 * 7. Verification test performed against live DB.
 */

const crypto = require('crypto');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('[ERROR] MONGODB_URI not found in environment.');
  process.exit(1);
}

const PRODUCTION_PORTAL_URL = 'https://tameer-e-rekhta.vercel.app';

async function provisionFinanceHead() {
  console.log('========================================================================');
  console.log('PHASE 10G: FINANCE HEAD PRODUCTION ACCOUNT PROVISIONING');
  console.log('========================================================================\n');

  console.log('[1/7] Connecting to MongoDB Atlas...');
  const conn = await mongoose.connect(MONGODB_URI);
  const db = conn.connection.db;

  const dbName = conn.connection.name;
  console.log(`      Target Database: ${dbName}`);
  if (dbName !== 'tameer_rekhta') {
    throw new Error(`Safety Gate Failed: Connected database '${dbName}' is NOT 'tameer_rekhta'.`);
  }

  // Pre-flight checks
  console.log('[2/7] Pre-flight Roster & Safety Verification...');
  const usersCollection = db.collection('users');
  const auditCollection = db.collection('auditlogs');
  const deptsCollection = db.collection('departments');

  const initialUserCount = await usersCollection.countDocuments();
  const deptCount = await deptsCollection.countDocuments();
  console.log(`      Current Total Users: ${initialUserCount}`);
  console.log(`      Current Official Departments: ${deptCount}`);

  if (deptCount !== 6) {
    throw new Error(`Safety Gate Failed: Expected exactly 6 official departments, found ${deptCount}.`);
  }

  // Check if Ahmad Maqsood already exists
  const targetEmail = 'ahmadmaqsood@rekhta.org';
  const existingUser = await usersCollection.findOne({ email: targetEmail.toLowerCase() });
  if (existingUser) {
    throw new Error(`Safety Gate Failed: Account for '${targetEmail}' already exists (ID: ${existingUser._id}).`);
  }

  // Check if any other user has role: 'finance'
  const existingFinance = await usersCollection.countDocuments({ role: 'finance' });
  if (existingFinance > 0) {
    throw new Error(`Safety Gate Failed: Found ${existingFinance} existing finance account(s). Exactly ONE authorized.`);
  }

  // Generate Cryptographic Activation Token
  console.log('[3/7] Generating Cryptographic Activation Credentials...');
  const rawActivationToken = crypto.randomBytes(32).toString('hex');
  const hashedActivationToken = crypto.createHash('sha256').update(rawActivationToken).digest('hex');
  const now = new Date();
  const activationExpires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  console.log(`      Generated At: ${now.toISOString()}`);
  console.log(`      Expires At:   ${activationExpires.toISOString()} (7 Days)`);
  console.log(`      Raw Token Length: ${rawActivationToken.length} characters (CSPRNG 256-bit)`);
  console.log(`      Hashed Token (SHA-256): ${hashedActivationToken.substring(0, 16)}...${hashedActivationToken.substring(48)}`);

  // Build Finance Head Account Document
  console.log('[4/7] Constructing Finance Head User Document...');
  const financeHeadDoc = {
    name: 'Ahmad Maqsood',
    email: targetEmail.toLowerCase(),
    role: 'finance',
    department: 'Finance',
    departmentCode: 'FIN',
    designation: 'head_of_finance',
    status: 'inactive',
    activationToken: hashedActivationToken,
    activationExpires,
    activationGeneratedAt: now,
    tokenVersion: 0,
    isPrivilegedHR: false,
    memberships: [
      {
        department: 'Finance',
        departmentCode: 'FIN',
        role: 'finance',
        designation: 'head_of_finance',
        isPrimary: true,
      },
    ],
    createdAt: now,
    updatedAt: now,
  };

  // Insert into Production Database
  console.log('[5/7] Inserting Document into Production tameer_rekhta Database...');
  const insertResult = await usersCollection.insertOne(financeHeadDoc);
  const provisionedId = insertResult.insertedId;
  console.log(`      Provisioned MongoDB _id: ${provisionedId}`);

  // Create Super Admin Audit Log
  const superAdmin = await usersCollection.findOne({ role: 'super_admin' });
  await auditCollection.insertOne({
    actorId: superAdmin?._id || 'usr_super_admin',
    actorName: superAdmin?.name || 'Super Administrator',
    actorRole: 'super_admin',
    action: 'FINANCE_HEAD_PROVISIONED',
    module: 'SUPER_ADMIN',
    targetId: provisionedId.toString(),
    targetModel: 'User',
    description: `Phase 10G: Provisioned single authorized Finance Head account for Ahmad Maqsood (${targetEmail}) with 7-day activation link.`,
    timestamp: now,
  });
  console.log('      Audit Log Created: Action=FINANCE_HEAD_PROVISIONED, Module=SUPER_ADMIN');

  // Verify Insertion via Database Query
  console.log('[6/7] Verifying Live Record & Token Hash Integrity...');
  const liveRecord = await usersCollection.findOne({ _id: provisionedId });
  if (!liveRecord) {
    throw new Error('Verification Failed: Record could not be retrieved after insert.');
  }

  if (liveRecord.status !== 'inactive') throw new Error('Verification Failed: Status is not inactive.');
  if (liveRecord.role !== 'finance') throw new Error('Verification Failed: Role is not finance.');
  if (liveRecord.department !== 'Finance') throw new Error('Verification Failed: Department is not Finance.');
  if (liveRecord.designation !== 'head_of_finance') throw new Error('Verification Failed: Designation is not head_of_finance.');
  if (liveRecord.activationToken !== hashedActivationToken) throw new Error('Verification Failed: Stored hash mismatch.');
  if (liveRecord.password) throw new Error('Verification Failed: Password field must be unset for inactive account.');

  // Verify Token against Raw Token using SHA-256
  const reHashed = crypto.createHash('sha256').update(rawActivationToken).digest('hex');
  if (reHashed !== liveRecord.activationToken) {
    throw new Error('Verification Failed: Raw token does not match stored hash.');
  }

  const finalUserCount = await usersCollection.countDocuments();
  console.log(`      Final Total Users in DB: ${finalUserCount} (Initial: ${initialUserCount})`);

  // Construct Individual Activation URL
  const individualActivationUrl = `${PRODUCTION_PORTAL_URL}/portal/activate?token=${rawActivationToken}`;

  console.log('\n========================================================================');
  console.log('FINANCE HEAD PROVISIONING COMPLETE & VERIFIED');
  console.log('========================================================================\n');
  console.log(`  Full Name:       ${liveRecord.name}`);
  console.log(`  Email:           ${liveRecord.email}`);
  console.log(`  Role:            ${liveRecord.role}`);
  console.log(`  Department:      ${liveRecord.department} (${liveRecord.departmentCode})`);
  console.log(`  Designation:     Head of Finance (${liveRecord.designation})`);
  console.log(`  Account Status:  ${liveRecord.status.toUpperCase()} (Pending Single-Use Activation)`);
  console.log(`  User ID:         ${liveRecord._id}`);
  console.log(`  Generated At:    ${liveRecord.activationGeneratedAt.toISOString()}`);
  console.log(`  Expires At:      ${liveRecord.activationExpires.toISOString()}`);
  console.log('\n------------------------------------------------------------------------');
  console.log('SUPER ADMIN MANUAL ACTIVATION LINK DELIVERY (CONFIDENTIAL):');
  console.log('------------------------------------------------------------------------');
  console.log(`  Activation URL:  ${individualActivationUrl}`);
  console.log(`  Raw Token:       ${rawActivationToken}`);
  console.log('------------------------------------------------------------------------\n');

  await mongoose.disconnect();
  console.log('[7/7] Database disconnected cleanly.');

  return {
    userId: liveRecord._id.toString(),
    name: liveRecord.name,
    email: liveRecord.email,
    role: liveRecord.role,
    department: liveRecord.department,
    departmentCode: liveRecord.departmentCode,
    designation: 'Head of Finance',
    canonicalDesignation: liveRecord.designation,
    status: liveRecord.status,
    generatedAt: liveRecord.activationGeneratedAt.toISOString(),
    expiresAt: liveRecord.activationExpires.toISOString(),
    activationUrl: individualActivationUrl,
    rawToken: rawActivationToken,
  };
}

if (require.main === module) {
  provisionFinanceHead()
    .then((res) => {
      console.log('Provisioning result output generated.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('[PROVISIONING ERROR]:', err);
      process.exit(1);
    });
}

module.exports = { provisionFinanceHead };
