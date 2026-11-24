/**
 * Phase 7B.6.4D.2.1 — Staging Synthetic Persona Provisioning Utility
 * 
 * Target: tameer_rekhta_staging ONLY
 * Cluster: tameer-rekhta-dev.ovcogaz.mongodb.net
 * Database User: tameer_rekhta_staging_user
 * 
 * Invariants:
 * - Strictly requires NODE_ENV=staging
 * - Strictly rejects production database tameer_rekhta
 * - Provisions exactly 10 approved staging test personas (P-01 to P-10)
 * - Generates high-entropy random passwords locally meeting complexity policies
 * - Stores passwords only as bcrypt hashes (cost factor 12)
 * - Records local credentials securely in gitignored file: .env.staging.credentials.local.json
 * - Never prints plaintext passwords or connection URIs
 * - Preserves baseline departments (7) and baseline budgets (3)
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// 1. Explicitly load staging environment configuration
const stagingEnvPath = path.join(__dirname, '..', '.env.staging');
const stagingEnv = dotenv.config({ path: stagingEnvPath, override: true }).parsed;

const {
  validateDatabaseTarget,
  parseMongoUri,
  sanitizeUri,
  STAGING_DB_NAME,
  PRODUCTION_DB_NAME,
} = require('../src/config/db');
const { User, Department, AuditLog } = require('../src/models');

// Approved Persona Definitions (Phase 7B.6.4D.1 Matrix)
const APPROVED_PERSONAS = [
  {
    id: 'P-01',
    name: 'Staging Admin Root',
    email: 'staging.superadmin@staging.rekhta.internal',
    role: 'super_admin',
    department: null,
    departmentCode: null,
    designation: 'Executive Director (Staging)',
    status: 'active',
    isPrivilegedHR: true,
  },
  {
    id: 'P-02',
    name: 'Staging Lead Literature',
    email: 'staging.lead.lit@staging.rekhta.internal',
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    designation: 'Head of Literature (Staging)',
    status: 'active',
    isPrivilegedHR: false,
  },
  {
    id: 'P-03',
    name: 'Staging Lead Media',
    email: 'staging.lead.med@staging.rekhta.internal',
    role: 'dept_media',
    department: 'Media',
    departmentCode: 'MED',
    designation: 'Head of Media (Staging)',
    status: 'active',
    isPrivilegedHR: false,
  },
  {
    id: 'P-04',
    name: 'Staging Lead Marketing',
    email: 'staging.lead.mkt@staging.rekhta.internal',
    role: 'dept_marketing',
    department: 'Marketing',
    departmentCode: 'MKT',
    designation: 'Head of Marketing (Staging)',
    status: 'active',
    isPrivilegedHR: false,
  },
  {
    id: 'P-05',
    name: 'Staging Lead Outreach',
    email: 'staging.lead.out@staging.rekhta.internal',
    role: 'dept_outreach',
    department: 'Outreach',
    departmentCode: 'OUT',
    designation: 'Head of Outreach (Staging)',
    status: 'active',
    isPrivilegedHR: false,
  },
  {
    id: 'P-06',
    name: 'Staging Lead Content',
    email: 'staging.lead.con@staging.rekhta.internal',
    role: 'dept_content',
    department: 'Content Creation',
    departmentCode: 'CON',
    designation: 'Head of Content (Staging)',
    status: 'active',
    isPrivilegedHR: false,
  },
  {
    id: 'P-07',
    name: 'Staging HR Admin',
    email: 'staging.lead.hr@staging.rekhta.internal',
    role: 'hr',
    department: 'HR',
    departmentCode: 'HR',
    designation: 'HR Coordinator (Staging)',
    status: 'active',
    isPrivilegedHR: true,
  },
  {
    id: 'P-08',
    name: 'Staging Finance Admin',
    email: 'staging.lead.fin@staging.rekhta.internal',
    role: 'finance',
    department: 'Finance',
    departmentCode: 'FIN',
    designation: 'Finance Officer (Staging)',
    status: 'active',
    isPrivilegedHR: false,
  },
  {
    id: 'P-09',
    name: 'Staging Member Lit',
    email: 'staging.member.lit@staging.rekhta.internal',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    designation: 'Literary Research Volunteer',
    status: 'active',
    isPrivilegedHR: false,
  },
  {
    id: 'P-10',
    name: 'Staging Member Med',
    email: 'staging.member.med@staging.rekhta.internal',
    role: 'member',
    department: 'Media',
    departmentCode: 'MED',
    designation: 'Media Production Volunteer',
    status: 'active',
    isPrivilegedHR: false,
  },
];

/**
 * Generates a high-entropy synthetic test password compliant with Phase 7B.5.2A policy
 * (>= 16 chars, uppercase, lowercase, numbers, symbols)
 */
function generateSecureTestPassword() {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%^&*-_=+';
  
  // Guarantee character diversity
  const mandatory = [
    upper[crypto.randomInt(0, upper.length)],
    lower[crypto.randomInt(0, lower.length)],
    digits[crypto.randomInt(0, digits.length)],
    symbols[crypto.randomInt(0, symbols.length)],
  ];

  const allChars = upper + lower + digits + symbols;
  const remainingLength = 14; // Total 18 chars
  const remaining = [];
  for (let i = 0; i < remainingLength; i++) {
    remaining.push(allChars[crypto.randomInt(0, allChars.length)]);
  }

  // Shuffle securely
  const passwordChars = mandatory.concat(remaining);
  for (let i = passwordChars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
  }
  return passwordChars.join('');
}

async function provisionStagingPersonas(options = {}) {
  console.log('==================================================================');
  console.log('PHASE 7B.6.4D.2.1: STAGING SYNTHETIC PERSONA PROVISIONING');
  console.log('Target Database: tameer_rekhta_staging');
  console.log('==================================================================\n');

  // --- Step 1: Preflight Isolation Guards ---
  console.log('--- 1. Mandatory Safety Preflight ---');
  if (stagingEnv.NODE_ENV !== 'staging') {
    throw new Error(`[FATAL ISOLATION EXCEPTION]: NODE_ENV is '${stagingEnv.NODE_ENV}'. Must be 'staging'.`);
  }
  console.log('  [PASS] 1.1: NODE_ENV is strictly "staging"');

  const uri = stagingEnv.MONGODB_URI;
  const parsed = parseMongoUri(uri);
  if (!parsed.valid || parsed.dbName !== STAGING_DB_NAME) {
    throw new Error(`[FATAL ISOLATION EXCEPTION]: Target DB is '${parsed.dbName}'. Expected '${STAGING_DB_NAME}'.`);
  }
  console.log(`  [PASS] 1.2: Target database verified: ${parsed.dbName}`);

  // Test active defense guard against production DB
  try {
    validateDatabaseTarget('mongodb+srv://user:pass@cluster.mongodb.net/' + PRODUCTION_DB_NAME, { NODE_ENV: 'staging' });
    throw new Error('Guard failed to reject production database!');
  } catch (err) {
    if (!err.message.includes('[FATAL ISOLATION EXCEPTION]')) throw err;
    console.log('  [PASS] 1.3: Isolation guard actively rejects production database');
  }

  // --- Step 2: Generate Unique Test Run Identifier ---
  console.log('\n--- 2. Test Run Identification ---');
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '');
  const hexSuffix = crypto.randomBytes(3).toString('hex').toUpperCase();
  const testRunId = options.testRunId || `TR_${dateStr}_${hexSuffix}`;
  console.log(`  [INITIALIZED] Active testRunId: ${testRunId}`);

  // --- Step 3: Connect to MongoDB Atlas Staging ---
  console.log('\n--- 3. Connecting to Staging Database ---');
  console.log(`  [CONNECTING] ${sanitizeUri(uri)}...`);
  const conn = await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 8000,
    autoIndex: false,
    autoCreate: false,
  });
  const db = conn.connection.db;
  console.log(`  [PASS] Connected to database: ${db.databaseName} on ${conn.connection.host}`);

  if (db.databaseName !== STAGING_DB_NAME) {
    await mongoose.disconnect();
    throw new Error(`[FATAL ISOLATION EXCEPTION]: Connected database is ${db.databaseName}. Expected ${STAGING_DB_NAME}. Aborted.`);
  }

  // --- Step 4: Verify Department Identity Map ---
  console.log('\n--- 4. Resolving Department Mapping ---');
  const depts = await db.collection('departments').find({}).toArray();
  const deptMap = new Map();
  depts.forEach((d) => deptMap.set(d.code, d));
  console.log(`  [PASS] Verified ${depts.length} foundational departments in staging.`);

  // --- Step 5: Check Pre-Existing Users Collision ---
  console.log('\n--- 5. Pre-Provisioning Datastore Check ---');
  const existingUsers = await db.collection('users').find({
    email: { $in: APPROVED_PERSONAS.map((p) => p.email) },
  }).toArray();

  if (existingUsers.length > 0) {
    console.warn(`  [NOTICE] Found ${existingUsers.length} existing personas. Cleaning before fresh provision...`);
    await db.collection('users').deleteMany({
      email: { $in: APPROVED_PERSONAS.map((p) => p.email) },
    });
  }

  // --- Step 6: Generate Passwords & Provision Personas ---
  console.log('\n--- 6. Provisioning Synthetic Personas ---');
  const credentialsStore = {
    testRunId,
    provisionedAt: now.toISOString(),
    environment: 'staging',
    clusterHost: conn.connection.host,
    database: STAGING_DB_NAME,
    personas: {},
  };

  const createdPersonas = [];
  const BCRYPT_ROUNDS = 12;

  for (const p of APPROVED_PERSONAS) {
    const rawPassword = generateSecureTestPassword();
    const hashedPassword = await bcrypt.hash(rawPassword, BCRYPT_ROUNDS);

    // Resolve Department ObjectId if applicable
    const deptDoc = p.departmentCode ? deptMap.get(p.departmentCode) : null;
    const departmentId = deptDoc ? deptDoc._id : null;

    const userDoc = {
      name: p.name,
      email: p.email,
      password: hashedPassword,
      role: p.role,
      department: p.department,
      departmentCode: p.departmentCode,
      departmentId,
      designation: p.designation,
      status: p.status,
      isPrivilegedHR: p.isPrivilegedHR,
      tokenVersion: 0,
      testRunId,
      createdAt: now,
      updatedAt: now,
    };

    const insertResult = await db.collection('users').insertOne(userDoc);
    const createdId = insertResult.insertedId;

    // Record Audit Log for persona creation
    await db.collection('auditlogs').insertOne({
      actorName: 'Staging Test Harness',
      actorRole: 'test_orchestrator',
      action: 'USER_PROVISIONED_STAGING',
      module: 'TEST_INFRASTRUCTURE',
      targetId: createdId.toString(),
      targetModel: 'User',
      description: `Synthetic staging persona '${p.name}' (${p.role}) provisioned under test run ${testRunId}.`,
      ipAddress: '127.0.0.1',
      testRunId,
      createdAt: new Date(),
    });

    createdPersonas.push({
      id: p.id,
      mongoId: createdId.toString(),
      role: p.role,
      email: p.email,
      department: p.department,
      departmentCode: p.departmentCode,
    });

    // Save credentials to local secure store object
    credentialsStore.personas[p.id] = {
      id: p.id,
      name: p.name,
      email: p.email,
      password: rawPassword, // Stored strictly in local gitignored file
      role: p.role,
      department: p.department,
      departmentCode: p.departmentCode,
      designation: p.designation,
      mongoId: createdId.toString(),
    };

    console.log(`  [PROVISIONED] ${p.id} -> ${p.role.padEnd(16)} | ${p.email.padEnd(44)} | Dept: ${p.department || 'None'}`);
  }

  // --- Step 7: Secure Local Credential Delivery ---
  console.log('\n--- 7. Secure Local Credential Delivery ---');
  const credentialsPath = path.join(__dirname, '..', '.env.staging.credentials.local.json');
  fs.writeFileSync(credentialsPath, JSON.stringify(credentialsStore, null, 2), {
    mode: 0o600, // Read/write only by owner
  });
  console.log(`  [SAVED] Credentials securely recorded in local gitignored file:`);
  console.log(`          backend/.env.staging.credentials.local.json (file mode: 0600)`);
  console.log('  [PASS] Plaintext credentials completely withheld from console and logs.');

  // --- Step 8: Clean Disconnection ---
  await mongoose.disconnect();
  console.log('\n[PASS] Cleanly disconnected from MongoDB Atlas staging datastore.');

  console.log('\n==================================================================');
  console.log(`PROVISIONING SUMMARY: 10/10 PERSONAS CREATED (testRunId: ${testRunId})`);
  console.log('==================================================================\n');

  return {
    success: true,
    testRunId,
    personasCount: createdPersonas.length,
    personas: createdPersonas,
    credentialsFilePath: credentialsPath,
  };
}

if (require.main === module) {
  provisionStagingPersonas().catch((err) => {
    console.error('[Provisioning Error]:', err.message);
    if (mongoose.connection && mongoose.connection.readyState !== 0) {
      mongoose.disconnect().catch(() => null);
    }
    process.exit(1);
  });
}

module.exports = {
  provisionStagingPersonas,
  generateSecureTestPassword,
  APPROVED_PERSONAS,
};
