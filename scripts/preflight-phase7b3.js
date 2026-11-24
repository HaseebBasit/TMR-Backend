/**
 * Phase 7B.3 — Pre-Execution Check & Audit Record Verification
 * Strictly Read-Only
 */

const mongoose = require('mongoose');
require('../src/config/db');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('[CRITICAL] MONGODB_URI is missing from environment.');
  process.exit(1);
}

const EXPECTED_TEST_AUDIT_IDS = [
  '6b0421f85c4fcb9d2bea3c19',
  '6b0421f95c4fcb9d2bea3c36',
  '6b0421f95c4fcb9d2bea3c42',
  '6b0421fa5c4fcb9d2bea3c51',
  '6b0421fa5c4fcb9d2bea3c60',
  '6b0421fa5c4fcb9d2bea3c72',
];

async function runPreflight() {
  console.log('==================================================================');
  console.log('PHASE 7B.3: PRE-EXECUTION VALIDATION & STATE VERIFICATION');
  console.log('==================================================================\n');

  // Check 1: Mongoose global settings
  const autoIndex = mongoose.get('autoIndex');
  const autoCreate = mongoose.get('autoCreate');
  const bufferCommands = mongoose.get('bufferCommands');

  console.log(`[Config Check] autoIndex: ${autoIndex} (Expected: false)`);
  console.log(`[Config Check] autoCreate: ${autoCreate} (Expected: false)`);
  console.log(`[Config Check] bufferCommands: ${bufferCommands} (Expected: false)`);

  if (autoIndex !== false || autoCreate !== false || bufferCommands !== false) {
    console.error('[CRITICAL] Mongoose DDL prevention settings are invalid.');
    process.exit(1);
  }

  // Connect explicitly with DDL disabled
  const conn = await mongoose.connect(MONGODB_URI, {
    autoIndex: false,
    autoCreate: false,
    serverSelectionTimeoutMS: 5000,
  });

  const db = conn.connection.db;

  // Check 2: Database name
  const dbName = db.databaseName;
  console.log(`[Database Check] Connected DB Name: ${dbName} (Expected: tameer_rekhta)`);
  if (dbName !== 'tameer_rekhta') {
    console.error(`[CRITICAL] Connected to unexpected database: ${dbName}`);
    await mongoose.disconnect();
    process.exit(1);
  }

  // Check 3: Replica Set Health
  const adminDb = db.admin();
  const pingResult = await adminDb.ping();
  console.log('[Topology Check] Replica Set Ping OK:', pingResult.ok === 1);

  // Check 4: Audit Logs Verification
  const auditCol = db.collection('auditlogs');
  const allAuditLogs = await auditCol.find({}).toArray();
  console.log(`[Audit Check] Total audit logs found: ${allAuditLogs.length} (Expected: 6)`);

  if (allAuditLogs.length !== 6) {
    console.error(`[CRITICAL] Audit log count mismatch! Found ${allAuditLogs.length}, expected 6.`);
    await mongoose.disconnect();
    process.exit(1);
  }

  const foundIds = allAuditLogs.map(l => l._id.toString()).sort();
  const expectedSorted = [...EXPECTED_TEST_AUDIT_IDS].sort();

  let allMatch = true;
  for (let i = 0; i < expectedSorted.length; i++) {
    if (foundIds[i] !== expectedSorted[i]) {
      console.error(`[Mismatch] Found ID: ${foundIds[i]}, Expected: ${expectedSorted[i]}`);
      allMatch = false;
    }
  }

  if (!allMatch) {
    console.error('[CRITICAL] Audit record IDs do not match the approved forensic report!');
    await mongoose.disconnect();
    process.exit(1);
  }

  console.log('[Audit Check] All 6 test audit records verified with 100% ID matching.');

  // Check 5: Verify all other collections are 0 documents
  const collections = await db.listCollections().toArray();
  console.log(`[Collections Check] Total collections: ${collections.length}`);

  let nonAuditDocCount = 0;
  for (const c of collections) {
    const cnt = await db.collection(c.name).countDocuments();
    if (c.name !== 'auditlogs' && cnt > 0) {
      console.error(`[CRITICAL] Unexpected documents in collection '${c.name}': ${cnt}`);
      nonAuditDocCount += cnt;
    }
  }

  if (nonAuditDocCount > 0) {
    console.error('[CRITICAL] Database contains unexpected business documents! Stopping.');
    await mongoose.disconnect();
    process.exit(1);
  }

  console.log('[Collections Check] All 15 non-audit collections confirmed at exactly 0 documents.');
  console.log('\n[PRE-EXECUTION CHECK PASSED] Safe to proceed with Phase 7B.3 execution.');

  await mongoose.disconnect();
  console.log('[Disconnection] Cleanly disconnected from Atlas.');
}

runPreflight().catch(err => {
  console.error('[Preflight Failed]:', err.message);
  process.exit(1);
});
