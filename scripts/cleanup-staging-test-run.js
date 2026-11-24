/**
 * Phase 7B.6.4D.2.1 — Staging Test Run Safe Cleanup Utility
 * 
 * Target: tameer_rekhta_staging ONLY
 * Cluster: tameer-rekhta-dev.ovcogaz.mongodb.net
 * Database User: tameer_rekhta_staging_user
 * 
 * Invariants:
 * - Strictly requires NODE_ENV=staging
 * - Strictly rejects production database tameer_rekhta
 * - Requires explicit, valid testRunId (Format: TR_YYYYMMDD_[A-Z0-9]{6})
 * - PROHIBITS dropDatabase(), dropCollection(), or unrestricted deleteMany({})
 * - Scopes all deletions strictly to { testRunId }
 * - Never modifies or deletes foundational departments (7) or baseline budgets (3)
 */

const path = require('path');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

// Load staging environment configuration
const stagingEnvPath = path.join(__dirname, '..', '.env.staging');
const stagingEnv = dotenv.config({ path: stagingEnvPath, override: true }).parsed;

const {
  validateDatabaseTarget,
  parseMongoUri,
  sanitizeUri,
  STAGING_DB_NAME,
  PRODUCTION_DB_NAME,
} = require('../src/config/db');

async function cleanupStagingTestRun(targetRunId) {
  console.log('==================================================================');
  console.log('TA\'MEER-E-REKHTA: STAGING TEST RUN SAFE CLEANUP');
  console.log('Target Database: tameer_rekhta_staging');
  console.log('==================================================================\n');

  // --- Step 1: Preflight Validation ---
  if (stagingEnv.NODE_ENV !== 'staging') {
    throw new Error(`[FATAL ISOLATION EXCEPTION]: NODE_ENV is '${stagingEnv.NODE_ENV}'. Must be 'staging'.`);
  }

  const uri = stagingEnv.MONGODB_URI;
  const parsed = parseMongoUri(uri);
  if (!parsed.valid || parsed.dbName !== STAGING_DB_NAME) {
    throw new Error(`[FATAL ISOLATION EXCEPTION]: Target DB is '${parsed.dbName}'. Expected '${STAGING_DB_NAME}'.`);
  }

  // Active rejection of production DB
  try {
    validateDatabaseTarget('mongodb+srv://user:pass@cluster.mongodb.net/' + PRODUCTION_DB_NAME, { NODE_ENV: 'staging' });
    throw new Error('Guard failed to reject production database!');
  } catch (err) {
    if (!err.message.includes('[FATAL ISOLATION EXCEPTION]')) throw err;
  }

  // Validate testRunId format strictly
  if (!targetRunId || typeof targetRunId !== 'string') {
    throw new Error('[CLEANUP BLOCKED]: Missing target testRunId.');
  }

  const trimmedRunId = targetRunId.trim();
  const runIdRegex = /^TR_\d{8}_[A-Z0-9]{6}$/;
  if (!runIdRegex.test(trimmedRunId)) {
    throw new Error(`[CLEANUP BLOCKED]: Invalid testRunId format '${trimmedRunId}'. Expected format: TR_YYYYMMDD_[A-Z0-9]{6}`);
  }

  console.log(`  [TARGET] Scoped testRunId for cleanup: ${trimmedRunId}`);

  // --- Step 2: Connect to Staging ---
  console.log(`  [CONNECTING] Connecting to: ${sanitizeUri(uri)}...`);
  const conn = await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 8000,
    autoIndex: false,
    autoCreate: false,
  });
  const db = conn.connection.db;

  if (db.databaseName !== STAGING_DB_NAME) {
    await mongoose.disconnect();
    throw new Error(`[FATAL ISOLATION EXCEPTION]: Connected database is '${db.databaseName}'. Expected '${STAGING_DB_NAME}'.`);
  }
  console.log(`  [CONNECTED] Cleanly connected to: ${db.databaseName}`);

  // --- Step 3: Scoped Deletion Across Collections ---
  console.log('\n--- Executing Targeted Scoped Deletions ---');
  const collectionsToClean = [
    'users',
    'tasks',
    'applications',
    'campaigns',
    'leaverequests',
    'expenses',
    'donations',
    'notifications',
    'assessments',
    'contactinquiries',
    'events',
    'eventregistrations',
    'mediaassets',
    'auditlogs',
  ];

  const results = {};

  for (const colName of collectionsToClean) {
    const col = db.collection(colName);
    // Explicit safety filter: NEVER deleteMany({})
    const filter = { testRunId: trimmedRunId };
    const res = await col.deleteMany(filter);
    results[colName] = res.deletedCount;
    if (res.deletedCount > 0) {
      console.log(`  [CLEANED] Collection '${colName}': deleted ${res.deletedCount} documents matching ${trimmedRunId}`);
    }
  }

  // Special case: Delete temporary budgets matching testRunId (NEVER touch baseline budgets)
  const budgetCleanRes = await db.collection('budgets').deleteMany({
    testRunId: trimmedRunId,
    budgetId: { $regex: /^BDG-STG-/ },
  });
  results.budgets = budgetCleanRes.deletedCount;
  if (budgetCleanRes.deletedCount > 0) {
    console.log(`  [CLEANED] Temporary test budgets: deleted ${budgetCleanRes.deletedCount} documents`);
  }

  // --- Step 4: Verify Foundational Baseline Invariance ---
  console.log('\n--- Verifying Baseline Invariance ---');
  const deptsCount = await db.collection('departments').countDocuments();
  const budgetsCount = await db.collection('budgets').countDocuments();

  if (deptsCount !== 7) {
    throw new Error(`[BASELINE INVARIANCE VIOLATION]: Found ${deptsCount} departments. Expected exactly 7.`);
  }
  console.log(`  [PASS] Foundational departments intact: ${deptsCount}/7`);

  if (budgetsCount !== 3) {
    throw new Error(`[BASELINE INVARIANCE VIOLATION]: Found ${budgetsCount} budgets. Expected exactly 3.`);
  }
  console.log(`  [PASS] Baseline operating budgets intact: ${budgetsCount}/3`);

  // --- Step 5: Disconnect ---
  await mongoose.disconnect();
  console.log('\n[PASS] Cleanly disconnected from MongoDB Atlas staging.');

  console.log('\n==================================================================');
  console.log(`CLEANUP COMPLETED: Scoped purge for ${trimmedRunId} finished.`);
  console.log('==================================================================\n');

  return {
    success: true,
    testRunId: trimmedRunId,
    deletedCounts: results,
    baselineDepartmentsIntact: deptsCount === 7,
    baselineBudgetsIntact: budgetsCount === 3,
  };
}

if (require.main === module) {
  const targetId = process.argv[2];
  if (!targetId) {
    console.error('Usage: node cleanup-staging-test-run.js <testRunId>');
    process.exit(1);
  }
  cleanupStagingTestRun(targetId).catch((err) => {
    console.error('[Cleanup Error]:', err.message);
    if (mongoose.connection && mongoose.connection.readyState !== 0) {
      mongoose.disconnect().catch(() => null);
    }
    process.exit(1);
  });
}

module.exports = { cleanupStagingTestRun };
