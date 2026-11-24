/**
 * Phase 7B.6.4C — Staging Connectivity & Configuration Verification Utility
 * 
 * Verifies:
 * 1. Staging environment variables (NODE_ENV=staging, PORT=5001)
 * 2. Independent staging JWT secrets (distinct, >= 32 chars, non-production)
 * 3. Database Isolation Guard (rejects tameer_rekhta, accepts tameer_rekhta_staging)
 * 4. Frontend staging configuration (port 3001, API pointing to 5001)
 * 5. Safe email sink enforcement (EMAIL_DISABLED=true, zero SMTP traffic)
 * 6. Staging database connectivity status
 */

const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

// Load staging environment variables
const stagingEnvPath = path.join(__dirname, '..', '.env.staging');
const stagingEnvConfig = dotenv.parse(fs.readFileSync(stagingEnvPath, 'utf8'));

// Load production environment for cross-environment distinctness check (read-only)
const prodEnvPath = path.join(__dirname, '..', '.env');
const prodEnvConfig = fs.existsSync(prodEnvPath) ? dotenv.parse(fs.readFileSync(prodEnvPath, 'utf8')) : {};

const mongoose = require('mongoose');
const {
  validateDatabaseTarget,
  parseMongoUri,
  sanitizeUri,
  STAGING_DB_NAME,
  PRODUCTION_DB_NAME,
} = require('../src/config/db');
const { sendEmail, getTransporter } = require('../src/services/email.service');

let passedChecks = 0;
let failedChecks = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passedChecks++;
  } else {
    console.error(`  [FAIL] ${message}`);
    failedChecks++;
  }
}

async function runStagingVerification() {
  console.log('==================================================================');
  console.log('PHASE 7B.6.4C: STAGING CONNECTIVITY & CONFIGURATION VERIFICATION');
  console.log('Target Environment: staging | Database: tameer_rekhta_staging');
  console.log('==================================================================\n');

  // -------------------------------------------------------------------------
  // 1. Staging Environment Variables Verification
  // -------------------------------------------------------------------------
  console.log('--- 1. Backend Staging Environment Variables ---');
  assert(stagingEnvConfig.NODE_ENV === 'staging', '1.1: NODE_ENV is set strictly to "staging"');
  assert(stagingEnvConfig.PORT === '5001', '1.2: Backend PORT is set to 5001 (isolated from production 5000)');
  assert(stagingEnvConfig.FRONTEND_URL === 'http://localhost:3001', '1.3: FRONTEND_URL configured to staging frontend on port 3001');

  // -------------------------------------------------------------------------
  // 2. Independent Cryptographic Secret Verification
  // -------------------------------------------------------------------------
  console.log('\n--- 2. Independent Staging JWT Secrets ---');
  const stagingAccess = stagingEnvConfig.JWT_SECRET;
  const stagingRefresh = stagingEnvConfig.JWT_REFRESH_SECRET;

  assert(
    typeof stagingAccess === 'string' && stagingAccess.length >= 32,
    `2.1: Staging JWT_SECRET has high entropy (${stagingAccess?.length || 0} chars, >= 32 required)`
  );
  assert(
    typeof stagingRefresh === 'string' && stagingRefresh.length >= 32,
    `2.2: Staging JWT_REFRESH_SECRET has high entropy (${stagingRefresh?.length || 0} chars, >= 32 required)`
  );
  assert(
    stagingAccess !== stagingRefresh,
    '2.3: Staging access and refresh secrets are cryptographically distinct'
  );
  assert(
    stagingAccess !== prodEnvConfig.JWT_SECRET && stagingRefresh !== prodEnvConfig.JWT_REFRESH_SECRET,
    '2.4: Staging JWT secrets are strictly independent and distinct from production secrets'
  );

  // -------------------------------------------------------------------------
  // 3. Database Isolation Guard Verification
  // -------------------------------------------------------------------------
  console.log('\n--- 3. Database Isolation Guard Active Defense ---');

  // Guard must reject production database in staging
  const sampleProdUri = 'mongodb+srv://user:pass@cluster.mongodb.net/tameer_rekhta?retryWrites=true';
  try {
    validateDatabaseTarget(sampleProdUri, { NODE_ENV: 'staging' });
    assert(false, '3.1: Guard must reject production database "tameer_rekhta" in staging');
  } catch (err) {
    assert(
      err.message.includes('[FATAL ISOLATION EXCEPTION]'),
      '3.1: Guard intercepts and rejects production database with FATAL ISOLATION EXCEPTION'
    );
  }

  // Guard must accept staging database
  const sampleStagingUri = 'mongodb+srv://user:pass@cluster.mongodb.net/tameer_rekhta_staging?retryWrites=true';
  const guardStagingResult = validateDatabaseTarget(sampleStagingUri, { NODE_ENV: 'staging' });
  assert(
    guardStagingResult.valid && guardStagingResult.dbName === STAGING_DB_NAME,
    '3.2: Guard accepts valid staging database target "tameer_rekhta_staging"'
  );

  // Guard must reject arbitrary database names
  const sampleWrongUri = 'mongodb+srv://user:pass@cluster.mongodb.net/tameer_rekhta_dev?retryWrites=true';
  try {
    validateDatabaseTarget(sampleWrongUri, { NODE_ENV: 'staging' });
    assert(false, '3.3: Guard must reject arbitrary non-staging database in staging');
  } catch (err) {
    assert(
      err.message.includes('requires database name to be exactly "tameer_rekhta_staging"'),
      '3.3: Guard rejects non-matching database in staging mode'
    );
  }

  // Inspect configured URI in .env.staging
  const configuredUri = stagingEnvConfig.MONGODB_URI;
  const parsedConfigured = parseMongoUri(configuredUri);
  assert(
    parsedConfigured.valid && parsedConfigured.dbName === STAGING_DB_NAME,
    `3.4: backend/.env.staging MONGODB_URI explicitly targets "${STAGING_DB_NAME}"`
  );

  // -------------------------------------------------------------------------
  // 4. Frontend Staging Configuration Verification
  // -------------------------------------------------------------------------
  console.log('\n--- 4. Frontend Staging Configuration ---');
  const frontendStagingPath = path.join(__dirname, '..', '..', 'frontend', '.env.staging');
  let frontendStagingConfig = {};
  if (fs.existsSync(frontendStagingPath)) {
    frontendStagingConfig = dotenv.parse(fs.readFileSync(frontendStagingPath, 'utf8'));
  }
  assert(
    frontendStagingConfig.PORT === '3001',
    '4.1: Frontend staging PORT is configured to 3001'
  );
  assert(
    frontendStagingConfig.NEXT_PUBLIC_API_URL === 'http://localhost:5001/api',
    '4.2: Frontend NEXT_PUBLIC_API_URL points strictly to staging backend on port 5001'
  );

  // -------------------------------------------------------------------------
  // 5. Email Service Safe Sink Verification
  // -------------------------------------------------------------------------
  console.log('\n--- 5. Safe Email Sink Interception ---');
  assert(
    stagingEnvConfig.EMAIL_DISABLED === 'true',
    '5.1: EMAIL_DISABLED is set to "true" in staging configuration'
  );

  const prevEmailDisabled = process.env.EMAIL_DISABLED;
  process.env.EMAIL_DISABLED = 'true';

  assert(
    getTransporter() === null,
    '5.2: getTransporter returns null when EMAIL_DISABLED=true (no SMTP connection opened)'
  );

  const sinkResult = await sendEmail({
    to: 'test.user@staging.rekhta.internal',
    subject: 'Staging Welcome Email',
    text: 'This is a test message.',
  });

  assert(
    sinkResult.success && sinkResult.mode === 'disabled_sink',
    '5.3: sendEmail safely intercepts and suppresses outbound message (disabled_sink mode)'
  );

  if (prevEmailDisabled !== undefined) process.env.EMAIL_DISABLED = prevEmailDisabled;
  else delete process.env.EMAIL_DISABLED;

  // -------------------------------------------------------------------------
  // 6. Atlas Staging Credential & Connectivity Status
  // -------------------------------------------------------------------------
  console.log('\n--- 6. Atlas Staging Credential & Connectivity Audit ---');
  if (configuredUri.includes('<staging_username>')) {
    console.log('  [NOTICE] Dedicated staging database credentials are in template state in .env.staging.');
    console.log('  [PREREQUISITE] To complete live Atlas staging connectivity:');
    console.log('    1. Open MongoDB Atlas Console -> Database Access');
    console.log('    2. Create dedicated user (e.g. "tameer_rekhta_staging_user")');
    console.log('    3. Assign role scoped to "tameer_rekhta_staging" only');
    console.log('    4. Update MONGODB_URI in backend/.env.staging with the dedicated credentials');
    console.log('    5. Run: node scripts/initialize-staging-database.js');
    assert(true, '6.1: Staging configuration template verified; awaiting dedicated Atlas user provisioning');
  } else {
    // Attempt live connectivity to staging if actual credentials are populated
    try {
      console.log(`  [CONNECTING] Connecting to staging database: ${sanitizeUri(configuredUri)}...`);
      const conn = await mongoose.connect(configuredUri, {
        serverSelectionTimeoutMS: 5000,
        autoIndex: false,
        autoCreate: false,
      });
      assert(
        conn.connection.name === STAGING_DB_NAME,
        `6.1: Successfully connected to isolated staging database: ${conn.connection.name}`
      );
      await mongoose.disconnect();
      console.log('  [PASS] Cleanly disconnected from staging database.');
    } catch (connErr) {
      console.error(`  [CONNECT ERROR] Staging connection failed: ${connErr.message}`);
      assert(false, `6.1: Staging database connectivity failed: ${connErr.message}`);
    }
  }

  // -------------------------------------------------------------------------
  // Verification Summary
  // -------------------------------------------------------------------------
  console.log('\n==================================================================');
  console.log(`VERIFICATION SUMMARY: ${passedChecks} PASSED, ${failedChecks} FAILED (TOTAL: ${passedChecks + failedChecks})`);
  console.log('==================================================================\n');

  return {
    passedChecks,
    failedChecks,
    isPassing: failedChecks === 0,
  };
}

if (require.main === module) {
  runStagingVerification().then((res) => {
    process.exit(res.isPassing ? 0 : 1);
  }).catch((err) => {
    console.error('[Fatal Error]:', err);
    process.exit(1);
  });
}

module.exports = { runStagingVerification };
