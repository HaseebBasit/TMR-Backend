/**
 * Phase 7B.6.4B — Staging Database Isolation Guard & Email Sink Offline Test Suite
 * Mode: Strictly Offline Mock Isolation — Zero Live Database Connections
 * 
 * Verifies:
 * 1. URI Parsing Robustness (Standard, SRV, Replica Sets, Malformed, Missing DB)
 * 2. Staging / Test Isolation Guard (Blocks connection to production tameer_rekhta)
 * 3. Test Live-DB Override Protection (TEST_USE_LIVE_DB=true cannot bypass isolation)
 * 4. Staging Integrity (Requires exact match tameer_rekhta_staging)
 * 5. Production Integrity (Requires exact match tameer_rekhta)
 * 6. Credential Sanitization in Logged Exceptions
 * 7. Global DDL Safety Flags (autoIndex: false, autoCreate: false, bufferCommands: false)
 * 8. Email Service Sink Mode (EMAIL_DISABLED=true intercepts outbound mail)
 */

process.env.NODE_ENV = 'test';

const mongoose = require('mongoose');
const {
  parseMongoUri,
  validateDatabaseTarget,
  sanitizeUri,
  PRODUCTION_DB_NAME,
  STAGING_DB_NAME,
} = require('../src/config/db');
const { sendEmail, getTransporter } = require('../src/services/email.service');

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

async function runIsolationTestSuite() {
  console.log('==================================================================');
  console.log('PHASE 7B.6.4B: STAGING ISOLATION GUARD & OFFLINE SAFETY TESTS');
  console.log('Mode: Isolated Mock Environment (Zero Live Database Connections)');
  console.log('==================================================================\n');

  // =========================================================================
  // 1. URI Parsing Robustness
  // =========================================================================
  console.log('--- 1. MongoDB Connection URI Parsing Robustness ---');

  // 1.1 Standard SRV with query string
  const srvUri = 'mongodb+srv://admin_user:secret123@cluster0.mongodb.net/tameer_rekhta?retryWrites=true&w=majority';
  const parsedSrv = parseMongoUri(srvUri);
  assert(
    parsedSrv.valid && parsedSrv.dbName === 'tameer_rekhta' && parsedSrv.hasExplicitDb,
    'Test 1.1: Standard SRV URI accurately parsed, extracting dbName "tameer_rekhta"'
  );

  // 1.2 Staging SRV with query string
  const stagingSrvUri = 'mongodb+srv://staging_user:pass456@cluster0.mongodb.net/tameer_rekhta_staging?retryWrites=true';
  const parsedStaging = parseMongoUri(stagingSrvUri);
  assert(
    parsedStaging.valid && parsedStaging.dbName === 'tameer_rekhta_staging' && parsedStaging.hasExplicitDb,
    'Test 1.2: Staging SRV URI accurately parsed, extracting dbName "tameer_rekhta_staging"'
  );

  // 1.3 Standard URI with port
  const standardUri = 'mongodb://127.0.0.1:27017/tameer_rekhta_staging';
  const parsedStandard = parseMongoUri(standardUri);
  assert(
    parsedStandard.valid && parsedStandard.dbName === 'tameer_rekhta_staging' && parsedStandard.hasExplicitDb,
    'Test 1.3: Standard local URI accurately parsed'
  );

  // 1.4 Replica set multi-host URI
  const replicaUri = 'mongodb://user:pass@host1:27017,host2:27017/tameer_rekhta?replicaSet=rs0';
  const parsedReplica = parseMongoUri(replicaUri);
  assert(
    parsedReplica.valid && parsedReplica.dbName === 'tameer_rekhta' && parsedReplica.hasExplicitDb,
    'Test 1.4: Multi-host replica set URI accurately parsed without crashing'
  );

  // 1.5 Missing database name with query parameters
  const missingDbUri = 'mongodb+srv://user:pass@cluster0.mongodb.net/?retryWrites=true';
  const parsedMissing = parseMongoUri(missingDbUri);
  assert(
    parsedMissing.valid && parsedMissing.dbName === null && !parsedMissing.hasExplicitDb,
    'Test 1.5: Missing database path correctly detected as hasExplicitDb: false'
  );

  // 1.6 Trailing slash with no database name
  const trailingSlashUri = 'mongodb://localhost:27017/';
  const parsedTrailing = parseMongoUri(trailingSlashUri);
  assert(
    parsedTrailing.valid && parsedTrailing.dbName === null && !parsedTrailing.hasExplicitDb,
    'Test 1.6: Trailing slash without database detected as hasExplicitDb: false'
  );

  // 1.7 Host only (no slash)
  const hostOnlyUri = 'mongodb://localhost:27017';
  const parsedHostOnly = parseMongoUri(hostOnlyUri);
  assert(
    parsedHostOnly.valid && parsedHostOnly.dbName === null && !parsedHostOnly.hasExplicitDb,
    'Test 1.7: Host-only URI without slash detected as hasExplicitDb: false'
  );

  // 1.8 Invalid path with multiple slashes
  const multiSlashUri = 'mongodb://localhost:27017/db/collection/extra';
  const parsedMultiSlash = parseMongoUri(multiSlashUri);
  assert(
    !parsedMultiSlash.valid && parsedMultiSlash.error.includes('invalid slash'),
    'Test 1.8: Path with extra slashes rejected as malformed database name'
  );

  // 1.9 Non-mongo scheme
  const invalidSchemeUri = 'http://localhost:27017/tameer_rekhta';
  const parsedInvalidScheme = parseMongoUri(invalidSchemeUri);
  assert(
    !parsedInvalidScheme.valid && parsedInvalidScheme.error.includes('Invalid connection scheme'),
    'Test 1.9: Non-mongodb scheme strictly rejected'
  );

  // 1.10 Empty string input
  const emptyParsed = parseMongoUri('');
  assert(
    !emptyParsed.valid,
    'Test 1.10: Empty string input rejected'
  );

  // 1.11 Multiple unencoded '@' characters in authority
  const multiAtUri = 'mongodb+srv://staging_user:p@ss@word@cluster.mongodb.net/tameer_rekhta_staging';
  const parsedMultiAt = parseMongoUri(multiAtUri);
  assert(
    !parsedMultiAt.valid && parsedMultiAt.error.includes('multiple unencoded "@" characters detected'),
    'Test 1.11: URI with unencoded "@" in password rejected with descriptive error'
  );

  // =========================================================================
  // 2. Production Database Isolation Guard Tests
  // =========================================================================
  console.log('\n--- 2. Production Database Isolation Guard Tests ---');

  const prodUri = 'mongodb+srv://prod_user:super_secret_password@cluster.mongodb.net/tameer_rekhta?retryWrites=true&w=majority';
  const stagingUri = 'mongodb+srv://staging_user:staging_password@staging.mongodb.net/tameer_rekhta_staging?retryWrites=true&w=majority';

  // 2.1 Production URI rejected in staging mode
  try {
    validateDatabaseTarget(prodUri, { NODE_ENV: 'staging' });
    assert(false, 'Test 2.1: Production URI in staging mode must throw fatal exception');
  } catch (err) {
    assert(
      err.message.includes('[FATAL ISOLATION EXCEPTION]') && err.message.includes('strictly forbidden in STAGING'),
      'Test 2.1: Production URI strictly rejected in staging mode with FATAL ISOLATION EXCEPTION'
    );
  }

  // 2.2 Production URI rejected in test mode
  try {
    validateDatabaseTarget(prodUri, { NODE_ENV: 'test' });
    assert(false, 'Test 2.2: Production URI in test mode must throw fatal exception');
  } catch (err) {
    assert(
      err.message.includes('[FATAL ISOLATION EXCEPTION]') && err.message.includes('strictly forbidden in TEST'),
      'Test 2.2: Production URI strictly rejected in test mode with FATAL ISOLATION EXCEPTION'
    );
  }

  // 2.3 TEST_USE_LIVE_DB=true CANNOT bypass production isolation
  try {
    validateDatabaseTarget(prodUri, { NODE_ENV: 'test', TEST_USE_LIVE_DB: 'true' });
    assert(false, 'Test 2.3: TEST_USE_LIVE_DB=true must NOT bypass production database isolation');
  } catch (err) {
    assert(
      err.message.includes('[FATAL ISOLATION EXCEPTION]'),
      'Test 2.3: TEST_USE_LIVE_DB=true cannot bypass production isolation guard'
    );
  }

  // 2.4 Staging URI accepted in staging mode
  const validStagingResult = validateDatabaseTarget(stagingUri, { NODE_ENV: 'staging' });
  assert(
    validStagingResult.valid && validStagingResult.dbName === STAGING_DB_NAME,
    'Test 2.4: Valid staging URI accepted in staging mode'
  );

  // 2.5 Wrong database name rejected in staging mode (e.g. tameer_rekhta_dev)
  const wrongStagingDbUri = 'mongodb+srv://user:pass@staging.mongodb.net/tameer_rekhta_dev?retryWrites=true';
  try {
    validateDatabaseTarget(wrongStagingDbUri, { NODE_ENV: 'staging' });
    assert(false, 'Test 2.5: Non-staging database name in staging mode must throw fatal exception');
  } catch (err) {
    assert(
      err.message.includes('requires database name to be exactly "tameer_rekhta_staging"'),
      'Test 2.5: Non-staging database name strictly rejected in staging mode'
    );
  }

  // 2.6 Ambiguous/missing database name rejected in staging mode
  const missingDbStagingUri = 'mongodb+srv://user:pass@staging.mongodb.net/?retryWrites=true';
  try {
    validateDatabaseTarget(missingDbStagingUri, { NODE_ENV: 'staging' });
    assert(false, 'Test 2.6: Missing database name in staging mode must throw fatal exception');
  } catch (err) {
    assert(
      err.message.includes('requires database name to be exactly "tameer_rekhta_staging"'),
      'Test 2.6: Missing database path strictly rejected in staging mode'
    );
  }

  // 2.7 Production URI accepted in production mode
  const validProdResult = validateDatabaseTarget(prodUri, { NODE_ENV: 'production' });
  assert(
    validProdResult.valid && validProdResult.dbName === PRODUCTION_DB_NAME,
    'Test 2.7: Production URI targeting "tameer_rekhta" accepted in production mode'
  );

  // 2.8 Staging URI rejected in production mode
  try {
    validateDatabaseTarget(stagingUri, { NODE_ENV: 'production' });
    assert(false, 'Test 2.8: Staging database in production mode must throw critical error');
  } catch (err) {
    assert(
      err.message.includes('requires database name to be exactly "tameer_rekhta"'),
      'Test 2.8: Staging database strictly rejected in production mode'
    );
  }

  // 2.9 Ambiguous/missing database name rejected in production mode
  try {
    validateDatabaseTarget(missingDbStagingUri, { NODE_ENV: 'production' });
    assert(false, 'Test 2.9: Missing database name in production mode must throw critical error');
  } catch (err) {
    assert(
      err.message.includes('requires database name to be exactly "tameer_rekhta"'),
      'Test 2.9: Missing database path strictly rejected in production mode'
    );
  }

  // 2.10 Test-only live DB override accepts tameer_rekhta_test or tameer_rekhta_staging
  const testDbUri = 'mongodb://localhost:27017/tameer_rekhta_test';
  const validTestResult = validateDatabaseTarget(testDbUri, { NODE_ENV: 'test', TEST_USE_LIVE_DB: 'true' });
  assert(
    validTestResult.valid && validTestResult.dbName === 'tameer_rekhta_test',
    'Test 2.10: TEST_USE_LIVE_DB=true permits dedicated test database "tameer_rekhta_test"'
  );

  // =========================================================================
  // 3. Credential Sanitization in Error Logs
  // =========================================================================
  console.log('\n--- 3. Credential Sanitization Verification ---');

  const credentialUri = 'mongodb+srv://super_admin:MyP@ssw0rd!2026@cluster0.mongodb.net/tameer_rekhta';
  const sanitized = sanitizeUri(credentialUri);
  assert(
    !sanitized.includes('MyP@ssw0rd!2026') && sanitized.includes('//***:***@'),
    'Test 3.1: sanitizeUri redacts credentials completely'
  );

  try {
    validateDatabaseTarget(credentialUri, { NODE_ENV: 'staging' });
  } catch (err) {
    assert(
      !err.message.includes('MyP@ssw0rd!2026'),
      'Test 3.2: Fatal exception message does not contain plaintext password'
    );
  }

  // =========================================================================
  // 4. Global DDL Safety Flags
  // =========================================================================
  console.log('\n--- 4. Global DDL Safety Invariants ---');

  assert(mongoose.get('autoIndex') === false, 'Test 4.1: mongoose autoIndex is strictly false');
  assert(mongoose.get('autoCreate') === false, 'Test 4.2: mongoose autoCreate is strictly false');
  assert(mongoose.get('bufferCommands') === false, 'Test 4.3: mongoose bufferCommands is strictly false');

  // =========================================================================
  // 5. Email Service Sink Mode Verification
  // =========================================================================
  console.log('\n--- 5. Email Service Sink Mode Verification ---');

  const prevEmailDisabled = process.env.EMAIL_DISABLED;
  process.env.EMAIL_DISABLED = 'true';

  assert(getTransporter() === null, 'Test 5.1: getTransporter returns null when EMAIL_DISABLED=true');

  const emailResult = await sendEmail({
    to: 'donor@example.com',
    subject: 'Donation Receipt',
    text: 'Thank you for your generous donation.',
  });

  assert(
    emailResult.success && emailResult.mode === 'disabled_sink',
    'Test 5.2: sendEmail suppresses outbound email and returns disabled_sink mode'
  );

  // Restore env
  if (prevEmailDisabled !== undefined) {
    process.env.EMAIL_DISABLED = prevEmailDisabled;
  } else {
    delete process.env.EMAIL_DISABLED;
  }

  // =========================================================================
  // 6. Zero Live Connection Verification
  // =========================================================================
  console.log('\n--- 6. Zero Live Connection Invariant ---');

  assert(
    mongoose.connection.readyState === 0,
    'Test 6.1: Mongoose connection remains strictly disconnected (readyState: 0)'
  );

  // =========================================================================
  // Final Summary
  // =========================================================================
  console.log('\n==================================================================');
  console.log(`TEST SUMMARY: ${passedTests} PASSED, ${failedTests} FAILED (TOTAL: ${passedTests + failedTests})`);
  console.log('==================================================================\n');

  process.exit(failedTests > 0 ? 1 : 0);
}

runIsolationTestSuite().catch((err) => {
  console.error('[Fatal Test Runner Error]:', err);
  process.exit(1);
});
