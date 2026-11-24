/**
 * Phase 7B.5.1 — Super Admin Initialization Script Hardening Test Suite
 * Mode: Strictly Offline Mock Isolation — Zero Database Writes
 */

const { Readable, Writable } = require('stream');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { User, AuditLog } = require('../src/models');
const {
  setupSuperAdmin,
  askHidden,
  validatePasswordPolicy,
  verifyDatabaseState,
  verifyPreflightUniqueness,
  executeTransactionCreation,
  AUTHORIZED_SUPER_ADMIN_EMAIL,
  EXPECTED_DATABASE_NAME,
  MIN_PASSWORD_LENGTH,
  BCRYPT_SALT_ROUNDS,
} = require('./setup-super-admin');

let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passedTests++;
  } else {
    console.error(`  [FAIL] ${message}`);
    failedTests++;
  }
}

async function runHardeningTests() {
  console.log('==================================================================');
  console.log('PHASE 7B.5.1: INITIALIZATION SCRIPT HARDENING & OFFLINE AUDIT');
  console.log('Mode: Isolated Mock Environment (Zero Live Database Mutations)');
  console.log('==================================================================\n');

  // -------------------------------------------------------------------------
  // 1. User Model Inspection: Password Hooks & Double-Hashing Prevention
  // -------------------------------------------------------------------------
  console.log('--- 1. User Model & Double Hashing Audit ---');
  
  // Inspect schema middleware hooks
  const savePres = User.schema.s?.hooks?._pres?.get('save') || [];
  const hasPasswordSaveHook = savePres.some((hook) => hook.fn?.toString().includes('bcrypt') || hook.fn?.name?.includes('password'));
  assert(!hasPasswordSaveHook, 'Test 1.1: User schema has no pre-save bcrypt hook (prevents double-hashing)');

  // Verify manual bcrypt hashing works with salt rounds = 10
  const samplePlain = 'SuperSecurePass2026!';
  const sampleHash = await bcrypt.hash(samplePlain, BCRYPT_SALT_ROUNDS);
  assert(sampleHash.startsWith('$2'), 'Test 1.2: Password correctly hashed with standard bcrypt format');
  assert(await bcrypt.compare(samplePlain, sampleHash), 'Test 1.3: Bcrypt verification confirms password match');
  assert(!(await bcrypt.compare('WrongPass', sampleHash)), 'Test 1.4: Bcrypt correctly rejects wrong password');

  // -------------------------------------------------------------------------
  // 2. AuditLog Schema Inspection & Compatibility
  // -------------------------------------------------------------------------
  console.log('\n--- 2. AuditLog Schema Compatibility ---');

  const auditPaths = AuditLog.schema.paths;
  assert(auditPaths['actorName']?.isRequired, 'Test 2.1: AuditLog enforces actorName as required');
  assert(auditPaths['actorRole']?.isRequired, 'Test 2.2: AuditLog enforces actorRole as required');
  assert(auditPaths['action']?.isRequired, 'Test 2.3: AuditLog enforces action as required');
  assert(auditPaths['module']?.isRequired, 'Test 2.4: AuditLog enforces module as required');
  assert(auditPaths['description']?.isRequired, 'Test 2.5: AuditLog enforces description as required');
  assert(auditPaths['metadata'], 'Test 2.6: AuditLog supports structured metadata object');

  // -------------------------------------------------------------------------
  // 3. Hidden Interactive Prompt Verification (Zero Echo)
  // -------------------------------------------------------------------------
  console.log('\n--- 3. Hidden Terminal Prompt Zero-Echo Verification ---');

  // Mock input stream simulating user typing 'MySecretPassword123\n'
  const mockInput = new Readable({
    read() {
      this.push('MySecretPassword123\n');
      this.push(null);
    },
  });

  let outputBuffer = '';
  const mockOutput = new Writable({
    write(chunk, encoding, callback) {
      outputBuffer += chunk.toString();
      callback();
    },
  });

  const capturedPromptAnswer = await askHidden('Enter Password: ', mockInput, mockOutput);

  assert(capturedPromptAnswer === 'MySecretPassword123', 'Test 3.1: askHidden correctly captures user input');
  assert(!outputBuffer.includes('MySecretPassword123'), 'Test 3.2: Output stream contains ZERO echoed password characters');
  assert(outputBuffer.startsWith('Enter Password: \n'), 'Test 3.3: Output contains only the prompt and final newline');

  // -------------------------------------------------------------------------
  // 4. Password Policy & Mismatch Verification
  // -------------------------------------------------------------------------
  console.log('\n--- 4. Password Policy & Confirmation Verification ---');

  // Mismatch
  let mismatchCaught = false;
  try {
    validatePasswordPolicy('Password123456789!', 'DifferentPassword123456789!');
  } catch (err) {
    if (err.message.includes('Passwords do not match')) mismatchCaught = true;
  }
  assert(mismatchCaught, 'Test 4.1: Mismatched password and confirmation strictly throws error');

  // Boundary check: 15 characters rejected
  let fifteenCharCaught = false;
  try {
    validatePasswordPolicy('123456789012345', '123456789012345');
  } catch (err) {
    if (err.message.includes('at least 16 characters')) fifteenCharCaught = true;
  }
  assert(fifteenCharCaught, 'Test 4.2a: Password with 15 characters is strictly rejected (< 16 chars)');

  // Boundary check: 16 characters accepted
  let sixteenCharPassed = false;
  try {
    sixteenCharPassed = validatePasswordPolicy('1234567890123456', '1234567890123456');
  } catch {}
  assert(sixteenCharPassed === true, 'Test 4.2b: Password with exactly 16 characters is accepted (boundary match)');

  // Empty password
  let emptyCaught = false;
  try {
    validatePasswordPolicy('', '');
  } catch (err) {
    if (err.message.includes('Password is required')) emptyCaught = true;
  }
  assert(emptyCaught, 'Test 4.3: Empty password strictly rejected');

  // Valid long password (>= 16 chars)
  let validPassed = false;
  try {
    validPassed = validatePasswordPolicy('ValidSecurePassword2026!', 'ValidSecurePassword2026!');
  } catch {}
  assert(validPassed === true, 'Test 4.4: Valid matching password (>= 16 chars) passes policy validation');

  // -------------------------------------------------------------------------
  // 5. Explicit Initialization-Mode Guard Verification
  // -------------------------------------------------------------------------
  console.log('\n--- 5. Accidental Invocation & Initialization Guard ---');

  let guardBlocked = false;
  try {
    await setupSuperAdmin({ args: [] });
  } catch (err) {
    if (err.message.includes('[GUARD] Super Admin initialization blocked')) guardBlocked = true;
  }
  assert(guardBlocked, 'Test 5.1: Executing setupSuperAdmin without confirmation flag is immediately blocked');

  // -------------------------------------------------------------------------
  // 6. Insecure Argument & Environment Variable Rejection
  // -------------------------------------------------------------------------
  console.log('\n--- 6. Insecure Input Parameter Rejection ---');

  // CLI argument --password
  let cliArgBlocked = false;
  try {
    await setupSuperAdmin({ args: ['--confirm-initialization', '--password', 'PlaintextPass'] });
  } catch (err) {
    if (err.message.includes('[SECURITY VIOLATION]')) cliArgBlocked = true;
  }
  assert(cliArgBlocked, 'Test 6.1: Passing --password via CLI argument is strictly rejected');

  // Environment variable INITIAL_SUPER_ADMIN_PASSWORD
  process.env.INITIAL_SUPER_ADMIN_PASSWORD = 'InsecureEnvPassword!';
  let envPassBlocked = false;
  try {
    await setupSuperAdmin({ args: ['--confirm-initialization'] });
  } catch (err) {
    if (err.message.includes('[SECURITY VIOLATION]')) envPassBlocked = true;
  }
  assert(envPassBlocked, 'Test 6.2: Setting INITIAL_SUPER_ADMIN_PASSWORD in environment is strictly rejected');
  delete process.env.INITIAL_SUPER_ADMIN_PASSWORD;

  // -------------------------------------------------------------------------
  // 7. Authorized Email Hard-Binding & Alternative Email Rejection
  // -------------------------------------------------------------------------
  console.log('\n--- 7. Email Hard-Binding & Unauthorized Email Rejection ---');

  assert(AUTHORIZED_SUPER_ADMIN_EMAIL === 'tameerrekhtaadmin@rekhta.org', 'Test 7.1: Authorized email hardcoded strictly to tameerrekhtaadmin@rekhta.org');

  let altEmailBlocked = false;
  try {
    await setupSuperAdmin({ args: ['--confirm-initialization', '--email', 'attacker@rekhta.org'] });
  } catch (err) {
    if (err.message.includes('[SECURITY REJECTION]')) altEmailBlocked = true;
  }
  assert(altEmailBlocked, 'Test 7.2: Attempting to supply alternative email is strictly rejected');

  // -------------------------------------------------------------------------
  // 8. Preflight Existing Account & Existing Super Admin Checks
  // -------------------------------------------------------------------------
  console.log('\n--- 8. Existing Account & Uniqueness Checks ---');

  // Existing Super Admin exists
  const mockUserWithSuperAdmin = {
    countDocuments: async ({ role }) => (role === 'super_admin' ? 1 : 0),
    findOne: async () => null,
  };
  let existingSABlocked = false;
  try {
    await verifyPreflightUniqueness(AUTHORIZED_SUPER_ADMIN_EMAIL, mockUserWithSuperAdmin);
  } catch (err) {
    if (err.message.includes('Super Admin account already exists')) existingSABlocked = true;
  }
  assert(existingSABlocked, 'Test 8.1: Preflight check aborts if any Super Admin already exists');

  // Target email already belongs to a user
  const mockUserWithEmail = {
    countDocuments: async () => 0,
    findOne: async ({ email }) => (email === AUTHORIZED_SUPER_ADMIN_EMAIL ? { role: 'member', status: 'active' } : null),
  };
  let existingEmailBlocked = false;
  try {
    await verifyPreflightUniqueness(AUTHORIZED_SUPER_ADMIN_EMAIL, mockUserWithEmail);
  } catch (err) {
    if (err.message.includes('Account overwriting is strictly prohibited')) existingEmailBlocked = true;
  }
  assert(existingEmailBlocked, 'Test 8.2: Preflight check aborts if target email belongs to any existing account');

  // -------------------------------------------------------------------------
  // 9. Database Identity & Disconnection Error Handling
  // -------------------------------------------------------------------------
  console.log('\n--- 9. Database Identity & Disconnected Atlas Checks ---');

  // Disconnected state (readyState !== 1)
  let disconnectedCaught = false;
  try {
    verifyDatabaseState({ readyState: 0, db: { databaseName: 'tameer_rekhta' } });
  } catch (err) {
    if (err.message.includes('readyState != 1')) disconnectedCaught = true;
  }
  assert(disconnectedCaught, 'Test 9.1: verifyDatabaseState immediately aborts if database is not connected (readyState != 1)');

  // Wrong database name
  let wrongDbCaught = false;
  try {
    verifyDatabaseState({ readyState: 1, db: { databaseName: 'test_db_wrong' } });
  } catch (err) {
    if (err.message.includes("Expected strictly 'tameer_rekhta'")) wrongDbCaught = true;
  }
  assert(wrongDbCaught, 'Test 9.2: verifyDatabaseState immediately aborts if database name is not tameer_rekhta');

  // Correct database name & connected state
  let correctDbName = '';
  try {
    correctDbName = verifyDatabaseState({ readyState: 1, db: { databaseName: 'tameer_rekhta' } });
  } catch {}
  assert(correctDbName === 'tameer_rekhta', 'Test 9.3: verifyDatabaseState succeeds for tameer_rekhta with readyState: 1');

  // -------------------------------------------------------------------------
  // 10. Multi-Document Transaction Atomic Rollback Behavior
  // -------------------------------------------------------------------------
  console.log('\n--- 10. Transaction Atomicity & Rollback Verification ---');

  let transactionRolledBack = false;
  let sessionEnded = false;

  const mockSession = {
    withTransaction: async (fn) => {
      try {
        await fn();
      } catch (err) {
        transactionRolledBack = true;
        throw err;
      }
    },
    endSession: async () => {
      sessionEnded = true;
    },
  };

  const mockConnection = {
    startSession: async () => mockSession,
  };

  const mockUserModel = {
    create: async ([doc], opts) => {
      return [{ _id: 'mock_sa_id_123', ...doc }];
    },
  };

  const mockFailingAuditModel = {
    create: async () => {
      throw new Error('[Simulated Audit Failure] Disk write error during transaction.');
    },
  };

  let txErrorCaught = false;
  try {
    await executeTransactionCreation({
      normalizedEmail: AUTHORIZED_SUPER_ADMIN_EMAIL,
      hashedPassword: sampleHash,
      dbName: 'tameer_rekhta',
      connection: mockConnection,
      UserModel: mockUserModel,
      AuditLogModel: mockFailingAuditModel,
    });
  } catch (err) {
    if (err.message.includes('Simulated Audit Failure')) txErrorCaught = true;
  }

  assert(txErrorCaught, 'Test 10.1: Downstream error inside transaction caught cleanly');
  assert(transactionRolledBack, 'Test 10.2: Failure in AuditLog creation triggers full transaction rollback');
  assert(sessionEnded, 'Test 10.3: MongoDB session ended cleanly in finally block regardless of error');

  // -------------------------------------------------------------------------
  // 11. Credential Sanitization Verification
  // -------------------------------------------------------------------------
  console.log('\n--- 11. Credential Sanitization & Non-Exposure Audit ---');

  assert(!process.env.INITIAL_SUPER_ADMIN_PASSWORD, 'Test 11.1: process.env.INITIAL_SUPER_ADMIN_PASSWORD is not set');
  assert(EXPECTED_DATABASE_NAME === 'tameer_rekhta', 'Test 11.2: Target database name verified strictly tameer_rekhta');

  console.log('\n==================================================================');
  console.log(`PHASE 7B.5.1 TEST SUMMARY: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log('==================================================================\n');

  process.exit(failedTests > 0 ? 1 : 0);
}

runHardeningTests().catch((err) => {
  console.error('[Hardening Test Error]:', err);
  process.exit(1);
});
