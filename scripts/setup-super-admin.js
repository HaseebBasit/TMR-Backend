/**
 * Phase 7B.5 — Secure Super Admin Initialization Script
 * 
 * Hardened Implementation:
 * 1. Hidden interactive terminal password prompt (zero character echo).
 * 2. Mandatory password confirmation.
 * 3. Enforced password policy (length >= 8) and bcrypt hashing (salt rounds: 10).
 * 4. Hardcoded authorized administrator email: tameerrekhtaadmin@rekhta.org.
 * 5. Strict rejection of any alternative email.
 * 6. Pre-creation check: Refuses execution if any Super Admin already exists.
 * 7. Pre-creation check: Refuses execution if authorized email already belongs to any account.
 * 8. Zero account overwriting.
 * 9. Zero in-memory fallback behavior (production fail-fast).
 * 10. Database connection and name validation: Strictly 'tameer_rekhta'.
 * 11. Does not automatically set TEST_USE_LIVE_DB.
 * 12. Explicit initialization guard flag required: --confirm-initialization.
 * 13. Single multi-document ACID transaction for User and AuditLog creation.
 * 14. Normalized email (lowercase, trimmed).
 * 15. Zero credential or hash leakage in logs or exceptions.
 * 16. Graceful cleanup and disconnection on success, error, or interruption.
 */

const readline = require('readline');
const { Writable } = require('stream');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const { connectDB } = require('../src/config/db');
const { User, AuditLog } = require('../src/models');

const AUTHORIZED_SUPER_ADMIN_EMAIL = 'tameerrekhtaadmin@rekhta.org';
const EXPECTED_DATABASE_NAME = 'tameer_rekhta';
const BCRYPT_SALT_ROUNDS = 10;
const MIN_PASSWORD_LENGTH = 16;

/**
 * Prompt for input on terminal with muted stdout so no typed characters are echoed.
 */
function askHidden(promptText, input = process.stdin, output = process.stdout) {
  return new Promise((resolve) => {
    let muted = false;
    const mutableOutput = new Writable({
      write(chunk, encoding, callback) {
        if (!muted) {
          output.write(chunk, encoding);
        }
        callback();
      },
    });

    const rl = readline.createInterface({
      input,
      output: mutableOutput,
      terminal: true,
    });

    output.write(promptText);
    muted = true;
    rl.question('', (answer) => {
      muted = false;
      output.write('\n');
      rl.close();
      resolve(answer ? answer.trim() : '');
    });
  });
}

/**
 * Validate password against policy requirements and verify confirmation.
 */
function validatePasswordPolicy(password, confirmPassword) {
  if (!password || typeof password !== 'string') {
    throw new Error('Password is required and cannot be empty.');
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`);
  }
  if (password !== confirmPassword) {
    throw new Error('Passwords do not match. Initialization aborted.');
  }
  return true;
}

/**
 * Verify connected database identity and readiness.
 */
function verifyDatabaseState(connection) {
  if (!connection || connection.readyState !== 1) {
    throw new Error('[CRITICAL DATABASE ERROR] MongoDB is not connected (readyState != 1).');
  }
  const dbName = connection.db?.databaseName;
  if (dbName !== EXPECTED_DATABASE_NAME) {
    throw new Error(
      `[CRITICAL DATABASE ERROR] Connected to invalid database '${dbName}'. Expected strictly '${EXPECTED_DATABASE_NAME}'.`
    );
  }
  return dbName;
}

/**
 * Preflight database checks:
 * 1. Verify 0 Super Admins currently exist.
 * 2. Verify target email is not currently registered.
 */
async function verifyPreflightUniqueness(normalizedEmail, UserModel = User) {
  const existingSuperAdminCount = await UserModel.countDocuments({ role: 'super_admin' });
  if (existingSuperAdminCount > 0) {
    throw new Error(
      `[SECURITY STOP] Super Admin account already exists (found: ${existingSuperAdminCount}). Multiple initial Super Admins are prohibited.`
    );
  }

  const existingEmailUser = await UserModel.findOne({ email: normalizedEmail });
  if (existingEmailUser) {
    throw new Error(
      `[SECURITY STOP] An account already exists for ${normalizedEmail} (Role: ${existingEmailUser.role}, Status: ${existingEmailUser.status}). Account overwriting is strictly prohibited.`
    );
  }
}

/**
 * Atomically create User and AuditLog inside a single multi-document transaction.
 */
async function executeTransactionCreation({
  normalizedEmail,
  hashedPassword,
  dbName,
  connection = mongoose.connection,
  UserModel = User,
  AuditLogModel = AuditLog,
}) {
  const session = await connection.startSession();
  try {
    let createdUser = null;
    let createdAudit = null;

    await session.withTransaction(async () => {
      const [superAdmin] = await UserModel.create(
        [
          {
            name: 'Super Administrator',
            email: normalizedEmail,
            password: hashedPassword,
            role: 'super_admin',
            department: null,
            departmentCode: null,
            status: 'active',
            tokenVersion: 0,
          },
        ],
        { session }
      );

      const [audit] = await AuditLogModel.create(
        [
          {
            actorId: superAdmin._id,
            actorName: 'SYSTEM_SETUP_CLI',
            actorRole: 'super_admin',
            action: 'SUPER_ADMIN_INITIALIZATION',
            module: 'SECURITY',
            targetId: superAdmin._id.toString(),
            targetModel: 'User',
            description: `Authorized initial Super Admin account provisioned for ${normalizedEmail}.`,
            metadata: {
              initializationMode: 'authorized_phase7b5',
              database: dbName,
              timestamp: new Date().toISOString(),
            },
          },
        ],
        { session }
      );

      createdUser = superAdmin;
      createdAudit = audit;
    });

    return { user: createdUser, auditLog: createdAudit };
  } finally {
    await session.endSession();
  }
}

/**
 * Main Super Admin Initialization Workflow
 */
async function setupSuperAdmin(options = {}) {
  const args = options.args || process.argv.slice(2);

  // 1. Insecure Parameter Rejection Guards
  if (args.includes('--password') || process.env.INITIAL_SUPER_ADMIN_PASSWORD) {
    throw new Error(
      '[SECURITY VIOLATION] Providing passwords via CLI arguments or environment variables is strictly prohibited. Passwords must be entered interactively via hidden terminal prompt.'
    );
  }

  // 2. Reject Alternative Email Overrides
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--email' && args[i + 1]) {
      const requestedEmail = args[i + 1].toLowerCase().trim();
      if (requestedEmail !== AUTHORIZED_SUPER_ADMIN_EMAIL) {
        throw new Error(
          `[SECURITY REJECTION] Email override is strictly forbidden. The only authorized initial administrator email is '${AUTHORIZED_SUPER_ADMIN_EMAIL}'.`
        );
      }
    }
  }

  // 3. Initialization Mode Guard
  const hasConfirmFlag = args.includes('--confirm-initialization');
  const hasEnvGuard = process.env.SUPER_ADMIN_INIT_MODE === 'authorized_phase7b5';
  if (!hasConfirmFlag && !hasEnvGuard) {
    throw new Error(
      '[GUARD] Super Admin initialization blocked: Missing explicit confirmation flag (--confirm-initialization) or environment guard. This prevents accidental execution.'
    );
  }

  console.log('==================================================================');
  console.log('PHASE 7B.5: SECURE SUPER ADMIN INITIALIZATION');
  console.log(`Authorized Administrator: ${AUTHORIZED_SUPER_ADMIN_EMAIL}`);
  console.log('==================================================================\n');

  // 4. Safe Database Connection (Respects test isolation; caller must set TEST_USE_LIVE_DB if testing)
  await connectDB();
  const dbName = verifyDatabaseState(mongoose.connection);
  console.log(`[Database Verified] Connected to target database: '${dbName}'`);

  const normalizedEmail = AUTHORIZED_SUPER_ADMIN_EMAIL.toLowerCase().trim();

  // 5. Preflight Uniqueness & Existing Account Checks
  await verifyPreflightUniqueness(normalizedEmail);
  console.log('[Preflight Passed] Zero Super Admins exist and target email is available.');

  // 6. Interactive Hidden Password Entry & Confirmation
  console.log('\nEnter credentials for initial Super Administrator.');
  const customInput = options.input || process.stdin;
  const customOutput = options.output || process.stdout;

  const password = await askHidden('Enter Super Admin Password (hidden): ', customInput, customOutput);
  const confirmPassword = await askHidden('Confirm Super Admin Password (hidden): ', customInput, customOutput);

  validatePasswordPolicy(password, confirmPassword);
  console.log('\n[Credentials Verified] Password meets policy requirements and confirmation matches.');

  // 7. Bcrypt Hashing (Salt rounds: 10)
  console.log(`[Security] Hashing password with bcrypt (rounds: ${BCRYPT_SALT_ROUNDS})...`);
  const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

  // 8. Atomic Multi-Document Transaction Execution
  console.log('[Database] Executing atomic transaction for User and AuditLog creation...');
  const result = await executeTransactionCreation({
    normalizedEmail,
    hashedPassword,
    dbName,
    connection: mongoose.connection,
    UserModel: User,
    AuditLogModel: AuditLog,
  });

  console.log('\n==================================================================');
  console.log(`[SUCCESS] Super Admin account initialized: ${result.user.email}`);
  console.log(`[User Record ID] ${result.user._id}`);
  console.log(`[Audit Log ID] ${result.auditLog._id}`);
  console.log('==================================================================');

  return result;
}

// Interruption Signal Handlers for Safe Disconnection
const handleSignal = async (signal) => {
  console.warn(`\n[Signal Received: ${signal}] Closing database connection cleanly...`);
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect().catch(() => null);
  }
  process.exit(130);
};

if (require.main === module) {
  process.once('SIGINT', () => handleSignal('SIGINT'));
  process.once('SIGTERM', () => handleSignal('SIGTERM'));

  setupSuperAdmin()
    .then(async () => {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.disconnect();
        console.log('[Disconnection] Cleanly disconnected from MongoDB Atlas.');
      }
      process.exit(0);
    })
    .catch(async (err) => {
      console.error(`\n[Execution Aborted]: ${err.message}`);
      if (mongoose.connection.readyState !== 0) {
        await mongoose.disconnect().catch(() => null);
      }
      process.exit(1);
    });
}

module.exports = {
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
};
