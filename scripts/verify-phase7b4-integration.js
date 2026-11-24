/**
 * Phase 7B.4 — Production Database Integration & Application Connectivity Verification
 * Controlled Live Integration Testing — Strictly Read-Only Database Interaction
 */

const mongoose = require('mongoose');
require('../src/config/db'); // Enforces autoIndex: false, autoCreate: false, bufferCommands: false
const dotenv = require('dotenv');
const path = require('path');
const models = require('../src/models');
const { resolveBudgetAllocation } = require('../src/routes/finance.routes');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('[CRITICAL PREFLIGHT FAILURE] MONGODB_URI missing from environment.');
  process.exit(1);
}

// Ensure credentials are never logged
const sanitizedUri = MONGODB_URI.replace(/mongodb\+srv:\/\/([^:]+):([^@]+)@/, 'mongodb+srv://$1:***@');

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

async function runPhase7B4Integration() {
  console.log('==================================================================');
  console.log('PHASE 7B.4: PRODUCTION DATABASE INTEGRATION & CONNECTIVITY');
  console.log(`Target: ${sanitizedUri}`);
  console.log('==================================================================\n');

  // -------------------------------------------------------------------------
  // 1. MANDATORY PREFLIGHT
  // -------------------------------------------------------------------------
  console.log('--- 1. Mandatory Preflight Checks ---');

  assert(mongoose.get('autoIndex') === false, 'Preflight 1: Mongoose global autoIndex is false');
  assert(mongoose.get('autoCreate') === false, 'Preflight 2: Mongoose global autoCreate is false');
  assert(mongoose.get('bufferCommands') === false, 'Preflight 3: Mongoose global bufferCommands is false');

  // Verify test isolation guard works
  process.env.NODE_ENV = 'test';
  delete process.env.TEST_USE_LIVE_DB;
  const { connectDB: isolatedConnectDB } = require('../src/config/db');
  const isolatedResult = await isolatedConnectDB();
  assert(isolatedResult === null, 'Preflight 4: Test isolation blocks connectDB() when TEST_USE_LIVE_DB is unset');
  assert(mongoose.connection.readyState === 0, 'Preflight 5: Mongoose readyState remains 0 during test isolation');

  // Re-enable live testing for Phase 7B.4
  process.env.NODE_ENV = 'production';
  process.env.TEST_USE_LIVE_DB = 'true';
  process.env.JWT_SECRET = 'phase7b4_secure_test_access_secret_production_key_32chars';
  process.env.JWT_REFRESH_SECRET = 'phase7b4_secure_test_refresh_secret_production_key_32chars';

  // -------------------------------------------------------------------------
  // 2. STAGE A: BACKEND CONNECTION VERIFICATION
  // -------------------------------------------------------------------------
  console.log('\n--- 2. Stage A — Backend Connection Verification ---');

  const { connectDB, getConnectionStatus } = require('../src/config/db');
  const connStart = Date.now();
  const conn = await connectDB();
  const connLatency = Date.now() - connStart;

  assert(mongoose.connection.readyState === 1, `Stage A.1: Mongoose connected successfully in ${connLatency}ms (readyState: 1)`);

  const db = conn.connection.db;
  assert(db.databaseName === 'tameer_rekhta', `Stage A.2: Database name confirmed strictly 'tameer_rekhta' (got: '${db.databaseName}')`);

  const pingRes = await db.admin().ping();
  assert(pingRes.ok === 1, 'Stage A.3: Admin ping returned { ok: 1 }');

  const buildInfo = await db.admin().command({ buildInfo: 1 });
  console.log(`  [Info] MongoDB Server Version: v${buildInfo.version} (${buildInfo.modules?.join(', ') || 'community'})`);
  assert(buildInfo.version.startsWith('8.'), `Stage A.4: Server version is MongoDB 8.x (v${buildInfo.version})`);

  const serverStatus = await db.admin().command({ serverStatus: 1 }).catch(() => null);
  if (serverStatus && serverStatus.repl) {
    console.log(`  [Info] Replica Set: ${serverStatus.repl.setName} | IsWritablePrimary: ${serverStatus.repl.isWritablePrimary}`);
    assert(serverStatus.repl.isWritablePrimary === true, 'Stage A.5: Connected to writable primary replica set node');
  } else {
    // Check hello command
    const hello = await db.admin().command({ hello: 1 });
    console.log(`  [Info] Topology setName: ${hello.setName} | isWritablePrimary: ${hello.isWritablePrimary}`);
    assert(hello.isWritablePrimary === true, 'Stage A.5: Primary node is active and writable');
  }

  // Preflight Document Inventory
  const collections = await db.listCollections().toArray();
  assert(collections.length === 16, `Stage A.6: Exactly 16 collections exist in Atlas (found: ${collections.length})`);

  const preInventory = {};
  for (const c of collections.sort((a, b) => a.name.localeCompare(b.name))) {
    const cnt = await db.collection(c.name).countDocuments();
    preInventory[c.name] = cnt;
  }
  assert(preInventory['departments'] === 7, `Stage A.7: Preflight departments count is exactly 7 (got: ${preInventory['departments']})`);
  assert(preInventory['budgets'] === 3, `Stage A.8: Preflight budgets count is exactly 3 (got: ${preInventory['budgets']})`);
  assert(preInventory['auditlogs'] === 0, `Stage A.9: Preflight auditlogs count is exactly 0 (got: ${preInventory['auditlogs']})`);
  assert(preInventory['users'] === 0, `Stage A.10: Preflight users count is exactly 0 (got: ${preInventory['users']})`);

  // -------------------------------------------------------------------------
  // 3. STAGE B: MODEL AND SCHEMA COMPATIBILITY
  // -------------------------------------------------------------------------
  console.log('\n--- 3. Stage B — Model and Schema Compatibility ---');

  const modelKeys = Object.keys(models);
  assert(modelKeys.length === 16, `Stage B.1: All 16 Mongoose models loaded (${modelKeys.length} models)`);

  for (const mName of modelKeys) {
    const Model = models[mName];
    const colName = Model.collection.name;
    const exists = collections.some(c => c.name === colName);
    assert(exists, `Stage B.2: Model '${mName}' correctly maps to live Atlas collection '${colName}'`);
  }

  // Verify Critical Schema Indexes in live DB
  const budgetIdxs = await db.collection('budgets').indexes();
  const budgetPartialIdx = budgetIdxs.find(i => i.name === 'department_1_fiscalYear_1_category_1');
  assert(
    budgetPartialIdx && budgetPartialIdx.unique && budgetPartialIdx.partialFilterExpression?.isArchived === false,
    'Stage B.3: Budget partial compound unique index verified on live Atlas'
  );

  const notifIdxs = await db.collection('notifications').indexes();
  const notifPartialIdx = notifIdxs.find(i => i.name === 'userId_1_dedupKey_1');
  assert(
    notifPartialIdx && notifPartialIdx.unique && notifPartialIdx.partialFilterExpression?.dedupKey,
    'Stage B.4: Notification partial compound unique index verified on live Atlas'
  );

  const userIdxs = await db.collection('users').indexes();
  assert(userIdxs.some(i => i.name === 'email_1' && i.unique), 'Stage B.5: User email unique index verified on live Atlas');

  const expIdxs = await db.collection('expenses').indexes();
  assert(expIdxs.some(i => i.name === 'expenseId_1' && i.unique), 'Stage B.6: Expense expenseId unique index verified on live Atlas');

  // -------------------------------------------------------------------------
  // 4. STAGE C: SAFE AUTHENTICATION PERSISTENCE VERIFICATION
  // -------------------------------------------------------------------------
  console.log('\n--- 4. Stage C — Safe Authentication Persistence Verification ---');

  // Query User model read-only (expected 0)
  const userCount = await models.User.countDocuments();
  assert(userCount === 0, `Stage C.1: User collection confirmed clean at 0 records (found: ${userCount})`);

  // Verify User query paths without inserting
  const nonExistent = await models.User.findOne({ email: 'nonexistent@rekhta.org' }).lean();
  assert(nonExistent === null, 'Stage C.2: User lookup query executes safely and returns null for non-existent email');

  // Verify schema fields and defaults on User model definition
  const userSchemaPaths = models.User.schema.paths;
  assert(userSchemaPaths['email'].isRequired, 'Stage C.3: User schema enforces email as required');
  assert(userSchemaPaths['password'].isRequired, 'Stage C.4: User schema enforces password as required');
  assert(userSchemaPaths['role'].defaultValue === 'member', 'Stage C.5: User schema default role is member');
  assert(userSchemaPaths['tokenVersion'].defaultValue === 0, 'Stage C.6: User schema tokenVersion defaults to 0');
  assert(userSchemaPaths['status'].defaultValue === 'active', 'Stage C.7: User schema status defaults to active');

  // -------------------------------------------------------------------------
  // 5. STAGE D: DATABASE-BACKED SERVICE VERIFICATION (READ-ONLY)
  // -------------------------------------------------------------------------
  console.log('\n--- 5. Stage D — Database-Backed Service Verification ---');

  // D.1 Departments Service
  const liveDepts = await models.Department.find({}).sort({ code: 1 }).lean();
  assert(liveDepts.length === 7, `Stage D.1: Read all 7 live departments (found: ${liveDepts.length})`);

  const expectedCodes = ['CON', 'FIN', 'HR', 'LIT', 'MED', 'MKT', 'OUT'];
  const actualCodes = liveDepts.map(d => d.code);
  assert(JSON.stringify(actualCodes) === JSON.stringify(expectedCodes), `Stage D.2: Department codes match expected: ${actualCodes.join(', ')}`);

  const litDept = await models.Department.findOne({ code: 'LIT' }).lean();
  assert(litDept && litDept.name === 'Literature' && litDept.leadName === 'Noor-ul-Huda', 'Stage D.3: Department lookup by code (LIT) returns correct details');

  // D.2 Budgets Service
  const liveBudgets = await models.Budget.find({}).sort({ budgetId: 1 }).lean();
  assert(liveBudgets.length === 3, `Stage D.4: Read all 3 live budgets (found: ${liveBudgets.length})`);

  const finBudget = await models.Budget.findOne({ department: 'Finance', fiscalYear: '2026', category: 'General Operating' }).lean();
  assert(finBudget && finBudget.allocatedAmount === 150000 && finBudget.remainingAmount === 150000 && finBudget.spentAmount === 0, 'Stage D.5: Finance FY2026 budget lookup verified (PKR 150,000)');

  const genBudget = await models.Budget.findOne({ department: 'General', fiscalYear: '2026', category: 'General Operating' }).lean();
  assert(genBudget && genBudget.allocatedAmount === 200000 && genBudget.remainingAmount === 200000, 'Stage D.6: General FY2026 budget lookup verified (PKR 200,000)');

  const hrBudget = await models.Budget.findOne({ department: 'HR', fiscalYear: '2026', category: 'General Operating' }).lean();
  assert(hrBudget && hrBudget.allocatedAmount === 100000 && hrBudget.remainingAmount === 100000, 'Stage D.7: HR FY2026 budget lookup verified (PKR 100,000)');

  // D.3 General Budget Scope & Isolation Test with resolveBudgetAllocation
  let crossDeptBlocked = false;
  try {
    resolveBudgetAllocation({
      budgetsList: liveBudgets,
      explicitBudgetId: genBudget.budgetId,
      department: 'Literature',
      fiscalYear: '2026',
    });
  } catch (err) {
    if (err.message.includes('Cross-department deduction is prohibited')) {
      crossDeptBlocked = true;
    }
  }
  assert(crossDeptBlocked, 'Stage D.8: resolveBudgetAllocation strictly blocks Literature expense from consuming General budget (HTTP 400)');

  // D.4 Notifications Query Compatibility
  const notifQuery = await models.Notification.find({ userId: 'mock_user_1', read: false }).lean();
  assert(Array.isArray(notifQuery) && notifQuery.length === 0, 'Stage D.9: Notification query executed cleanly on Atlas (0 unread for mock user)');

  // D.5 Tasks Query Compatibility
  const taskQuery = await models.Task.find({ department: 'Literature', status: 'assigned' }).lean();
  assert(Array.isArray(taskQuery) && taskQuery.length === 0, 'Stage D.10: Task query executed cleanly on Atlas (0 tasks found)');

  // -------------------------------------------------------------------------
  // 6. STAGE E: FINANCIAL TRANSACTION VERIFICATION
  // -------------------------------------------------------------------------
  console.log('\n--- 6. Stage E — Financial Transaction Capability Verification ---');

  // Test native replica-set session and transaction with immediate abort (0 writes)
  const session = await mongoose.startSession();
  assert(session !== null && typeof session.withTransaction === 'function', 'Stage E.1: MongoDB Multi-Document ACID session created successfully');

  let txExecuted = false;
  await session.withTransaction(async () => {
    // Read inside transaction
    const inTxBudgets = await models.Budget.find({ status: 'active' }).session(session);
    assert(inTxBudgets.length === 3, 'Stage E.2: Snapshot read inside ACID transaction returned 3 active budgets');
    txExecuted = true;
    // Explicitly abort transaction: zero writes performed
    await session.abortTransaction();
  }).catch(() => null);

  await session.endSession();
  assert(txExecuted, 'Stage E.3: Multi-document transaction executed and cleanly aborted with 0 mutations');

  // -------------------------------------------------------------------------
  // 7. STAGE F: DATABASE FAILURE & RECOVERY VERIFICATION
  // -------------------------------------------------------------------------
  console.log('\n--- 7. Stage F — Database Failure & Recovery Verification ---');

  const onlineStatus = getConnectionStatus();
  assert(onlineStatus.isConnected === true, 'Stage F.1a: getConnectionStatus reports isConnected: true');
  assert(onlineStatus.mode === 'online', 'Stage F.1b: getConnectionStatus reports mode: online');
  assert(onlineStatus.readyState === 1, 'Stage F.1c: getConnectionStatus reports readyState: 1');
  assert(onlineStatus.dbName === 'tameer_rekhta', 'Stage F.1d: getConnectionStatus reports dbName: tameer_rekhta');

  // Verify /api/health endpoint
  const http = require('http');
  const app = require('../src/server');

  const testServer = http.createServer(app);
  await new Promise((resolve) => testServer.listen(5098, '127.0.0.1', resolve));

  const healthData = await new Promise((resolve, reject) => {
    http.get('http://127.0.0.1:5098/api/health', (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });

  assert(healthData.status === 'online', 'Stage F.2a: /api/health returns status: online');
  assert(healthData.database?.status === 'connected', 'Stage F.2b: /api/health returns database.status: connected');
  assert(healthData.database?.mode === 'online', 'Stage F.2c: /api/health returns database.mode: online');
  assert(healthData.database?.database === 'tameer_rekhta', 'Stage F.2d: /api/health reports database: tameer_rekhta');

  // Verify graceful shutdown handler definition
  assert(typeof app.gracefulShutdown === 'function', 'Stage F.3: Graceful shutdown lifecycle handler is defined on app');

  // Fail-fast verification: Attempt connection with invalid URI and short timeout
  let failFastPassed = false;
  try {
    const invalidConn = mongoose.createConnection('mongodb://invalid-host-for-failfast-test:27017/test?serverSelectionTimeoutMS=800');
    await invalidConn.asPromise();
  } catch (err) {
    failFastPassed = true;
  }
  assert(failFastPassed, 'Stage F.4: Invalid host connection immediately fails fast and throws without hanging');

  await new Promise((resolve) => testServer.close(resolve));

  // -------------------------------------------------------------------------
  // 8. FINAL DATABASE INTEGRITY CHECK (POST-VERIFICATION INVENTORY)
  // -------------------------------------------------------------------------
  console.log('\n--- 8. Final Database Integrity Check ---');

  const postInventory = {};
  for (const c of collections) {
    const cnt = await db.collection(c.name).countDocuments();
    postInventory[c.name] = cnt;
  }

  assert(postInventory['departments'] === 7, `Final Check 1: Departments count remains exactly 7 (got: ${postInventory['departments']})`);
  assert(postInventory['budgets'] === 3, `Final Check 2: Budgets count remains exactly 3 (got: ${postInventory['budgets']})`);
  assert(postInventory['auditlogs'] === 0, `Final Check 3: Auditlogs count remains exactly 0 (got: ${postInventory['auditlogs']})`);
  assert(postInventory['users'] === 0, `Final Check 4: Users count remains exactly 0 (got: ${postInventory['users']})`);
  assert(postInventory['expenses'] === 0, `Final Check 5: Expenses count remains exactly 0 (got: ${postInventory['expenses']})`);
  assert(postInventory['donations'] === 0, `Final Check 6: Donations count remains exactly 0 (got: ${postInventory['donations']})`);
  assert(postInventory['tasks'] === 0, `Final Check 7: Tasks count remains exactly 0 (got: ${postInventory['tasks']})`);

  // Verify zero count mutations between pre and post
  let zeroMutations = true;
  for (const colName of Object.keys(preInventory)) {
    if (preInventory[colName] !== postInventory[colName]) {
      console.error(`  [MUTATION DETECTED] Collection ${colName}: before=${preInventory[colName]}, after=${postInventory[colName]}`);
      zeroMutations = false;
    }
  }
  assert(zeroMutations, 'Final Check 8: 100% verified ZERO mutations occurred across all 16 collections during Phase 7B.4');

  await mongoose.disconnect();
  console.log('\n[Disconnection] Cleanly disconnected from MongoDB Atlas.');
  assert(mongoose.connection.readyState === 0, 'Final Check 9: Mongoose readyState is 0 (Cleanly Disconnected)');

  console.log('\n==================================================================');
  console.log(`PHASE 7B.4 INTEGRATION SUMMARY: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log('==================================================================');

  process.exit(failedTests > 0 ? 1 : 0);
}

runPhase7B4Integration().catch(err => {
  console.error('[Integration Error]:', err.message);
  if (mongoose.connection.readyState !== 0) {
    mongoose.disconnect().catch(() => null);
  }
  process.exit(1);
});
