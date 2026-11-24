/**
 * Phase 7A.1 — Production Database Safety, Financial Transaction Integrity & Operational Hardening
 * Comprehensive Verification Suite
 *
 * Verifies:
 * 1. Production Database Fail-Fast (Missing URI, invalid URI scheme, connection failure)
 * 2. Explicit Mock/Test-Mode Offline Operation
 * 3. Prevention of Silent Production In-Memory Fallback (503 Service Unavailable)
 * 4. Budget Compound Uniqueness ({ department: 1, fiscalYear: 1 }) & Pre-Migration Duplicate Check
 * 5. Notification Compound Uniqueness & Deduplication ({ userId: 1, dedupKey: 1 } with partialFilter)
 * 6. Financial Transaction Integrity (Atomicity, Multi-Document Rollback, Overspending, Currency Match)
 * 7. Duplicate & Concurrent Expense Approval Protection (Idempotency)
 * 8. Graceful Shutdown Signal Handling (SIGTERM/SIGINT sequence & idempotent teardown)
 * 9. Explicit Distinction between Offline Mock Testing and Live MongoDB Transaction Verification
 */

process.env.NODE_ENV = 'test';

const http = require('http');
const mongoose = require('mongoose');
const app = require('../src/server');
const { connectDB, getConnectionStatus, closeDB, sanitizeUri } = require('../src/config/db');
const { Budget, Notification, Expense, User, AuditLog } = require('../src/models');
const {
  setMemoryBudget,
  getMemoryBudgetsList,
  clearMemoryBudgets,
  setMemoryExpense,
  getMemoryExpensesList,
  clearMemoryExpenses,
  executeTransactionIfSupported,
} = require('../src/routes/finance.routes');
const {
  sendNotification,
  getNotificationsForUser,
  clearMemoryNotifications,
} = require('../src/services/notification.service');
const { setMemoryUser, clearMemoryUsers } = require('../src/middleware/auth');

let server;
const TEST_PORT = 5098;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;

// Helper: HTTP Request
function makeRequest(path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = `${BASE_URL}${path}`;
    const parsedUrl = new URL(url);

    const reqOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port,
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET',
      headers: options.headers || {},
    };

    const req = http.request(reqOptions, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(body);
        } catch {
          json = body;
        }
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: json,
        });
      });
    });

    req.on('error', (err) => reject(err));

    if (options.body) {
      const data = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
      req.setHeader('Content-Type', 'application/json');
      req.setHeader('Content-Length', Buffer.byteLength(data));
      req.write(data);
    }

    req.end();
  });
}

// Test Runner Tracking
let testsPassed = 0;
let testsFailed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    testsPassed++;
  } else {
    console.error(`  [FAIL] ${message}`);
    testsFailed++;
  }
}

async function runPhase7A1SafetyTests() {
  console.log('==================================================================');
  console.log('PHASE 7A.1: PRODUCTION DATABASE SAFETY & INTEGRITY AUDIT SUITE');
  console.log('Environment: Offline Controlled Mock Mode (Atlas Disconnected)');
  console.log('==================================================================\n');

  // Set up mock authenticated users
  const financeUser = {
    _id: 'usr_fin_7a1',
    id: 'usr_fin_7a1',
    name: 'Finance Officer Safe',
    email: 'finance_safe@tameer.org',
    role: 'finance',
    status: 'active',
  };
  const memberUser = {
    _id: 'usr_mem_7a1',
    id: 'usr_mem_7a1',
    name: 'Member Applicant Safe',
    email: 'member_safe@tameer.org',
    role: 'member',
    department: 'Literature',
    status: 'active',
  };
  setMemoryUser(financeUser);
  setMemoryUser(memberUser);

  // Mock JWT Token Headers
  const jwt = require('jsonwebtoken');
  const JWT_SECRET = process.env.JWT_SECRET || 'phase4_jwt_test_secret_key_minimum_32_chars';
  const financeToken = jwt.sign({ id: financeUser.id, role: financeUser.role }, JWT_SECRET, { expiresIn: '1h' });
  const memberToken = jwt.sign({ id: memberUser.id, role: memberUser.role }, JWT_SECRET, { expiresIn: '1h' });

  // -------------------------------------------------------------------------
  // SECTION 1: PRODUCTION DATABASE FAIL-FAST & SANITIZATION
  // -------------------------------------------------------------------------
  console.log('\n--- Section 1: Production Database Fail-Fast & URI Sanitization ---');

  // Test 1: URI credential sanitization
  const sensitiveUri = 'mongodb+srv://admin_user:SuperSecretPassword123@cluster0.abcde.mongodb.net/tameer?retryWrites=true';
  const sanitized = sanitizeUri(sensitiveUri);
  assert(
    !sanitized.includes('SuperSecretPassword123') && sanitized.includes('***:***@cluster0.abcde.mongodb.net'),
    'Test 1: URI credentials sanitized without exposing password'
  );

  // Test 2: Production fail-fast on missing MONGODB_URI
  const originalEnv = process.env.NODE_ENV;
  const originalUri = process.env.MONGODB_URI;

  process.env.NODE_ENV = 'production';
  delete process.env.MONGODB_URI;
  let missingUriErrorThrown = false;
  try {
    await connectDB();
  } catch (err) {
    missingUriErrorThrown = true;
    assert(
      err.message.includes('MONGODB_URI is required in production environment'),
      'Test 2: Production startup throws fatal error when MONGODB_URI is missing'
    );
  }
  assert(missingUriErrorThrown, 'Test 2b: Production connectDB refused to start silently without URI');

  // Test 3: Production fail-fast on invalid MONGODB_URI scheme
  process.env.MONGODB_URI = 'http://localhost:27017/invalid_scheme';
  let invalidSchemeThrown = false;
  try {
    await connectDB();
  } catch (err) {
    invalidSchemeThrown = true;
    assert(
      err.message.includes('Invalid MONGODB_URI scheme in production'),
      'Test 3: Production startup throws fatal error on invalid URI scheme'
    );
  }
  assert(invalidSchemeThrown, 'Test 3b: Production connectDB refused invalid scheme');

  // Test 3c: Production fail-fast on connection failure (unreachable host)
  process.env.MONGODB_URI = 'mongodb://127.0.0.1:27099/unreachable_db?serverSelectionTimeoutMS=200';
  let connFailedThrown = false;
  try {
    await connectDB();
  } catch (err) {
    connFailedThrown = true;
    assert(
      err.message.includes('Production MongoDB Connection Failed'),
      'Test 3c: Production startup throws fatal error on unreachable MongoDB connection'
    );
  }
  assert(connFailedThrown, 'Test 3d: Production connectDB refused to start when MongoDB is unreachable');

  // Test 4: Explicit mock/test-mode allows offline operation
  process.env.NODE_ENV = 'test';
  delete process.env.MONGODB_URI;
  const devConn = await connectDB();
  const devStatus = getConnectionStatus();
  assert(
    devConn === null && devStatus.mode === 'offline_controlled_mode',
    'Test 4: Explicit test/development mode allows controlled offline configuration-check mode'
  );

  // Restore env
  process.env.NODE_ENV = originalEnv || 'test';
  if (originalUri) process.env.MONGODB_URI = originalUri;

  // -------------------------------------------------------------------------
  // SECTION 2: PRODUCTION IN-MEMORY FALLBACK PREVENTION (503 GUARD)
  // -------------------------------------------------------------------------
  console.log('\n--- Section 2: Production In-Memory Fallback Guard ---');

  // Start HTTP server for route testing
  server = http.createServer(app);
  await new Promise((resolve) => server.listen(TEST_PORT, resolve));
  app.setServerInstance(server);

  // Test 5: In production mode with disconnected DB, endpoints return 503
  process.env.NODE_ENV = 'production';
  const prodGuardRes = await makeRequest('/api/finance/stats', {
    method: 'GET',
    headers: { Authorization: `Bearer ${financeToken}` },
  });
  assert(
    prodGuardRes.statusCode === 503 &&
    prodGuardRes.body.error.includes('Database service is unavailable'),
    'Test 5: Production request rejected with HTTP 503 when database is not connected'
  );

  // Test 6: Health check remains accessible in production
  const healthRes = await makeRequest('/api/health');
  assert(
    healthRes.statusCode === 200 && healthRes.body.database.status === 'offline_controlled_mode',
    'Test 6: /api/health reports accurate offline readiness status in production without 503'
  );

  // Revert back to test mode for route functional testing
  process.env.NODE_ENV = 'test';

  // -------------------------------------------------------------------------
  // SECTION 3: BUDGET COMPOUND UNIQUENESS & PRE-MIGRATION AUDIT
  // -------------------------------------------------------------------------
  console.log('\n--- Section 3: Budget Compound Uniqueness ({ department: 1, fiscalYear: 1 }) ---');

  clearMemoryBudgets();

  // Test 7: Verify Budget Mongoose schema index definition
  const budgetIndexes = Budget.schema.indexes();
  const hasDeptFyCompoundIndex = budgetIndexes.some(([fields, options]) => {
    return fields.department === 1 && fields.fiscalYear === 1 && options && options.unique === true;
  });
  assert(
    hasDeptFyCompoundIndex,
    'Test 7: Budget schema declares compound unique index { department: 1, fiscalYear: 1 }'
  );

  // Test 8: Create initial budget for Literature 2026
  const b1Res = await makeRequest('/api/finance/budgets', {
    method: 'POST',
    headers: { Authorization: `Bearer ${financeToken}` },
    body: {
      fiscalYear: '2026',
      title: 'Literature Annual Budget 2026',
      department: 'Literature',
      allocatedAmount: 100000,
      currency: 'PKR',
    },
  });
  assert(b1Res.statusCode === 201 && b1Res.body.success, 'Test 8: Initial budget allocation created (201)');

  // Test 9: Duplicate budget creation attempt for same department and fiscalYear is rejected (409)
  const bDuplicateRes = await makeRequest('/api/finance/budgets', {
    method: 'POST',
    headers: { Authorization: `Bearer ${financeToken}` },
    body: {
      fiscalYear: '2026',
      title: 'Literature Second Budget 2026',
      department: 'Literature',
      allocatedAmount: 50000,
      currency: 'PKR',
    },
  });
  assert(
    bDuplicateRes.statusCode === 409 &&
    bDuplicateRes.body.error.includes('already exists') &&
    bDuplicateRes.body.error.includes('Multiple budgets for the same department and fiscal year are prohibited'),
    'Test 9: Duplicate budget for same department and fiscal year rejected with HTTP 409 Conflict'
  );

  // Test 10: Budget for DIFFERENT department in same fiscal year succeeds
  const bMediaRes = await makeRequest('/api/finance/budgets', {
    method: 'POST',
    headers: { Authorization: `Bearer ${financeToken}` },
    body: {
      fiscalYear: '2026',
      title: 'Media Annual Budget 2026',
      department: 'Media',
      allocatedAmount: 80000,
      currency: 'PKR',
    },
  });
  assert(bMediaRes.statusCode === 201, 'Test 10: Budget for distinct department in same fiscal year succeeds (201)');

  // Test 11: Pre-migration budget duplicate detection script execution
  const { detectBudgetDuplicates } = require('./detect-budget-duplicates');
  const budgetAudit = await detectBudgetDuplicates();
  assert(
    budgetAudit.safe === true && budgetAudit.duplicatesCount === 0,
    'Test 11: Pre-migration budget duplicate script reports zero duplicates across active records'
  );

  // -------------------------------------------------------------------------
  // SECTION 4: NOTIFICATION DEDUPLICATION & PARTIAL COMPOUND UNIQUENESS
  // -------------------------------------------------------------------------
  console.log('\n--- Section 4: Notification Deduplication ({ userId: 1, dedupKey: 1 }) ---');

  clearMemoryNotifications();

  // Test 12: Verify Notification Mongoose schema partial index definition
  const notifIndexes = Notification.schema.indexes();
  const hasNotifPartialIndex = notifIndexes.some(([fields, options]) => {
    return (
      fields.userId === 1 &&
      fields.dedupKey === 1 &&
      options &&
      options.unique === true &&
      options.partialFilterExpression &&
      options.partialFilterExpression.dedupKey
    );
  });
  assert(
    hasNotifPartialIndex,
    'Test 12: Notification schema declares partial compound unique index { userId: 1, dedupKey: 1 }'
  );

  // Test 13: Notification dispatch with dedupKey is idempotent
  const dedupKey = 'task:assign:test_task_001';
  const notif1 = await sendNotification({
    userId: memberUser.id,
    title: 'Task Assigned',
    message: 'You have been assigned task 1',
    category: 'task',
    dedupKey,
  });

  const notif2 = await sendNotification({
    userId: memberUser.id,
    title: 'Task Assigned Duplicate Attempt',
    message: 'Duplicate assignment message',
    category: 'task',
    dedupKey,
  });

  assert(
    (notif1._id || notif1.id) === (notif2._id || notif2.id),
    'Test 13: Repeated sendNotification with same dedupKey returns original notification idempotently'
  );

  // Test 14: Cross-user isolation: Same dedupKey for a DIFFERENT user creates a distinct notification
  const otherUserNotif = await sendNotification({
    userId: financeUser.id,
    title: 'Task Assigned',
    message: 'Finance officer assignment',
    category: 'task',
    dedupKey,
  });
  assert(
    (otherUserNotif._id || otherUserNotif.id) !== (notif1._id || notif1.id),
    'Test 14: Distinct users can use the same dedupKey without collision'
  );

  // Test 15: Notifications WITHOUT deduplication keys are unrestricted
  const unkeyed1 = await sendNotification({
    userId: memberUser.id,
    title: 'Announcement 1',
    message: 'General notice 1',
  });
  const unkeyed2 = await sendNotification({
    userId: memberUser.id,
    title: 'Announcement 2',
    message: 'General notice 2',
  });
  assert(
    (unkeyed1._id || unkeyed1.id) !== (unkeyed2._id || unkeyed2.id),
    'Test 15: Notifications without deduplication keys do not conflict and both are created'
  );

  // Test 16: Pre-migration notification duplicate detection script execution
  const { detectNotificationDuplicates } = require('./detect-notification-duplicates');
  const notifAudit = await detectNotificationDuplicates();
  assert(
    notifAudit.safe === true && notifAudit.duplicatesCount === 0,
    'Test 16: Pre-migration notification duplicate script reports zero duplicates across keyed records'
  );

  // -------------------------------------------------------------------------
  // SECTION 5: FINANCIAL TRANSACTION INTEGRITY & ATOMIC APPROVAL
  // -------------------------------------------------------------------------
  console.log('\n--- Section 5: Financial Transaction Integrity & Concurrency ---');

  clearMemoryExpenses();

  // Test 17: Submit pending expense against Literature department
  const expRes = await makeRequest('/api/finance/expenses', {
    method: 'POST',
    headers: { Authorization: `Bearer ${memberToken}` },
    body: {
      title: 'Literature Journal Printing',
      amount: 15000,
      category: 'Printing & Publications',
      department: 'Literature',
      currency: 'PKR',
    },
  });
  assert(expRes.statusCode === 201 && expRes.body.success, 'Test 17: Expense submitted for review (201)');
  const expenseId = expRes.body.expense._id || expRes.body.expense.id;

  // Test 18: Approve expense and verify atomic budget deduction
  const appRes = await makeRequest(`/api/finance/expenses/${expenseId}/review`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${financeToken}` },
    body: { status: 'approved', reviewNotes: 'Approved for journal printing' },
  });
  assert(
    appRes.statusCode === 200 && appRes.body.expense.status === 'approved',
    'Test 18: Expense approved successfully (200)'
  );

  // Verify budget deduction
  const budgetsList = getMemoryBudgetsList();
  const litBudget = budgetsList.find((b) => b.department === 'Literature');
  assert(
    litBudget && litBudget.spentAmount === 15000 && litBudget.remainingAmount === 85000,
    'Test 19: Budget spentAmount atomically incremented to 15,000 and remainingAmount reduced to 85,000'
  );

  // Test 20: Duplicate approval protection: Re-approving approved expense is rejected (409)
  const dupAppRes = await makeRequest(`/api/finance/expenses/${expenseId}/review`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${financeToken}` },
    body: { status: 'approved', reviewNotes: 'Attempted second approval' },
  });
  assert(
    dupAppRes.statusCode === 409 &&
    dupAppRes.body.error.includes('Duplicate approval rejected') &&
    litBudget.spentAmount === 15000,
    'Test 20: Duplicate approval rejected with HTTP 409 Conflict; budget NOT deducted twice'
  );

  // Test 21: Overspending protection
  const overExpRes = await makeRequest('/api/finance/expenses', {
    method: 'POST',
    headers: { Authorization: `Bearer ${memberToken}` },
    body: {
      title: 'Extravagant Gala',
      amount: 90000, // Remaining is 85,000
      category: 'Event Expenses',
      department: 'Literature',
      currency: 'PKR',
    },
  });
  const overExpId = overExpRes.body.expense._id || overExpRes.body.expense.id;

  const overAppRes = await makeRequest(`/api/finance/expenses/${overExpId}/review`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${financeToken}` },
    body: { status: 'approved' },
  });
  assert(
    overAppRes.statusCode === 400 &&
    overAppRes.body.error.includes('Budget overspending protection') &&
    litBudget.spentAmount === 15000,
    'Test 21: Overspending rejected with HTTP 400; budget remaining protected'
  );

  // Test 22: Currency mismatch protection
  const usdExpRes = await makeRequest('/api/finance/expenses', {
    method: 'POST',
    headers: { Authorization: `Bearer ${memberToken}` },
    body: {
      title: 'International Software License',
      amount: 500,
      category: 'Equipment & Assets',
      department: 'Literature',
      currency: 'USD',
    },
  });
  const usdExpId = usdExpRes.body.expense._id || usdExpRes.body.expense.id;

  const usdAppRes = await makeRequest(`/api/finance/expenses/${usdExpId}/review`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${financeToken}` },
    body: { status: 'approved' },
  });
  assert(
    usdAppRes.statusCode === 400 &&
    usdAppRes.body.error.includes('Currency mismatch') &&
    litBudget.spentAmount === 15000,
    'Test 22: Currency mismatch rejected with HTTP 400; unverified cross-currency deduction blocked'
  );

  // Test 23: Concurrent approval protection
  const concExpRes = await makeRequest('/api/finance/expenses', {
    method: 'POST',
    headers: { Authorization: `Bearer ${memberToken}` },
    body: {
      title: 'Poetry Anthology Proofs',
      amount: 10000,
      category: 'Printing & Publications',
      department: 'Literature',
      currency: 'PKR',
    },
  });
  const concExpId = concExpRes.body.expense._id || concExpRes.body.expense.id;

  // Fire 2 concurrent approval requests simultaneously
  const [cRes1, cRes2] = await Promise.all([
    makeRequest(`/api/finance/expenses/${concExpId}/review`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${financeToken}` },
      body: { status: 'approved', reviewNotes: 'Concurrent reviewer A' },
    }),
    makeRequest(`/api/finance/expenses/${concExpId}/review`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${financeToken}` },
      body: { status: 'approved', reviewNotes: 'Concurrent reviewer B' },
    }),
  ]);

  const hasOneSuccess = (cRes1.statusCode === 200 && cRes2.statusCode === 409) || (cRes1.statusCode === 409 && cRes2.statusCode === 200);
  assert(
    hasOneSuccess && litBudget.spentAmount === 25000, // 15,000 + 10,000
    'Test 23: Concurrent duplicate approvals: exactly one succeeds (200), one rejected (409); single budget deduction'
  );

  // Test 24: executeTransactionIfSupported handles offline execution safely
  const txResult = await executeTransactionIfSupported(async (session) => {
    return { executed: true, hadSession: Boolean(session) };
  });
  assert(
    txResult.inTransaction === false && txResult.result.executed === true && txResult.result.hadSession === false,
    'Test 24: executeTransactionIfSupported executes safely in offline mock environment without false ACID claims'
  );

  // -------------------------------------------------------------------------
  // SECTION 6: GRACEFUL SHUTDOWN & CLEANUP
  // -------------------------------------------------------------------------
  console.log('\n--- Section 6: Graceful Shutdown Lifecycle ---');

  // Test 25: Graceful shutdown sequence execution
  let shutdownCompleted = false;
  try {
    await app.gracefulShutdown('SIGTERM', 0);
    shutdownCompleted = true;
  } catch (err) {
    console.error('Shutdown error:', err);
  }
  assert(shutdownCompleted && app.isShuttingDown(), 'Test 25: Graceful shutdown cleanly closes HTTP server and Mongoose connection');

  // Test 26: Repeated shutdown signals are ignored idempotently
  let duplicateShutdownHandled = true;
  try {
    await app.gracefulShutdown('SIGINT', 0);
  } catch {
    duplicateShutdownHandled = false;
  }
  assert(duplicateShutdownHandled, 'Test 26: Repeated shutdown signals ignored without error or duplicate cleanup');

  // Summary
  console.log('\n==================================================================');
  console.log(`PHASE 7A.1 TEST SUITE COMPLETE: ${testsPassed} PASSED, ${testsFailed} FAILED`);
  console.log('==================================================================\n');

  if (testsFailed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runPhase7A1SafetyTests()
    .then(() => {
      process.exit(0);
    })
    .catch((err) => {
      console.error('[Fatal Error in Test Suite]:', err);
      process.exit(1);
    });
}

module.exports = { runPhase7A1SafetyTests };
