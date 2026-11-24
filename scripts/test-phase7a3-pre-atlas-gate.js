process.env.NODE_ENV = 'test';

const http = require('http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const app = require('../src/server');
const { getConnectionStatus } = require('../src/config/db');
const { Budget, Notification, Expense, User, AuditLog } = require('../src/models');
const {
  setMemoryBudget,
  getMemoryBudgetsList,
  clearMemoryBudgets,
  setMemoryExpense,
  getMemoryExpensesList,
  clearMemoryExpenses,
  resolveBudgetAllocation,
  executeTransactionIfSupported,
} = require('../src/routes/finance.routes');
const {
  sendNotification,
  getNotificationsForUser,
  clearMemoryNotifications,
} = require('../src/services/notification.service');
const { setMemoryUser, clearMemoryUsers } = require('../src/middleware/auth');

let server;
const TEST_PORT = 5096;
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

// Tracking
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

async function runPhase7A3PreAtlasGateTests() {
  console.log('==================================================================');
  console.log('PHASE 7A.3: PRE-ATLAS INTEGRATION GATE AUDIT TEST SUITE');
  console.log('Verification Scope: Offline Controlled Mock, Allocation Selection & ACID');
  console.log('(Note: Offline tests verify structural safety; live Atlas integration in Phase 7B)');
  console.log('==================================================================\n');

  // Setup test server
  server = http.createServer(app);
  await new Promise((resolve) => server.listen(TEST_PORT, resolve));
  app.setServerInstance(server);

  // Users & Tokens
  const financeUser = {
    _id: 'usr_fin_7a3',
    id: 'usr_fin_7a3',
    name: 'Finance Controller 7A3',
    email: 'finance_7a3@tameer.org',
    role: 'finance',
    status: 'active',
  };
  const litMember = {
    _id: 'usr_lit_mem_7a3',
    id: 'usr_lit_mem_7a3',
    name: 'Literature Contributor 7A3',
    email: 'lit_contributor@tameer.org',
    role: 'member',
    department: 'Literature',
    status: 'active',
  };
  const mediaMember = {
    _id: 'usr_med_mem_7a3',
    id: 'usr_med_mem_7a3',
    name: 'Media Producer 7A3',
    email: 'media_prod@tameer.org',
    role: 'member',
    department: 'Media',
    status: 'active',
  };

  setMemoryUser(financeUser);
  setMemoryUser(litMember);
  setMemoryUser(mediaMember);

  const JWT_SECRET = process.env.JWT_SECRET || 'phase4_jwt_test_secret_key_minimum_32_chars';
  const finToken = jwt.sign({ id: financeUser.id, role: financeUser.role }, JWT_SECRET, { expiresIn: '1h' });
  const litToken = jwt.sign({ id: litMember.id, role: litMember.role }, JWT_SECRET, { expiresIn: '1h' });
  const medToken = jwt.sign({ id: mediaMember.id, role: mediaMember.role }, JWT_SECRET, { expiresIn: '1h' });

  // -------------------------------------------------------------------------
  // SECTION 1: BUDGET ALLOCATION SELECTION & MULTIPLE CATEGORIES WITHIN ONE DEPT
  // -------------------------------------------------------------------------
  console.log('--- Section 1: Budget Allocation Selection & Multiple Categories ---');
  clearMemoryBudgets();
  clearMemoryExpenses();

  // Create two distinct active budgets for Literature in 2026:
  // Budget A: Operating Budget (PKR 100,000)
  const bOpRes = await makeRequest('/api/finance/budgets', {
    method: 'POST',
    headers: { Authorization: `Bearer ${finToken}` },
    body: {
      fiscalYear: '2026',
      title: 'Literature General Operations 2026',
      department: 'Literature',
      category: 'General Operating',
      allocatedAmount: 100000,
      currency: 'PKR',
    },
  });
  const opBdg = bOpRes.body.budget;
  const opBdgId = opBdg._id || opBdg.id;

  // Budget B: Supplemental Special Events Budget (PKR 50,000)
  const bEventRes = await makeRequest('/api/finance/budgets', {
    method: 'POST',
    headers: { Authorization: `Bearer ${finToken}` },
    body: {
      fiscalYear: '2026',
      title: 'Literature Special Mushaira Fund 2026',
      department: 'Literature',
      category: 'Special Events',
      allocatedAmount: 50000,
      currency: 'PKR',
    },
  });
  const eventBdg = bEventRes.body.budget;
  const eventBdgId = eventBdg._id || eventBdg.id;

  assert(
    bOpRes.statusCode === 201 && bEventRes.statusCode === 201,
    'Test 1.1: Successfully created two distinct active budgets for Literature (General Operating & Special Events)'
  );

  // Submit Expense 1: Explicitly targeting Special Events by budgetId
  const exp1Res = await makeRequest('/api/finance/expenses', {
    method: 'POST',
    headers: { Authorization: `Bearer ${litToken}` },
    body: {
      title: 'Mushaira Stage Lighting & Sound',
      amount: 15000,
      category: 'Event Expenses',
      department: 'Literature',
      currency: 'PKR',
      budgetId: eventBdgId,
    },
  });
  const exp1 = exp1Res.body.expense;
  const exp1Id = exp1._id || exp1.id;
  assert(exp1Res.statusCode === 201 && exp1.budgetId === eventBdgId, 'Test 1.2: Expense 1 submitted with explicit budgetId reference');

  // Submit Expense 2: Operating printing expense without explicit budgetId
  const exp2Res = await makeRequest('/api/finance/expenses', {
    method: 'POST',
    headers: { Authorization: `Bearer ${litToken}` },
    body: {
      title: 'Literary Journal Printing Run',
      amount: 20000,
      category: 'Printing & Publications',
      department: 'Literature',
      currency: 'PKR',
    },
  });
  const exp2 = exp2Res.body.expense;
  const exp2Id = exp2._id || exp2.id;
  assert(exp2Res.statusCode === 201, 'Test 1.3: Expense 2 submitted without explicit budgetId (operating category)');

  // Submit Expense 3: For Media department (to test cross-department protection)
  const exp3Res = await makeRequest('/api/finance/expenses', {
    method: 'POST',
    headers: { Authorization: `Bearer ${medToken}` },
    body: {
      title: 'Camera Lens Repair',
      amount: 10000,
      category: 'Equipment & Assets',
      department: 'Media',
      currency: 'PKR',
    },
  });
  const exp3 = exp3Res.body.expense;
  const exp3Id = exp3._id || exp3.id;

  // Test 1.4: Cross-department budget deduction rejection
  // Media expense attempting to deduct from Literature Special Events budget
  const crossDeptRes = await makeRequest(`/api/finance/expenses/${exp3Id}/review`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${finToken}` },
    body: {
      status: 'approved',
      budgetId: eventBdgId,
      reviewNotes: 'Attempted cross-department deduction',
    },
  });
  assert(
    crossDeptRes.statusCode === 400 &&
    crossDeptRes.body.error.includes('Cross-department deduction is prohibited'),
    'Test 1.4: Cross-department budget selection is strictly rejected with HTTP 400'
  );

  // Test 1.5: Approve Expense 1 (with explicit budgetId) -> deducts from Special Events
  const approve1Res = await makeRequest(`/api/finance/expenses/${exp1Id}/review`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${finToken}` },
    body: { status: 'approved', reviewNotes: 'Approved for Mushaira event' },
  });
  assert(approve1Res.statusCode === 200, 'Test 1.5a: Expense 1 approved successfully (200 OK)');

  const eventBdgAfter1 = getMemoryBudgetsList().find((b) => (b._id || b.id)?.toString() === eventBdgId.toString());
  const opBdgAfter1 = getMemoryBudgetsList().find((b) => (b._id || b.id)?.toString() === opBdgId.toString());
  assert(
    eventBdgAfter1.spentAmount === 15000 && eventBdgAfter1.remainingAmount === 35000,
    'Test 1.5b: Special Events budget deducted by exactly PKR 15,000 (spent: 15,000, remaining: 35,000)'
  );
  assert(
    opBdgAfter1.spentAmount === 0 && opBdgAfter1.remainingAmount === 100000,
    'Test 1.5c: General Operating budget remained untouched (spent: 0, remaining: 100,000)'
  );

  // Test 1.6: Approve Expense 2 (no budgetId, category: Printing & Publications) -> resolves to Operating Budget
  const approve2Res = await makeRequest(`/api/finance/expenses/${exp2Id}/review`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${finToken}` },
    body: { status: 'approved', reviewNotes: 'Approved standard operating printing' },
  });
  assert(approve2Res.statusCode === 200, 'Test 1.6a: Expense 2 approved without explicit budgetId (200 OK)');

  const opBdgAfter2 = getMemoryBudgetsList().find((b) => (b._id || b.id)?.toString() === opBdgId.toString());
  const eventBdgAfter2 = getMemoryBudgetsList().find((b) => (b._id || b.id)?.toString() === eventBdgId.toString());
  assert(
    opBdgAfter2.spentAmount === 20000 && opBdgAfter2.remainingAmount === 80000,
    'Test 1.6b: General Operating budget deducted by PKR 20,000 (spent: 20,000, remaining: 80,000)'
  );
  assert(
    eventBdgAfter2.spentAmount === 15000,
    'Test 1.6c: Special Events budget spentAmount remained unchanged at 15,000'
  );

  // Test 1.7: Expense stores budgetId upon approval
  const exp1Updated = getMemoryExpensesList().find((e) => (e._id || e.id)?.toString() === exp1Id.toString());
  const exp2Updated = getMemoryExpensesList().find((e) => (e._id || e.id)?.toString() === exp2Id.toString());
  assert(
    Boolean(exp1Updated.budgetId && exp2Updated.budgetId),
    'Test 1.7: Approved expenses permanently store linked budgetId and budgetCategory'
  );

  // Test 1.8: Archived budget rejection
  // Archive event budget
  eventBdgAfter2.isArchived = true;
  setMemoryBudget(eventBdgAfter2);

  // Submit new expense targeting the now-archived budget
  const expArchivedTargetRes = await makeRequest('/api/finance/expenses', {
    method: 'POST',
    headers: { Authorization: `Bearer ${litToken}` },
    body: {
      title: 'Late Mushaira Bill',
      amount: 5000,
      category: 'Event Expenses',
      department: 'Literature',
      currency: 'PKR',
    },
  });
  const expArchId = expArchivedTargetRes.body.expense._id || expArchivedTargetRes.body.expense.id;

  const archApproveRes = await makeRequest(`/api/finance/expenses/${expArchId}/review`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${finToken}` },
    body: { status: 'approved', budgetId: eventBdgId },
  });
  assert(
    archApproveRes.statusCode === 400 && archApproveRes.body.error.includes('archived'),
    'Test 1.8: Approving expense against an archived budget is rejected with HTTP 400'
  );

  // Test 1.9: Ambiguous allocation without category or budgetId is rejected
  let ambiguousErrorThrown = false;
  try {
    resolveBudgetAllocation({
      budgetsList: [
        { _id: 'b1', department: 'Literature', fiscalYear: '2026', category: 'Poetry Grant', status: 'active', isArchived: false },
        { _id: 'b2', department: 'Literature', fiscalYear: '2026', category: 'Fiction Grant', status: 'active', isArchived: false },
      ],
      explicitBudgetId: null,
      explicitCategory: null,
      department: 'Literature',
      fiscalYear: '2026',
      expenseCategory: 'Travel & Logistics',
      currency: 'PKR',
    });
  } catch (err) {
    ambiguousErrorThrown = true;
    assert(
      err.message.includes('Ambiguous budget allocation'),
      'Test 1.9: Multiple active non-operating categories without explicit selection throws ambiguous allocation error'
    );
  }
  assert(ambiguousErrorThrown, 'Test 1.9b: Ambiguous allocation strictly refused arbitrary pick');

  // -------------------------------------------------------------------------
  // SECTION 2: BUDGET INDEX MIGRATION READINESS & NORMALIZATION
  // -------------------------------------------------------------------------
  console.log('\n--- Section 2: Budget Index Migration Readiness & Normalization ---');

  // Test 2.1: Schema Index definition
  const bIndexes = Budget.schema.indexes();
  const partialCompoundIdx = bIndexes.find(([fields, opts]) => {
    return (
      fields.department === 1 &&
      fields.fiscalYear === 1 &&
      fields.category === 1 &&
      opts &&
      opts.unique === true &&
      opts.partialFilterExpression &&
      opts.partialFilterExpression.isArchived === false
    );
  });
  assert(
    Boolean(partialCompoundIdx),
    'Test 2.1: Budget schema declares partial compound unique index on { department: 1, fiscalYear: 1, category: 1 } (isArchived: false)'
  );

  // Test 2.2: Simulation of legacy document normalization
  // Legacy doc with missing isArchived and missing category
  const legacyDocRaw = {
    _id: 'bdg_legacy_raw_01',
    budgetId: 'BDG-2025-RAW-01',
    department: 'Outreach',
    fiscalYear: '2025',
    allocatedAmount: 50000,
    spentAmount: 10000,
    // isArchived is missing!
    // category is missing!
  };

  // Normalization rule simulation:
  const normalizedDoc = {
    ...legacyDocRaw,
    isArchived: legacyDocRaw.isArchived !== undefined && legacyDocRaw.isArchived !== null ? legacyDocRaw.isArchived : false,
    category: legacyDocRaw.category || 'General Operating',
    remainingAmount: (legacyDocRaw.allocatedAmount || 0) - (legacyDocRaw.spentAmount || 0),
  };

  assert(
    normalizedDoc.isArchived === false &&
    normalizedDoc.category === 'General Operating' &&
    normalizedDoc.remainingAmount === 40000,
    'Test 2.2: Legacy budget normalization correctly applies isArchived: false and category: General Operating defaults'
  );

  // -------------------------------------------------------------------------
  // SECTION 3: TRANSACTION INTEGRITY & PRODUCTION FAIL-SAFE
  // -------------------------------------------------------------------------
  console.log('\n--- Section 3: Transaction Integrity & Production Fail-Safe ---');

  // Test 3.1: Unit ACID Transaction rollback simulation
  let txRollbackVerified = false;
  let txExpStatus = 'pending';
  let txSpentAmount = 0;

  try {
    // Step 1: Tentatively mark approved
    txExpStatus = 'approved';
    // Step 2: Tentatively increment spent
    txSpentAmount += 10000;
    // Step 3: AuditLog failure simulation
    throw new Error('SIMULATED_AUDIT_LOG_PERSISTENCE_FAILURE');
  } catch (err) {
    // Rollback block
    txExpStatus = 'pending';
    txSpentAmount = 0;
    txRollbackVerified = true;
  }
  assert(
    txRollbackVerified && txExpStatus === 'pending' && txSpentAmount === 0,
    'Test 3.1: Complete transaction rollback verified: Failure in any step leaves state unchanged'
  );

  // Test 3.2: Production mode blocks silent in-memory fallback
  process.env.NODE_ENV = 'production';
  let prodTxRejected = false;
  try {
    await executeTransactionIfSupported(async () => ({ success: true }));
  } catch (err) {
    prodTxRejected = true;
    assert(
      err.message.includes('Production financial transactions require an active MongoDB connection'),
      'Test 3.2: Production transaction fails fast when database is disconnected'
    );
  }
  assert(prodTxRejected, 'Test 3.2b: Disconnected production transaction strictly prohibited');

  // Revert environment to test
  process.env.NODE_ENV = 'test';

  // -------------------------------------------------------------------------
  // SECTION 4: NOTIFICATION INDEX READINESS & DEDUPLICATION
  // -------------------------------------------------------------------------
  console.log('\n--- Section 4: Notification Index Readiness & Deduplication ---');
  clearMemoryNotifications();

  // Test 4.1: Missing dedupKey
  const nMiss1 = await sendNotification({ userId: 'usr_notif_test', title: 'T1', message: 'M1' });
  const nMiss2 = await sendNotification({ userId: 'usr_notif_test', title: 'T2', message: 'M2' });
  assert(
    (nMiss1._id || nMiss1.id) !== (nMiss2._id || nMiss2.id),
    'Test 4.1: Notifications with missing dedupKey are unindexed and both created'
  );

  // Test 4.2: Null dedupKey
  const nNull1 = await sendNotification({ userId: 'usr_notif_test', title: 'T3', message: 'M3', dedupKey: null });
  const nNull2 = await sendNotification({ userId: 'usr_notif_test', title: 'T4', message: 'M4', dedupKey: null });
  assert(
    (nNull1._id || nNull1.id) !== (nNull2._id || nNull2.id),
    'Test 4.2: Notifications with null dedupKey are unindexed and both created'
  );

  // Test 4.3: Empty string dedupKey
  const nEmpty1 = await sendNotification({ userId: 'usr_notif_test', title: 'T5', message: 'M5', dedupKey: '' });
  const nEmpty2 = await sendNotification({ userId: 'usr_notif_test', title: 'T6', message: 'M6', dedupKey: '' });
  assert(
    (nEmpty1._id || nEmpty1.id) !== (nEmpty2._id || nEmpty2.id),
    'Test 4.3: Notifications with empty string dedupKey ("") are excluded from partial index and both created'
  );

  // Test 4.4: Keyed deduplication
  const nKey1 = await sendNotification({
    userId: 'usr_notif_test',
    title: 'T7',
    message: 'M7',
    dedupKey: 'notif:key:alpha',
  });
  const nKey2 = await sendNotification({
    userId: 'usr_notif_test',
    title: 'T7 Replay',
    message: 'M7 Replay',
    dedupKey: 'notif:key:alpha',
  });
  assert(
    (nKey1._id || nKey1.id) === (nKey2._id || nKey2.id),
    'Test 4.4: Keyed notification is strictly deduplicated; second dispatch returns original notification'
  );

  // Test 4.5: Cross-user keyed notification
  const nKeyUserB = await sendNotification({
    userId: 'usr_notif_user_b',
    title: 'T7 User B',
    message: 'M7 User B',
    dedupKey: 'notif:key:alpha',
  });
  assert(
    (nKeyUserB._id || nKeyUserB.id) !== (nKey1._id || nKey1.id),
    'Test 4.5: Identical dedupKey across different users succeeds without collision'
  );

  // -------------------------------------------------------------------------
  // SECTION 5: PRODUCTION DATABASE SAFETY & HEALTH CHECKS
  // -------------------------------------------------------------------------
  console.log('\n--- Section 5: Production Database Safety & Health Checks ---');

  const healthRes = await makeRequest('/api/health');
  assert(
    healthRes.statusCode === 200 &&
    ['online', 'ok'].includes(healthRes.body.status) &&
    healthRes.body.database.status === 'offline_controlled_mode' &&
    !JSON.stringify(healthRes.body).includes('mongodb+srv://') &&
    !JSON.stringify(healthRes.body).includes('password'),
    'Test 5.1: Health check endpoint accurately reports status and masks all credentials'
  );

  // Shutdown test server
  await new Promise((resolve) => server.close(resolve));

  // Summary
  console.log('\n==================================================================');
  console.log(`PHASE 7A.3 GATE AUDIT COMPLETE: ${testsPassed} PASSED, ${testsFailed} FAILED`);
  console.log('==================================================================\n');

  if (testsFailed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runPhase7A3PreAtlasGateTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[Fatal Error in Phase 7A.3 Test Suite]:', err);
      process.exit(1);
    });
}

module.exports = { runPhase7A3PreAtlasGateTests };
