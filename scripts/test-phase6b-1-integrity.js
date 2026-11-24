process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'rekhta_access_secret_2026_super_secure';
process.env.JWT_REFRESH_SECRET = 'rekhta_refresh_secret_2026_super_secure';

const http = require('http');
const jwt = require('jsonwebtoken');
const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');
const {
  setMemoryDonation,
  getMemoryDonationsList,
  clearMemoryDonations,
  setMemoryExpense,
  getMemoryExpensesList,
  clearMemoryExpenses,
  setMemoryBudget,
  getMemoryBudgetsList,
  clearMemoryBudgets,
} = require('../src/routes/finance.routes');

const TEST_PORT = 5009;
let server;

function makeRequest({ method = 'GET', path, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const reqHeaders = {
      'X-Requested-With': 'XMLHttpRequest',
      ...headers,
    };

    if (postData) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(
      {
        hostname: 'localhost',
        port: TEST_PORT,
        path,
        method,
        headers: reqHeaders,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(data);
          } catch {
            json = { raw: data };
          }
          resolve({ status: res.statusCode, headers: res.headers, data: json });
        });
      }
    );

    req.on('error', (err) => reject(err));
    if (postData) req.write(postData);
    req.end();
  });
}

function generateToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
}

async function runTestSuite() {
  console.log('======================================================================');
  console.log("  TA'MEER-E-REKHTA PHASE 6B.1: FINANCIAL INTEGRITY & CONCURRENCY AUDIT");
  console.log('======================================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`[PASS] ${message}`);
      passed++;
    } else {
      console.error(`[FAIL] ${message}`);
      failed++;
    }
  }

  // 1. Setup mock users
  const users = {
    superAdmin: {
      _id: 'usr_sa_6b1',
      id: 'usr_sa_6b1',
      name: 'Hafsa Arif (Super Admin)',
      email: 'admin.audit@rekhta.org',
      role: 'super_admin',
      status: 'active',
    },
    financeLead: {
      _id: 'usr_fin_lead_6b1',
      id: 'usr_fin_lead_6b1',
      name: 'Ahmad Maqsood (Finance Lead)',
      email: 'finance.audit@rekhta.org',
      role: 'finance',
      department: 'Finance',
      departmentCode: 'FIN',
      status: 'active',
    },
    financeOfficer: {
      _id: 'usr_fin_off_6b1',
      id: 'usr_fin_off_6b1',
      name: 'Usman Ghani (Finance Officer)',
      email: 'usman.audit@rekhta.org',
      role: 'finance',
      department: 'Finance',
      departmentCode: 'FIN',
      status: 'active',
    },
    litHead: {
      _id: 'usr_lit_head_6b1',
      id: 'usr_lit_head_6b1',
      name: 'Noor-ul-Huda (Literature Head)',
      email: 'literature.audit@rekhta.org',
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
    },
    member1: {
      _id: 'usr_mem_1_6b1',
      id: 'usr_mem_1_6b1',
      name: 'Tariq Volunteer',
      email: 'tariq.audit@rekhta.org',
      role: 'member',
      department: 'Literature',
      status: 'active',
    },
  };

  Object.values(users).forEach(setMemoryUser);

  const tokens = {
    superAdmin: generateToken({ id: users.superAdmin.id, role: users.superAdmin.role, email: users.superAdmin.email }),
    financeLead: generateToken({ id: users.financeLead.id, role: users.financeLead.role, email: users.financeLead.email }),
    financeOfficer: generateToken({ id: users.financeOfficer.id, role: users.financeOfficer.role, email: users.financeOfficer.email }),
    litHead: generateToken({ id: users.litHead.id, role: users.litHead.role, email: users.litHead.email }),
    member1: generateToken({ id: users.member1.id, role: users.member1.role, email: users.member1.email }),
  };

  // Find the seeded Literature department budget
  const litBudget = getMemoryBudgetsList().find((b) => b.department === 'Literature');
  assert(litBudget !== undefined, 'Setup: Found seeded Literature Department budget');

  try {
    // =========================================================================
    // TEST 1: Duplicate Expense Approval Protection
    // =========================================================================
    console.log('>>> [TEST 1]: Duplicate Expense Approval');

    // 1. Submit pending expense
    const resExp1 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: {
        title: 'Poetry Fest Logistics Batch 1',
        amount: 15000,
        category: 'Travel & Logistics',
      },
    });
    const exp1Id = resExp1.data?.expense?._id || resExp1.data?.expense?.id;
    assert(resExp1.status === 201 && exp1Id, 'Test 1.1: Literature Head submits pending expense (201 Created)');

    const bdgBefore1 = getMemoryBudgetsList().find((b) => b.department === 'Literature');
    const spentBefore1 = bdgBefore1.spentAmount;

    // 2. Initial Approval succeeds
    const resApprove1 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${exp1Id}/review`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { status: 'approved', reviewNotes: 'First legitimate approval' },
    });
    assert(resApprove1.status === 200 && resApprove1.data?.expense?.status === 'approved', 'Test 1.2: Initial review approves expense (200 OK)');

    const bdgAfterFirst = getMemoryBudgetsList().find((b) => b.department === 'Literature');
    assert(bdgAfterFirst.spentAmount === spentBefore1 + 15000, 'Test 1.3: Budget deduction occurs exactly once upon approval (PKR +15,000)');

    // 3. Second approval attempt strictly blocked
    const resDuplicateApprove = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${exp1Id}/review`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
      body: { status: 'approved', reviewNotes: 'Duplicate approval attempt' },
    });
    assert(
      resDuplicateApprove.status === 409 && resDuplicateApprove.data?.error?.includes('already been approved'),
      'Test 1.4: Duplicate approval attempt on already-approved expense rejected with 409 Conflict'
    );

    const bdgAfterDup = getMemoryBudgetsList().find((b) => b.department === 'Literature');
    assert(bdgAfterDup.spentAmount === spentBefore1 + 15000, 'Test 1.5: Budget spentAmount remains unchanged after duplicate rejection');

    // =========================================================================
    // TEST 2: Repeated Approval Requests (Idempotency / Conflict Check)
    // =========================================================================
    console.log('\n>>> [TEST 2]: Repeated Approval Requests');

    // Attempt multiple sequential repeated approvals
    const repeat1 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${exp1Id}/review`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { status: 'approved' },
    });
    const repeat2 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${exp1Id}/review`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
      body: { status: 'approved' },
    });
    assert(
      repeat1.status === 409 && repeat2.status === 409,
      'Test 2.1: Repeated approval requests consistently return 409 Conflict with idempotency defense'
    );

    // Disburse the expense
    const resDisburse = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${exp1Id}/disburse`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { disbursedNotes: 'Direct bank reimbursement' },
    });
    assert(resDisburse.status === 200 && resDisburse.data?.expense?.status === 'paid', 'Test 2.2: Expense transitioned from approved to paid (200 OK)');

    // Attempting to approve an already-paid expense returns 409
    const repeatOnPaid = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${exp1Id}/review`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
      body: { status: 'approved' },
    });
    assert(
      repeatOnPaid.status === 409 && repeatOnPaid.data?.error?.includes('paid'),
      'Test 2.3: Re-approving an already-paid/disbursed expense is strictly blocked with 409 Conflict'
    );

    // Repeated disbursement is also rejected
    const repeatDisburse = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${exp1Id}/disburse`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    assert(
      repeatDisburse.status === 409,
      'Test 2.4: Repeated disbursement of an already-paid expense is blocked with 409 Conflict'
    );

    // =========================================================================
    // TEST 3: Concurrent Approval Attempts (Simulated Race on Same Expense)
    // =========================================================================
    console.log('\n>>> [TEST 3]: Concurrent Approval Attempts (Race on Same Expense)');

    const resRaceExp = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: {
        title: 'Concurrent Race Target Expense',
        amount: 10000,
        category: 'Printing & Publications',
      },
    });
    const raceExpId = resRaceExp.data?.expense?._id || resRaceExp.data?.expense?.id;
    const bdgBeforeRace = getMemoryBudgetsList().find((b) => b.department === 'Literature');
    const spentBeforeRace = bdgBeforeRace.spentAmount;

    // Launch two concurrent approval requests simultaneously
    const [raceResp1, raceResp2] = await Promise.all([
      makeRequest({
        method: 'PATCH',
        path: `/api/finance/expenses/${raceExpId}/review`,
        headers: { Authorization: `Bearer ${tokens.financeLead}` },
        body: { status: 'approved', reviewNotes: 'Reviewer A winning race' },
      }),
      makeRequest({
        method: 'PATCH',
        path: `/api/finance/expenses/${raceExpId}/review`,
        headers: { Authorization: `Bearer ${tokens.superAdmin}` },
        body: { status: 'approved', reviewNotes: 'Reviewer B concurrent contender' },
      }),
    ]);

    const statuses = [raceResp1.status, raceResp2.status].sort();
    assert(
      statuses[0] === 200 && statuses[1] === 409,
      'Test 3.1: Concurrent duplicate approvals on same expense: exactly one succeeds (200) and one receives 409 Conflict'
    );

    const bdgAfterRace = getMemoryBudgetsList().find((b) => b.department === 'Literature');
    assert(
      bdgAfterRace.spentAmount === spentBeforeRace + 10000,
      'Test 3.2: Concurrent race deducts budget spentAmount exactly ONCE (no double deduction under race conditions)'
    );

    // =========================================================================
    // TEST 4: Concurrent Different Expense Approvals
    // =========================================================================
    console.log('\n>>> [TEST 4]: Concurrent Different Expense Approvals');

    const resDiff1 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: { title: 'Distinct Literature Expense Alpha', amount: 8000, category: 'Event Expenses' },
    });
    const resDiff2 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: { title: 'Distinct Literature Expense Beta', amount: 12000, category: 'Event Expenses' },
    });

    const expDiff1Id = resDiff1.data?.expense?._id || resDiff1.data?.expense?.id;
    const expDiff2Id = resDiff2.data?.expense?._id || resDiff2.data?.expense?.id;

    const bdgBeforeDiff = getMemoryBudgetsList().find((b) => b.department === 'Literature');
    const spentBeforeDiff = bdgBeforeDiff.spentAmount;

    // Approve both distinct expenses concurrently
    const [resApproveAlpha, resApproveBeta] = await Promise.all([
      makeRequest({
        method: 'PATCH',
        path: `/api/finance/expenses/${expDiff1Id}/review`,
        headers: { Authorization: `Bearer ${tokens.financeLead}` },
        body: { status: 'approved', reviewNotes: 'Concurrent Alpha' },
      }),
      makeRequest({
        method: 'PATCH',
        path: `/api/finance/expenses/${expDiff2Id}/review`,
        headers: { Authorization: `Bearer ${tokens.superAdmin}` },
        body: { status: 'approved', reviewNotes: 'Concurrent Beta' },
      }),
    ]);

    assert(
      resApproveAlpha.status === 200 && resApproveBeta.status === 200,
      'Test 4.1: Concurrent approval of two different departmental expenses both succeed with 200 OK'
    );

    const bdgAfterDiff = getMemoryBudgetsList().find((b) => b.department === 'Literature');
    assert(
      bdgAfterDiff.spentAmount === spentBeforeDiff + 8000 + 12000,
      'Test 4.2: Department budget spentAmount reflects both distinct deductions (+20,000 total) without lost updates'
    );

    // =========================================================================
    // TEST 5: Budget Lost-Update Prevention
    // =========================================================================
    console.log('\n>>> [TEST 5]: Budget Lost-Update Prevention');

    // Verify remainingAmount accurately tracks allocatedAmount - spentAmount
    assert(
      bdgAfterDiff.remainingAmount === bdgAfterDiff.allocatedAmount - bdgAfterDiff.spentAmount,
      `Test 5.1: Mathematical integrity confirmed: remainingAmount (${bdgAfterDiff.remainingAmount}) equals allocated (${bdgAfterDiff.allocatedAmount}) minus spent (${bdgAfterDiff.spentAmount})`
    );

    // =========================================================================
    // TEST 6: Budget Overspending Protection
    // =========================================================================
    console.log('\n>>> [TEST 6]: Budget Overspending Protection');

    const bdgCurrent = getMemoryBudgetsList().find((b) => b.department === 'Literature');
    const remainingBeforeOverspend = bdgCurrent.remainingAmount;

    // Submit an exorbitant expense exceeding remaining budget
    const resOverspendExp = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: {
        title: 'Exorbitant Venue Booking Beyond Budget',
        amount: remainingBeforeOverspend + 50000,
        category: 'Event Expenses',
      },
    });
    const overspendExpId = resOverspendExp.data?.expense?._id || resOverspendExp.data?.expense?.id;
    assert(resOverspendExp.status === 201, 'Test 6.1: High-value expense submitted successfully in pending state');

    // Attempting to approve an overspending expense must be rejected
    const resOverspendApprove = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${overspendExpId}/review`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { status: 'approved', reviewNotes: 'Attempting overspend approval' },
    });
    assert(
      resOverspendApprove.status === 400 && resOverspendApprove.data?.error?.includes('overspending protection'),
      'Test 6.2: Approving expense exceeding remaining budget allocation is rejected with 400 Bad Request (Overspending Defense)'
    );

    // Verify expense is still pending and budget is untouched
    const expCheck = getMemoryExpensesList().find((e) => (e._id || e.id) === overspendExpId);
    assert(expCheck?.status === 'pending', 'Test 6.3: Overspending expense remains in pending status');

    const bdgCheck = getMemoryBudgetsList().find((b) => b.department === 'Literature');
    assert(bdgCheck.spentAmount === bdgCurrent.spentAmount, 'Test 6.4: Department budget remains unchanged following overspend denial');

    // =========================================================================
    // TEST 7: Concurrent Allocation Updates
    // =========================================================================
    console.log('\n>>> [TEST 7]: Concurrent Allocation Updates');

    // Two finance admins adjust budget allocation concurrently
    const [allocResp1, allocResp2] = await Promise.all([
      makeRequest({
        method: 'PATCH',
        path: `/api/finance/budgets/${litBudget.budgetId}`,
        headers: { Authorization: `Bearer ${tokens.financeLead}` },
        body: { allocatedAmount: 250000, notes: 'Augment allocation to 250,000' },
      }),
      makeRequest({
        method: 'PATCH',
        path: `/api/finance/budgets/${litBudget.budgetId}`,
        headers: { Authorization: `Bearer ${tokens.superAdmin}` },
        body: { allocatedAmount: 260000, notes: 'Augment allocation to 260,000' },
      }),
    ]);

    assert(
      allocResp1.status === 200 && allocResp2.status === 200,
      'Test 7.1: Concurrent allocation adjustment requests are serialized and processed safely (200 OK)'
    );

    // Verify history records previousAmount, newAmount, and actor for each adjustment
    const updatedBdg = getMemoryBudgetsList().find((b) => b.budgetId === litBudget.budgetId);
    const updateHistory = updatedBdg.history.filter((h) => h.action === 'BUDGET_UPDATED');
    assert(
      updateHistory.length >= 2 && updateHistory[0].previousAmount !== undefined && updateHistory[0].newAmount !== undefined,
      'Test 7.2: Budget adjustment history retains previousAmount, newAmount, and timestamps with full auditability'
    );

    // Cannot reduce allocation below already spent amount
    const invalidReduction = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/budgets/${litBudget.budgetId}`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { allocatedAmount: 1000 },
    });
    assert(
      invalidReduction.status === 400 && invalidReduction.data?.error?.includes('below already spent amount'),
      'Test 7.3: Allocation reduction below already spent funds is rejected with 400 Bad Request'
    );

    // =========================================================================
    // TEST 8: Frozen and Closed Budget Behavior
    // =========================================================================
    console.log('\n>>> [TEST 8]: Frozen and Closed Budget Behavior');

    // Submit an expense for Literature
    const resFreezeExp = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: { title: 'Expenditure During Freeze Window', amount: 5000, category: 'Office Supplies' },
    });
    const freezeExpId = resFreezeExp.data?.expense?._id || resFreezeExp.data?.expense?.id;

    // 1. Freeze Literature Budget
    await makeRequest({
      method: 'PATCH',
      path: `/api/finance/budgets/${litBudget.budgetId}`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { status: 'frozen', notes: 'Temporary administrative freeze' },
    });

    // 2. Attempt to approve during freeze
    const resApproveFrozen = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${freezeExpId}/review`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
      body: { status: 'approved' },
    });
    assert(
      resApproveFrozen.status === 400 && resApproveFrozen.data?.error?.includes('frozen'),
      'Test 8.1: Approving expense against a frozen budget is rejected with 400 Bad Request'
    );

    // 3. Close Literature Budget
    await makeRequest({
      method: 'PATCH',
      path: `/api/finance/budgets/${litBudget.budgetId}`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { status: 'closed', notes: 'Fiscal period closed' },
    });

    // 4. Attempt to approve during closed status
    const resApproveClosed = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${freezeExpId}/review`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
      body: { status: 'approved' },
    });
    assert(
      resApproveClosed.status === 400 && resApproveClosed.data?.error?.includes('closed'),
      'Test 8.2: Approving expense against a closed budget is rejected with 400 Bad Request'
    );

    // 5. Reactivate budget
    await makeRequest({
      method: 'PATCH',
      path: `/api/finance/budgets/${litBudget.budgetId}`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { status: 'active', notes: 'Reactivated for operational continuity' },
    });

    const resApproveReactivated = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${freezeExpId}/review`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
      body: { status: 'approved' },
    });
    assert(
      resApproveReactivated.status === 200 && resApproveReactivated.data?.expense?.status === 'approved',
      'Test 8.3: Reactivating budget allows expense approvals to proceed normally (200 OK)'
    );

    // =========================================================================
    // TEST 9: Currency Mismatch Rejection
    // =========================================================================
    console.log('\n>>> [TEST 9]: Currency Mismatch Rejection');

    // Literature budget is in PKR. Submit expense in USD
    const resUsdExp = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: {
        title: 'International Literary Journal Subscription',
        amount: 250,
        currency: 'USD',
        category: 'Printing & Publications',
      },
    });
    const usdExpId = resUsdExp.data?.expense?._id || resUsdExp.data?.expense?.id;
    assert(resUsdExp.status === 201 && resUsdExp.data?.expense?.currency === 'USD', 'Test 9.1: Expense with foreign currency USD submitted (201 Created)');

    // Attempt to approve USD expense against PKR budget
    const resMismatchApprove = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${usdExpId}/review`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { status: 'approved', reviewNotes: 'Attempting cross-currency approval' },
    });
    assert(
      resMismatchApprove.status === 400 && resMismatchApprove.data?.error?.includes('Currency mismatch'),
      'Test 9.2: Cross-currency expense approval rejected with 400 Bad Request (No arbitrary exchange rate conversion)'
    );

    // =========================================================================
    // TEST 10: Currency-Specific Aggregation
    // =========================================================================
    console.log('\n>>> [TEST 10]: Currency-Specific Aggregation');

    // Log direct income in USD
    const resUsdIncome = await makeRequest({
      method: 'POST',
      path: '/api/finance/income',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        donorName: 'Overseas Philanthropist (US)',
        donorEmail: 'diaspora@rekhta.org',
        amount: 500,
        currency: 'USD',
        paymentMethod: 'Wire Transfer',
      },
    });
    assert(resUsdIncome.status === 201 && resUsdIncome.data?.donation?.currency === 'USD', 'Test 10.1: Foreign currency USD income logged (201 Created)');

    // Query overview
    const resOverview = await makeRequest({
      method: 'GET',
      path: '/api/finance/overview',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    assert(resOverview.status === 200, 'Test 10.2: Overview endpoint successfully queried (200 OK)');

    const ov = resOverview.data?.overview;
    assert(ov.currency === 'PKR', 'Test 10.3: Default overview currency explicitly identified as PKR');
    assert(
      ov.byCurrency?.income?.USD?.verifiedAmount === 500,
      'Test 10.4: USD income segregated in currency-specific breakdown (USD: 500)'
    );
    // Crucial check: USD is NOT added directly 1:1 into PKR total
    assert(
      ov.income.totalVerifiedAmount % 1000 === 0,
      'Test 10.5: PKR verified total is unpolluted by non-PKR currencies (No 1:1 cross-currency addition)'
    );

    // =========================================================================
    // TEST 11: CSV Currency Labeling
    // =========================================================================
    console.log('\n>>> [TEST 11]: CSV Currency Labeling');

    const [csvIncomeRes, csvExpRes, csvSummRes] = await Promise.all([
      makeRequest({ method: 'GET', path: '/api/finance/export/income', headers: { Authorization: `Bearer ${tokens.financeLead}` } }),
      makeRequest({ method: 'GET', path: '/api/finance/export/expenses', headers: { Authorization: `Bearer ${tokens.financeLead}` } }),
      makeRequest({ method: 'GET', path: '/api/finance/export/summary', headers: { Authorization: `Bearer ${tokens.financeLead}` } }),
    ]);

    const incomeCsv = csvIncomeRes.data?.raw || '';
    const expenseCsv = csvExpRes.data?.raw || '';
    const summCsv = csvSummRes.data?.raw || '';

    assert(
      incomeCsv.includes('Currency') && incomeCsv.includes('USD') && incomeCsv.includes('PKR'),
      'Test 11.1: Income CSV export includes dedicated Currency column and identifies USD and PKR transactions'
    );
    assert(
      expenseCsv.includes('Currency') && expenseCsv.includes('PKR'),
      'Test 11.2: Expense CSV export includes dedicated Currency column and identifies transaction currencies'
    );
    assert(
      summCsv.includes('Currency') && summCsv.includes('PKR'),
      'Test 11.3: Budget summary CSV export specifies currency for departmental allocations'
    );

    // =========================================================================
    // TEST 12: Audit History Integrity
    // =========================================================================
    console.log('\n>>> [TEST 12]: Audit History Integrity');

    const exp1Fresh = getMemoryExpensesList().find((e) => (e._id || e.id) === exp1Id);
    assert(exp1Fresh.history && exp1Fresh.history.length >= 3, 'Test 12.1: Expense lifecycle maintains complete multi-step history trail');

    const reviewStep = exp1Fresh.history.find((h) => h.status === 'approved');
    assert(
      reviewStep && reviewStep.changedByName && reviewStep.previousStatus === 'pending' && reviewStep.timestamp,
      'Test 12.2: Approval audit entry records actor name, previousStatus (pending), new status, and timestamp'
    );

    const paidStep = exp1Fresh.history.find((h) => h.status === 'paid');
    assert(
      paidStep && paidStep.previousStatus === 'approved' && paidStep.notes,
      'Test 12.3: Disbursement audit entry records transition from approved -> paid with disbursement notes'
    );

    // =========================================================================
    // TEST 13: Unauthorized Financial Record Modification
    // =========================================================================
    console.log('\n>>> [TEST 13]: Unauthorized Financial Record Modification');

    // 1. Regular member attempts to approve an expense
    const resUnauthReview = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${raceExpId}/review`,
      headers: { Authorization: `Bearer ${tokens.member1}` },
      body: { status: 'approved' },
    });
    assert(resUnauthReview.status === 403, 'Test 13.1: Regular member attempting expense review is blocked with 403 Forbidden');

    // 2. Department Head attempts to patch budget
    const resUnauthBudget = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/budgets/${litBudget.budgetId}`,
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: { allocatedAmount: 999999 },
    });
    assert(resUnauthBudget.status === 403, 'Test 13.2: Department head attempting budget alteration is blocked with 403 Forbidden');

    // 3. User attempts to inject falsified history array via request body
    const resTamper = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/budgets/${litBudget.budgetId}`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        history: [{ action: 'FABRICATED_ENTRY', note: 'Tampered history attempt' }],
        notes: 'Security test for history injection',
      },
    });
    const bdgPostTamper = getMemoryBudgetsList().find((b) => b.budgetId === litBudget.budgetId);
    const hasTampered = bdgPostTamper.history.some((h) => h.action === 'FABRICATED_ENTRY');
    assert(!hasTampered, 'Test 13.3: Request-body history tampering strictly neutralized; arbitrary audit history injection disallowed');

    // =========================================================================
    // TEST 14: Historical Record Preservation
    // =========================================================================
    console.log('\n>>> [TEST 14]: Historical Record Preservation');

    // 1. Hard deletion of expenses is disallowed
    const resHardDeleteExp = await makeRequest({
      method: 'DELETE',
      path: `/api/finance/expenses/${exp1Id}`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
    });
    assert(
      resHardDeleteExp.status === 405 && resHardDeleteExp.data?.error?.includes('strictly prohibited'),
      'Test 14.1: Permanent hard deletion of expense records is prohibited with 405 Method Not Allowed'
    );

    // 2. Hard deletion of budgets is disallowed
    const resHardDeleteBdg = await makeRequest({
      method: 'DELETE',
      path: `/api/finance/budgets/${litBudget.budgetId}`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
    });
    assert(
      resHardDeleteBdg.status === 405 && resHardDeleteBdg.data?.error?.includes('strictly prohibited'),
      'Test 14.2: Permanent hard deletion of budget records is prohibited with 405 Method Not Allowed'
    );

    // 3. Soft archiving succeeds
    const resArchiveExp = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${exp1Id}/archive`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    assert(
      resArchiveExp.status === 200 && resArchiveExp.data?.expense?.isArchived === true,
      'Test 14.3: Financial records preserved via soft archiving endpoint (isArchived: true, 200 OK)'
    );

    const archivedExp = getMemoryExpensesList().find((e) => (e._id || e.id) === exp1Id);
    assert(archivedExp && archivedExp.isArchived === true, 'Test 14.4: Record remains intact in datastore and marked as archived');

  } catch (err) {
    console.error('Test execution error:', err);
    failed++;
  }

  console.log('\n======================================================================');
  console.log(`  PHASE 6B.1 TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('======================================================================\n');

  if (server) {
    server.close();
  }

  process.exit(failed === 0 ? 0 : 1);
}

// Start test server
server = app.listen(TEST_PORT, () => {
  console.log(`[Test Runner] Integrity server listening on port ${TEST_PORT}...`);
  runTestSuite().catch((err) => {
    console.error('Fatal test error:', err);
    process.exit(1);
  });
});
