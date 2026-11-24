/**
 * Phase D.2.2.5 Finance Operations, Budget Allocation, Expense Lifecycle & Donation Audit Test Suite
 *
 * Execution:
 *   node backend/scripts/test-phase-d225-finance.js
 */

const http = require('http');
const express = require('express');
const jwt = require('jsonwebtoken');

// Set staging test environment
process.env.NODE_ENV = 'staging';
process.env.JWT_SECRET = 'staging_test_jwt_secret_d225_super_safe_and_long_enough';

const { router: financeRouter } = require('../src/routes/finance.routes');
const {
  setMemoryUser,
  getMemoryUsersList,
  TECHNICAL_ROLES,
  OPERATIONAL_DESIGNATIONS,
  HR_DESIGNATIONS,
} = require('../src/middleware/auth');
const { hasCapability, CAPABILITIES } = require('../src/constants/roles');

// ---------------------------------------------------------------------------
// 1. Synthetic Test Personas Setup
// ---------------------------------------------------------------------------
const TEST_PERSONAS = {
  superAdmin: {
    id: 'user_sa_d225',
    _id: 'user_sa_d225',
    name: 'Super Administrator',
    email: 'superadmin.d225@rekhta.org',
    role: TECHNICAL_ROLES.SUPER_ADMIN,
    designation: 'super_admin',
    department: 'Administration',
    status: 'active',
  },
  financeLead: {
    id: 'user_fin_d225',
    _id: 'user_fin_d225',
    name: 'Ahmad Maqsood (Finance Lead)',
    email: 'finance.lead.d225@rekhta.org',
    role: TECHNICAL_ROLES.FINANCE,
    designation: 'member',
    department: 'Finance',
    status: 'active',
  },
  hrHead: {
    id: 'user_hr_head_d225',
    _id: 'user_hr_head_d225',
    name: 'Hania Mehmood (HR Head)',
    email: 'hr.head.d225@rekhta.org',
    role: TECHNICAL_ROLES.HR,
    designation: HR_DESIGNATIONS.HR_HEAD,
    department: 'HR',
    status: 'active',
  },
  litHead: {
    id: 'user_lit_head_d225',
    _id: 'user_lit_head_d225',
    name: 'Noor-ul-Huda (Literature Head)',
    email: 'lit.head.d225@rekhta.org',
    role: TECHNICAL_ROLES.DEPT_LITERATURE,
    designation: OPERATIONAL_DESIGNATIONS.HEAD,
    department: 'Literature',
    status: 'active',
  },
  litDirector: {
    id: 'user_lit_dir_d225',
    _id: 'user_lit_dir_d225',
    name: 'Zainab Qazi (Literature Director)',
    email: 'lit.dir.d225@rekhta.org',
    role: TECHNICAL_ROLES.DEPT_LITERATURE,
    designation: OPERATIONAL_DESIGNATIONS.DIRECTOR,
    department: 'Literature',
    status: 'active',
  },
  litAssistant: {
    id: 'user_lit_ast_d225',
    _id: 'user_lit_ast_d225',
    name: 'Hamza Tariq (Literature Assistant Director)',
    email: 'lit.ast.d225@rekhta.org',
    role: TECHNICAL_ROLES.DEPT_LITERATURE,
    designation: OPERATIONAL_DESIGNATIONS.ASSISTANT_DIRECTOR,
    department: 'Literature',
    status: 'active',
  },
  litMember: {
    id: 'user_lit_mem_d225',
    _id: 'user_lit_mem_d225',
    name: 'Usman Farooq (Literature Member)',
    email: 'lit.mem.d225@rekhta.org',
    role: TECHNICAL_ROLES.MEMBER,
    designation: OPERATIONAL_DESIGNATIONS.MEMBER,
    department: 'Literature',
    status: 'active',
  },
};

// Seed personas into auth memory store
Object.values(TEST_PERSONAS).forEach((p) => setMemoryUser(p));

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id || user._id,
      email: user.email,
      role: user.role,
      designation: user.designation,
      department: user.department,
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// ---------------------------------------------------------------------------
// 2. Test Express App Server
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use('/api', financeRouter);
app.use('/api/finance', financeRouter);

let server;
let port;
let baseUrl;

function startServer() {
  return new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}/api`;
      resolve();
    });
  });
}

function stopServer() {
  return new Promise((resolve) => {
    if (server) server.close(resolve);
    else resolve();
  });
}

async function request(method, path, body = null, token = null) {
  const url = `${baseUrl}${path}`;
  const parsed = new URL(url);

  return new Promise((resolve, reject) => {
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (body) headers['Content-Type'] = 'application/json';

    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          let json = null;
          const text = buffer.toString('utf8');
          try {
            json = JSON.parse(text);
          } catch {}
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: json,
            text,
            buffer,
          });
        });
      }
    );

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ---------------------------------------------------------------------------
// 3. Test Runner & Assertion Harness
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;
const results = [];

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  [PASS] ${message}`);
    results.push({ message, pass: true });
  } else {
    failed++;
    console.error(`  [FAIL] ${message}`);
    results.push({ message, pass: false });
  }
}

// ---------------------------------------------------------------------------
// 4. Test Execution Sequence
// ---------------------------------------------------------------------------
async function runTests() {
  await startServer();
  console.log('\n======================================================================');
  console.log("  TA'MEER-E-REKHTA PHASE D.2.2.5: FINANCE OPERATIONS & INTEGRITY AUDIT");
  console.log('======================================================================\n');

  try {
    // Record initial baseline budget spent amounts before running tests
    const preRes = await request('GET', '/finance/budgets', null, makeToken(TEST_PERSONAS.financeLead));
    const preBudgets = preRes.body.budgets || [];
    const preFinSpent = preBudgets.find((b) => b.department === 'Finance' && b.fiscalYear === '2026')?.spentAmount || 0;
    const preGenSpent = preBudgets.find((b) => b.department === 'General' && b.fiscalYear === '2026')?.spentAmount || 0;
    const preHRSpent = preBudgets.find((b) => b.department === 'HR' && b.fiscalYear === '2026')?.spentAmount || 0;

    // -----------------------------------------------------------------------
    // SECTION 1: Capability Matrix & Role Separation
    // -----------------------------------------------------------------------
    console.log('>>> [SECTION 1]: Role-Based Capabilities & Separation of Concerns');

    assert(
      hasCapability(TEST_PERSONAS.financeLead, CAPABILITIES.FINANCE_DASHBOARD_VIEW) === true,
      'Test 1.1: Finance lead possesses FINANCE_DASHBOARD_VIEW capability'
    );
    assert(
      hasCapability(TEST_PERSONAS.superAdmin, CAPABILITIES.FINANCE_DASHBOARD_VIEW) === true,
      'Test 1.2: Super Admin possesses FINANCE_DASHBOARD_VIEW capability'
    );
    assert(
      hasCapability(TEST_PERSONAS.hrHead, CAPABILITIES.FINANCE_DASHBOARD_VIEW) === false,
      'Test 1.3: HR Head is DENIED FINANCE_DASHBOARD_VIEW capability'
    );
    assert(
      hasCapability(TEST_PERSONAS.litHead, CAPABILITIES.FINANCE_DASHBOARD_VIEW) === false,
      'Test 1.4: Department Head is DENIED organizational FINANCE_DASHBOARD_VIEW capability'
    );
    assert(
      hasCapability(TEST_PERSONAS.litMember, CAPABILITIES.FINANCE_DASHBOARD_VIEW) === false,
      'Test 1.5: Regular Member is DENIED FINANCE_DASHBOARD_VIEW capability'
    );
    assert(
      hasCapability(TEST_PERSONAS.financeLead, CAPABILITIES.FINANCE_BUDGET_MANAGE) === true,
      'Test 1.6: Finance lead possesses FINANCE_BUDGET_MANAGE capability'
    );
    assert(
      hasCapability(TEST_PERSONAS.hrHead, CAPABILITIES.FINANCE_BUDGET_MANAGE) === false,
      'Test 1.7: HR Head is DENIED FINANCE_BUDGET_MANAGE capability'
    );
    assert(
      hasCapability(TEST_PERSONAS.financeLead, CAPABILITIES.FINANCE_DATA_EXPORT) === true,
      'Test 1.8: Finance lead possesses FINANCE_DATA_EXPORT capability'
    );
    assert(
      hasCapability(TEST_PERSONAS.hrHead, CAPABILITIES.FINANCE_DATA_EXPORT) === false,
      'Test 1.9: HR Head is DENIED FINANCE_DATA_EXPORT capability'
    );

    // -----------------------------------------------------------------------
    // SECTION 2: Finance Dashboard & Overview Access Control
    // -----------------------------------------------------------------------
    console.log('\n>>> [SECTION 2]: Finance Overview & Dashboard Endpoint Authorization');

    const resOverviewFin = await request('GET', '/finance/overview', null, makeToken(TEST_PERSONAS.financeLead));
    assert(resOverviewFin.status === 200 && resOverviewFin.body.success === true, 'Test 2.1: Finance lead accesses Finance Overview (HTTP 200 OK)');

    const resOverviewSA = await request('GET', '/finance/overview', null, makeToken(TEST_PERSONAS.superAdmin));
    assert(resOverviewSA.status === 200 && resOverviewSA.body.success === true, 'Test 2.2: Super Admin accesses Finance Overview (HTTP 200 OK)');

    const resOverviewHR = await request('GET', '/finance/overview', null, makeToken(TEST_PERSONAS.hrHead));
    assert(resOverviewHR.status === 403, 'Test 2.3: HR Head accessing Finance Overview is blocked with HTTP 403 Forbidden');

    const resOverviewLit = await request('GET', '/finance/overview', null, makeToken(TEST_PERSONAS.litHead));
    assert(resOverviewLit.status === 403, 'Test 2.4: Department Head accessing full Finance Overview is blocked with HTTP 403 Forbidden');

    const resOverviewMem = await request('GET', '/finance/overview', null, makeToken(TEST_PERSONAS.litMember));
    assert(resOverviewMem.status === 403, 'Test 2.5: Regular Member accessing Finance Overview is blocked with HTTP 403 Forbidden');

    const resOverviewAnon = await request('GET', '/finance/overview');
    assert(resOverviewAnon.status === 401, 'Test 2.6: Unauthenticated request to Finance Overview is rejected with HTTP 401 Unauthorized');

    // -----------------------------------------------------------------------
    // SECTION 3: Department Leadership vs Assistant Director / Member Scoping
    // -----------------------------------------------------------------------
    console.log('\n>>> [SECTION 3]: Designation-Aware Departmental Financial Access');

    const resBdgHead = await request('GET', '/finance/budgets', null, makeToken(TEST_PERSONAS.litHead));
    assert(resBdgHead.status === 200 && resBdgHead.body.success === true, 'Test 3.1: Literature Head can view Literature departmental budget (HTTP 200 OK)');

    const resBdgDir = await request('GET', '/finance/budgets', null, makeToken(TEST_PERSONAS.litDirector));
    assert(resBdgDir.status === 200 && resBdgDir.body.success === true, 'Test 3.2: Literature Director can view Literature departmental budget (HTTP 200 OK)');

    const resBdgAst = await request('GET', '/finance/budgets', null, makeToken(TEST_PERSONAS.litAssistant));
    assert(
      resBdgAst.status === 403,
      'Test 3.3: Literature Assistant Director is BLOCKED from viewing budgets (HTTP 403 Forbidden)'
    );

    const resBdgMem = await request('GET', '/finance/budgets', null, makeToken(TEST_PERSONAS.litMember));
    assert(
      resBdgMem.status === 403,
      'Test 3.4: Department Member is BLOCKED from viewing budgets (HTTP 403 Forbidden)'
    );

    const resDeptExpHead = await request('GET', '/finance/expenses/department', null, makeToken(TEST_PERSONAS.litHead));
    assert(resDeptExpHead.status === 200 && resDeptExpHead.body.success === true, 'Test 3.5: Literature Head can view Literature departmental expenses (HTTP 200 OK)');

    const resDeptExpAst = await request('GET', '/finance/expenses/department', null, makeToken(TEST_PERSONAS.litAssistant));
    assert(
      resDeptExpAst.status === 403,
      'Test 3.6: Literature Assistant Director is BLOCKED from departmental expenses (HTTP 403 Forbidden)'
    );

    // -----------------------------------------------------------------------
    // SECTION 4: Budget Allocation & Baseline Isolation
    // -----------------------------------------------------------------------
    console.log('\n>>> [SECTION 4]: Budget Allocation, Uniqueness & Baseline Protection');

    // Allocate a test-specific budget for Literature department
    const testBudgetPayload = {
      title: 'Literature Poetry Recital & Literary Workshop FY2026',
      department: 'Literature',
      fiscalYear: '2026',
      category: 'Event Expenses',
      allocatedAmount: 75000,
      currency: 'PKR',
      notes: 'Dedicated test allocation under TR_20261124_1EA2B4',
      stagingTestRunId: 'TR_20261124_1EA2B4',
    };

    const resAlloc = await request('POST', '/finance/budgets', testBudgetPayload, makeToken(TEST_PERSONAS.financeLead));
    assert(resAlloc.status === 201 && resAlloc.body.success === true, 'Test 4.1: Finance lead successfully allocates test budget (HTTP 201 Created)');

    // Attempting duplicate active budget for same department, fiscal year, and category
    const resAllocDup = await request('POST', '/finance/budgets', testBudgetPayload, makeToken(TEST_PERSONAS.financeLead));
    assert(
      resAllocDup.status === 409,
      'Test 4.2: Duplicate active budget allocation for same department, fiscal year & category rejected (HTTP 409 Conflict)'
    );

    // Department Head attempting to create a budget allocation
    const resAllocLitHead = await request('POST', '/finance/budgets', testBudgetPayload, makeToken(TEST_PERSONAS.litHead));
    assert(
      resAllocLitHead.status === 403,
      'Test 4.3: Department Head attempting to allocate budget is blocked with HTTP 403 Forbidden'
    );

    // Soft-archiving budget
    const createdBudgetId = resAlloc.body.budget.budgetId;
    const resArchive = await request('PATCH', `/finance/budgets/${createdBudgetId}/archive`, {}, makeToken(TEST_PERSONAS.financeLead));
    assert(resArchive.status === 200 && resArchive.body.budget.isArchived === true, 'Test 4.4: Soft-archiving budget marks isArchived: true (HTTP 200 OK)');

    // Permanent hard delete is prohibited
    const resDelete = await request('DELETE', `/finance/budgets/${createdBudgetId}`, null, makeToken(TEST_PERSONAS.financeLead));
    assert(resDelete.status === 405, 'Test 4.5: Hard deletion of budget rejected with HTTP 405 Method Not Allowed');

    // -----------------------------------------------------------------------
    // SECTION 5: Expense Lifecycle & Anti-Self-Approval
    // -----------------------------------------------------------------------
    console.log('\n>>> [SECTION 5]: Expense Submission, Anti-Self-Approval & Lifecycle');

    // Member submits personal reimbursement expense
    const memberExpPayload = {
      title: 'Literary Workshop Stationery & Pamphlets',
      amount: 4500,
      category: 'Office Supplies',
      department: 'Literature',
      currency: 'PKR',
      notes: 'Purchased markers and printed handouts',
    };
    const resExpSubmit = await request('POST', '/finance/expenses', memberExpPayload, makeToken(TEST_PERSONAS.litMember));
    assert(resExpSubmit.status === 201 && resExpSubmit.body.success === true, 'Test 5.1: Member submits expense claim (HTTP 201 Created)');
    const memberExpId = resExpSubmit.body.expense.expenseId;

    // Member views their own expense
    const resMyExp = await request('GET', '/finance/expenses/my', null, makeToken(TEST_PERSONAS.litMember));
    assert(
      resMyExp.status === 200 && resMyExp.body.expenses.some((e) => e.expenseId === memberExpId),
      'Test 5.2: Member views own submitted expenses via /api/finance/expenses/my (HTTP 200 OK)'
    );

    // CRITICAL: Finance Lead submits an expense and attempts to approve their own
    const finExpPayload = {
      title: 'Literature Event Audio Equipment Rental',
      amount: 2500,
      category: 'Event Expenses',
      department: 'Literature',
      currency: 'PKR',
    };
    const resFinExpSubmit = await request('POST', '/finance/expenses', finExpPayload, makeToken(TEST_PERSONAS.financeLead));
    assert(resFinExpSubmit.status === 201, 'Test 5.3: Finance lead submits an operational expense (HTTP 201 Created)');
    const finExpId = resFinExpSubmit.body.expense.expenseId;

    // Finance lead attempts to self-approve
    const resFinSelfApprove = await request(
      'PATCH',
      `/finance/expenses/${finExpId}/review`,
      { status: 'approved' },
      makeToken(TEST_PERSONAS.financeLead)
    );
    assert(
      resFinSelfApprove.status === 403,
      'Test 5.4: CRITICAL Anti-Self-Approval: Finance lead attempting to approve own expense BLOCKED (HTTP 403 Forbidden)'
    );

    // Super Admin approves Finance lead's expense
    const resSAApproveFin = await request(
      'PATCH',
      `/finance/expenses/${finExpId}/review`,
      { status: 'approved' },
      makeToken(TEST_PERSONAS.superAdmin)
    );
    assert(resSAApproveFin.status === 200, "Test 5.5: Super Admin successfully reviews and approves Finance lead's expense (HTTP 200 OK)");

    // Super Admin submits expense and attempts self-approval
    const saExpPayload = {
      title: 'Literature Poetry Anthologies Printing',
      amount: 3000,
      category: 'Printing & Publications',
      department: 'Literature',
      currency: 'PKR',
    };
    const resSAExpSubmit = await request('POST', '/finance/expenses', saExpPayload, makeToken(TEST_PERSONAS.superAdmin));
    const saExpId = resSAExpSubmit.body.expense.expenseId;

    const resSASelfApprove = await request(
      'PATCH',
      `/finance/expenses/${saExpId}/review`,
      { status: 'approved' },
      makeToken(TEST_PERSONAS.superAdmin)
    );
    assert(
      resSASelfApprove.status === 403,
      'Test 5.6: CRITICAL Anti-Self-Approval: Super Admin attempting to approve own expense BLOCKED (HTTP 403 Forbidden)'
    );

    // Disburse approved expense
    const resDisburse = await request('PATCH', `/finance/expenses/${finExpId}/disburse`, { disbursedNotes: 'Paid via bank transfer' }, makeToken(TEST_PERSONAS.financeLead));
    assert(resDisburse.status === 200 && resDisburse.body.expense.status === 'paid', 'Test 5.7: Finance marks approved expense as disbursed/paid (HTTP 200 OK)');

    // Duplicate disbursement attempt
    const resDupDisburse = await request('PATCH', `/finance/expenses/${finExpId}/disburse`, {}, makeToken(TEST_PERSONAS.financeLead));
    assert(resDupDisburse.status === 409, 'Test 5.8: Duplicate disbursement attempt rejected with HTTP 409 Conflict');

    // -----------------------------------------------------------------------
    // SECTION 6: Donation Verification
    // -----------------------------------------------------------------------
    console.log('\n>>> [SECTION 6]: Donation Verification & Rejection Workflow');

    // Log direct donation
    const donPayload = {
      receiptNo: `REC-D225-${Date.now()}`,
      donorName: 'Farhan Zaidi',
      donorEmail: 'farhan.zaidi@example.com',
      amount: 15000,
      paymentMethod: 'Bank Transfer',
      currency: 'PKR',
      notes: 'General literary patronage',
    };
    const resDirectDon = await request('POST', '/finance/income', donPayload, makeToken(TEST_PERSONAS.financeLead));
    assert(resDirectDon.status === 201, 'Test 6.1: Finance lead logs donation record (HTTP 201 Created)');
    const donId = resDirectDon.body.donation._id || resDirectDon.body.donation.id;

    // Verify donation
    const resVerify = await request(
      'PATCH',
      `/finance/income/${donId}/verify`,
      { status: 'Verified', notes: 'Bank statement confirmed receipt' },
      makeToken(TEST_PERSONAS.financeLead)
    );
    assert(
      resVerify.status === 200 && resVerify.body.donation.verificationStatus === 'Verified',
      'Test 6.2: Finance lead verifies donation with verification notes (HTTP 200 OK)'
    );

    // HR attempting to verify donation
    const resHRVerify = await request(
      'PATCH',
      `/finance/income/${donId}/verify`,
      { status: 'Rejected' },
      makeToken(TEST_PERSONAS.hrHead)
    );
    assert(resHRVerify.status === 403, 'Test 6.3: HR attempting to verify donation is blocked with HTTP 403 Forbidden');

    // -----------------------------------------------------------------------
    // SECTION 7: Multi-Format Financial Export & Formula Injection Defense
    // -----------------------------------------------------------------------
    console.log('\n>>> [SECTION 7]: Financial Reports, Multi-Format Exports & Formula Defense');

    // 1. Log an entry containing formula injection trigger characters
    const maliciousIncomePayload = {
      receiptNo: `REC-INJ-${Date.now()}`,
      donorName: '=cmd|\'/C calc\'!A0',
      donorEmail: 'malicious@example.com',
      amount: 1000,
      paymentMethod: '+DDE("cmd", "/C calc")',
      cause: '@SUM(1+1)',
      currency: 'PKR',
    };
    await request('POST', '/finance/income', maliciousIncomePayload, makeToken(TEST_PERSONAS.financeLead));

    // 2. Export Income as CSV
    const resCsvIncome = await request('GET', '/finance/export/income?format=csv', null, makeToken(TEST_PERSONAS.financeLead));
    assert(resCsvIncome.status === 200, 'Test 7.1: Export Income as CSV returns HTTP 200 OK');
    assert(
      resCsvIncome.headers['content-type'].includes('text/csv'),
      'Test 7.2: CSV Content-Type is text/csv with UTF-8'
    );
    // Verify UTF-8 BOM
    const hasBom = resCsvIncome.buffer[0] === 0xef && resCsvIncome.buffer[1] === 0xbb && resCsvIncome.buffer[2] === 0xbf;
    assert(hasBom === true, 'Test 7.3: CSV export contains UTF-8 Byte Order Mark (0xEF, 0xBB, 0xBF)');

    // Verify Formula Injection Defense in CSV
    const csvIncomeText = resCsvIncome.text;
    assert(
      csvIncomeText.includes("'=cmd") || csvIncomeText.includes("\"'=cmd"),
      "Test 7.4: Formula injection trigger '=' is neutralized with leading apostrophe (')"
    );
    assert(
      csvIncomeText.includes("'+DDE") || csvIncomeText.includes("\"'+DDE"),
      "Test 7.5: Formula injection trigger '+' is neutralized with leading apostrophe (')"
    );
    assert(
      csvIncomeText.includes("'@SUM") || csvIncomeText.includes("\"'@SUM"),
      "Test 7.6: Formula injection trigger '@' is neutralized with leading apostrophe (')"
    );

    // 3. Export Income as Excel (.xlsx)
    const resXlsxIncome = await request('GET', '/finance/export/income?format=xlsx', null, makeToken(TEST_PERSONAS.financeLead));
    assert(resXlsxIncome.status === 200, 'Test 7.7: Export Income as Excel (.xlsx) returns HTTP 200 OK');
    assert(
      resXlsxIncome.headers['content-type'].includes('spreadsheetml.sheet'),
      'Test 7.8: Excel Content-Type is openxmlformats-officedocument.spreadsheetml.sheet'
    );
    // OpenXML format starts with PK zip header 0x50 0x4B
    const isZip = resXlsxIncome.buffer[0] === 0x50 && resXlsxIncome.buffer[1] === 0x4b;
    assert(isZip === true, 'Test 7.9: Excel file is valid binary OpenXML spreadsheet container (PK header)');

    // 4. Export Expenses as CSV & Excel
    const resCsvExp = await request('GET', '/finance/export/expenses?format=csv', null, makeToken(TEST_PERSONAS.financeLead));
    assert(resCsvExp.status === 200, 'Test 7.10: Export Expenses as CSV returns HTTP 200 OK');

    const resXlsxExp = await request('GET', '/finance/export/expenses?format=xlsx', null, makeToken(TEST_PERSONAS.financeLead));
    assert(resXlsxExp.status === 200 && resXlsxExp.buffer[0] === 0x50, 'Test 7.11: Export Expenses as Excel (.xlsx) returns valid binary spreadsheet (HTTP 200 OK)');

    // 5. Export Summary as CSV & Excel
    const resCsvSum = await request('GET', '/finance/export/summary?format=csv', null, makeToken(TEST_PERSONAS.financeLead));
    assert(resCsvSum.status === 200, 'Test 7.12: Export Budget Summary as CSV returns HTTP 200 OK');

    const resXlsxSum = await request('GET', '/finance/export/summary?format=xlsx', null, makeToken(TEST_PERSONAS.financeLead));
    assert(resXlsxSum.status === 200 && resXlsxSum.buffer[0] === 0x50, 'Test 7.13: Export Budget Summary as Excel (.xlsx) returns valid binary spreadsheet (HTTP 200 OK)');

    // 6. Unauthorized Export Attempts
    const resHRExport = await request('GET', '/finance/export/expenses?format=csv', null, makeToken(TEST_PERSONAS.hrHead));
    assert(resHRExport.status === 403, 'Test 7.14: HR Head attempting financial export is blocked with HTTP 403 Forbidden');

    const resMemExport = await request('GET', '/finance/export/expenses?format=csv', null, makeToken(TEST_PERSONAS.litMember));
    assert(resMemExport.status === 403, 'Test 7.15: Regular Member attempting financial export is blocked with HTTP 403 Forbidden');

    // -----------------------------------------------------------------------
    // SECTION 8: Baseline Budget Protection Verification
    // -----------------------------------------------------------------------
    console.log('\n>>> [SECTION 8]: Baseline Budget Preservation Verification');

    const resAllBudgets = await request('GET', '/finance/budgets', null, makeToken(TEST_PERSONAS.financeLead));
    const allBudgets = resAllBudgets.body.budgets || [];

    // Confirm that the 3 baseline budgets exist and were never modified or spent from:
    const baselineFin = allBudgets.find((b) => b.department === 'Finance' && b.fiscalYear === '2026');
    const baselineGen = allBudgets.find((b) => b.department === 'General' && b.fiscalYear === '2026');
    const baselineHR = allBudgets.find((b) => b.department === 'HR' && b.fiscalYear === '2026');

    assert(
      !baselineFin || Number(baselineFin.spentAmount) === preFinSpent,
      'Test 8.1: Finance Baseline Budget spentAmount remains unchanged from pre-test baseline (Untouched)'
    );
    assert(
      !baselineGen || Number(baselineGen.spentAmount) === preGenSpent,
      'Test 8.2: General Baseline Budget spentAmount remains unchanged from pre-test baseline (Untouched)'
    );
    assert(
      !baselineHR || Number(baselineHR.spentAmount) === preHRSpent,
      'Test 8.3: HR Baseline Budget spentAmount remains unchanged from pre-test baseline (Untouched)'
    );

    console.log('\n======================================================================');
    console.log(`  PHASE D.2.2.5 TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
    console.log('======================================================================\n');
  } finally {
    await stopServer();
  }

  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('[FATAL TEST ERROR]', err);
  process.exit(1);
});
