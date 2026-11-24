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
  setMemoryExpense,
  getMemoryExpensesList,
  setMemoryBudget,
  getMemoryBudgetsList,
} = require('../src/routes/finance.routes');

const TEST_PORT = 5008;
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
  console.log("  TA'MEER-E-REKHTA PHASE 6B: FINANCE MANAGEMENT TEST SUITE");
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

  // 1. Setup mock users across the 9 approved roles
  const users = {
    superAdmin: {
      _id: 'usr_sa_6b',
      id: 'usr_sa_6b',
      name: 'Hafsa Arif (Super Admin)',
      email: 'admin@rekhta.org',
      role: 'super_admin',
      status: 'active',
    },
    financeLead: {
      _id: 'usr_fin_lead_6b',
      id: 'usr_fin_lead_6b',
      name: 'Ahmad Maqsood (Finance Lead)',
      email: 'finance@rekhta.org',
      role: 'finance',
      department: 'Finance',
      departmentCode: 'FIN',
      status: 'active',
    },
    financeOfficer: {
      _id: 'usr_fin_off_6b',
      id: 'usr_fin_off_6b',
      name: 'Usman Ghani (Finance Officer)',
      email: 'usman.fin@rekhta.org',
      role: 'finance',
      department: 'Finance',
      departmentCode: 'FIN',
      status: 'active',
    },
    hrLead: {
      _id: 'usr_hr_lead_6b',
      id: 'usr_hr_lead_6b',
      name: 'Hania Mehmood (HR Lead)',
      email: 'hr@rekhta.org',
      role: 'hr',
      department: 'HR',
      departmentCode: 'HR',
      status: 'active',
    },
    litHead: {
      _id: 'usr_lit_head_6b',
      id: 'usr_lit_head_6b',
      name: 'Noor-ul-Huda (Literature Head)',
      email: 'literature@rekhta.org',
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
    },
    mediaHead: {
      _id: 'usr_med_head_6b',
      id: 'usr_med_head_6b',
      name: 'Aisha Tariq (Media Head)',
      email: 'media@rekhta.org',
      role: 'dept_media',
      department: 'Media',
      departmentCode: 'MED',
      status: 'active',
    },
    member1: {
      _id: 'usr_mem_1_6b',
      id: 'usr_mem_1_6b',
      name: 'Bilal Khan (Volunteer Member)',
      email: 'bilal@rekhta.org',
      role: 'member',
      department: 'Literature',
      departmentCode: 'LIT',
      status: 'active',
    },
  };

  Object.values(users).forEach(setMemoryUser);

  const tokens = {
    superAdmin: generateToken({ id: users.superAdmin.id, role: users.superAdmin.role, email: users.superAdmin.email }),
    financeLead: generateToken({ id: users.financeLead.id, role: users.financeLead.role, email: users.financeLead.email }),
    financeOfficer: generateToken({ id: users.financeOfficer.id, role: users.financeOfficer.role, email: users.financeOfficer.email }),
    hrLead: generateToken({ id: users.hrLead.id, role: users.hrLead.role, email: users.hrLead.email }),
    litHead: generateToken({ id: users.litHead.id, role: users.litHead.role, email: users.litHead.email }),
    mediaHead: generateToken({ id: users.mediaHead.id, role: users.mediaHead.role, email: users.mediaHead.email }),
    member1: generateToken({ id: users.member1.id, role: users.member1.role, email: users.member1.email }),
  };

  try {
    // =========================================================================
    // GROUP 1: Role Access & Isolation (RBAC & Confidentiality)
    // =========================================================================
    console.log('>>> [GROUP 1]: Role Access & Isolation (RBAC & Confidentiality)');

    // 1.1 Finance lead accesses overview
    const res1_1 = await makeRequest({
      method: 'GET',
      path: '/api/finance/overview',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    assert(res1_1.status === 200 && res1_1.data?.success === true, 'Test 1.1: Finance lead accesses Finance Overview (200 OK)');

    // 1.2 Super Admin accesses overview
    const res1_2 = await makeRequest({
      method: 'GET',
      path: '/api/finance/overview',
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
    });
    assert(res1_2.status === 200 && res1_2.data?.success === true, 'Test 1.2: Super Admin accesses Finance Overview (200 OK)');

    // 1.3 HR lead blocked from finance overview
    const res1_3 = await makeRequest({
      method: 'GET',
      path: '/api/finance/overview',
      headers: { Authorization: `Bearer ${tokens.hrLead}` },
    });
    assert(res1_3.status === 403, 'Test 1.3: HR lead attempting to access Finance Overview is blocked with 403 Forbidden');

    // 1.4 Department Head blocked from finance overview
    const res1_4 = await makeRequest({
      method: 'GET',
      path: '/api/finance/overview',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
    });
    assert(res1_4.status === 403, 'Test 1.4: Department Head attempting to access Finance Overview is blocked with 403 Forbidden');

    // 1.5 Regular member blocked from finance overview
    const res1_5 = await makeRequest({
      method: 'GET',
      path: '/api/finance/overview',
      headers: { Authorization: `Bearer ${tokens.member1}` },
    });
    assert(res1_5.status === 403, 'Test 1.5: Regular member attempting to access Finance Overview is blocked with 403 Forbidden');

    // 1.6 Unauthenticated request blocked with 401
    const res1_6 = await makeRequest({
      method: 'GET',
      path: '/api/finance/overview',
    });
    assert(res1_6.status === 401, 'Test 1.6: Unauthenticated request to Finance Overview is rejected with 401 Unauthorized');

    // =========================================================================
    // GROUP 2: Income & Donation Management
    // =========================================================================
    console.log('\n>>> [GROUP 2]: Income & Donation Management');

    // 2.1 Finance lists income records
    const res2_1 = await makeRequest({
      method: 'GET',
      path: '/api/finance/income?page=1&limit=10',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    assert(
      res2_1.status === 200 && Array.isArray(res2_1.data?.income) && res2_1.data?.success === true,
      'Test 2.1: Finance lead lists income records with pagination & search (200 OK)'
    );

    // 2.2 HR blocked from income ledger
    const res2_2 = await makeRequest({
      method: 'GET',
      path: '/api/finance/income',
      headers: { Authorization: `Bearer ${tokens.hrLead}` },
    });
    assert(res2_2.status === 403, 'Test 2.2: HR lead attempting to access Income ledger is blocked with 403 Forbidden');

    // 2.3 Member blocked from income ledger
    const res2_3 = await makeRequest({
      method: 'GET',
      path: '/api/finance/income',
      headers: { Authorization: `Bearer ${tokens.member1}` },
    });
    assert(res2_3.status === 403, 'Test 2.3: Member attempting to access Income ledger is blocked with 403 Forbidden');

    // 2.4 Department Head blocked from income ledger
    const res2_4 = await makeRequest({
      method: 'GET',
      path: '/api/finance/income',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
    });
    assert(res2_4.status === 403, 'Test 2.4: Department Head attempting to access Income ledger is blocked with 403 Forbidden');

    // 2.5 Finance manually logs direct donation
    const res2_5 = await makeRequest({
      method: 'POST',
      path: '/api/finance/income',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        donorName: 'Chaudhry Rahmat Ali',
        donorEmail: 'rahmat.ali@example.com',
        donorPhone: '+92 333 1122334',
        amount: 35000,
        paymentMethod: 'Bank Transfer',
        category: 'Patron Contribution',
        cause: 'Annual Mushaira Sponsorship',
        notes: 'Direct wire received in Habib Bank account',
      },
    });
    const createdDonation = res2_5.data?.donation;
    assert(
      res2_5.status === 201 &&
        createdDonation?.donorName === 'Chaudhry Rahmat Ali' &&
        createdDonation?.amount === 35000 &&
        createdDonation?.receiptNo?.startsWith('REC-'),
      'Test 2.5: Finance lead manually logs a direct donation / income record (201 Created)'
    );

    // 2.6 Missing required donation fields rejected
    const res2_6 = await makeRequest({
      method: 'POST',
      path: '/api/finance/income',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        donorName: 'Anonymous',
        // missing donorEmail, amount, paymentMethod
      },
    });
    assert(res2_6.status === 400, 'Test 2.6: Direct income logging missing required fields rejected with 400 Bad Request');

    // 2.7 Negative or zero amount rejected
    const res2_7 = await makeRequest({
      method: 'POST',
      path: '/api/finance/income',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        donorName: 'Test User',
        donorEmail: 'test@example.com',
        amount: -500,
        paymentMethod: 'Cash',
      },
    });
    assert(res2_7.status === 400, 'Test 2.7: Direct income logging with negative or zero amount rejected with 400 Bad Request');

    // 2.8 Single income lookup succeeds
    const res2_8 = await makeRequest({
      method: 'GET',
      path: `/api/finance/income/${createdDonation?.id || createdDonation?._id}`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    assert(
      res2_8.status === 200 && res2_8.data?.donation?.donorEmail === 'rahmat.ali@example.com',
      'Test 2.8: Single income record lookup succeeds for Finance (200 OK)'
    );

    // 2.9 Non-existent income lookup returns 404
    const res2_9 = await makeRequest({
      method: 'GET',
      path: '/api/finance/income/non_existent_rec_9999',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    assert(res2_9.status === 404, 'Test 2.9: Non-existent income record lookup returns 404 Not Found');

    // 2.10 Verify a pending donation
    // Seed a pending donation first
    const pendingDon = {
      _id: 'don_pending_test_01',
      id: 'don_pending_test_01',
      receiptNo: 'REC-20260220-7711',
      referenceNumber: 'JAZZ-882199',
      donorName: 'Zainab Bibi',
      donorEmail: 'zainab@example.com',
      amount: 10000,
      paymentMethod: 'JazzCash',
      verificationStatus: 'Pending',
      createdAt: new Date(),
    };
    setMemoryDonation(pendingDon);

    const res2_10 = await makeRequest({
      method: 'PATCH',
      path: '/api/finance/income/don_pending_test_01/verify',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        status: 'Verified',
        notes: 'JazzCash transaction reference confirmed against merchant portal',
      },
    });
    assert(
      res2_10.status === 200 && (res2_10.data?.donation?.verificationStatus || '').toLowerCase() === 'verified',
      'Test 2.10: Finance lead verifies a pending donation with verification notes (200 OK)'
    );

    // =========================================================================
    // GROUP 3: Expense Submission & Department Scoping
    // =========================================================================
    console.log('\n>>> [GROUP 3]: Expense Submission & Department Scoping');

    // 3.1 Member submits personal reimbursement expense
    const res3_1 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.member1}` },
      body: {
        title: 'Volunteer Travel Reimbursement - Lahore Book Fair',
        description: 'Intercity train tickets for attending book stall',
        amount: 4500,
        category: 'Travel & Logistics',
        receiptUrl: 'https://storage.rekhta.org/receipts/train_bilal_01.pdf',
      },
    });
    const memberExpense = res3_1.data?.expense;
    assert(
      res3_1.status === 201 &&
        memberExpense?.title?.includes('Volunteer Travel') &&
        memberExpense?.amount === 4500 &&
        memberExpense?.status === 'pending',
      'Test 3.1: Member submits a personal reimbursement expense (201 Created)'
    );

    // 3.2 Literature Head submits departmental expense
    const res3_2 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: {
        title: 'Urdu Calligraphy Masterclass Materials',
        description: 'Purchased specialized bamboo Qalam pens and sumi ink for 40 participants',
        amount: 12000,
        category: 'Event Expenses',
        department: 'Literature',
      },
    });
    const litExpense = res3_2.data?.expense;
    assert(
      res3_2.status === 201 &&
        litExpense?.department === 'Literature' &&
        litExpense?.amount === 12000 &&
        litExpense?.expenseId?.startsWith('EXP-'),
      'Test 3.2: Literature Department Head submits a departmental expense (201 Created)'
    );

    // 3.3 Server enforces Literature department when Lit Head attempts forging Media
    const res3_3 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: {
        title: 'Sneaky cross-department expense attempt',
        amount: 8000,
        category: 'Office Supplies',
        department: 'Media', // Tampering attempt: lit head submitting for Media
      },
    });
    assert(
      res3_3.status === 201 && res3_3.data?.expense?.department === 'Literature',
      'Test 3.3: Department binding: Server enforces Literature department when Literature Head submits expense'
    );

    // 3.4 Missing required fields rejected
    const res3_4 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.member1}` },
      body: {
        title: 'Only title',
      },
    });
    assert(res3_4.status === 400, 'Test 3.4: Expense submission missing required fields rejected with 400 Bad Request');

    // 3.5 Negative amount rejected
    const res3_5 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.member1}` },
      body: {
        title: 'Negative expense',
        amount: -2500,
        category: 'Other',
      },
    });
    assert(res3_5.status === 400, 'Test 3.5: Expense submission with negative amount rejected with 400 Bad Request');

    // 3.6 Submitter views own expenses via /api/finance/expenses/my
    const res3_6 = await makeRequest({
      method: 'GET',
      path: '/api/finance/expenses/my',
      headers: { Authorization: `Bearer ${tokens.member1}` },
    });
    assert(
      res3_6.status === 200 &&
        Array.isArray(res3_6.data?.expenses) &&
        res3_6.data.expenses.every((e) => (e.submittedBy || '').toString() === users.member1.id),
      "Test 3.6: Submitter views their own submitted expenses via /api/finance/expenses/my (200 OK)"
    );

    // 3.7 Literature Head views departmental expenses
    const res3_7 = await makeRequest({
      method: 'GET',
      path: '/api/finance/expenses/department',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
    });
    assert(
      res3_7.status === 200 &&
        res3_7.data?.department === 'Literature' &&
        res3_7.data.expenses.every((e) => e.department === 'Literature'),
      'Test 3.7: Literature Head views departmental expenses via /api/finance/expenses/department (200 OK)'
    );

    // 3.8 Literature Head does not see Media department expenses
    // Add a Media expense
    const mediaExpense = {
      _id: 'exp_media_isolation_01',
      id: 'exp_media_isolation_01',
      expenseId: 'EXP-2602-MED-551',
      title: 'Studio Lighting Rig',
      amount: 32000,
      department: 'Media',
      category: 'Equipment & Assets',
      status: 'pending',
      submittedBy: users.mediaHead.id,
      submittedByName: users.mediaHead.name,
      createdAt: new Date(),
    };
    setMemoryExpense(mediaExpense);

    const res3_8 = await makeRequest({
      method: 'GET',
      path: '/api/finance/expenses/department',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
    });
    const hasMedia = res3_8.data?.expenses?.some((e) => e.department === 'Media');
    assert(!hasMedia, 'Test 3.8: Literature Head querying departmental expenses does not see Media department expenses');

    // =========================================================================
    // GROUP 4: Expense Review, Approval & Mandatory Anti-Self-Approval
    // =========================================================================
    console.log('\n>>> [GROUP 4]: Expense Review, Approval & Mandatory Anti-Self-Approval');

    // 4.1 Finance lead submits an operational expense
    const res4_1 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        title: 'Accounting Software Subscription (Q1 2026)',
        amount: 18000,
        category: 'Operations & Maintenance',
        department: 'Finance',
      },
    });
    const finLeadExpense = res4_1.data?.expense;
    assert(
      res4_1.status === 201 && finLeadExpense?.submittedBy === users.financeLead.id,
      'Test 4.1: Finance lead submits an operational expense (201 Created)'
    );

    // 4.2 CRITICAL Anti-Self-Approval: Finance lead cannot approve their own expense
    const res4_2 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${finLeadExpense?.id || finLeadExpense?._id}/review`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        status: 'approved',
        reviewNotes: 'Self-approval attempt should fail',
      },
    });
    assert(
      res4_2.status === 403 && res4_2.data?.error?.includes('Anti-self-approval rule'),
      'Test 4.2: CRITICAL Anti-Self-Approval: Finance lead attempting to approve their own expense is strictly blocked with 403 Forbidden'
    );

    // 4.3 Super Admin approves the Finance lead's expense
    const res4_3 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${finLeadExpense?.id || finLeadExpense?._id}/review`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
      body: {
        status: 'approved',
        reviewNotes: 'Approved by Super Admin oversight',
      },
    });
    assert(
      res4_3.status === 200 && res4_3.data?.expense?.status === 'approved',
      "Test 4.3: Super Admin successfully reviews and approves the Finance lead's expense (200 OK)"
    );

    // 4.4 Super Admin submits an expense
    const res4_4 = await makeRequest({
      method: 'POST',
      path: '/api/finance/expenses',
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
      body: {
        title: 'Presidential Delegation Refreshments',
        amount: 8500,
        category: 'Honorarium & Refreshments',
        department: 'General',
      },
    });
    const saExpense = res4_4.data?.expense;
    assert(
      res4_4.status === 201 && saExpense?.submittedBy === users.superAdmin.id,
      'Test 4.4: Super Admin submits an expense (201 Created)'
    );

    // 4.5 CRITICAL Anti-Self-Approval: Super Admin cannot approve their own expense
    const res4_5 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${saExpense?.id || saExpense?._id}/review`,
      headers: { Authorization: `Bearer ${tokens.superAdmin}` },
      body: {
        status: 'approved',
      },
    });
    assert(
      res4_5.status === 403 && res4_5.data?.error?.includes('Anti-self-approval rule'),
      'Test 4.5: CRITICAL Anti-Self-Approval: Super Admin attempting to approve their own expense is strictly blocked with 403 Forbidden'
    );

    // 4.6 Finance lead approves the Super Admin's expense
    const res4_6 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${saExpense?.id || saExpense?._id}/review`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        status: 'approved',
        reviewNotes: 'Finance lead independent review complete',
      },
    });
    assert(
      res4_6.status === 200 && res4_6.data?.expense?.status === 'approved',
      "Test 4.6: Finance lead successfully reviews and approves the Super Admin's expense (200 OK)"
    );

    // 4.7 Finance rejects an invalid expense with notes
    const res4_7 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${memberExpense?.id || memberExpense?._id}/review`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        status: 'rejected',
        reviewNotes: 'Missing official ticket counterfoil receipt.',
      },
    });
    assert(
      res4_7.status === 200 &&
        res4_7.data?.expense?.status === 'rejected' &&
        res4_7.data?.expense?.reviewNotes?.includes('Missing official ticket'),
      'Test 4.7: Finance lead reviews and rejects an invalid expense with notes (200 OK, status -> rejected)'
    );

    // 4.8 Department Head cannot approve expense
    const res4_8 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${litExpense?.id || litExpense?._id}/review`,
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: { status: 'approved' },
    });
    assert(res4_8.status === 403, 'Test 4.8: Department Head attempting to approve an expense is blocked with 403 Forbidden');

    // 4.9 Regular member cannot approve expense
    const res4_9 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${litExpense?.id || litExpense?._id}/review`,
      headers: { Authorization: `Bearer ${tokens.member1}` },
      body: { status: 'approved' },
    });
    assert(res4_9.status === 403, 'Test 4.9: Regular member attempting to approve an expense is blocked with 403 Forbidden');

    // 4.10 Finance marks approved expense as disbursed
    const res4_10 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${finLeadExpense?.id || finLeadExpense?._id}/disburse`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        disbursedNotes: 'Cheque #CHK-99182 disbursed and cleared',
      },
    });
    assert(
      res4_10.status === 200 && res4_10.data?.expense?.status === 'paid',
      'Test 4.10: Finance marks an approved expense as disbursed / paid (200 OK, status -> paid)'
    );

    // 4.11 Disbursing an unapproved/pending expense is rejected with 400
    const res4_11 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${mediaExpense?.id || mediaExpense?._id}/disburse`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: { disbursedNotes: 'premature disbursement' },
    });
    assert(
      res4_11.status === 400,
      'Test 4.11: Attempting to disburse an unapproved/pending expense is rejected with 400 Bad Request'
    );

    // =========================================================================
    // GROUP 5: Budget Allocation & Utilization Tracking
    // =========================================================================
    console.log('\n>>> [GROUP 5]: Budget Allocation & Utilization Tracking');

    // 5.1 Finance lists all budgets
    const res5_1 = await makeRequest({
      method: 'GET',
      path: '/api/finance/budgets',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    assert(
      res5_1.status === 200 && Array.isArray(res5_1.data?.budgets) && res5_1.data.budgets.length >= 5,
      'Test 5.1: Finance lead lists all organization budgets (200 OK)'
    );

    // 5.2 Literature Head receives only Literature departmental budget
    const res5_2 = await makeRequest({
      method: 'GET',
      path: '/api/finance/budgets',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
    });
    assert(
      res5_2.status === 200 &&
        res5_2.data.budgets.every((b) => b.department === 'Literature'),
      'Test 5.2: Literature Head lists budgets and receives only Literature departmental budgets (200 OK)'
    );

    // 5.3 HR blocked from budgets
    const res5_3 = await makeRequest({
      method: 'GET',
      path: '/api/finance/budgets',
      headers: { Authorization: `Bearer ${tokens.hrLead}` },
    });
    assert(res5_3.status === 403, 'Test 5.3: HR lead attempting to query budgets is blocked with 403 Forbidden');

    // 5.4 Member blocked from budgets
    const res5_4 = await makeRequest({
      method: 'GET',
      path: '/api/finance/budgets',
      headers: { Authorization: `Bearer ${tokens.member1}` },
    });
    assert(res5_4.status === 403, 'Test 5.4: Regular member attempting to query budgets is blocked with 403 Forbidden');

    // 5.5 Finance allocates new departmental budget
    const res5_5 = await makeRequest({
      method: 'POST',
      path: '/api/finance/budgets',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        fiscalYear: '2026',
        title: 'Special Urdu Book Fair Supplemental Budget',
        department: 'Literature',
        category: 'Special Events',
        allocatedAmount: 75000,
        notes: 'Approved supplemental allocation for winter exhibition',
      },
    });
    const createdBudget = res5_5.data?.budget;
    assert(
      res5_5.status === 201 &&
        createdBudget?.allocatedAmount === 75000 &&
        createdBudget?.remainingAmount === 75000 &&
        createdBudget?.budgetId?.startsWith('BDG-2026-'),
      'Test 5.5: Finance lead allocates a new departmental budget (201 Created)'
    );

    // 5.6 Missing required budget fields rejected
    const res5_6 = await makeRequest({
      method: 'POST',
      path: '/api/finance/budgets',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        title: 'Incomplete Budget',
      },
    });
    assert(res5_6.status === 400, 'Test 5.6: Budget allocation missing required fields rejected with 400 Bad Request');

    // 5.7 Department Head cannot allocate budget
    const res5_7 = await makeRequest({
      method: 'POST',
      path: '/api/finance/budgets',
      headers: { Authorization: `Bearer ${tokens.litHead}` },
      body: {
        fiscalYear: '2026',
        title: 'Self-allocated budget',
        department: 'Literature',
        allocatedAmount: 500000,
      },
    });
    assert(res5_7.status === 403, 'Test 5.7: Department Head attempting to allocate a budget is blocked with 403 Forbidden');

    // 5.8 Member cannot allocate budget
    const res5_8 = await makeRequest({
      method: 'POST',
      path: '/api/finance/budgets',
      headers: { Authorization: `Bearer ${tokens.member1}` },
      body: {
        fiscalYear: '2026',
        title: 'Member budget',
        department: 'Literature',
        allocatedAmount: 100000,
      },
    });
    assert(res5_8.status === 403, 'Test 5.8: Member attempting to allocate a budget is blocked with 403 Forbidden');

    // 5.9 Finance updates budget allocation amount and status
    const res5_9 = await makeRequest({
      method: 'PATCH',
      path: `/api/finance/budgets/${createdBudget?.id || createdBudget?._id}`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        allocatedAmount: 85000,
        status: 'active',
        notes: 'Augmented allocation by PKR 10,000',
      },
    });
    assert(
      res5_9.status === 200 && res5_9.data?.budget?.allocatedAmount === 85000,
      'Test 5.9: Finance lead updates budget allocation amount and status (200 OK)'
    );

    // 5.10 Approving an expense updates the department budget spentAmount
    // Check initial Literature budget spent amount
    const litBdgBefore = getMemoryBudgetsList().find((b) => b.department === 'Literature' && b.status === 'active');
    const spentBefore = litBdgBefore ? litBdgBefore.spentAmount || 0 : 0;

    // Approve the lit expense (PKR 12,000)
    await makeRequest({
      method: 'PATCH',
      path: `/api/finance/expenses/${litExpense?.id || litExpense?._id}/review`,
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
      body: {
        status: 'approved',
        reviewNotes: 'Masterclass materials verified',
      },
    });

    const litBdgAfter = getMemoryBudgetsList().find((b) => b.department === 'Literature' && b.status === 'active');
    const spentAfter = litBdgAfter ? litBdgAfter.spentAmount || 0 : 0;
    assert(
      spentAfter === spentBefore + 12000,
      'Test 5.10: Approving an expense automatically updates the department budget spentAmount and remainingAmount'
    );

    // =========================================================================
    // GROUP 6: Financial Reports & CSV Data Export
    // =========================================================================
    console.log('\n>>> [GROUP 6]: Financial Reports & CSV Data Export');

    // 6.1 Finance queries reports endpoint
    const res6_1 = await makeRequest({
      method: 'GET',
      path: '/api/finance/reports',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    assert(
      res6_1.status === 200 &&
        res6_1.data?.report?.summary?.totalVerifiedIncome !== undefined &&
        res6_1.data?.report?.summary?.totalApprovedExpenses !== undefined,
      'Test 6.1: Finance lead queries /api/finance/reports for fiscal analytics (200 OK)'
    );

    // 6.2 HR blocked from reports
    const res6_2 = await makeRequest({
      method: 'GET',
      path: '/api/finance/reports',
      headers: { Authorization: `Bearer ${tokens.hrLead}` },
    });
    assert(res6_2.status === 403, 'Test 6.2: HR lead attempting to query financial reports is blocked with 403 Forbidden');

    // 6.3 Finance exports Income as CSV
    const res6_3 = await makeRequest({
      method: 'GET',
      path: '/api/finance/export/income',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    const incomeCsvContent = res6_3.data?.raw || '';
    assert(
      res6_3.status === 200 &&
        res6_3.headers['content-type']?.includes('text/csv') &&
        incomeCsvContent.includes('Receipt No') &&
        incomeCsvContent.includes('Donor Name'),
      'Test 6.3: Finance lead exports Income ledger as CSV (200 OK, text/csv content-type)'
    );

    // 6.4 Finance exports Expenses as CSV
    const res6_4 = await makeRequest({
      method: 'GET',
      path: '/api/finance/export/expenses',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    const expenseCsvContent = res6_4.data?.raw || '';
    assert(
      res6_4.status === 200 &&
        res6_4.headers['content-type']?.includes('text/csv') &&
        expenseCsvContent.includes('Expense ID') &&
        expenseCsvContent.includes('Title'),
      'Test 6.4: Finance lead exports Expenses ledger as CSV (200 OK, text/csv content-type)'
    );

    // 6.5 Finance exports Budget summary as CSV
    const res6_5 = await makeRequest({
      method: 'GET',
      path: '/api/finance/export/summary',
      headers: { Authorization: `Bearer ${tokens.financeLead}` },
    });
    const summaryCsvContent = res6_5.data?.raw || '';
    assert(
      res6_5.status === 200 &&
        res6_5.headers['content-type']?.includes('text/csv') &&
        summaryCsvContent.includes('Budget ID') &&
        summaryCsvContent.includes('Utilization Rate'),
      'Test 6.5: Finance lead exports Budget summary as CSV (200 OK, text/csv content-type)'
    );

    // 6.6 Regular member blocked from CSV exports
    const res6_6 = await makeRequest({
      method: 'GET',
      path: '/api/finance/export/income',
      headers: { Authorization: `Bearer ${tokens.member1}` },
    });
    assert(res6_6.status === 403, 'Test 6.6: Regular member attempting CSV export is blocked with 403 Forbidden');

  } catch (err) {
    console.error('Test execution error:', err);
    failed++;
  }

  console.log('\n======================================================================');
  console.log(`  PHASE 6B TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('======================================================================\n');

  if (server) {
    server.close();
  }

  process.exit(failed > 0 ? 1 : 0);
}

// Start test server
server = http.createServer(app);
server.listen(TEST_PORT, () => {
  runTestSuite();
});
