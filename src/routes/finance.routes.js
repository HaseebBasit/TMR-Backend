const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const XLSX = require('xlsx');
const {
  User,
  Donation,
  Expense,
  Budget,
  Department,
  AuditLog,
  Notification,
} = require('../models');
const { sendNotification } = require('../services/notification.service');
const {
  protect,
  authorize,
  requireDepartmentScope,
  ALLOWED_ROLES,
  getMemoryUsersList,
  normalizeDesignation,
} = require('../middleware/auth');

function escapeCsv(val) {
  let str = String(val ?? '');
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

// ---------------------------------------------------------------------------
// In-Memory Storage Fallback for Controlled Configuration Mode
// ---------------------------------------------------------------------------
const memoryDonations = new Map();
const memoryExpenses = new Map();
const memoryBudgets = new Map();

function setMemoryDonation(donation) {
  const id = donation._id ? donation._id.toString() : donation.id;
  memoryDonations.set(id, donation);
}

function getMemoryDonationsList() {
  return Array.from(memoryDonations.values());
}

function clearMemoryDonations() {
  memoryDonations.clear();
}

function setMemoryExpense(expense) {
  const id = expense._id ? expense._id.toString() : expense.id;
  memoryExpenses.set(id, expense);
}

function getMemoryExpensesList() {
  return Array.from(memoryExpenses.values());
}

function clearMemoryExpenses() {
  memoryExpenses.clear();
}

function setMemoryBudget(budget) {
  const id = budget._id ? budget._id.toString() : budget.id;
  memoryBudgets.set(id, budget);
}

function getMemoryBudgetsList() {
  return Array.from(memoryBudgets.values());
}

function clearMemoryBudgets() {
  memoryBudgets.clear();
}

// ---------------------------------------------------------------------------
// Concurrency & Mutex Primitives (In-Memory & Multi-Stage Async Safety)
// ---------------------------------------------------------------------------
const activeLocks = new Set();
async function acquireLock(key) {
  while (activeLocks.has(key)) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  activeLocks.add(key);
  return () => {
    activeLocks.delete(key);
  };
}

/**
 * Resolves the target budget allocation for an expense using an explicit budget reference
 * or a complete allocation key (department, fiscalYear, category, currency).
 * Prevents arbitrary selection when multiple active budget categories exist.
 */
function resolveBudgetAllocation({
  budgetsList = [],
  explicitBudgetId,
  explicitCategory,
  department,
  fiscalYear,
  expenseCategory,
  currency,
}) {
  // 1. If explicit budgetId is provided:
  if (explicitBudgetId) {
    const matched = budgetsList.find(
      (b) =>
        (b._id || b.id)?.toString() === explicitBudgetId.toString() ||
        b.budgetId === explicitBudgetId
    );
    if (!matched) {
      const err = new Error(`Specified budget '${explicitBudgetId}' does not exist.`);
      err.statusCode = 400;
      throw err;
    }
    // Verify department
    if (matched.department !== department && matched.department !== 'All') {
      const err = new Error(
        `Budget allocation mismatch: Specified budget '${explicitBudgetId}' belongs to department '${matched.department}', but expense belongs to '${department}'. Cross-department deduction is prohibited.`
      );
      err.statusCode = 400;
      throw err;
    }
    // Verify not archived
    if (matched.isArchived) {
      const err = new Error(
        `Specified budget '${explicitBudgetId}' is archived. Expenses cannot be approved against an archived budget.`
      );
      err.statusCode = 400;
      throw err;
    }
    return matched;
  }

  // 2. Filter candidate budgets for this department
  const deptBudgets = budgetsList.filter(
    (b) => b.department === department || b.department === 'All'
  );

  const activeCandidates = deptBudgets.filter(
    (b) => b.isArchived !== true && b.status === 'active'
  );

  if (activeCandidates.length === 0) {
    // Return any non-active department budget if exists for proper error messaging (frozen/closed)
    return deptBudgets[0] || null;
  }

  // Filter candidates by fiscal year if available
  const yearCandidates = fiscalYear
    ? activeCandidates.filter((b) => b.fiscalYear === fiscalYear)
    : activeCandidates;
  const pool = yearCandidates.length > 0 ? yearCandidates : activeCandidates;

  // If exactly one active allocation exists for this department/year:
  if (pool.length === 1) {
    return pool[0];
  }

  // If multiple active allocations exist:
  // Check explicit category match
  const targetCategory = (explicitCategory || '').trim().toLowerCase();
  if (targetCategory) {
    const categoryMatch = pool.find(
      (b) => (b.category || '').trim().toLowerCase() === targetCategory
    );
    if (categoryMatch) {
      return categoryMatch;
    }
  }

  // Check if expense.category matches a budget category
  const expCat = (expenseCategory || '').trim().toLowerCase();
  if (expCat) {
    const expCatMatch = pool.find(
      (b) => (b.category || '').trim().toLowerCase() === expCat
    );
    if (expCatMatch) {
      return expCatMatch;
    }
  }

  // Check if one is standard operating budget (General Operating or Operating Budget)
  const opBudget = pool.find(
    (b) =>
      (b.category || '').toLowerCase().includes('operating') ||
      (b.category || '').toLowerCase().includes('general')
  );
  if (opBudget) {
    return opBudget;
  }

  // If multiple active categories exist and no category match can be determined:
  const err = new Error(
    `Ambiguous budget allocation: Department '${department}' has multiple active budget categories (${pool.map((b) => b.category || b.title).join(', ')}). Please specify an explicit 'budgetId' or matching 'category' to approve this expense.`
  );
  err.statusCode = 400;
  throw err;
}

/**
 * Executes a callback within a MongoDB multi-document ACID transaction.
 * In production: strictly requires an active MongoDB connection and transaction session; fails fast if unavailable.
 * In development/test: safely executes within current execution context if offline without false distributed ACID claims.
 */
async function executeTransactionIfSupported(workFn) {
  const isProduction = process.env.NODE_ENV === 'production';

  if (isProduction) {
    if (!mongoose.connection || mongoose.connection.readyState !== 1) {
      throw new Error('[CRITICAL DATABASE ERROR] Production financial transactions require an active MongoDB connection. In-memory execution is prohibited in production.');
    }
  }

  if (mongoose.connection && mongoose.connection.readyState === 1) {
    let session = null;
    try {
      session = await mongoose.startSession();
      let result;
      await session.withTransaction(async () => {
        result = await workFn(session);
      });
      return { inTransaction: true, result };
    } catch (err) {
      throw err;
    } finally {
      if (session) await session.endSession();
    }
  } else {
    // Offline controlled mode / mock environment (explicitly non-ACID distributed, test/dev only)
    const result = await workFn(null);
    return { inTransaction: false, result };
  }
}

// Department mapping
const DEPT_ROLE_MAP = {
  dept_literature: { name: 'Literature', code: 'LIT' },
  dept_media: { name: 'Media', code: 'MED' },
  dept_marketing: { name: 'Marketing', code: 'MKT' },
  dept_outreach: { name: 'Outreach', code: 'OUT' },
  dept_content: { name: 'Content Creation', code: 'CON' },
  hr: { name: 'HR', code: 'HR' },
  finance: { name: 'Finance', code: 'FIN' },
};

const VALID_DEPARTMENTS = [
  'Literature',
  'Media',
  'Marketing',
  'Outreach',
  'Content Creation',
  'HR',
  'Finance',
  'General',
  'Administration',
];

const VALID_EXPENSE_CATEGORIES = [
  'Event Expenses',
  'Printing & Publications',
  'Travel & Logistics',
  'Marketing & Promotion',
  'Equipment & Assets',
  'Office Supplies',
  'Honorarium & Refreshments',
  'Operations & Maintenance',
  'Other',
];

// Helper to resolve user department
function getUserDept(user) {
  if (user.role && DEPT_ROLE_MAP[user.role]) {
    return DEPT_ROLE_MAP[user.role].name;
  }
  return user.department || null;
}

// Production Zero-State: Memory stores initialize strictly empty without sample or dummy seed records.
function initializeMemoryStores() {
  memoryBudgets.clear();
  memoryDonations.clear();
  memoryExpenses.clear();
}

initializeMemoryStores();

// ---------------------------------------------------------------------------
// 1. OVERVIEW & ANALYTICS
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/finance/overview (and /api/overview)
 * @desc    Comprehensive organization-wide financial overview & metrics
 * @access  Protected (Super Admin, Finance)
 */
router.get(['/overview', '/finance/overview'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    // 1. Currency-specific income aggregation
    let donations = [];
    try {
      donations = await Donation.find();
    } catch {}
    if (!donations || donations.length === 0) {
      donations = getMemoryDonationsList();
    }

    const incomeByCurrency = {};
    donations.forEach((d) => {
      const curr = (d.currency || 'PKR').toUpperCase();
      if (!incomeByCurrency[curr]) {
        incomeByCurrency[curr] = { verifiedAmount: 0, pendingAmount: 0, verifiedCount: 0, pendingCount: 0, totalCount: 0 };
      }
      incomeByCurrency[curr].totalCount++;
      const amt = Number(d.amount) || 0;
      const status = (d.verificationStatus || '').toLowerCase();
      if (status === 'verified') {
        incomeByCurrency[curr].verifiedAmount += amt;
        incomeByCurrency[curr].verifiedCount++;
      } else if (status === 'pending') {
        incomeByCurrency[curr].pendingAmount += amt;
        incomeByCurrency[curr].pendingCount++;
      }
    });

    // 2. Currency-specific expenses aggregation
    let expenses = [];
    try {
      expenses = await Expense.find();
    } catch {}
    if (!expenses || expenses.length === 0) {
      expenses = getMemoryExpensesList();
    }

    const expensesByCurrency = {};
    expenses.forEach((e) => {
      const curr = (e.currency || 'PKR').toUpperCase();
      if (!expensesByCurrency[curr]) {
        expensesByCurrency[curr] = { approvedAmount: 0, pendingAmount: 0, approvedCount: 0, pendingCount: 0, totalCount: 0 };
      }
      expensesByCurrency[curr].totalCount++;
      const amt = Number(e.amount) || 0;
      const status = (e.status || '').toLowerCase();
      if (['approved', 'paid', 'reimbursed'].includes(status)) {
        expensesByCurrency[curr].approvedAmount += amt;
        expensesByCurrency[curr].approvedCount++;
      } else if (status === 'pending') {
        expensesByCurrency[curr].pendingAmount += amt;
        expensesByCurrency[curr].pendingCount++;
      }
    });

    // Pure per-currency net balances (Currencies are never added or mixed together)
    const netBalanceByCurrency = {};
    const allCurrencies = new Set([...Object.keys(incomeByCurrency), ...Object.keys(expensesByCurrency), 'PKR']);
    allCurrencies.forEach((curr) => {
      const inc = incomeByCurrency[curr]?.verifiedAmount || 0;
      const exp = expensesByCurrency[curr]?.approvedAmount || 0;
      netBalanceByCurrency[curr] = inc - exp;
    });

    // Default PKR totals (Strictly filtered for PKR; avoids foreign-currency pollution)
    const pkrIncome = incomeByCurrency['PKR'] || { verifiedAmount: 0, pendingAmount: 0, verifiedCount: 0, pendingCount: 0 };
    const pkrExpenses = expensesByCurrency['PKR'] || { approvedAmount: 0, pendingAmount: 0, approvedCount: 0, pendingCount: 0 };
    const verifiedIncome = pkrIncome.verifiedAmount;
    const pendingIncome = pkrIncome.pendingAmount;
    const verifiedCount = pkrIncome.verifiedCount;
    const pendingCount = pkrIncome.pendingCount;

    const approvedExpenses = pkrExpenses.approvedAmount;
    const pendingExpenses = pkrExpenses.pendingAmount;
    const approvedExpenseCount = pkrExpenses.approvedCount;
    const pendingExpenseCount = pkrExpenses.pendingCount;

    const netBalance = verifiedIncome - approvedExpenses;

    // 3. Budgets aggregation
    let budgets = [];
    try {
      budgets = await Budget.find();
    } catch {}
    if (!budgets || budgets.length === 0) {
      budgets = getMemoryBudgetsList();
    }

    const totalAllocatedBudget = budgets.reduce((sum, b) => sum + (Number(b.allocatedAmount) || 0), 0);
    const totalSpentBudget = budgets.reduce((sum, b) => sum + (Number(b.spentAmount) || 0), 0);
    const totalRemainingBudget = totalAllocatedBudget - totalSpentBudget;
    const overallUtilizationRate =
      totalAllocatedBudget > 0 ? Number(((totalSpentBudget / totalAllocatedBudget) * 100).toFixed(1)) : 0;

    // Department budget breakdown (dynamically derived from genuine database departments)
    let activeDepts = [];
    try {
      activeDepts = await Department.find({ status: 'active' }).sort({ name: 1 });
    } catch {}

    const departmentBreakdown = activeDepts.map((dept) => {
      const deptName = dept.name;
      const deptBudgets = budgets.filter((b) => b.department?.toLowerCase() === deptName.toLowerCase() && !b.isArchived);
      const allocated = deptBudgets.reduce((s, b) => s + (Number(b.allocatedAmount) || 0), 0);
      const deptExpenses = expenses.filter(
        (e) => e.department?.toLowerCase() === deptName.toLowerCase() && ['approved', 'paid', 'reimbursed'].includes((e.status || '').toLowerCase())
      );
      const spent = deptExpenses.reduce((s, e) => s + (Number(e.amount) || 0), 0);
      return {
        department: deptName,
        allocated,
        spent,
        remaining: allocated - spent,
        utilizationRate: allocated > 0 ? Number(((spent / allocated) * 100).toFixed(1)) : 0,
        approvedExpensesCount: deptExpenses.length,
      };
    });

    // Category breakdown
    const categoryBreakdown = {};
    expenses
      .filter((e) => ['approved', 'paid', 'reimbursed'].includes((e.status || '').toLowerCase()))
      .forEach((e) => {
        const cat = e.category || 'Other';
        categoryBreakdown[cat] = (categoryBreakdown[cat] || 0) + (Number(e.amount) || 0);
      });

    return res.json({
      success: true,
      overview: {
        currency: 'PKR',
        income: {
          currency: 'PKR',
          totalVerifiedAmount: verifiedIncome,
          totalPendingAmount: pendingIncome,
          verifiedCount,
          pendingCount,
          totalDonations: donations.length,
        },
        expenses: {
          currency: 'PKR',
          totalApprovedAmount: approvedExpenses,
          totalPendingAmount: pendingExpenses,
          approvedCount: approvedExpenseCount,
          pendingCount: pendingExpenseCount,
          totalExpenses: expenses.length,
        },
        netBalance,
        byCurrency: {
          income: incomeByCurrency,
          expenses: expensesByCurrency,
          netBalance: netBalanceByCurrency,
        },
        budgets: {
          currency: 'PKR',
          totalAllocatedAmount: totalAllocatedBudget,
          totalSpentAmount: totalSpentBudget,
          totalRemainingAmount: totalRemainingBudget,
          utilizationRate: overallUtilizationRate,
          activeBudgetsCount: budgets.filter((b) => b.status === 'active').length,
        },
        departmentBreakdown,
        categoryBreakdown,
        recentIncome: donations.slice(0, 5),
        recentExpenses: expenses.slice(0, 5),
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   GET /api/finance/stats (and /api/stats)
 * @desc    Backward compatibility with existing test suites
 * @access  Protected (Super Admin, Finance)
 */
router.get(['/stats', '/finance/stats'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  let donations = [];
  try {
    donations = await Donation.find();
  } catch {}
  if (!donations || donations.length === 0) {
    donations = getMemoryDonationsList();
  }

  const isVerified = (d) => (d.verificationStatus || '').toLowerCase() === 'verified';
  const isPending = (d) => (d.verificationStatus || '').toLowerCase() === 'pending';
  const isPKR = (d) => (d.currency || 'PKR').toUpperCase() === 'PKR';

  const totalVerified = donations.filter((d) => isVerified(d) && isPKR(d)).reduce((sum, d) => sum + (Number(d.amount) || 0), 0);
  const totalPending = donations.filter((d) => isPending(d) && isPKR(d)).reduce((sum, d) => sum + (Number(d.amount) || 0), 0);

  return res.json({
    success: true,
    stats: {
      currency: 'PKR',
      totalDonations: donations.length,
      verifiedCount: donations.filter(isVerified).length,
      pendingCount: donations.filter(isPending).length,
      totalVerifiedAmount: totalVerified,
      totalPendingAmount: totalPending,
    },
  });
});

/**
 * @route   GET /api/finance/reports (and /api/reports)
 * @desc    Detailed reports & analytics breakdown
 * @access  Protected (Super Admin, Finance)
 */
router.get(['/reports', '/finance/reports'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    let donations = [];
    let expenses = [];
    let budgets = [];
    try {
      donations = await Donation.find();
      expenses = await Expense.find();
      budgets = await Budget.find();
    } catch {}

    if (!donations || donations.length === 0) donations = getMemoryDonationsList();
    if (!expenses || expenses.length === 0) expenses = getMemoryExpensesList();
    if (!budgets || budgets.length === 0) budgets = getMemoryBudgetsList();

    // Group income and expenses strictly by currency
    const incomeByCurrency = {};
    donations.forEach((d) => {
      const curr = (d.currency || 'PKR').toUpperCase();
      if (!incomeByCurrency[curr]) incomeByCurrency[curr] = { verified: 0, pending: 0 };
      const status = (d.verificationStatus || '').toLowerCase();
      if (status === 'verified') incomeByCurrency[curr].verified += Number(d.amount) || 0;
      else if (status === 'pending') incomeByCurrency[curr].pending += Number(d.amount) || 0;
    });

    const expensesByCurrency = {};
    expenses.forEach((e) => {
      const curr = (e.currency || 'PKR').toUpperCase();
      if (!expensesByCurrency[curr]) expensesByCurrency[curr] = { approved: 0, pending: 0 };
      const status = (e.status || '').toLowerCase();
      if (['approved', 'paid', 'reimbursed'].includes(status)) expensesByCurrency[curr].approved += Number(e.amount) || 0;
      else if (status === 'pending') expensesByCurrency[curr].pending += Number(e.amount) || 0;
    });

    const summaryByCurrency = {};
    const allCurrs = new Set([...Object.keys(incomeByCurrency), ...Object.keys(expensesByCurrency), 'PKR']);
    allCurrs.forEach((curr) => {
      const inc = incomeByCurrency[curr]?.verified || 0;
      const exp = expensesByCurrency[curr]?.approved || 0;
      summaryByCurrency[curr] = {
        currency: curr,
        verifiedIncome: inc,
        approvedExpenses: exp,
        netBalance: inc - exp,
      };
    });

    const pkrSummary = summaryByCurrency['PKR'] || { verifiedIncome: 0, approvedExpenses: 0, netBalance: 0 };

    return res.json({
      success: true,
      report: {
        generatedAt: new Date(),
        fiscalYear: '2026',
        summary: {
          currency: 'PKR',
          totalVerifiedIncome: pkrSummary.verifiedIncome,
          totalApprovedExpenses: pkrSummary.approvedExpenses,
          netBalance: pkrSummary.netBalance,
        },
        summaryByCurrency,
        incomeByPaymentMethod: donations.reduce((acc, d) => {
          const method = d.paymentMethod || 'Unknown';
          acc[method] = (acc[method] || 0) + (Number(d.amount) || 0);
          return acc;
        }, {}),
        expensesByDepartment: expenses.reduce((acc, e) => {
          const dept = e.department || 'General';
          acc[dept] = (acc[dept] || 0) + (Number(e.amount) || 0);
          return acc;
        }, {}),
        budgetAllocations: budgets,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ---------------------------------------------------------------------------
// 2. INCOME & DONATION MANAGEMENT
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/finance/income (and /api/income)
 * @desc    List all donations / income records with search, filter & pagination
 * @access  Protected (Super Admin, Finance)
 */
router.get(['/income', '/finance/income'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    const { status, category, paymentMethod, search, page = 1, limit = 50 } = req.query;

    let donations = [];
    try {
      const query = {};
      if (status) query.verificationStatus = new RegExp(`^${status}$`, 'i');
      if (category) query.category = category;
      if (paymentMethod) query.paymentMethod = paymentMethod;
      if (search) {
        query.$or = [
          { donorName: { $regex: search, $options: 'i' } },
          { donorEmail: { $regex: search, $options: 'i' } },
          { receiptNo: { $regex: search, $options: 'i' } },
          { referenceNumber: { $regex: search, $options: 'i' } },
        ];
      }
      donations = await Donation.find(query).sort({ createdAt: -1 });
    } catch {}

    if (!donations || donations.length === 0) {
      donations = getMemoryDonationsList();
      if (status) {
        donations = donations.filter((d) => (d.verificationStatus || '').toLowerCase() === status.toLowerCase());
      }
      if (category) {
        donations = donations.filter((d) => (d.category || '').toLowerCase() === category.toLowerCase());
      }
      if (paymentMethod) {
        donations = donations.filter((d) => (d.paymentMethod || '').toLowerCase() === paymentMethod.toLowerCase());
      }
      if (search) {
        const s = search.toLowerCase();
        donations = donations.filter(
          (d) =>
            (d.donorName || '').toLowerCase().includes(s) ||
            (d.donorEmail || '').toLowerCase().includes(s) ||
            (d.receiptNo || '').toLowerCase().includes(s) ||
            (d.referenceNumber || '').toLowerCase().includes(s)
        );
      }
    }

    const total = donations.length;
    const pageNum = Math.max(1, parseInt(page, 10));
    const limitNum = Math.max(1, parseInt(limit, 10));
    const paginated = donations.slice((pageNum - 1) * limitNum, pageNum * limitNum);

    return res.json({
      success: true,
      count: paginated.length,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum) || 1,
      income: paginated,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   POST /api/finance/income (and /api/income)
 * @desc    Direct manual income record entry by Finance or Super Admin
 * @access  Protected (Super Admin, Finance)
 */
router.post(['/income', '/finance/income'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    const { donorName, donorEmail, donorPhone, amount, paymentMethod, referenceNumber, category, cause, notes, currency } = req.body;

    if (!donorName || !donorEmail || !amount || !paymentMethod) {
      return res.status(400).json({
        success: false,
        error: 'Missing required donation fields: donorName, donorEmail, amount, and paymentMethod are required.',
      });
    }

    const numAmount = Number(amount);
    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ success: false, error: 'Donation amount must be a positive number.' });
    }

    const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const randSeq = Math.floor(1000 + Math.random() * 9000);
    const receiptNo = `REC-${dateStr}-${randSeq}`;
    const refNum = referenceNumber || `REF-${Date.now().toString().slice(-6)}`;
    const resolvedCurrency = currency ? currency.toUpperCase().trim() : 'PKR';

    const donationData = {
      receiptNo,
      referenceNumber: refNum,
      donorName: donorName.trim(),
      donorEmail: donorEmail.toLowerCase().trim(),
      donorPhone: donorPhone || '',
      amount: numAmount,
      currency: resolvedCurrency,
      isArchived: false,
      paymentMethod,
      category: category || 'Donation',
      cause: cause || 'General Welfare Fund',
      notes: notes || '',
      verificationStatus: 'Verified',
      verifiedBy: req.user.id || req.user._id,
      verifiedByName: req.user.name,
      verifiedAt: new Date(),
      verificationNotes: 'Manually logged by Finance Officer.',
      history: [
        {
          status: 'Verified',
          changedBy: req.user.id || req.user._id,
          changedByName: req.user.name,
          notes: 'Direct entry recorded by Finance',
          timestamp: new Date(),
        },
      ],
      createdAt: new Date(),
    };

    let donation = null;
    try {
      donation = await Donation.create(donationData);
    } catch {
      donation = { ...donationData, _id: `don_${Date.now()}`, id: `don_${Date.now()}` };
    }
    setMemoryDonation(donation);

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'DIRECT_INCOME_LOGGED',
      module: 'FINANCE_INCOME',
      targetId: donation._id?.toString() || receiptNo,
      targetModel: 'Donation',
      description: `Manual income entry of PKR ${numAmount} recorded for ${donorName} (Receipt: ${receiptNo}).`,
    }).catch(() => null);

    return res.status(201).json({
      success: true,
      message: 'Income record successfully logged.',
      donation,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   GET /api/finance/income/:id (and /api/income/:id)
 * @desc    Lookup single income / donation record
 * @access  Protected (Super Admin, Finance)
 */
router.get(['/income/:id', '/finance/income/:id'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    let donation = null;
    try {
      donation = await Donation.findById(req.params.id);
    } catch {}

    if (!donation) {
      donation = getMemoryDonationsList().find(
        (d) => (d._id || d.id)?.toString() === req.params.id || d.receiptNo === req.params.id
      );
    }

    if (!donation) {
      return res.status(404).json({ success: false, error: 'Donation record not found.' });
    }

    return res.json({ success: true, donation });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   PATCH /api/finance/income/:id/verify (and /api/income/:id/verify)
 * @desc    Verify or reject donation transaction
 * @access  Protected (Super Admin, Finance)
 */
router.patch(['/income/:id/verify', '/finance/income/:id/verify'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    const { status, notes } = req.body;
    if (!status) {
      return res.status(400).json({ success: false, error: 'Verification status is required.' });
    }

    // Normalize status: accept 'Verified', 'verified', 'Rejected', 'rejected'
    const formattedStatus = status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();

    let donation = null;
    try {
      donation = await Donation.findByIdAndUpdate(
        req.params.id,
        {
          verificationStatus: formattedStatus,
          verificationNotes: notes || '',
          verifiedBy: req.user.id || req.user._id,
          verifiedByName: req.user.name,
          verifiedAt: new Date(),
          $push: {
            history: {
              status: formattedStatus,
              changedBy: req.user.id || req.user._id,
              changedByName: req.user.name,
              notes: notes || '',
              timestamp: new Date(),
            },
          },
        },
        { new: true }
      );
    } catch {}

    if (!donation) {
      donation = getMemoryDonationsList().find(
        (d) => (d._id || d.id)?.toString() === req.params.id || d.receiptNo === req.params.id
      );
      if (donation) {
        donation.verificationStatus = formattedStatus;
        donation.verificationNotes = notes || '';
        donation.verifiedBy = req.user.id || req.user._id;
        donation.verifiedByName = req.user.name;
        donation.verifiedAt = new Date();
        donation.history = donation.history || [];
        donation.history.push({
          status: formattedStatus,
          changedBy: req.user.id || req.user._id,
          changedByName: req.user.name,
          notes: notes || '',
          timestamp: new Date(),
        });
        setMemoryDonation(donation);
      }
    }

    if (!donation) {
      return res.status(404).json({ success: false, error: 'Donation record not found.' });
    }

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'DONATION_VERIFIED',
      module: 'FINANCE_INCOME',
      targetId: donation._id?.toString() || req.params.id,
      targetModel: 'Donation',
      description: `Donation receipt ${donation.receiptNo} marked as ${formattedStatus} by ${req.user.name}.`,
    }).catch(() => null);

    return res.json({ success: true, message: `Donation status updated to ${formattedStatus}.`, donation });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ---------------------------------------------------------------------------
// 3. EXPENSE MANAGEMENT
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/finance/expenses (and /api/expenses)
 * @desc    List all expenses with department, category, and date filtering
 * @access  Protected (Super Admin, Finance only)
 */
router.get(['/expenses', '/finance/expenses'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    const { department, category, status, search, page = 1, limit = 50 } = req.query;

    let expenses = [];
    try {
      const q = {};
      if (department) q.department = department;
      if (category) q.category = category;
      if (status) q.status = status.toLowerCase();
      if (search) {
        q.$or = [
          { title: { $regex: search, $options: 'i' } },
          { expenseId: { $regex: search, $options: 'i' } },
          { submittedByName: { $regex: search, $options: 'i' } },
        ];
      }
      expenses = await Expense.find(q).sort({ createdAt: -1 });
    } catch {}

    if (!expenses || expenses.length === 0) {
      expenses = getMemoryExpensesList();
      if (department) {
        expenses = expenses.filter((e) => (e.department || '').toLowerCase() === department.toLowerCase());
      }
      if (category) {
        expenses = expenses.filter((e) => (e.category || '').toLowerCase() === category.toLowerCase());
      }
      if (status) {
        expenses = expenses.filter((e) => (e.status || '').toLowerCase() === status.toLowerCase());
      }
      if (search) {
        const s = search.toLowerCase();
        expenses = expenses.filter(
          (e) =>
            (e.title || '').toLowerCase().includes(s) ||
            (e.expenseId || '').toLowerCase().includes(s) ||
            (e.submittedByName || '').toLowerCase().includes(s)
        );
      }
    }

    const total = expenses.length;
    const pageNum = Math.max(1, parseInt(page, 10));
    const limitNum = Math.max(1, parseInt(limit, 10));
    const paginated = expenses.slice((pageNum - 1) * limitNum, pageNum * limitNum);

    return res.json({
      success: true,
      count: paginated.length,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum) || 1,
      expenses: paginated,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   GET /api/finance/expenses/department (and /api/expenses/department)
 * @desc    Department Head views expenses for their assigned department ONLY
 * @access  Protected (Department Heads, Super Admin, Finance)
 */
router.get(
  ['/expenses/department', '/finance/expenses/department'],
  protect,
  authorize('super_admin', 'finance', 'dept_literature', 'dept_media', 'dept_marketing', 'dept_outreach', 'dept_content'),
  async (req, res) => {
    try {
      if (req.user.role.startsWith('dept_')) {
        const desig = normalizeDesignation(req.user.designation) || 'head';
        if (!['head', 'director'].includes(desig)) {
          return res.status(403).json({
            success: false,
            error: 'Forbidden: Assistant Directors and Members do not hold departmental financial access privileges.',
          });
        }
      }

      let targetDept = null;
      if (req.user.role.startsWith('dept_')) {
        targetDept = getUserDept(req.user);
      } else {
        targetDept = req.query.department || null;
      }

      let expenses = [];
      try {
        const q = targetDept ? { department: targetDept } : {};
        expenses = await Expense.find(q).sort({ createdAt: -1 });
      } catch {}

      if (!expenses || expenses.length === 0) {
        expenses = getMemoryExpensesList();
        if (targetDept) {
          expenses = expenses.filter((e) => (e.department || '').toLowerCase() === targetDept.toLowerCase());
        }
      }

      return res.json({
        success: true,
        department: targetDept,
        count: expenses.length,
        expenses,
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }
);

/**
 * @route   GET /api/finance/expenses/my (and /api/expenses/my)
 * @desc    Authenticated user views their own submitted expenses
 * @access  Protected (All authenticated roles)
 */
router.get(['/expenses/my', '/finance/expenses/my'], protect, async (req, res) => {
  try {
    const userId = (req.user.id || req.user._id).toString();

    let expenses = [];
    try {
      expenses = await Expense.find({ submittedBy: req.user.id || req.user._id }).sort({ createdAt: -1 });
    } catch {}

    if (!expenses || expenses.length === 0) {
      expenses = getMemoryExpensesList().filter((e) => (e.submittedBy || '').toString() === userId);
    }

    return res.json({
      success: true,
      count: expenses.length,
      expenses,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   POST /api/finance/expenses (and /api/expenses)
 * @desc    Submit a new expense or reimbursement claim
 * @access  Protected (All authenticated staff & members)
 */
router.post(['/expenses', '/finance/expenses'], protect, async (req, res) => {
  try {
    const { title, description, amount, category, department, eventId, eventTitle, receiptUrl, receipts, date, currency, budgetId, fiscalYear, budgetCategory } = req.body;

    if (!title || !amount || !category) {
      return res.status(400).json({
        success: false,
        error: 'Missing required expense fields: title, amount, and category are required.',
      });
    }

    const numAmount = Number(amount);
    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ success: false, error: 'Expense amount must be a positive number greater than 0.' });
    }

    // Determine and enforce department
    let resolvedDepartment = department;
    if (req.user.role.startsWith('dept_')) {
      // Department Heads are strictly bound to their assigned department
      resolvedDepartment = getUserDept(req.user);
    } else if (req.user.role === 'member') {
      resolvedDepartment = department || req.user.department || 'General';
    } else if (!resolvedDepartment) {
      resolvedDepartment = 'General';
    }

    if (!VALID_DEPARTMENTS.includes(resolvedDepartment)) {
      resolvedDepartment = 'General';
    }

    const randSeq = Math.floor(100 + Math.random() * 900);
    const dateCode = new Date().toISOString().slice(2, 7).replace('-', '');
    const deptCode = resolvedDepartment.slice(0, 3).toUpperCase();
    const expenseId = `EXP-${dateCode}-${deptCode}-${randSeq}`;
    const resolvedCurrency = currency ? currency.toUpperCase().trim() : 'PKR';

    const expenseData = {
      expenseId,
      title: title.trim(),
      description: description || '',
      amount: numAmount,
      currency: resolvedCurrency,
      isArchived: false,
      budgetId: budgetId || null,
      fiscalYear: fiscalYear || null,
      budgetCategory: budgetCategory || null,
      category: category.trim(),
      department: resolvedDepartment,
      eventId: eventId || null,
      eventTitle: eventTitle || '',
      receiptUrl: receiptUrl || (receipts && receipts[0]?.url) || '',
      receipts: receipts || (receiptUrl ? [{ url: receiptUrl, filename: 'receipt.pdf', uploadDate: new Date() }] : []),
      status: 'pending',
      submittedBy: req.user.id || req.user._id,
      submittedByName: req.user.name,
      submittedByEmail: req.user.email,
      submittedByRole: req.user.role,
      date: date ? new Date(date) : new Date(),
      history: [
        {
          status: 'pending',
          changedBy: req.user.id || req.user._id,
          changedByName: req.user.name,
          changedByRole: req.user.role,
          notes: 'Expense submitted for review',
          timestamp: new Date(),
        },
      ],
      createdAt: new Date(),
    };

    let expense = null;
    try {
      expense = await Expense.create(expenseData);
    } catch {
      expense = { ...expenseData, _id: `exp_${Date.now()}`, id: `exp_${Date.now()}` };
    }
    setMemoryExpense(expense);

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'EXPENSE_SUBMITTED',
      module: 'FINANCE_EXPENSES',
      targetId: expense._id?.toString() || expenseId,
      targetModel: 'Expense',
      description: `Expense '${title}' for PKR ${numAmount} submitted by ${req.user.name} (${resolvedDepartment}).`,
    }).catch(() => null);

    const finRecipients = getMemoryUsersList().filter((u) => ['finance', 'super_admin'].includes(u.role));
    for (const recipient of finRecipients) {
      await sendNotification({
        userId: recipient.id || recipient._id,
        title: 'New Expense Claim Submitted',
        message: `Expense '${expense.title}' for ${expense.currency || 'PKR'} ${expense.amount} submitted by ${req.user.name}.`,
        type: 'info',
        category: 'finance',
        link: '/portal/finance?tab=expenses',
        dedupKey: `expense:submit:${expense.expenseId}:${recipient.id || recipient._id}`,
      }).catch(() => null);
    }

    return res.status(201).json({
      success: true,
      message: 'Expense submission received. Awaiting Finance review.',
      expense,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   GET /api/finance/expenses/:id (and /api/expenses/:id)
 * @desc    Lookup single expense record with access control
 * @access  Protected
 */
router.get(['/expenses/:id', '/finance/expenses/:id'], protect, async (req, res) => {
  try {
    let expense = null;
    try {
      expense = await Expense.findById(req.params.id);
    } catch {}

    if (!expense) {
      expense = getMemoryExpensesList().find(
        (e) => (e._id || e.id)?.toString() === req.params.id || e.expenseId === req.params.id
      );
    }

    if (!expense) {
      return res.status(404).json({ success: false, error: 'Expense record not found.' });
    }

    // Role-based visibility check
    const isGlobal = ['super_admin', 'finance'].includes(req.user.role);
    const isOwner = (expense.submittedBy || '').toString() === (req.user.id || req.user._id).toString();
    const isDeptHeadOfSameDept =
      req.user.role.startsWith('dept_') && getUserDept(req.user) === expense.department;

    if (!isGlobal && !isOwner && !isDeptHeadOfSameDept) {
      return res.status(403).json({ success: false, error: 'Access denied to this expense record.' });
    }

    return res.json({ success: true, expense });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   PATCH /api/finance/expenses/:id/review (and /api/expenses/:id/review)
 * @desc    Approve or reject expense (Strict Anti-Self-Approval, Idempotency & Concurrency Enforced)
 * @access  Protected (Super Admin, Finance only)
 */
router.patch(['/expenses/:id/review', '/finance/expenses/:id/review'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  const expenseIdKey = req.params.id;
  const releaseExpenseLock = await acquireLock(`expense:review:${expenseIdKey}`);
  let releaseBudgetLock = null;

  try {
    const rawStatus = req.body.status || (req.body.action === 'approve' ? 'approved' : req.body.action === 'reject' ? 'rejected' : null);
    const { reviewNotes, budgetId, budgetCategory } = req.body;
    const status = rawStatus;

    if (!status || !['approved', 'rejected'].includes(status.toLowerCase())) {
      return res.status(400).json({
        success: false,
        error: "Valid status ('approved' or 'rejected') is required.",
      });
    }

    let expense = null;
    try {
      expense = await Expense.findById(req.params.id);
    } catch {}

    if (!expense) {
      expense = getMemoryExpensesList().find(
        (e) => (e._id || e.id)?.toString() === req.params.id || e.expenseId === req.params.id
      );
    }

    if (!expense) {
      return res.status(404).json({ success: false, error: 'Expense record not found.' });
    }

    // CRITICAL: Anti-Self-Approval Defense
    const currentUserId = (req.user.id || req.user._id).toString();
    const submitterId = (expense.submittedBy || '').toString();

    if (submitterId && submitterId === currentUserId) {
      return res.status(403).json({
        success: false,
        error: 'Anti-self-approval rule: You cannot approve or review your own expense submission.',
      });
    }

    // Idempotency & Duplicate Approval Protection: Only pending expenses can be reviewed
    if (expense.status !== 'pending') {
      if (expense.status === 'approved') {
        return res.status(409).json({
          success: false,
          error: 'Duplicate approval rejected: This expense has already been approved.',
        });
      }
      if (['paid', 'reimbursed'].includes(expense.status)) {
        return res.status(409).json({
          success: false,
          error: `Invalid operation: Expense is already ${expense.status}. Cannot re-approve.`,
        });
      }
      if (expense.status === 'rejected') {
        return res.status(409).json({
          success: false,
          error: 'Invalid operation: Expense has already been rejected and cannot be re-reviewed.',
        });
      }
      return res.status(409).json({
        success: false,
        error: `Expense is not pending review. Current status is '${expense.status}'.`,
      });
    }

    const formattedStatus = status.toLowerCase();

    // If approving, acquire budget lock and validate budget availability, currency consistency, and status
    let targetBudget = null;
    let matchingBudget = null;
    let memBudget = null;

    if (formattedStatus === 'approved') {
      releaseBudgetLock = await acquireLock(`budget:dept:${expense.department}`);

      // Gather candidate budgets from both DB and in-memory store
      let dbBudgets = [];
      try {
        dbBudgets = await Budget.find();
      } catch {}

      const memBudgets = getMemoryBudgetsList();
      const candidatePool = dbBudgets.length > 0 ? dbBudgets : memBudgets;

      const expFiscalYear =
        expense.fiscalYear ||
        (expense.date ? String(new Date(expense.date).getFullYear()) : new Date().getFullYear().toString());

      try {
        targetBudget = resolveBudgetAllocation({
          budgetsList: candidatePool,
          explicitBudgetId: budgetId || expense.budgetId,
          explicitCategory: budgetCategory || req.body.category || expense.budgetCategory,
          department: expense.department,
          fiscalYear: expFiscalYear,
          expenseCategory: expense.category,
          currency: expense.currency || 'PKR',
        });
      } catch (allocErr) {
        if (allocErr.statusCode) {
          return res.status(allocErr.statusCode).json({ success: false, error: allocErr.message });
        }
        throw allocErr;
      }

      if (!targetBudget) {
        return res.status(400).json({
          success: false,
          error: `No budget found for department '${expense.department}'. Cannot approve expense without an allocated budget.`,
        });
      }

      matchingBudget = dbBudgets.find(
        (b) =>
          (b._id || b.id)?.toString() === (targetBudget._id || targetBudget.id)?.toString() ||
          b.budgetId === targetBudget.budgetId
      );

      memBudget = memBudgets.find(
        (b) =>
          (b._id || b.id)?.toString() === (targetBudget._id || targetBudget.id)?.toString() ||
          b.budgetId === targetBudget.budgetId
      );

      // 1. Frozen / Closed Budget Protection
      if (targetBudget.status === 'frozen') {
        return res.status(400).json({
          success: false,
          error: `Department budget for '${expense.department}' is currently frozen. Expense approval is suspended until the budget is reactivated.`,
        });
      }
      if (targetBudget.status === 'closed') {
        return res.status(400).json({
          success: false,
          error: `Department budget for '${expense.department}' is closed. No new expenses can be approved against a closed budget.`,
        });
      }

      // 2. Currency Consistency Verification
      const expCurrency = (expense.currency || 'PKR').toUpperCase();
      const bdgCurrency = (targetBudget.currency || 'PKR').toUpperCase();
      if (expCurrency !== bdgCurrency) {
        return res.status(400).json({
          success: false,
          error: `Currency mismatch: Expense currency ('${expCurrency}') does not match department budget currency ('${bdgCurrency}'). Cross-currency deduction without verified exchange rates is prohibited.`,
        });
      }

      // 3. Budget Overspending Protection
      const allocated = Number(targetBudget.allocatedAmount) || 0;
      const spent = Number(targetBudget.spentAmount) || 0;
      const remaining = allocated - spent;

      if (expense.amount > remaining) {
        return res.status(400).json({
          success: false,
          error: `Budget overspending protection: Expense amount (${expCurrency} ${expense.amount}) exceeds remaining department budget allocation (${bdgCurrency} ${remaining}). Approval denied.`,
        });
      }
    }

    // In production, database transaction is strictly mandatory
    if (process.env.NODE_ENV === 'production' && (!mongoose.connection || mongoose.connection.readyState !== 1)) {
      return res.status(503).json({
        success: false,
        error: 'Database service is unavailable. Financial transactions require an active MongoDB connection in production.',
      });
    }

    // Atomic Expense update: Use MongoDB Multi-Document ACID Transaction if connected to live DB
    let dbUpdateSucceeded = false;
    let txSession = null;

    if (mongoose.connection && mongoose.connection.readyState === 1) {
      try {
        txSession = await mongoose.startSession();
        await txSession.withTransaction(async () => {
          // 1. Re-verify Expense inside transaction
          const dbExp = await Expense.findOne({ _id: expense._id, status: 'pending' }).session(txSession);
          if (!dbExp) {
            const conflictErr = new Error('Duplicate approval rejected: Expense is no longer pending review.');
            conflictErr.statusCode = 409;
            throw conflictErr;
          }

          if (formattedStatus === 'approved') {
            // 2. Fetch and atomically validate Budget inside transaction using resolved targetBudget
            const targetBdgId = targetBudget._id || targetBudget.id;
            let dbBudget = null;
            try {
              dbBudget = await Budget.findById(targetBdgId).session(txSession);
            } catch {}
            if (!dbBudget && targetBudget.budgetId) {
              dbBudget = await Budget.findOne({ budgetId: targetBudget.budgetId }).session(txSession);
            }
            if (!dbBudget) {
              const noBdgErr = new Error(`Resolved budget '${targetBudget.budgetId || targetBdgId}' not found in database.`);
              noBdgErr.statusCode = 400;
              throw noBdgErr;
            }

            if (dbBudget.status === 'frozen') {
              const err = new Error(`Department budget for '${dbExp.department}' is currently frozen. Expense approval is suspended until the budget is reactivated.`);
              err.statusCode = 400;
              throw err;
            }
            if (dbBudget.status === 'closed') {
              const err = new Error(`Department budget for '${dbExp.department}' is closed. No new expenses can be approved against a closed budget.`);
              err.statusCode = 400;
              throw err;
            }

            const expCurrency = (dbExp.currency || 'PKR').toUpperCase();
            const bdgCurrency = (dbBudget.currency || 'PKR').toUpperCase();
            if (expCurrency !== bdgCurrency) {
              const err = new Error(`Currency mismatch: Expense currency ('${expCurrency}') does not match department budget currency ('${bdgCurrency}'). Cross-currency deduction without verified exchange rates is prohibited.`);
              err.statusCode = 400;
              throw err;
            }

            // ATOMIC CONDITIONAL UPDATE:
            // Filter requires remainingAmount >= dbExp.amount alongside _id, active status, and matching currency.
            const budgetUpdateRes = await Budget.updateOne(
              {
                _id: dbBudget._id,
                status: 'active',
                currency: expCurrency,
                remainingAmount: { $gte: dbExp.amount },
              },
              {
                $inc: { spentAmount: dbExp.amount, remainingAmount: -dbExp.amount },
                $push: {
                  history: {
                    action: 'EXPENSE_DEDUCTION',
                    amount: dbExp.amount,
                    previousSpent: dbBudget.spentAmount,
                    newSpent: dbBudget.spentAmount + dbExp.amount,
                    changedBy: req.user.id || req.user._id,
                    changedByName: req.user.name,
                    note: `Expense ${dbExp.expenseId} approved`,
                    timestamp: new Date(),
                  },
                },
              }
            ).session(txSession);

            const matched = budgetUpdateRes && (budgetUpdateRes.matchedCount !== undefined ? budgetUpdateRes.matchedCount : budgetUpdateRes.n);
            if (!matched || matched === 0) {
              const overspendErr = new Error(`Budget overspending protection: Insufficient remaining budget at commit time (${expCurrency} ${dbExp.amount} exceeds available allocation). Approval aborted.`);
              overspendErr.statusCode = 400;
              throw overspendErr;
            }
          }

          // 3. Atomically update Expense status inside transaction
          const expenseUpdates = {
            status: formattedStatus,
            reviewedBy: req.user.id || req.user._id,
            reviewedByName: req.user.name,
            reviewedAt: new Date(),
            reviewNotes: reviewNotes || '',
            $push: {
              history: {
                status: formattedStatus,
                previousStatus: 'pending',
                changedBy: req.user.id || req.user._id,
                changedByName: req.user.name,
                changedByRole: req.user.role,
                notes: reviewNotes || '',
                timestamp: new Date(),
              },
            },
          };
          if (formattedStatus === 'approved' && targetBudget) {
            expenseUpdates.budgetId = (targetBudget.budgetId || targetBudget._id || targetBudget.id).toString();
            expenseUpdates.budgetCategory = targetBudget.category;
          }

          const updated = await Expense.findOneAndUpdate(
            { _id: dbExp._id, status: 'pending' },
            expenseUpdates,
            { new: true, session: txSession }
          );

          if (!updated) {
            const err = new Error('Concurrent state modification: Expense was updated by another request.');
            err.statusCode = 409;
            throw err;
          }

          // 4. Record AuditLog inside transaction (exact same session)
          await AuditLog.create(
            [
              {
                actorName: req.user.name,
                actorRole: req.user.role,
                action: formattedStatus === 'approved' ? 'EXPENSE_APPROVED' : 'EXPENSE_REJECTED',
                module: 'FINANCE_EXPENSES',
                targetId: dbExp._id.toString(),
                targetModel: 'Expense',
                description: `Expense ${dbExp.expenseId} (${dbExp.title}, ${dbExp.currency || 'PKR'} ${dbExp.amount}) was ${formattedStatus} by ${req.user.name}.`,
                metadata: {
                  previousStatus: 'pending',
                  newStatus: formattedStatus,
                  amount: dbExp.amount,
                  currency: dbExp.currency || 'PKR',
                  department: dbExp.department,
                  budgetId: targetBudget?.budgetId || targetBudget?._id?.toString(),
                  budgetCategory: targetBudget?.category,
                },
              },
            ],
            { session: txSession }
          );

          expense = updated;
          dbUpdateSucceeded = true;
        });
      } catch (txErr) {
        if (txErr.statusCode) {
          return res.status(txErr.statusCode).json({ success: false, error: txErr.message });
        }
        throw txErr;
      } finally {
        if (txSession) await txSession.endSession();
      }
    }

    // In production, sequential fallback is strictly prohibited
    if (process.env.NODE_ENV === 'production' && !dbUpdateSucceeded) {
      return res.status(503).json({
        success: false,
        error: 'Database service is unavailable. Non-transactional fallback is strictly forbidden in production mode.',
      });
    }

    // In-memory atomic transition (Offline controlled test mode)
    const memExp = getMemoryExpensesList().find(
      (e) => (e._id || e.id)?.toString() === req.params.id || e.expenseId === req.params.id
    );

    if (memExp) {
      if (memExp.status !== 'pending') {
        return res.status(409).json({
          success: false,
          error: `Duplicate approval rejected: Expense is already ${memExp.status}.`,
        });
      }
      memExp.previousStatus = memExp.status;
      memExp.status = formattedStatus;
      memExp.reviewedBy = req.user.id || req.user._id;
      memExp.reviewedByName = req.user.name;
      memExp.reviewedAt = new Date();
      memExp.reviewNotes = reviewNotes || '';
      memExp.history = memExp.history || [];
      memExp.history.push({
        status: formattedStatus,
        previousStatus: 'pending',
        changedBy: req.user.id || req.user._id,
        changedByName: req.user.name,
        changedByRole: req.user.role,
        notes: reviewNotes || '',
        timestamp: new Date(),
      });
      if (formattedStatus === 'approved' && targetBudget) {
        memExp.budgetId = (targetBudget.budgetId || targetBudget._id || targetBudget.id).toString();
        memExp.budgetCategory = targetBudget.category;
      }
      setMemoryExpense(memExp);
      expense = memExp;
    }

    // Deduct from budget exactly once if approved (In-memory offline mode)
    if (formattedStatus === 'approved') {
      if (memBudget) {
        const prevAllocated = Number(memBudget.allocatedAmount) || 0;
        const prevSpent = Number(memBudget.spentAmount) || 0;
        const remaining = prevAllocated - prevSpent;
        if (expense.amount > remaining) {
          return res.status(400).json({
            success: false,
            error: `Budget overspending protection: Expense amount (${expense.currency || 'PKR'} ${expense.amount}) exceeds remaining department budget allocation (${memBudget.currency || 'PKR'} ${remaining}). Approval denied.`,
          });
        }
        memBudget.spentAmount = prevSpent + expense.amount;
        memBudget.remainingAmount = prevAllocated - memBudget.spentAmount;
        memBudget.history = memBudget.history || [];
        memBudget.history.push({
          action: 'EXPENSE_DEDUCTION',
          amount: expense.amount,
          previousSpent: prevSpent,
          newSpent: memBudget.spentAmount,
          changedBy: req.user.id || req.user._id,
          changedByName: req.user.name,
          note: `Expense ${expense.expenseId} approved`,
          timestamp: new Date(),
        });
        setMemoryBudget(memBudget);
      }
    }

    if (!dbUpdateSucceeded) {
      await AuditLog.create({
        actorName: req.user.name,
        actorRole: req.user.role,
        action: formattedStatus === 'approved' ? 'EXPENSE_APPROVED' : 'EXPENSE_REJECTED',
        module: 'FINANCE_EXPENSES',
        targetId: expense._id?.toString() || req.params.id,
        targetModel: 'Expense',
        description: `Expense ${expense.expenseId} (${expense.title}, ${expense.currency || 'PKR'} ${expense.amount}) was ${formattedStatus} by ${req.user.name}.`,
        metadata: {
          previousStatus: 'pending',
          newStatus: formattedStatus,
          amount: expense.amount,
          currency: expense.currency || 'PKR',
          department: expense.department,
          budgetId: targetBudget?.budgetId || targetBudget?._id?.toString(),
          budgetCategory: targetBudget?.category,
        },
      }).catch(() => null);
    }

    if (expense.submittedBy) {
      await sendNotification({
        userId: expense.submittedBy,
        title: `Expense Claim ${formattedStatus === 'approved' ? 'Approved' : 'Rejected'}`,
        message: `Your expense claim '${expense.title}' for ${expense.currency || 'PKR'} ${expense.amount} was ${formattedStatus} by ${req.user.name}.`,
        type: formattedStatus === 'approved' ? 'success' : 'warning',
        category: 'finance',
        link: '/portal/finance?tab=expenses',
        dedupKey: `expense:review:${expense.expenseId}:${formattedStatus}`,
      }).catch(() => null);
    }

    return res.json({
      success: true,
      message: `Expense ${formattedStatus === 'approved' ? 'approved' : 'rejected'} successfully.`,
      expense,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  } finally {
    if (releaseBudgetLock) releaseBudgetLock();
    releaseExpenseLock();
  }
});

/**
 * @route   PATCH /api/finance/expenses/:id/disburse (and /api/expenses/:id/disburse)
 * @desc    Mark an approved expense as paid or disbursed
 * @access  Protected (Super Admin, Finance only)
 */
router.patch(['/expenses/:id/disburse', '/finance/expenses/:id/disburse'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  const releaseLock = await acquireLock(`expense:disburse:${req.params.id}`);
  try {
    const { disbursedNotes } = req.body;

    let expense = null;
    try {
      expense = await Expense.findById(req.params.id);
    } catch {}

    if (!expense) {
      expense = getMemoryExpensesList().find(
        (e) => (e._id || e.id)?.toString() === req.params.id || e.expenseId === req.params.id
      );
    }

    if (!expense) {
      return res.status(404).json({ success: false, error: 'Expense record not found.' });
    }

    if (expense.status === 'paid' || expense.status === 'reimbursed') {
      return res.status(409).json({
        success: false,
        error: `Expense has already been marked as ${expense.status}.`,
      });
    }

    if (expense.status !== 'approved') {
      return res.status(400).json({
        success: false,
        error: `Cannot disburse an expense with status '${expense.status}'. Expense must be approved first.`,
      });
    }

    const previousStatus = expense.status;

    try {
      expense = await Expense.findByIdAndUpdate(
        req.params.id,
        {
          status: 'paid',
          disbursedAt: new Date(),
          disbursedBy: req.user.id || req.user._id,
          disbursedNotes: disbursedNotes || 'Reimbursement disbursed to submitter',
          $push: {
            history: {
              status: 'paid',
              previousStatus,
              changedBy: req.user.id || req.user._id,
              changedByName: req.user.name,
              changedByRole: req.user.role,
              notes: disbursedNotes || 'Reimbursement disbursed',
              timestamp: new Date(),
            },
          },
        },
        { new: true }
      );
    } catch {}

    if (!expense || expense.status !== 'paid') {
      const memExp = getMemoryExpensesList().find(
        (e) => (e._id || e.id)?.toString() === req.params.id || e.expenseId === req.params.id
      );
      if (memExp) {
        memExp.previousStatus = memExp.status;
        memExp.status = 'paid';
        memExp.disbursedAt = new Date();
        memExp.disbursedBy = req.user.id || req.user._id;
        memExp.disbursedNotes = disbursedNotes || 'Reimbursement disbursed';
        memExp.history = memExp.history || [];
        memExp.history.push({
          status: 'paid',
          previousStatus,
          changedBy: req.user.id || req.user._id,
          changedByName: req.user.name,
          changedByRole: req.user.role,
          notes: disbursedNotes || 'Reimbursement disbursed',
          timestamp: new Date(),
        });
        setMemoryExpense(memExp);
        expense = memExp;
      }
    }

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'EXPENSE_DISBURSED',
      module: 'FINANCE_EXPENSES',
      targetId: expense._id?.toString() || req.params.id,
      targetModel: 'Expense',
      description: `Expense ${expense.expenseId} marked as paid / disbursed by ${req.user.name}.`,
      metadata: {
        previousStatus,
        newStatus: 'paid',
        amount: expense.amount,
        currency: expense.currency || 'PKR',
      },
    }).catch(() => null);

    if (expense.submittedBy) {
      await sendNotification({
        userId: expense.submittedBy,
        title: 'Expense Claim Disbursed',
        message: `Your expense claim '${expense.title}' (${expense.currency || 'PKR'} ${expense.amount}) has been paid / disbursed.`,
        type: 'success',
        category: 'finance',
        link: '/portal/finance?tab=expenses',
        dedupKey: `expense:disburse:${expense.expenseId}`,
      }).catch(() => null);
    }

    return res.json({ success: true, message: 'Expense disbursed successfully.', expense });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  } finally {
    releaseLock();
  }
});

// ---------------------------------------------------------------------------
// 4. BUDGET MANAGEMENT
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/finance/budgets (and /api/budgets)
 * @desc    List all budgets (scoped for Department Heads)
 * @access  Protected (Super Admin, Finance, Dept Heads)
 */
router.get(
  ['/budgets', '/finance/budgets'],
  protect,
  authorize('super_admin', 'finance', 'dept_literature', 'dept_media', 'dept_marketing', 'dept_outreach', 'dept_content'),
  async (req, res) => {
    try {
      if (req.user.role.startsWith('dept_')) {
        const desig = normalizeDesignation(req.user.designation) || 'head';
        if (!['head', 'director'].includes(desig)) {
          return res.status(403).json({
            success: false,
            error: 'Forbidden: Assistant Directors and Members do not hold departmental budget access privileges.',
          });
        }
      }

      const isDeptHead = req.user.role.startsWith('dept_');
      const deptFilter = isDeptHead ? getUserDept(req.user) : req.query.department;

      let budgets = [];
      try {
        const q = deptFilter ? { department: deptFilter } : {};
        budgets = await Budget.find(q).sort({ fiscalYear: -1, department: 1 });
      } catch {}

      if (!budgets || budgets.length === 0) {
        budgets = getMemoryBudgetsList();
        if (deptFilter) {
          budgets = budgets.filter((b) => (b.department || '').toLowerCase() === deptFilter.toLowerCase());
        }
      }

      return res.json({
        success: true,
        count: budgets.length,
        budgets,
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }
);

/**
 * @route   POST /api/finance/budgets (and /api/budgets)
 * @desc    Allocate a new departmental or organizational budget
 * @access  Protected (Super Admin, Finance only)
 */
router.post(['/budgets', '/finance/budgets'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    const { fiscalYear, title, department, category, allocatedAmount, notes } = req.body;

    if (!fiscalYear || !title || !department || allocatedAmount === undefined) {
      return res.status(400).json({
        success: false,
        error: 'Missing required budget fields: fiscalYear, title, department, and allocatedAmount are required.',
      });
    }

    const numAllocated = Number(allocatedAmount);
    if (isNaN(numAllocated) || numAllocated < 0) {
      return res.status(400).json({ success: false, error: 'Allocated amount must be a non-negative number.' });
    }

    if (!VALID_DEPARTMENTS.includes(department) && department !== 'All') {
      return res.status(400).json({
        success: false,
        error: `Invalid department '${department}'. Must be one of: ${VALID_DEPARTMENTS.join(', ')}.`,
      });
    }

    const normDept = department;
    const normYear = fiscalYear.trim();
    const normCategory = (category || 'General Operating').trim();

    // Compound Uniqueness Guard: Prevent duplicate active budgets for same department, fiscal year, and category
    let existingBudget = null;
    try {
      existingBudget = await Budget.findOne({
        department: normDept,
        fiscalYear: normYear,
        category: normCategory,
        isArchived: false,
      });
    } catch {}

    const existingMem = getMemoryBudgetsList().find(
      (b) =>
        b.department === normDept &&
        b.fiscalYear === normYear &&
        (b.category || 'General Operating').trim().toLowerCase() === normCategory.toLowerCase() &&
        !b.isArchived
    );

    const duplicateRecord = existingBudget || existingMem;
    if (duplicateRecord) {
      const existingId = duplicateRecord.budgetId || duplicateRecord._id;
      return res.status(409).json({
        success: false,
        error: `Budget for department '${normDept}' in fiscal year '${normYear}' already exists (ID: ${existingId}). Multiple budgets for the same department and fiscal year are prohibited for the same category ('${normCategory}'). Please update the existing budget or archive it before allocating a new one.`,
      });
    }

    const randSeq = Math.floor(100 + Math.random() * 900);
    const yrCode = fiscalYear.replace(/[^0-9]/g, '').slice(0, 4) || '2026';
    const deptCode = department.slice(0, 3).toUpperCase();
    const budgetId = `BDG-${yrCode}-${deptCode}-${randSeq}`;
    const budgetCurrency = (req.body.currency || 'PKR').toUpperCase().trim();

    const budgetData = {
      budgetId,
      fiscalYear: normYear,
      title: title.trim(),
      department: normDept,
      category: category || 'General Operating',
      currency: budgetCurrency,
      isArchived: false,
      allocatedAmount: numAllocated,
      spentAmount: 0,
      remainingAmount: numAllocated,
      status: 'active',
      allocatedBy: req.user.id || req.user._id,
      allocatedByName: req.user.name,
      notes: notes || '',
      history: [
        {
          action: 'BUDGET_ALLOCATED',
          amount: numAllocated,
          previousAmount: 0,
          newAmount: numAllocated,
          previousSpent: 0,
          newSpent: 0,
          previousStatus: 'none',
          newStatus: 'active',
          changedBy: req.user.id || req.user._id,
          changedByName: req.user.name,
          note: `Initial budget allocated: ${budgetCurrency} ${numAllocated}`,
          timestamp: new Date(),
        },
      ],
      createdAt: new Date(),
    };

    let budget = null;
    try {
      budget = await Budget.create(budgetData);
    } catch (err) {
      if (err && (err.code === 11000 || err.name === 'MongoServerError')) {
        return res.status(409).json({
          success: false,
          error: `Duplicate budget conflict: A budget for department '${normDept}' and fiscal year '${normYear}' already exists in the database.`,
        });
      }
      budget = { ...budgetData, _id: `bdg_${Date.now()}`, id: `bdg_${Date.now()}` };
    }
    setMemoryBudget(budget);

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'BUDGET_ALLOCATED',
      module: 'FINANCE_BUDGET',
      targetId: budget._id?.toString() || budgetId,
      targetModel: 'Budget',
      description: `Budget '${title}' (${budgetCurrency} ${numAllocated}) allocated for ${department} [${fiscalYear}].`,
      metadata: {
        allocatedAmount: numAllocated,
        currency: budgetCurrency,
        department,
        fiscalYear,
      },
    }).catch(() => null);

    return res.status(201).json({
      success: true,
      message: 'Budget successfully created and allocated.',
      budget,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   PATCH /api/finance/budgets/:id (and /api/budgets/:id)
 * @desc    Update budget allocation or lifecycle status (active, frozen, closed)
 * @access  Protected (Super Admin, Finance only)
 */
router.patch(['/budgets/:id', '/finance/budgets/:id'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  const releaseLock = await acquireLock(`budget:update:${req.params.id}`);
  try {
    const { allocatedAmount, status, notes } = req.body;

    let budget = null;
    try {
      budget = await Budget.findById(req.params.id);
    } catch {}

    if (!budget) {
      budget = getMemoryBudgetsList().find(
        (b) => (b._id || b.id)?.toString() === req.params.id || b.budgetId === req.params.id
      );
    }

    if (!budget) {
      return res.status(404).json({ success: false, error: 'Budget record not found.' });
    }

    const previousAllocated = Number(budget.allocatedAmount) || 0;
    const previousSpent = Number(budget.spentAmount) || 0;
    const previousStatus = budget.status || 'active';

    const updates = {};
    if (allocatedAmount !== undefined) {
      const num = Number(allocatedAmount);
      if (isNaN(num) || num < 0) {
        return res.status(400).json({ success: false, error: 'Allocated amount must be a non-negative number.' });
      }
      if (num < previousSpent) {
        return res.status(400).json({
          success: false,
          error: `Budget allocation integrity error: Cannot reduce allocated amount (${num}) below already spent amount (${previousSpent}).`,
        });
      }
      updates.allocatedAmount = num;
      updates.remainingAmount = num - previousSpent;
    }
    if (status) {
      if (!['active', 'frozen', 'closed'].includes(status)) {
        return res.status(400).json({ success: false, error: "Status must be 'active', 'frozen', or 'closed'." });
      }
      updates.status = status;
    }
    if (notes !== undefined) {
      updates.notes = notes;
    }

    const newAllocated = updates.allocatedAmount !== undefined ? updates.allocatedAmount : previousAllocated;
    const newStatus = updates.status || previousStatus;

    try {
      budget = await Budget.findByIdAndUpdate(
        req.params.id,
        {
          ...updates,
          $push: {
            history: {
              action: 'BUDGET_UPDATED',
              amount: newAllocated,
              previousAmount: previousAllocated,
              newAmount: newAllocated,
              previousSpent,
              newSpent: previousSpent,
              previousStatus,
              newStatus,
              changedBy: req.user.id || req.user._id,
              changedByName: req.user.name,
              note: notes || 'Budget updated by finance administration',
              timestamp: new Date(),
            },
          },
        },
        { new: true }
      );
    } catch {}

    if (!budget || updates.status || updates.allocatedAmount !== undefined) {
      const memBdg = getMemoryBudgetsList().find(
        (b) => (b._id || b.id)?.toString() === req.params.id || b.budgetId === req.params.id
      );
      if (memBdg) {
        Object.assign(memBdg, updates);
        memBdg.history = memBdg.history || [];
        memBdg.history.push({
          action: 'BUDGET_UPDATED',
          amount: newAllocated,
          previousAmount: previousAllocated,
          newAmount: newAllocated,
          previousSpent,
          newSpent: previousSpent,
          previousStatus,
          newStatus,
          changedBy: req.user.id || req.user._id,
          changedByName: req.user.name,
          note: notes || 'Budget updated',
          timestamp: new Date(),
        });
        setMemoryBudget(memBdg);
        budget = memBdg;
      }
    }

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'BUDGET_UPDATED',
      module: 'FINANCE_BUDGET',
      targetId: budget._id?.toString() || req.params.id,
      targetModel: 'Budget',
      description: `Budget ${budget.budgetId} updated by ${req.user.name}.`,
      metadata: {
        previousAllocated,
        newAllocated,
        previousSpent,
        previousStatus,
        newStatus,
        currency: budget.currency || 'PKR',
      },
    }).catch(() => null);

    return res.json({ success: true, message: 'Budget record successfully updated.', budget });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  } finally {
    releaseLock();
  }
});

// ---------------------------------------------------------------------------
// 5. FINANCIAL DATA EXPORT (CSV & EXCEL XLSX)
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/finance/export/income (and /api/export/income)
 * @desc    Export income records as CSV or Excel (.xlsx)
 * @access  Protected (Super Admin, Finance only)
 */
router.get(['/export/income', '/finance/export/income'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    const format = (req.query.format || 'csv').toLowerCase();

    let donations = [];
    try {
      donations = await Donation.find().sort({ createdAt: -1 });
    } catch {}
    if (!donations || donations.length === 0) {
      donations = getMemoryDonationsList();
    }

    if (format === 'xlsx') {
      const data = donations.map((d) => ({
        'Receipt No': d.receiptNo || '',
        'Donor Name': d.donorName || '',
        'Donor Email': d.donorEmail || '',
        'Donor Phone': d.donorPhone || '',
        'Amount': Number(d.amount) || 0,
        'Currency': d.currency || 'PKR',
        'Payment Method': d.paymentMethod || '',
        'Reference Number': d.referenceNumber || '',
        'Cause': d.cause || 'General',
        'Status': d.verificationStatus || 'Pending',
        'Verified By': d.verifiedByName || '',
        'Date': d.createdAt ? new Date(d.createdAt).toISOString().slice(0, 10) : '',
      }));

      const ws = XLSX.utils.json_to_sheet(data);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Income Ledger');
      const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

      await AuditLog.create({
        actorName: req.user.name,
        actorRole: req.user.role,
        action: 'FINANCIAL_REPORT_EXPORTED',
        module: 'FINANCE_REPORTS',
        description: `Income ledger exported in XLSX format by ${req.user.name}.`,
        metadata: { format: 'xlsx', reportType: 'income', count: donations.length },
      }).catch(() => null);

      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', 'attachment; filename="rekhta_income_export.xlsx"');
      return res.status(200).send(buffer);
    }

    // Default: CSV format with formula injection protection and UTF-8 BOM
    const headers = [
      'Receipt No',
      'Donor Name',
      'Donor Email',
      'Donor Phone',
      'Amount',
      'Currency',
      'Payment Method',
      'Reference Number',
      'Cause',
      'Status',
      'Verified By',
      'Date',
    ];

    const rows = donations.map((d) => [
      escapeCsv(d.receiptNo || ''),
      escapeCsv(d.donorName || ''),
      escapeCsv(d.donorEmail || ''),
      escapeCsv(d.donorPhone || ''),
      d.amount || 0,
      escapeCsv(d.currency || 'PKR'),
      escapeCsv(d.paymentMethod || ''),
      escapeCsv(d.referenceNumber || ''),
      escapeCsv(d.cause || 'General'),
      escapeCsv(d.verificationStatus || 'Pending'),
      escapeCsv(d.verifiedByName || ''),
      d.createdAt ? new Date(d.createdAt).toISOString().slice(0, 10) : '',
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    const csvBuffer = Buffer.concat([bom, Buffer.from(csvContent, 'utf-8')]);

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'FINANCIAL_REPORT_EXPORTED',
      module: 'FINANCE_REPORTS',
      description: `Income ledger exported in CSV format by ${req.user.name}.`,
      metadata: { format: 'csv', reportType: 'income', count: donations.length },
    }).catch(() => null);

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="rekhta_income_export.csv"');
    return res.status(200).send(csvBuffer);
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   GET /api/finance/export/expenses (and /api/export/expenses)
 * @desc    Export expense records as CSV or Excel (.xlsx)
 * @access  Protected (Super Admin, Finance only)
 */
router.get(['/export/expenses', '/finance/export/expenses'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    const format = (req.query.format || 'csv').toLowerCase();
    const { department, category, status } = req.query;

    let expenses = [];
    try {
      const q = {};
      if (department) q.department = department;
      if (category) q.category = category;
      if (status) q.status = status.toLowerCase();
      expenses = await Expense.find(q).sort({ createdAt: -1 });
    } catch {}
    if (!expenses || expenses.length === 0) {
      expenses = getMemoryExpensesList();
      if (department) expenses = expenses.filter((e) => (e.department || '').toLowerCase() === department.toLowerCase());
      if (category) expenses = expenses.filter((e) => (e.category || '').toLowerCase() === category.toLowerCase());
      if (status) expenses = expenses.filter((e) => (e.status || '').toLowerCase() === status.toLowerCase());
    }

    if (format === 'xlsx') {
      const data = expenses.map((e) => ({
        'Expense ID': e.expenseId || '',
        'Title': e.title || '',
        'Amount': Number(e.amount) || 0,
        'Currency': e.currency || 'PKR',
        'Department': e.department || '',
        'Category': e.category || '',
        'Status': e.status || 'pending',
        'Submitted By': e.submittedByName || '',
        'Date': e.date ? new Date(e.date).toISOString().slice(0, 10) : '',
        'Reviewed By': e.reviewedByName || '',
        'Review Notes': e.reviewNotes || '',
      }));

      const ws = XLSX.utils.json_to_sheet(data);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Expense Records');
      const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

      await AuditLog.create({
        actorName: req.user.name,
        actorRole: req.user.role,
        action: 'FINANCIAL_REPORT_EXPORTED',
        module: 'FINANCE_REPORTS',
        description: `Expense records exported in XLSX format by ${req.user.name}.`,
        metadata: { format: 'xlsx', reportType: 'expenses', count: expenses.length },
      }).catch(() => null);

      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', 'attachment; filename="rekhta_expenses_export.xlsx"');
      return res.status(200).send(buffer);
    }

    // Default: CSV format with formula injection protection and UTF-8 BOM
    const headers = [
      'Expense ID',
      'Title',
      'Amount',
      'Currency',
      'Department',
      'Category',
      'Status',
      'Submitted By',
      'Date',
      'Reviewed By',
      'Review Notes',
    ];

    const rows = expenses.map((e) => [
      escapeCsv(e.expenseId || ''),
      escapeCsv(e.title || ''),
      e.amount || 0,
      escapeCsv(e.currency || 'PKR'),
      escapeCsv(e.department || ''),
      escapeCsv(e.category || ''),
      escapeCsv(e.status || 'pending'),
      escapeCsv(e.submittedByName || ''),
      e.date ? new Date(e.date).toISOString().slice(0, 10) : '',
      escapeCsv(e.reviewedByName || ''),
      escapeCsv(e.reviewNotes || ''),
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    const csvBuffer = Buffer.concat([bom, Buffer.from(csvContent, 'utf-8')]);

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'FINANCIAL_REPORT_EXPORTED',
      module: 'FINANCE_REPORTS',
      description: `Expense records exported in CSV format by ${req.user.name}.`,
      metadata: { format: 'csv', reportType: 'expenses', count: expenses.length },
    }).catch(() => null);

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="rekhta_expenses_export.csv"');
    return res.status(200).send(csvBuffer);
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   GET /api/finance/export/summary (and /api/export/summary)
 * @desc    Export financial & budget summary as CSV or Excel (.xlsx)
 * @access  Protected (Super Admin, Finance only)
 */
router.get(['/export/summary', '/finance/export/summary'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    const format = (req.query.format || 'csv').toLowerCase();

    let budgets = [];
    try {
      budgets = await Budget.find().sort({ department: 1 });
    } catch {}
    if (!budgets || budgets.length === 0) {
      budgets = getMemoryBudgetsList();
    }

    if (format === 'xlsx') {
      const data = budgets.map((b) => {
        const allocated = Number(b.allocatedAmount) || 0;
        const spent = Number(b.spentAmount) || 0;
        const rate = allocated > 0 ? ((spent / allocated) * 100).toFixed(1) : '0.0';
        return {
          'Budget ID': b.budgetId || '',
          'Fiscal Year': b.fiscalYear || '',
          'Department': b.department || '',
          'Title': b.title || '',
          'Allocated': allocated,
          'Spent': spent,
          'Remaining': allocated - spent,
          'Currency': b.currency || 'PKR',
          'Utilization Rate (%)': rate,
          'Status': b.status || 'active',
        };
      });

      const ws = XLSX.utils.json_to_sheet(data);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Budget Summary');
      const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

      await AuditLog.create({
        actorName: req.user.name,
        actorRole: req.user.role,
        action: 'FINANCIAL_REPORT_EXPORTED',
        module: 'FINANCE_REPORTS',
        description: `Budget summary exported in XLSX format by ${req.user.name}.`,
        metadata: { format: 'xlsx', reportType: 'summary', count: budgets.length },
      }).catch(() => null);

      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', 'attachment; filename="rekhta_budget_summary.xlsx"');
      return res.status(200).send(buffer);
    }

    // Default: CSV format with formula injection protection and UTF-8 BOM
    const headers = [
      'Budget ID',
      'Fiscal Year',
      'Department',
      'Title',
      'Allocated',
      'Spent',
      'Remaining',
      'Currency',
      'Utilization Rate (%)',
      'Status',
    ];

    const rows = budgets.map((b) => {
      const allocated = Number(b.allocatedAmount) || 0;
      const spent = Number(b.spentAmount) || 0;
      const rate = allocated > 0 ? ((spent / allocated) * 100).toFixed(1) : '0.0';
      return [
        escapeCsv(b.budgetId || ''),
        escapeCsv(b.fiscalYear || ''),
        escapeCsv(b.department || ''),
        escapeCsv(b.title || ''),
        allocated,
        spent,
        allocated - spent,
        escapeCsv(b.currency || 'PKR'),
        rate,
        escapeCsv(b.status || 'active'),
      ];
    });

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    const csvBuffer = Buffer.concat([bom, Buffer.from(csvContent, 'utf-8')]);

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'FINANCIAL_REPORT_EXPORTED',
      module: 'FINANCE_REPORTS',
      description: `Budget summary exported in CSV format by ${req.user.name}.`,
      metadata: { format: 'csv', reportType: 'summary', count: budgets.length },
    }).catch(() => null);

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="rekhta_budget_summary.csv"');
    return res.status(200).send(csvBuffer);
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ---------------------------------------------------------------------------
// 6. RECORD ARCHIVING & PRESERVATION SAFEGUARDS
// ---------------------------------------------------------------------------

/**
 * @route   DELETE /api/finance/expenses/:id, /api/finance/budgets/:id, /api/finance/income/:id
 * @desc    Prohibition against hard deletion of financial records (Preservation Safeguard)
 * @access  Protected (Super Admin, Finance only)
 */
router.delete(
  ['/expenses/:id', '/finance/expenses/:id', '/budgets/:id', '/finance/budgets/:id', '/income/:id', '/finance/income/:id'],
  protect,
  authorize('super_admin', 'finance'),
  (req, res) => {
    return res.status(405).json({
      success: false,
      error: 'Financial integrity policy: Permanent deletion of financial records is strictly prohibited. Records must be archived rather than permanently deleted.',
    });
  }
);

/**
 * @route   PATCH /api/finance/expenses/:id/archive
 * @desc    Soft-archive an expense record
 * @access  Protected (Super Admin, Finance only)
 */
router.patch(['/expenses/:id/archive', '/finance/expenses/:id/archive'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    let expense = null;
    try {
      expense = await Expense.findByIdAndUpdate(req.params.id, { isArchived: true }, { new: true });
    } catch {}

    const memExp = getMemoryExpensesList().find(
      (e) => (e._id || e.id)?.toString() === req.params.id || e.expenseId === req.params.id
    );
    if (memExp) {
      memExp.isArchived = true;
      setMemoryExpense(memExp);
      expense = memExp;
    }

    if (!expense) {
      return res.status(404).json({ success: false, error: 'Expense record not found.' });
    }

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'EXPENSE_ARCHIVED',
      module: 'FINANCE_EXPENSES',
      targetId: expense.expenseId || req.params.id,
      targetModel: 'Expense',
      description: `Expense ${expense.expenseId} was archived by ${req.user.name}.`,
      metadata: {
        isArchived: true,
      },
    }).catch(() => null);

    return res.json({ success: true, message: 'Expense record successfully archived.', expense });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * @route   PATCH /api/finance/budgets/:id/archive
 * @desc    Soft-archive a budget record
 * @access  Protected (Super Admin, Finance only)
 */
router.patch(['/budgets/:id/archive', '/finance/budgets/:id/archive'], protect, authorize('super_admin', 'finance'), async (req, res) => {
  try {
    let budget = null;
    try {
      budget = await Budget.findByIdAndUpdate(req.params.id, { isArchived: true }, { new: true });
    } catch {}

    const memBdg = getMemoryBudgetsList().find(
      (b) => (b._id || b.id)?.toString() === req.params.id || b.budgetId === req.params.id
    );
    if (memBdg) {
      memBdg.isArchived = true;
      setMemoryBudget(memBdg);
      budget = memBdg;
    }

    if (!budget) {
      return res.status(404).json({ success: false, error: 'Budget record not found.' });
    }

    await AuditLog.create({
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'BUDGET_ARCHIVED',
      module: 'FINANCE_BUDGET',
      targetId: budget.budgetId || req.params.id,
      targetModel: 'Budget',
      description: `Budget ${budget.budgetId} was archived by ${req.user.name}.`,
      metadata: {
        isArchived: true,
      },
    }).catch(() => null);

    return res.json({ success: true, message: 'Budget record successfully archived.', budget });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = {
  router,
  resolveBudgetAllocation,
  executeTransactionIfSupported,
  setMemoryDonation,
  getMemoryDonationsList,
  clearMemoryDonations,
  setMemoryExpense,
  getMemoryExpensesList,
  clearMemoryExpenses,
  setMemoryBudget,
  getMemoryBudgetsList,
  clearMemoryBudgets,
  VALID_DEPARTMENTS,
  VALID_EXPENSE_CATEGORIES,
};
