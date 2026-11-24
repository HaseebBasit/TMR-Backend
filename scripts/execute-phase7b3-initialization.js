/**
 * Phase 7B.3 — Controlled Atlas Initialization & Approved Seeding Script
 * 
 * Execution Scope:
 * - Pre-Execution Checks (Database name, replica set, audit provenance)
 * - Stage A: Exact Test Audit Record Cleanup (6 verified IDs only)
 * - Stage B: Collection & Explicit Index Initialization (16 Models)
 * - Stage C: Approved Foundational Seed Data (7 Departments, 3 FY2026 Budgets)
 * - Post-Execution Read-Only Verification
 */

const mongoose = require('mongoose');
require('../src/config/db'); // Ensures autoIndex, autoCreate, and bufferCommands are false
const dotenv = require('dotenv');
const path = require('path');
const models = require('../src/models');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('[CRITICAL] MONGODB_URI is missing from environment.');
  process.exit(1);
}

const AUTHORIZED_TEST_AUDIT_IDS = [
  '6b0421f85c4fcb9d2bea3c19',
  '6b0421f95c4fcb9d2bea3c36',
  '6b0421f95c4fcb9d2bea3c42',
  '6b0421fa5c4fcb9d2bea3c51',
  '6b0421fa5c4fcb9d2bea3c60',
  '6b0421fa5c4fcb9d2bea3c72',
];

const APPROVED_DEPARTMENTS = [
  {
    name: 'Literature',
    code: 'LIT',
    description: 'Reviving Urdu poetry, prose, and literary discourse.',
    leadName: 'Noor-ul-Huda',
    status: 'active',
    iconName: 'BookOpen',
  },
  {
    name: 'Media',
    code: 'MED',
    description: 'Photography, videography, graphic design, and video production.',
    leadName: 'Aisha Tariq',
    status: 'active',
    iconName: 'Camera',
  },
  {
    name: 'Marketing',
    code: 'MKT',
    description: 'Digital campaigns, social media growth, and branding.',
    leadName: 'Ahmad Raza Waseem',
    status: 'active',
    iconName: 'TrendingUp',
  },
  {
    name: 'Outreach',
    code: 'OUT',
    description: 'Community welfare, youth events, and relief distribution.',
    leadName: 'Asfand Yar Karimi',
    status: 'active',
    iconName: 'HeartHandshake',
  },
  {
    name: 'Content Creation',
    code: 'CON',
    description: 'Urdu scripting, editorial copywriting, and Gen-Z series.',
    leadName: 'Salman Mallana',
    status: 'active',
    iconName: 'PenTool',
  },
  {
    name: 'HR',
    code: 'HR',
    description: 'Human Resources, talent recruitment, workforce onboarding, and leave management.',
    leadName: 'Hania Mehmood',
    status: 'active',
    iconName: 'UserCheck',
  },
  {
    name: 'Finance',
    code: 'FIN',
    description: 'Financial accounting, income tracking, departmental budgets, and disbursement verification.',
    leadName: 'Ahmad Maqsood',
    status: 'active',
    iconName: 'DollarSign',
  },
];

const APPROVED_FY2026_BUDGETS = [
  {
    budgetId: 'BDG-FIN-2026-OP',
    title: 'Finance General Operations 2026',
    department: 'Finance',
    fiscalYear: '2026',
    category: 'General Operating',
    allocatedAmount: 150000,
    currency: 'PKR',
    notes: 'Approved Foundational Operating Budget for Finance (FY 2026)',
  },
  {
    budgetId: 'BDG-GEN-2026-OP',
    title: 'General Operating Budget 2026',
    department: 'General',
    fiscalYear: '2026',
    category: 'General Operating',
    allocatedAmount: 200000,
    currency: 'PKR',
    notes: 'Approved Foundational General Operating Budget (FY 2026)',
  },
  {
    budgetId: 'BDG-HR-2026-OP',
    title: 'HR General Operations 2026',
    department: 'HR',
    fiscalYear: '2026',
    category: 'General Operating',
    allocatedAmount: 100000,
    currency: 'PKR',
    notes: 'Approved Foundational Operating Budget for HR (FY 2026)',
  },
];

async function executePhase7B3() {
  console.log('==================================================================');
  console.log('PHASE 7B.3: CONTROLLED ATLAS INITIALIZATION & APPROVED SEEDING');
  console.log('Database: tameer_rekhta | Replica Set: atlas-pw4qff-shard-0');
  console.log('==================================================================\n');

  // -------------------------------------------------------------------------
  // 1. PRE-EXECUTION CHECKS
  // -------------------------------------------------------------------------
  console.log('--- Section 1: Pre-Execution Verification ---');

  if (mongoose.get('autoIndex') !== false || mongoose.get('autoCreate') !== false) {
    throw new Error('Pre-execution failed: autoIndex or autoCreate is not disabled.');
  }
  console.log('  [PASS] Mongoose autoIndex and autoCreate confirmed false globally.');

  const conn = await mongoose.connect(MONGODB_URI, {
    autoIndex: false,
    autoCreate: false,
    serverSelectionTimeoutMS: 5000,
  });

  const db = conn.connection.db;
  if (db.databaseName !== 'tameer_rekhta') {
    throw new Error(`Pre-execution failed: Connected to wrong database '${db.databaseName}'. Expected 'tameer_rekhta'.`);
  }
  console.log(`  [PASS] Verified database name: ${db.databaseName}`);

  const pingRes = await db.admin().ping();
  if (pingRes.ok !== 1) {
    throw new Error('Pre-execution failed: Replica set ping did not return ok: 1.');
  }
  console.log('  [PASS] Replica set health confirmed (ping: ok 1).');

  // Verify the exact 6 audit records exist before proceeding
  const auditCol = db.collection('auditlogs');
  const existingAuditLogs = await auditCol.find({}).toArray();
  if (existingAuditLogs.length !== 6) {
    throw new Error(`Pre-execution failed: Expected exactly 6 audit logs, found ${existingAuditLogs.length}.`);
  }

  const existingIds = existingAuditLogs.map(l => l._id.toString()).sort();
  const authorizedIdsSorted = [...AUTHORIZED_TEST_AUDIT_IDS].sort();

  for (let i = 0; i < 6; i++) {
    if (existingIds[i] !== authorizedIdsSorted[i]) {
      throw new Error(`Pre-execution failed: Audit record ID mismatch! Found: ${existingIds[i]}, Expected: ${authorizedIdsSorted[i]}`);
    }
  }
  console.log('  [PASS] All six test audit records verified against approved forensic list.');

  // Verify non-audit collections contain 0 documents
  const allCols = await db.listCollections().toArray();
  for (const c of allCols) {
    if (c.name !== 'auditlogs') {
      const docCount = await db.collection(c.name).countDocuments();
      if (docCount !== 0) {
        throw new Error(`Pre-execution failed: Collection '${c.name}' has ${docCount} documents. Expected 0.`);
      }
    }
  }
  console.log('  [PASS] All other 15 collections confirmed at 0 documents.');

  // -------------------------------------------------------------------------
  // 2. STAGE A: EXACT TEST AUDIT RECORD CLEANUP
  // -------------------------------------------------------------------------
  console.log('\n--- Section 2: Stage A — Exact Test Audit Record Cleanup ---');

  // Re-read and verify details of all 6 records immediately before deletion
  const objectIdsToDelete = AUTHORIZED_TEST_AUDIT_IDS.map(id => new mongoose.Types.ObjectId(id));
  const docsToVerify = await auditCol.find({ _id: { $in: objectIdsToDelete } }).toArray();

  if (docsToVerify.length !== 6) {
    throw new Error(`Stage A failed: Expected 6 matching documents for deletion, found ${docsToVerify.length}.`);
  }

  console.log('  [Pre-Delete Verification] Inspecting documents to be purged:');
  docsToVerify.forEach((d, idx) => {
    console.log(`    #${idx + 1}: ID=${d._id} | Action=${d.action} | Actor=${d.actorName} | CreatedAt=${d.createdAt.toISOString()}`);
  });

  // Execute deletion strictly by exact _id list
  const deleteResult = await auditCol.deleteMany({ _id: { $in: objectIdsToDelete } });
  console.log(`  [Delete Executed] Deleted count: ${deleteResult.deletedCount}`);

  if (deleteResult.deletedCount !== 6) {
    throw new Error(`Stage A failed: Expected deletedCount === 6, got ${deleteResult.deletedCount}.`);
  }

  // Verify auditlogs collection is now exactly 0 documents
  const remainingAuditCount = await auditCol.countDocuments();
  if (remainingAuditCount !== 0) {
    throw new Error(`Stage A failed: auditlogs collection still has ${remainingAuditCount} documents. Expected 0.`);
  }
  console.log('  [PASS] Exactly 6 test audit records deleted. auditlogs collection count is now 0.');

  // -------------------------------------------------------------------------
  // 3. STAGE B: COLLECTION & INDEX INITIALIZATION
  // -------------------------------------------------------------------------
  console.log('\n--- Section 3: Stage B — Collection & Index Initialization ---');

  const modelKeys = Object.keys(models);
  console.log(`  [Models] Initializing indexes for ${modelKeys.length} Mongoose models explicitly...`);

  for (const modelName of modelKeys) {
    const Model = models[modelName];
    try {
      await Model.createIndexes();
      console.log(`    [Index OK] ${modelName} -> collection: '${Model.collection.name}'`);
    } catch (err) {
      throw new Error(`Stage B failed: Error building indexes for model '${modelName}': ${err.message}`);
    }
  }

  // Detailed Index Verification on Live Atlas Collections
  console.log('  [Index Validation] Verifying critical indexes against specifications:');

  // Budget Indexes
  const budgetIndexes = await db.collection('budgets').indexes();
  const budgetCompoundIdx = budgetIndexes.find(i => i.name === 'department_1_fiscalYear_1_category_1');
  const budgetIdIdx = budgetIndexes.find(i => i.name === 'budgetId_1');

  if (!budgetIdIdx || !budgetIdIdx.unique) {
    throw new Error("Stage B failed: Budget 'budgetId_1' unique index is missing or non-unique.");
  }
  if (!budgetCompoundIdx || !budgetCompoundIdx.unique || !budgetCompoundIdx.partialFilterExpression?.isArchived === false) {
    throw new Error("Stage B failed: Budget compound unique partial index { department, fiscalYear, category } (isArchived: false) is missing or invalid.");
  }
  console.log("    [PASS] Budget unique and partial compound indexes verified.");

  // Notification Indexes
  const notifIndexes = await db.collection('notifications').indexes();
  const notifCompoundIdx = notifIndexes.find(i => i.name === 'userId_1_dedupKey_1');

  if (!notifCompoundIdx || !notifCompoundIdx.unique || !notifCompoundIdx.partialFilterExpression?.dedupKey) {
    throw new Error("Stage B failed: Notification compound unique partial index { userId, dedupKey } is missing or invalid.");
  }
  console.log("    [PASS] Notification unique partial compound index verified.");

  // User Indexes
  const userIndexes = await db.collection('users').indexes();
  const userEmailIdx = userIndexes.find(i => i.name === 'email_1');
  if (!userEmailIdx || !userEmailIdx.unique) {
    throw new Error("Stage B failed: User 'email_1' unique index is missing or non-unique.");
  }
  console.log("    [PASS] User email unique index verified.");

  // Expense Indexes
  const expenseIndexes = await db.collection('expenses').indexes();
  const expenseIdIdx = expenseIndexes.find(i => i.name === 'expenseId_1');
  if (!expenseIdIdx || !expenseIdIdx.unique) {
    throw new Error("Stage B failed: Expense 'expenseId_1' unique index is missing or non-unique.");
  }
  console.log("    [PASS] Expense expenseId unique index verified.");

  // Department Indexes
  const deptIndexes = await db.collection('departments').indexes();
  const deptNameIdx = deptIndexes.find(i => i.name === 'name_1');
  const deptCodeIdx = deptIndexes.find(i => i.name === 'code_1');
  if (!deptNameIdx || !deptNameIdx.unique || !deptCodeIdx || !deptCodeIdx.unique) {
    throw new Error("Stage B failed: Department 'name_1' or 'code_1' unique indexes are missing.");
  }
  console.log("    [PASS] Department name and code unique indexes verified.");

  // Donation Indexes
  const donationIndexes = await db.collection('donations').indexes();
  const donReceiptIdx = donationIndexes.find(i => i.name === 'receiptNo_1');
  const donSubIdx = donationIndexes.find(i => i.name === 'submissionId_1');
  if (!donReceiptIdx || !donReceiptIdx.unique || !donSubIdx || !donSubIdx.unique) {
    throw new Error("Stage B failed: Donation unique indexes are missing.");
  }
  console.log("    [PASS] Donation receiptNo and submissionId unique indexes verified.");

  // -------------------------------------------------------------------------
  // 4. STAGE C: APPROVED FOUNDATIONAL SEED DATA
  // -------------------------------------------------------------------------
  console.log('\n--- Section 4: Stage C — Approved Foundational Seed Data ---');

  // 4.1 Departments Seeding (7 Core Departments)
  console.log(`  [Departments] Idempotently seeding ${APPROVED_DEPARTMENTS.length} approved departments...`);
  const Department = models.Department;

  for (const dept of APPROVED_DEPARTMENTS) {
    const res = await Department.findOneAndUpdate(
      { code: dept.code },
      {
        $setOnInsert: {
          name: dept.name,
          code: dept.code,
          description: dept.description,
          leadName: dept.leadName,
          status: dept.status,
          iconName: dept.iconName,
          memberCount: 0,
          activeTasksCount: 0,
        },
      },
      { upsert: true, new: true }
    );
    console.log(`    [Seeded] Dept: ${res.name} (${res.code}) | ID: ${res._id}`);
  }

  const seededDeptCount = await Department.countDocuments();
  if (seededDeptCount !== APPROVED_DEPARTMENTS.length) {
    throw new Error(`Stage C failed: Expected ${APPROVED_DEPARTMENTS.length} departments, found ${seededDeptCount}.`);
  }
  console.log(`  [PASS] All ${seededDeptCount} approved departments successfully seeded and verified.`);

  // 4.2 Initial FY2026 Operating Budgets Seeding (3 Budgets: Finance, General, HR)
  console.log(`  [Budgets] Idempotently seeding ${APPROVED_FY2026_BUDGETS.length} approved FY2026 operating budgets...`);
  const Budget = models.Budget;

  for (const b of APPROVED_FY2026_BUDGETS) {
    const res = await Budget.findOneAndUpdate(
      {
        department: b.department,
        fiscalYear: b.fiscalYear,
        category: b.category,
        isArchived: false,
      },
      {
        $setOnInsert: {
          budgetId: b.budgetId,
          title: b.title,
          department: b.department,
          fiscalYear: b.fiscalYear,
          category: b.category,
          allocatedAmount: b.allocatedAmount,
          currency: b.currency,
          spentAmount: 0,
          remainingAmount: b.allocatedAmount,
          status: 'active',
          isArchived: false,
          notes: b.notes,
          history: [
            {
              action: 'BUDGET_INITIALIZED',
              amount: b.allocatedAmount,
              previousAmount: 0,
              newAmount: b.allocatedAmount,
              previousSpent: 0,
              newSpent: 0,
              previousStatus: 'none',
              newStatus: 'active',
              note: 'Approved Foundational FY2026 Operating Budget Allocation',
              timestamp: new Date(),
            },
          ],
        },
      },
      { upsert: true, new: true }
    );
    console.log(`    [Seeded] Budget: ${res.department} [${res.fiscalYear}] ${res.category} | Allocated: ${res.currency} ${res.allocatedAmount} | Remaining: ${res.currency} ${res.remainingAmount} | ID: ${res.budgetId}`);
  }

  const seededBudgetCount = await Budget.countDocuments();
  if (seededBudgetCount !== APPROVED_FY2026_BUDGETS.length) {
    throw new Error(`Stage C failed: Expected ${APPROVED_FY2026_BUDGETS.length} budgets, found ${seededBudgetCount}.`);
  }
  console.log(`  [PASS] All ${seededBudgetCount} approved budgets successfully seeded and verified.`);

  // -------------------------------------------------------------------------
  // 5. POST-EXECUTION READ-ONLY VERIFICATION
  // -------------------------------------------------------------------------
  console.log('\n--- Section 5: Post-Execution Complete Verification ---');

  // Verify document counts across all collections
  const liveCollections = await db.listCollections().toArray();
  console.log(`  Total Live Collections: ${liveCollections.length}`);

  const counts = {};
  for (const col of liveCollections.sort((a, b) => a.name.localeCompare(b.name))) {
    const count = await db.collection(col.name).countDocuments();
    counts[col.name] = count;
    console.log(`    ${col.name.padEnd(22)} : ${count} documents`);
  }

  // Exact assertions
  if (counts['departments'] !== 7) {
    throw new Error(`Post-execution check failed: 'departments' count is ${counts['departments']}, expected 7.`);
  }
  if (counts['budgets'] !== 3) {
    throw new Error(`Post-execution check failed: 'budgets' count is ${counts['budgets']}, expected 3.`);
  }
  if (counts['auditlogs'] !== 0) {
    throw new Error(`Post-execution check failed: 'auditlogs' count is ${counts['auditlogs']}, expected 0.`);
  }

  const zeroDocCollections = [
    'applications', 'assessments', 'campaigns', 'contactinquiries',
    'donations', 'eventregistrations', 'events', 'expenses',
    'leaverequests', 'mediaassets', 'notifications', 'tasks', 'users'
  ];

  for (const name of zeroDocCollections) {
    if (counts[name] !== 0) {
      throw new Error(`Post-execution check failed: '${name}' count is ${counts[name]}, expected 0.`);
    }
  }
  console.log('  [PASS] Document counts across all 16 collections match exact authorization specifications.');

  // Validate Budget balances
  const allBudgets = await Budget.find({}).lean();
  for (const b of allBudgets) {
    if (b.currency !== 'PKR') throw new Error(`Budget ${b.budgetId} currency is ${b.currency}, expected PKR.`);
    if (b.spentAmount !== 0) throw new Error(`Budget ${b.budgetId} spentAmount is ${b.spentAmount}, expected 0.`);
    if (b.remainingAmount !== b.allocatedAmount) {
      throw new Error(`Budget ${b.budgetId} remainingAmount (${b.remainingAmount}) does not match allocatedAmount (${b.allocatedAmount}).`);
    }
    if (b.isArchived !== false) throw new Error(`Budget ${b.budgetId} isArchived is ${b.isArchived}, expected false.`);
    if (b.status !== 'active') throw new Error(`Budget ${b.budgetId} status is ${b.status}, expected active.`);
  }
  console.log('  [PASS] All 3 budgets validated: currency PKR, spentAmount 0, remainingAmount equals allocatedAmount.');

  console.log('\n==================================================================');
  console.log('PHASE 7B.3 EXECUTION SUCCESSFULLY COMPLETED');
  console.log('==================================================================');

  await mongoose.disconnect();
  console.log('[Disconnection] Cleanly disconnected from MongoDB Atlas.');
}

executePhase7B3().catch(err => {
  console.error('\n[CRITICAL FAILURE IN PHASE 7B.3]:', err.message);
  if (mongoose.connection.readyState !== 0) {
    mongoose.disconnect().catch(() => null);
  }
  process.exit(1);
});
