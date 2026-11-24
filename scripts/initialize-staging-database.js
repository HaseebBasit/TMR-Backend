/**
 * Phase 7B.6.4C — Staging Database Initialization Utility
 * 
 * Target: tameer_rekhta_staging ONLY
 * 
 * Safely provisions:
 * 1. The 16 approved collections and schema indexes
 * 2. The 7 approved baseline departments (LIT, MED, MKT, OUT, CON, HR, FIN)
 * 3. The 3 baseline FY2026 operating budget templates
 * 
 * Invariants:
 * - Strictly aborts if connected database is NOT tameer_rekhta_staging.
 * - Does NOT copy production users, passwords, sessions, or audit logs.
 * - Does NOT copy production Super Admin.
 * - Does NOT create deferred leadership accounts.
 */

const path = require('path');
const dotenv = require('dotenv');

// Explicitly load staging environment configuration
dotenv.config({ path: path.join(__dirname, '..', '.env.staging'), override: true });

const mongoose = require('mongoose');
const {
  validateDatabaseTarget,
  STAGING_DB_NAME,
  PRODUCTION_DB_NAME,
} = require('../src/config/db');
const models = require('../src/models');

const EXPECTED_STAGING_DB = STAGING_DB_NAME; // 'tameer_rekhta_staging'

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

const BASELINE_BUDGETS = [
  {
    budgetId: 'BDG-FIN-2026-OP',
    title: 'Finance Department Operating Budget FY2026',
    department: 'Finance',
    fiscalYear: 2026,
    category: 'General Operating',
    allocatedAmount: 150000,
    spentAmount: 0,
    currency: 'PKR',
    status: 'active',
  },
  {
    budgetId: 'BDG-GEN-2026-OP',
    title: 'General Operating & Contingency Reserve FY2026',
    department: 'General',
    fiscalYear: 2026,
    category: 'General Operating',
    allocatedAmount: 200000,
    spentAmount: 0,
    currency: 'PKR',
    status: 'active',
  },
  {
    budgetId: 'BDG-HR-2026-OP',
    title: 'HR & Volunteer Onboarding Operating Budget FY2026',
    department: 'HR',
    fiscalYear: 2026,
    category: 'General Operating',
    allocatedAmount: 100000,
    spentAmount: 0,
    currency: 'PKR',
    status: 'active',
  },
];

async function initializeStagingDatabase() {
  console.log('==================================================================');
  console.log('TA\'MEER-E-REKHTA: STAGING DATABASE INITIALIZATION');
  console.log('Target: Isolated Database "tameer_rekhta_staging"');
  console.log('==================================================================\n');

  const uri = process.env.MONGODB_URI;

  if (!uri || uri.includes('<staging_username>')) {
    console.error('[STAGING PROVISIONING PREREQUISITE]');
    console.error('Dedicated staging database credentials not yet configured in backend/.env.staging.');
    console.error('Please create dedicated staging user in Atlas Console and populate MONGODB_URI.');
    return {
      status: 'BLOCKED_CREDENTIALS',
      message: 'Dedicated staging credentials pending in backend/.env.staging.',
    };
  }

  // 1. Validate Target Database Isolation Guard
  console.log('--- 1. Database Target Isolation Guard Check ---');
  const guardResult = validateDatabaseTarget(uri, { NODE_ENV: 'staging' });
  console.log(`  [PASS] Target database validated: ${guardResult.dbName}`);

  if (guardResult.dbName !== EXPECTED_STAGING_DB) {
    throw new Error(`[CRITICAL] Refusing to initialize non-staging database: ${guardResult.dbName}`);
  }

  // 2. Connect to Atlas Staging
  console.log('\n--- 2. Connecting to Staging Database ---');
  const conn = await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 8000,
    autoIndex: false,
    autoCreate: false,
  });

  const db = conn.connection.db;
  const connectedDbName = db.databaseName;
  console.log(`  [PASS] Connected successfully to database: ${connectedDbName}`);

  if (connectedDbName !== EXPECTED_STAGING_DB) {
    await mongoose.disconnect();
    throw new Error(`[FATAL ISOLATION EXCEPTION]: Connected to unexpected database "${connectedDbName}". Expected "${EXPECTED_STAGING_DB}". Aborted.`);
  }

  // 3. Create Required 16 Collections Explicitly
  console.log('\n--- 3. Explicit Collection Creation ---');
  const existingCollections = await db.listCollections().toArray();
  const existingNames = new Set(existingCollections.map(c => c.name));

  const modelNames = Object.keys(models);
  const createdCollections = [];

  for (const modelName of modelNames) {
    const colName = models[modelName].collection.name;
    if (!existingNames.has(colName)) {
      await db.createCollection(colName);
      createdCollections.push(colName);
      console.log(`  [CREATED] Collection: ${colName}`);
    } else {
      console.log(`  [EXISTS]  Collection: ${colName}`);
    }
  }

  // 4. Build Schema Indexes Explicitly
  console.log('\n--- 4. Schema Index Initialization ---');
  for (const modelName of modelNames) {
    const model = models[modelName];
    try {
      await model.createIndexes();
      const idxs = await model.collection.indexes();
      console.log(`  [INDEXED] Model ${modelName} (${model.collection.name}): ${idxs.length} indexes verified`);
    } catch (idxErr) {
      console.warn(`  [INDEX WARN] Model ${modelName}: ${idxErr.message}`);
    }
  }

  // 5. Seed Foundational Departments (Idempotent via $setOnInsert)
  console.log('\n--- 5. Baseline Department Seeding ---');
  let deptsInserted = 0;
  for (const d of APPROVED_DEPARTMENTS) {
    const res = await db.collection('departments').updateOne(
      { code: d.code },
      {
        $setOnInsert: {
          name: d.name,
          code: d.code,
          description: d.description,
          leadName: d.leadName,
          status: d.status,
          iconName: d.iconName,
          memberCount: 0,
          activeTasksCount: 0,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      },
      { upsert: true }
    );
    if (res.upsertedCount > 0) deptsInserted++;
  }
  const totalDepts = await db.collection('departments').countDocuments();
  console.log(`  [PASS] Departments seeded (${deptsInserted} new, ${totalDepts} total).`);

  // 6. Seed Baseline Budgets (Idempotent via $setOnInsert)
  console.log('\n--- 6. Baseline Operating Budgets Seeding ---');
  let budgetsInserted = 0;
  for (const b of BASELINE_BUDGETS) {
    const res = await db.collection('budgets').updateOne(
      { budgetId: b.budgetId },
      {
        $setOnInsert: {
          ...b,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      },
      { upsert: true }
    );
    if (res.upsertedCount > 0) budgetsInserted++;
  }
  const totalBudgets = await db.collection('budgets').countDocuments();
  console.log(`  [PASS] Baseline budgets seeded (${budgetsInserted} new, ${totalBudgets} total).`);

  // 7. Data Isolation Verification
  console.log('\n--- 7. Data Isolation Verification ---');
  const userCount = await db.collection('users').countDocuments();
  const auditCount = await db.collection('auditlogs').countDocuments();
  const expenseCount = await db.collection('expenses').countDocuments();
  const donationCount = await db.collection('donations').countDocuments();

  console.log(`  [VERIFY] Users count in staging: ${userCount} (Must be 0 - Zero production users copied)`);
  console.log(`  [VERIFY] Audit logs in staging:  ${auditCount} (Must be 0 - Zero production audit history copied)`);
  console.log(`  [VERIFY] Expenses in staging:    ${expenseCount} (Must be 0)`);
  console.log(`  [VERIFY] Donations in staging:   ${donationCount} (Must be 0)`);

  if (userCount > 0) {
    console.warn('  [WARNING] Users exist in staging. Confirm they are synthetic disposable accounts.');
  }

  // 8. Clean Disconnection
  await mongoose.disconnect();
  console.log('\n[PASS] Cleanly disconnected from MongoDB Atlas staging.');

  console.log('\n==================================================================');
  console.log('STAGING DATABASE INITIALIZATION COMPLETED SUCCESSFULLY');
  console.log('==================================================================\n');

  return {
    status: 'SUCCESS',
    database: connectedDbName,
    createdCollections: createdCollections.length,
    departmentsCount: totalDepts,
    budgetsCount: totalBudgets,
    usersCount: userCount,
  };
}

if (require.main === module) {
  initializeStagingDatabase().catch((err) => {
    console.error('[Initialization Error]:', err.message);
    if (mongoose.connection && mongoose.connection.readyState !== 0) {
      mongoose.disconnect().catch(() => null);
    }
    process.exit(1);
  });
}

module.exports = {
  initializeStagingDatabase,
  APPROVED_DEPARTMENTS,
  BASELINE_BUDGETS,
};
