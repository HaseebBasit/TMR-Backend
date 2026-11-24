/**
 * Standalone Idempotent Seed Script for MongoDB Atlas Foundational Data
 * 
 * Safely seeds:
 * 1. Approved 7 Departments (LIT, MED, MKT, OUT, CON, HR, FIN)
 * 2. Approved 3 Initial FY2026 Operating Budgets (Finance, General, HR)
 * 
 * Uses $setOnInsert so existing documents and balances are NEVER overwritten.
 */

const mongoose = require('mongoose');
require('../src/config/db'); // Enforces autoIndex, autoCreate, bufferCommands false
const dotenv = require('dotenv');
const path = require('path');
const models = require('../src/models');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('[CRITICAL] MONGODB_URI is missing from environment.');
  process.exit(1);
}

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

async function seedFoundationalData() {
  console.log('[Seed] Connecting to MongoDB Atlas for idempotent seeding check...');
  await mongoose.connect(MONGODB_URI, {
    autoIndex: false,
    autoCreate: false,
    serverSelectionTimeoutMS: 5000,
  });

  const Department = models.Department;
  const Budget = models.Budget;

  console.log('[Seed] Checking / Upserting Departments...');
  for (const dept of APPROVED_DEPARTMENTS) {
    await Department.findOneAndUpdate(
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
  }

  console.log('[Seed] Checking / Upserting Budgets...');
  for (const b of APPROVED_FY2026_BUDGETS) {
    await Budget.findOneAndUpdate(
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
  }

  const deptCount = await Department.countDocuments();
  const budgetCount = await Budget.countDocuments();
  console.log(`[Seed Complete] Total Departments: ${deptCount} (Expected: 7) | Total Budgets: ${budgetCount} (Expected: 3)`);

  await mongoose.disconnect();
  console.log('[Seed] Disconnected cleanly.');
}

if (require.main === module) {
  seedFoundationalData().catch(err => {
    console.error('[Seed Error]:', err.message);
    process.exit(1);
  });
}

module.exports = seedFoundationalData;
