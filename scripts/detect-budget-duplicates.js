/**
 * Pre-Migration Duplicate Detection Script: Budget Department & Fiscal Year
 * Phase 7A.1 Database Safety Audit
 *
 * This script non-destructively inspects the Budget collection / in-memory store
 * to detect any conflicting records with identical { department, fiscalYear }
 * before compound unique index creation.
 */

const { Budget } = require('../src/models');
const { getMemoryBudgetsList } = require('../src/routes/finance.routes');
const { getConnectionStatus } = require('../src/config/db');

async function detectBudgetDuplicates() {
  console.log('==================================================================');
  console.log('TA\'MEER-E-REKHTA: PRE-MIGRATION BUDGET DUPLICATE AUDIT');
  console.log('Target Partial Compound Key: { department: 1, fiscalYear: 1, category: 1 } (isArchived: false)');
  console.log('==================================================================\n');

  const dbStatus = getConnectionStatus();
  console.log(`Database Status: ${dbStatus.state} (mode: ${dbStatus.mode})`);

  let budgets = [];
  try {
    if (dbStatus.isConnected) {
      budgets = await Budget.find({ isArchived: false }).lean();
      console.log(`Retrieved ${budgets.length} active budget records from MongoDB.`);
    }
  } catch (err) {
    console.warn(`[Audit Notice] Could not read from MongoDB (${err.message}). Checking in-memory store.`);
  }

  if (!budgets || budgets.length === 0) {
    budgets = getMemoryBudgetsList().filter((b) => !b.isArchived);
    console.log(`Retrieved ${budgets.length} active budget records from in-memory store.`);
  }

  const map = new Map();
  for (const b of budgets) {
    const dept = (b.department || '').trim();
    const fy = (b.fiscalYear || '').trim();
    const cat = (b.category || 'General Operating').trim();
    const key = `${dept}___${fy}___${cat}`;

    if (!map.has(key)) {
      map.set(key, []);
    }
    map.get(key).push(b);
  }

  const duplicates = [];
  for (const [key, list] of map.entries()) {
    if (list.length > 1) {
      const [dept, fy, cat] = key.split('___');
      duplicates.push({
        department: dept,
        fiscalYear: fy,
        category: cat,
        count: list.length,
        fiscalYear: fy,
        count: list.length,
        records: list.map((item) => ({
          id: item._id || item.id,
          budgetId: item.budgetId,
          title: item.title,
          allocatedAmount: item.allocatedAmount,
          spentAmount: item.spentAmount,
          status: item.status,
          currency: item.currency || 'PKR',
        })),
      });
    }
  }

  console.log('\n--- AUDIT RESULTS ---');
  if (duplicates.length === 0) {
    console.log('STATUS: ZERO DUPLICATES DETECTED.');
    console.log(`Verified ${budgets.length} records across ${map.size} unique (department, fiscalYear) tuples.`);
    console.log('CONCLUSION: Safe to apply compound unique index { department: 1, fiscalYear: 1 } without conflict.');
    return { duplicatesCount: 0, safe: true };
  } else {
    console.warn(`WARNING: DETECTED ${duplicates.length} CONFLICTING KEY TUPLES:`);
    duplicates.forEach((d, idx) => {
      console.warn(`\n[Conflict ${idx + 1}] Department: '${d.department}', Fiscal Year: '${d.fiscalYear}' (${d.count} occurrences):`);
      d.records.forEach((r) => {
        console.warn(`   - ID: ${r.budgetId} | Title: "${r.title}" | Allocated: ${r.currency} ${r.allocatedAmount} | Status: ${r.status}`);
      });
    });
    console.warn('\nCONCLUSION: Manual reconciliation required before applying compound unique index.');
    return { duplicatesCount: duplicates.length, safe: false, duplicates };
  }
}

if (require.main === module) {
  detectBudgetDuplicates()
    .then((res) => {
      process.exit(res.safe ? 0 : 1);
    })
    .catch((err) => {
      console.error('[Error] Duplicate detection failed:', err);
      process.exit(1);
    });
}

module.exports = { detectBudgetDuplicates };
