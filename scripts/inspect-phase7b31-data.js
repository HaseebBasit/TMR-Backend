/**
 * Phase 7B.3.1 — Seed Data Integrity & Audit Trail Verification Script
 * Strictly Read-Only Inspection
 */

const mongoose = require('mongoose');
require('../src/config/db'); // Ensures autoIndex: false, autoCreate: false, bufferCommands: false
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('[CRITICAL] MONGODB_URI missing from environment.');
  process.exit(1);
}

async function runInspection() {
  console.log('==================================================================');
  console.log('PHASE 7B.3.1: LIVE SEED INTEGRITY & AUDIT TRAIL VERIFICATION');
  console.log('Database: tameer_rekhta | Read-Only Inspection');
  console.log('==================================================================\n');

  await mongoose.connect(MONGODB_URI, {
    autoIndex: false,
    autoCreate: false,
    serverSelectionTimeoutMS: 5000,
  });

  const db = mongoose.connection.db;

  // 1. Department Inspection
  console.log('--- 1. Department Documents Inspection ---');
  const depts = await db.collection('departments').find({}).toArray();
  console.log(`Total departments found: ${depts.length}`);
  depts.forEach((d, idx) => {
    console.log(`\n  [Department #${idx + 1}]`);
    console.log(`    _id: ${d._id}`);
    console.log(`    name: ${d.name}`);
    console.log(`    code: ${d.code}`);
    console.log(`    leadName: ${d.leadName}`);
    console.log(`    status: ${d.status}`);
    console.log(`    iconName: ${d.iconName}`);
    console.log(`    description: ${d.description}`);
    console.log(`    memberCount: ${d.memberCount}`);
    console.log(`    activeTasksCount: ${d.activeTasksCount}`);
  });

  // 2. Budget Documents & Embedded History Inspection
  console.log('\n--- 2. Budget Documents & Embedded History Inspection ---');
  const budgets = await db.collection('budgets').find({}).toArray();
  console.log(`Total budgets found: ${budgets.length}`);
  budgets.forEach((b, idx) => {
    console.log(`\n  [Budget #${idx + 1}]`);
    console.log(`    _id: ${b._id}`);
    console.log(`    budgetId: ${b.budgetId}`);
    console.log(`    title: ${b.title}`);
    console.log(`    department: ${b.department}`);
    console.log(`    fiscalYear: ${b.fiscalYear}`);
    console.log(`    category: ${b.category}`);
    console.log(`    currency: ${b.currency}`);
    console.log(`    allocatedAmount: ${b.allocatedAmount}`);
    console.log(`    spentAmount: ${b.spentAmount}`);
    console.log(`    remainingAmount: ${b.remainingAmount}`);
    console.log(`    status: ${b.status}`);
    console.log(`    isArchived: ${b.isArchived}`);
    console.log(`    notes: ${b.notes}`);
    console.log(`    embedded history count: ${b.history ? b.history.length : 0}`);
    if (b.history) {
      b.history.forEach((h, hIdx) => {
        console.log(`      History entry #${hIdx + 1}:`);
        console.log(`        action: ${h.action}`);
        console.log(`        amount: ${h.amount}`);
        console.log(`        previousAmount: ${h.previousAmount}`);
        console.log(`        newAmount: ${h.newAmount}`);
        console.log(`        previousSpent: ${h.previousSpent}`);
        console.log(`        newSpent: ${h.newSpent}`);
        console.log(`        previousStatus: ${h.previousStatus}`);
        console.log(`        newStatus: ${h.newStatus}`);
        console.log(`        note: ${h.note}`);
        console.log(`        timestamp: ${h.timestamp}`);
      });
    }
  });

  // 3. AuditLogs Collection Inspection
  console.log('\n--- 3. AuditLogs Collection Inspection ---');
  const auditLogsCount = await db.collection('auditlogs').countDocuments();
  console.log(`Total documents in 'auditlogs': ${auditLogsCount}`);

  // 4. Complete Collection Inventory & Counts
  console.log('\n--- 4. Complete Collection Document Counts ---');
  const collections = await db.listCollections().toArray();
  for (const c of collections.sort((a, b) => a.name.localeCompare(b.name))) {
    const count = await db.collection(c.name).countDocuments();
    console.log(`  ${c.name.padEnd(22)} : ${count} documents`);
  }

  // 5. Index Verification
  console.log('\n--- 5. Key Indexes Verification ---');
  const budgetIdxs = await db.collection('budgets').indexes();
  console.log('  budgets indexes:', budgetIdxs.map(i => ({ name: i.name, key: i.key, unique: i.unique, partial: i.partialFilterExpression })));

  const notifIdxs = await db.collection('notifications').indexes();
  console.log('  notifications indexes:', notifIdxs.map(i => ({ name: i.name, key: i.key, unique: i.unique, partial: i.partialFilterExpression })));

  const userIdxs = await db.collection('users').indexes();
  console.log('  users indexes:', userIdxs.map(i => ({ name: i.name, key: i.key, unique: i.unique })));

  const deptIdxs = await db.collection('departments').indexes();
  console.log('  departments indexes:', deptIdxs.map(i => ({ name: i.name, key: i.key, unique: i.unique })));

  const expIdxs = await db.collection('expenses').indexes();
  console.log('  expenses indexes:', expIdxs.map(i => ({ name: i.name, key: i.key, unique: i.unique })));

  await mongoose.disconnect();
  console.log('\n[Disconnection] Cleanly disconnected from MongoDB Atlas.');
}

runInspection().catch(err => {
  console.error('[Inspection Error]:', err.message);
  process.exit(1);
});
