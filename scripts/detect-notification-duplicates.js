/**
 * Pre-Migration Duplicate Detection Script: Notification User & DedupKey
 * Phase 7A.1 Database Safety Audit
 *
 * This script non-destructively inspects the Notification collection / in-memory store
 * to detect any conflicting records with identical non-empty { userId, dedupKey }
 * before partial compound unique index creation.
 */

const { Notification } = require('../src/models');
const { getNotificationsForUser } = require('../src/services/notification.service');
const { getConnectionStatus } = require('../src/config/db');

async function detectNotificationDuplicates() {
  console.log('==================================================================');
  console.log('TA\'MEER-E-REKHTA: PRE-MIGRATION NOTIFICATION DUPLICATE AUDIT');
  console.log('Target Partial Compound Key: { userId: 1, dedupKey: 1 } (where dedupKey > "")');
  console.log('==================================================================\n');

  const dbStatus = getConnectionStatus();
  console.log(`Database Status: ${dbStatus.state} (mode: ${dbStatus.mode})`);

  let notifications = [];
  try {
    if (dbStatus.isConnected) {
      notifications = await Notification.find({}).lean();
      console.log(`Retrieved ${notifications.length} notification records from MongoDB.`);
    }
  } catch (err) {
    console.warn(`[Audit Notice] Could not read from MongoDB (${err.message}). Checking in-memory store.`);
  }

  // Filter only records that have a meaningful dedupKey
  const keyedNotifications = notifications.filter(
    (n) => n.dedupKey && typeof n.dedupKey === 'string' && n.dedupKey.trim().length > 0
  );
  const unkeyedCount = notifications.length - keyedNotifications.length;

  console.log(`Auditing ${keyedNotifications.length} notifications with explicit dedupKey.`);
  console.log(`(${unkeyedCount} notifications without dedupKey ignored by partial index filter.)`);

  const map = new Map();
  for (const n of keyedNotifications) {
    const user = (n.userId || '').toString().trim();
    const key = `${user}___${n.dedupKey.trim()}`;

    if (!map.has(key)) {
      map.set(key, []);
    }
    map.get(key).push(n);
  }

  const duplicates = [];
  for (const [key, list] of map.entries()) {
    if (list.length > 1) {
      const [userId, dedupKey] = key.split('___');
      duplicates.push({
        userId,
        dedupKey,
        count: list.length,
        records: list.map((item) => ({
          id: item._id || item.id,
          title: item.title,
          category: item.category,
          type: item.type,
          createdAt: item.createdAt,
        })),
      });
    }
  }

  console.log('\n--- AUDIT RESULTS ---');
  if (duplicates.length === 0) {
    console.log('STATUS: ZERO DUPLICATES DETECTED.');
    console.log(`Verified ${keyedNotifications.length} keyed records across ${map.size} unique (userId, dedupKey) tuples.`);
    console.log('CONCLUSION: Safe to apply partial compound unique index without conflict.');
    return { duplicatesCount: 0, safe: true };
  } else {
    console.warn(`WARNING: DETECTED ${duplicates.length} CONFLICTING KEY TUPLES:`);
    duplicates.forEach((d, idx) => {
      console.warn(`\n[Conflict ${idx + 1}] User: '${d.userId}', DedupKey: '${d.dedupKey}' (${d.count} occurrences):`);
      d.records.forEach((r) => {
        console.warn(`   - ID: ${r.id} | Title: "${r.title}" | CreatedAt: ${r.createdAt}`);
      });
    });
    console.warn('\nCONCLUSION: Manual deduplication required before applying unique index.');
    return { duplicatesCount: duplicates.length, safe: false, duplicates };
  }
}

if (require.main === module) {
  detectNotificationDuplicates()
    .then((res) => {
      process.exit(res.safe ? 0 : 1);
    })
    .catch((err) => {
      console.error('[Error] Duplicate detection failed:', err);
      process.exit(1);
    });
}

module.exports = { detectNotificationDuplicates };
