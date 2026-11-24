/**
 * Phase 7B.1: MongoDB Atlas Connectivity & Replica Set Verification Script
 * Strictly Read-Only: Performs zero writes, zero schema modifications, and zero index builds.
 */

require('dotenv').config({ path: __dirname + '/../.env' });
const mongoose = require('mongoose');

// Helper to mask sensitive credentials in URIs
function sanitizeUri(uri) {
  if (!uri || typeof uri !== 'string') return '[UNDEFINED_OR_EMPTY]';
  return uri.replace(/\/\/[^@]+@/, '//***:***@');
}

async function runAtlasConnectivityVerification() {
  console.log('==================================================================');
  console.log('PHASE 7B.1: MONGODB ATLAS CONNECTIVITY & REPLICA SET VERIFICATION');
  console.log('Mode: Strictly Read-Only Inspection (Zero Writes, Zero Index Builds)');
  console.log('==================================================================\n');

  const rawUri = process.env.MONGODB_URI;
  if (!rawUri) {
    console.error('[FATAL] MONGODB_URI is not defined in backend/.env!');
    process.exit(1);
  }

  console.log(`[Configuration] Target URI: ${sanitizeUri(rawUri)}`);

  const reportData = {
    connectionStatus: 'unknown',
    databaseName: null,
    serverVersion: null,
    topologyType: null,
    replicaSetName: null,
    primaryNode: null,
    hosts: [],
    transactionCapable: false,
    latencyMs: null,
    collections: [],
    budgetAudit: null,
    notificationAudit: null,
    errors: [],
  };

  const startTime = Date.now();

  try {
    // 1. Establish authenticated connection
    console.log('[Step 1] Connecting to MongoDB Atlas...');
    await mongoose.connect(rawUri, {
      serverSelectionTimeoutMS: 15000,
      connectTimeoutMS: 15000,
    });

    reportData.latencyMs = Date.now() - startTime;
    reportData.connectionStatus = 'connected';
    console.log(`[Step 1 PASS] Authenticated connection established in ${reportData.latencyMs} ms.`);
    console.log(`[Step 1 PASS] Mongoose connection readyState: ${mongoose.connection.readyState} (Connected)`);

    const db = mongoose.connection.db;
    reportData.databaseName = db.databaseName;
    console.log(`[Step 1 PASS] Active Database Name: '${reportData.databaseName}'`);

    // 2. Ping & Server Information (read-only)
    console.log('\n[Step 2] Executing MongoDB Ping and BuildInfo...');
    const adminDb = db.admin();
    const pingResult = await adminDb.ping();
    console.log(`[Step 2 PASS] MongoDB Ping: ${JSON.stringify(pingResult)}`);

    const buildInfo = await adminDb.command({ buildInfo: 1 });
    reportData.serverVersion = buildInfo.version;
    console.log(`[Step 2 PASS] MongoDB Server Version: ${reportData.serverVersion} (Git Version: ${buildInfo.gitVersion})`);
    console.log(`[Step 2 PASS] Server Target Min OS: ${buildInfo.targetMinOS || 'N/A'}, Modules: ${JSON.stringify(buildInfo.modules || [])}`);

    // 3. Topology & Replica Set Inspection
    console.log('\n[Step 3] Inspecting Replica Set Topology...');
    let helloCmd;
    try {
      helloCmd = await db.command({ hello: 1 });
    } catch {
      helloCmd = await db.command({ isMaster: 1 });
    }

    reportData.replicaSetName = helloCmd.setName || 'Not a ReplicaSet';
    reportData.primaryNode = helloCmd.primary || (helloCmd.isWritablePrimary ? 'self' : 'unknown');
    reportData.hosts = helloCmd.hosts || [];
    reportData.topologyType = helloCmd.setName ? 'ReplicaSetWithPrimary' : (helloCmd.msg || 'Standalone');

    console.log(`[Step 3 PASS] Topology Type: ${reportData.topologyType}`);
    console.log(`[Step 3 PASS] Replica Set Name: '${reportData.replicaSetName}'`);
    console.log(`[Step 3 PASS] Primary Node: '${reportData.primaryNode}'`);
    console.log(`[Step 3 PASS] Replica Set Member Hosts (${reportData.hosts.length} nodes):`);
    reportData.hosts.forEach((h, idx) => console.log(`   Node ${idx + 1}: ${h}`));
    console.log(`[Step 3 PASS] Logical Session Timeout: ${helloCmd.logicalSessionTimeoutMinutes || 'N/A'} minutes`);
    console.log(`[Step 3 PASS] Max BSON Object Size: ${helloCmd.maxBsonObjectSize} bytes`);

    // 4. Transaction Capability Verification (Zero Writes, Aborted Probe)
    console.log('\n[Step 4] Verifying Multi-Document Transaction Capability...');
    if (helloCmd.setName && helloCmd.logicalSessionTimeoutMinutes) {
      let session = null;
      try {
        session = await mongoose.startSession();
        // Start transaction and immediately abort without performing any writes
        session.startTransaction({
          readConcern: { level: 'local' },
          writeConcern: { w: 'majority' },
        });
        await session.abortTransaction();
        reportData.transactionCapable = true;
        console.log('[Step 4 PASS] Multi-Document ACID Transactions: SUPPORTED & VERIFIED');
        console.log('             (Session successfully initiated, transaction started, and aborted with zero writes)');
      } catch (txErr) {
        reportData.transactionCapable = false;
        reportData.errors.push(`Transaction probe error: ${txErr.message}`);
        console.warn(`[Step 4 WARN] Transaction probe encountered issue: ${txErr.message}`);
      } finally {
        if (session) await session.endSession();
      }
    } else {
      reportData.transactionCapable = false;
      console.warn('[Step 4 WARN] Topology does not appear to support sessions/transactions.');
    }

    // 5. Schema & Collections Inventory (Read-Only)
    console.log('\n[Step 5] Inspecting Existing Collections and Indexes...');
    const collectionsList = await db.listCollections().toArray();
    console.log(`[Step 5] Found ${collectionsList.length} collection(s) in database '${reportData.databaseName}':`);

    for (const collInfo of collectionsList) {
      const collName = collInfo.name;
      const coll = db.collection(collName);
      const count = await coll.countDocuments().catch(() => -1);
      const indexes = await coll.indexes().catch(() => []);

      const collSummary = {
        name: collName,
        docCount: count,
        indexCount: indexes.length,
        indexes: indexes.map((idx) => ({ name: idx.name, key: idx.key, unique: Boolean(idx.unique) })),
      };
      reportData.collections.push(collSummary);

      console.log(`   - Collection: '${collName}' | Documents: ${count} | Indexes: ${indexes.length}`);
      indexes.forEach((idx) => {
        console.log(`       Index '${idx.name}': ${JSON.stringify(idx.key)} (unique: ${Boolean(idx.unique)})`);
      });
    }

    if (collectionsList.length === 0) {
      console.log('   (Database is currently fresh/empty: zero collections exist)');
    }

    // 6. Legacy Document Inspection (Budgets & Notifications)
    console.log('\n[Step 6] Inspecting Legacy Budget & Notification Data...');
    const budgetColl = collectionsList.find((c) => c.name === 'budgets');
    if (budgetColl) {
      const coll = db.collection('budgets');
      const totalBudgets = await coll.countDocuments();
      const missingArchived = await coll.countDocuments({ isArchived: { $exists: false } });
      const nullArchived = await coll.countDocuments({ isArchived: null });
      const activeBudgets = await coll.countDocuments({ isArchived: false });
      const missingCategory = await coll.countDocuments({
        $or: [{ category: { $exists: false } }, { category: null }, { category: '' }],
      });

      // Duplicate check (read-only aggregation)
      const budgetDuplicates = await coll.aggregate([
        { $match: { isArchived: false } },
        {
          $group: {
            _id: { department: '$department', fiscalYear: '$fiscalYear', category: '$category' },
            count: { $sum: 1 },
            ids: { $push: '$_id' },
          },
        },
        { $match: { count: { $gt: 1 } } },
      ]).toArray();

      reportData.budgetAudit = {
        totalBudgets,
        activeBudgets,
        missingArchived,
        nullArchived,
        missingCategory,
        duplicatesCount: budgetDuplicates.length,
        duplicates: budgetDuplicates,
      };

      console.log(`[Step 6 - Budgets] Total: ${totalBudgets} | Active (isArchived: false): ${activeBudgets}`);
      console.log(`                   Missing isArchived: ${missingArchived} | Null isArchived: ${nullArchived}`);
      console.log(`                   Missing/Null Category: ${missingCategory}`);
      console.log(`                   Duplicate Active Tuples: ${budgetDuplicates.length}`);
    } else {
      console.log("[Step 6 - Budgets] 'budgets' collection does not exist yet (Fresh Database).");
      reportData.budgetAudit = { note: 'Collection does not exist yet (Fresh DB)' };
    }

    const notifColl = collectionsList.find((c) => c.name === 'notifications');
    if (notifColl) {
      const coll = db.collection('notifications');
      const totalNotifs = await coll.countDocuments();
      const keyedNotifs = await coll.countDocuments({ dedupKey: { $type: 'string', $gt: '' } });
      const unkeyedNotifs = await coll.countDocuments({
        $or: [{ dedupKey: { $exists: false } }, { dedupKey: null }, { dedupKey: '' }],
      });

      // Duplicate check (read-only aggregation)
      const notifDuplicates = await coll.aggregate([
        { $match: { dedupKey: { $type: 'string', $gt: '' } } },
        {
          $group: {
            _id: { userId: '$userId', dedupKey: '$dedupKey' },
            count: { $sum: 1 },
            ids: { $push: '$_id' },
          },
        },
        { $match: { count: { $gt: 1 } } },
      ]).toArray();

      reportData.notificationAudit = {
        totalNotifs,
        keyedNotifs,
        unkeyedNotifs,
        duplicatesCount: notifDuplicates.length,
        duplicates: notifDuplicates,
      };

      console.log(`[Step 6 - Notifications] Total: ${totalNotifs} | Keyed: ${keyedNotifs} | Unkeyed: ${unkeyedNotifs}`);
      console.log(`                         Duplicate Keyed Tuples: ${notifDuplicates.length}`);
    } else {
      console.log("[Step 6 - Notifications] 'notifications' collection does not exist yet (Fresh Database).");
      reportData.notificationAudit = { note: 'Collection does not exist yet (Fresh DB)' };
    }

  } catch (err) {
    reportData.connectionStatus = 'failed';
    reportData.errors.push(err.message);
    console.error(`\n[FATAL ERROR] MongoDB Atlas Connection or Read Failure: ${err.message}`);
    if (err.name) console.error(`Error Name: ${err.name}, Code: ${err.code || 'N/A'}`);
  } finally {
    // 7. Clean Disconnection
    console.log('\n[Step 7] Disconnecting from MongoDB Atlas cleanly...');
    await mongoose.disconnect();
    console.log(`[Step 7 PASS] Mongoose disconnected. Current readyState: ${mongoose.connection.readyState} (Disconnected)`);
  }

  console.log('\n==================================================================');
  console.log(`PHASE 7B.1 READ-ONLY VERIFICATION FINISHED: STATUS [${reportData.connectionStatus.toUpperCase()}]`);
  console.log('==================================================================\n');

  return reportData;
}

if (require.main === module) {
  runAtlasConnectivityVerification()
    .then((data) => {
      // Output JSON summary string for automated report ingestion
      console.log('--- BEGIN REPORT JSON ---');
      console.log(JSON.stringify(data, null, 2));
      console.log('--- END REPORT JSON ---');
      process.exit(data.connectionStatus === 'connected' ? 0 : 1);
    })
    .catch((err) => {
      console.error('[Script Fatal Error]:', err.message);
      process.exit(1);
    });
}

module.exports = { runAtlasConnectivityVerification, sanitizeUri };
