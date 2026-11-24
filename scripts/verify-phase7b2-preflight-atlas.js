/**
 * Phase 7B.2 — Live Atlas Schema & Index Preflight Verification Script
 * Strictly Read-Only Inspection
 * Does NOT mutate data, create collections, or build indexes.
 */

const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('[CRITICAL] MONGODB_URI environment variable is missing.');
  process.exit(1);
}

// Ensure credentials are never logged
const sanitizedUri = MONGODB_URI.replace(/mongodb\+srv:\/\/([^:]+):([^@]+)@/, 'mongodb+srv://$1:***@');
console.log(`[Phase 7B.2] Connecting to MongoDB Atlas (${sanitizedUri})...`);

async function runPreflight() {
  let connection = null;
  try {
    const conn = await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
    });
    connection = conn.connection;
    const db = connection.db;

    console.log(`[Phase 7B.2] Connected successfully. Database: ${db.databaseName}`);

    // 1. List all collections
    const collections = await db.listCollections().toArray();
    console.log(`[Phase 7B.2] Total live collections found: ${collections.length}`);

    const collectionDetails = [];

    for (const col of collections) {
      const colName = col.name;
      const count = await db.collection(colName).countDocuments();
      const indexes = await db.collection(colName).indexes();
      collectionDetails.push({
        name: colName,
        type: col.type,
        documentCount: count,
        indexCount: indexes.length,
        indexes: indexes.map(idx => ({
          name: idx.name,
          key: idx.key,
          unique: !!idx.unique,
          partialFilterExpression: idx.partialFilterExpression || null,
        })),
      });
    }

    console.log(`[Phase 7B.2] Collection Details:`, JSON.stringify(collectionDetails, null, 2));

    // 2. DB Stats
    const stats = await db.stats();
    console.log(`[Phase 7B.2] DB Stats - collections: ${stats.collections}, objects: ${stats.objects}, dataSize: ${stats.dataSize}`);

    console.log('[Phase 7B.2] Live Atlas preflight inspection completed successfully.');
  } catch (err) {
    console.error('[Phase 7B.2] Preflight check error:', err.message);
    process.exitCode = 1;
  } finally {
    if (mongoose.connection && mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
      console.log('[Phase 7B.2] Disconnected cleanly from MongoDB Atlas.');
    }
  }
}

runPreflight();
