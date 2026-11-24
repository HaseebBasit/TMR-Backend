/**
 * Phase 7B.6.1 — Automated MongoDB Atlas Backup Utility
 * 
 * Safely exports all collections, documents, and index definitions from live Atlas database 'tameer_rekhta'.
 * Preserves canonical BSON types (ObjectIds, Dates, Decimals) using Extended JSON (EJSON).
 * Generates SHA-256 checksums for each collection and writes an immutable backup manifest.
 * Zero credentials or secrets are logged or included in the archive.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const { connectDB } = require('../src/config/db');

const EXPECTED_DATABASE_NAME = 'tameer_rekhta';
const BACKUP_VERSION = '1.0.0';

function calculateSha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function sanitizeUri(uri) {
  if (!uri || typeof uri !== 'string') return '';
  return uri.replace(/\/\/[^@]+@/, '//***:***@');
}

async function runBackup() {
  console.log('==================================================================');
  console.log('PHASE 7B.6.1: AUTOMATED MONGODB ATLAS DATABASE BACKUP');
  console.log('Mode: Strictly Read-Only Export');
  console.log('==================================================================\n');

  // 1. Preflight Connection & Validation
  const rawUri = process.env.MONGODB_URI;
  if (!rawUri) {
    console.error('[CRITICAL ERROR] MONGODB_URI is not set in environment.');
    process.exit(1);
  }

  console.log(`[Target] ${sanitizeUri(rawUri)}`);

  process.env.TEST_USE_LIVE_DB = 'true';
  await connectDB();

  const connection = mongoose.connection;
  if (connection.readyState !== 1) {
    console.error('[CRITICAL ERROR] Failed to connect to MongoDB Atlas (readyState != 1).');
    process.exit(1);
  }

  const db = connection.db;
  if (!db || db.databaseName !== EXPECTED_DATABASE_NAME) {
    console.error(`[CRITICAL ERROR] Connected to invalid database '${db?.databaseName}'. Expected strictly '${EXPECTED_DATABASE_NAME}'.`);
    await mongoose.disconnect();
    process.exit(1);
  }

  const buildInfo = await db.admin().command({ buildInfo: 1 }).catch(() => ({ version: 'unknown' }));
  console.log(`[Database Verified] Database: '${db.databaseName}' | Engine: MongoDB v${buildInfo.version}\n`);

  // 2. Prepare Backup Destination Directory
  const now = new Date();
  const timestampStr = now.toISOString().replace(/[-:T]/g, '_').split('.')[0];
  const backupDirName = `backup_tameer_rekhta_${timestampStr}`;
  const baseBackupsDir = path.resolve(__dirname, '..', '..', 'backups', 'database');
  const backupDirPath = path.join(baseBackupsDir, backupDirName);
  const collectionsDirPath = path.join(backupDirPath, 'collections');

  if (fs.existsSync(backupDirPath)) {
    console.error(`[ERROR] Target backup directory already exists: ${backupDirPath}`);
    await mongoose.disconnect();
    process.exit(1);
  }

  fs.mkdirSync(collectionsDirPath, { recursive: true });
  console.log(`[Backup Destination] ${backupDirPath}`);

  // 3. Export Collections & Indexes
  const EJSON = mongoose.mongo.BSON.EJSON;
  const collections = await db.listCollections().toArray();
  collections.sort((a, b) => a.name.localeCompare(b.name));

  console.log(`[Exporting] Found ${collections.length} collections in '${EXPECTED_DATABASE_NAME}'...\n`);

  const manifestCollections = {};
  let totalExportedDocs = 0;

  for (const col of collections) {
    const colName = col.name;
    const colInstance = db.collection(colName);

    // Fetch all documents and all index definitions
    const docs = await colInstance.find({}).toArray();
    const indexes = await colInstance.indexes().catch(() => []);

    // Serialize documents using Canonical Extended JSON (preserves $oid, $date, etc.)
    const serializedData = EJSON.stringify(docs, { relaxed: false }, 2);
    const checksum = calculateSha256(serializedData);
    const fileName = `${colName}.json`;
    const filePath = path.join(collectionsDirPath, fileName);

    fs.writeFileSync(filePath, serializedData, 'utf8');

    manifestCollections[colName] = {
      collectionName: colName,
      documentCount: docs.length,
      file: `collections/${fileName}`,
      checksumSha256: checksum,
      sizeBytes: Buffer.byteLength(serializedData, 'utf8'),
      indexes: indexes,
    };

    totalExportedDocs += docs.length;
    console.log(`  [Exported] ${colName.padEnd(20)}: ${docs.length.toString().padStart(4)} docs | ${indexes.length} indexes | SHA256: ${checksum.substring(0, 12)}...`);
  }

  // 4. Generate Root Manifest Checksum & Manifest File
  const manifestDataWithoutRootHash = {
    manifestVersion: BACKUP_VERSION,
    databaseName: EXPECTED_DATABASE_NAME,
    clusterHost: connection.host || 'atlas-cluster',
    engineVersion: buildInfo.version,
    backupTimestamp: now.toISOString(),
    backupDirectory: backupDirName,
    totalCollections: collections.length,
    totalDocuments: totalExportedDocs,
    collections: manifestCollections,
  };

  const manifestCanonicalString = JSON.stringify(manifestDataWithoutRootHash, null, 2);
  const rootChecksum = calculateSha256(manifestCanonicalString);

  const finalManifest = {
    ...manifestDataWithoutRootHash,
    rootChecksumSha256: rootChecksum,
  };

  const manifestPath = path.join(backupDirPath, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(finalManifest, null, 2), 'utf8');

  // Also create a standalone CHECKSUMS.txt file
  let checksumsFileContent = `# SHA-256 Checksums for Backup: ${backupDirName}\n# Timestamp: ${now.toISOString()}\n\n`;
  for (const colName of Object.keys(manifestCollections)) {
    const item = manifestCollections[colName];
    checksumsFileContent += `${item.checksumSha256}  ${item.file}\n`;
  }
  checksumsFileContent += `${rootChecksum}  manifest.json\n`;
  fs.writeFileSync(path.join(backupDirPath, 'CHECKSUMS.txt'), checksumsFileContent, 'utf8');

  // 5. Clean Disconnection
  await mongoose.disconnect();
  console.log('\n[Disconnection] Cleanly disconnected from MongoDB Atlas.');

  console.log('\n==================================================================');
  console.log('BACKUP COMPLETED SUCCESSFULLY');
  console.log(`Location:         ${backupDirPath}`);
  console.log(`Total Collections: ${collections.length}`);
  console.log(`Total Documents:   ${totalExportedDocs}`);
  console.log(`Manifest Checksum: ${rootChecksum}`);
  console.log('==================================================================\n');

  return {
    backupDirPath,
    totalCollections: collections.length,
    totalExportedDocs,
    rootChecksum,
    manifest: finalManifest,
  };
}

if (require.main === module) {
  runBackup().catch(async (err) => {
    console.error('[Backup Failed]:', err.message);
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect().catch(() => null);
    }
    process.exit(1);
  });
}

module.exports = {
  runBackup,
  calculateSha256,
  EXPECTED_DATABASE_NAME,
  BACKUP_VERSION,
};
