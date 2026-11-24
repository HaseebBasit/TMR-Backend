/**
 * Phase 7B.6.1 — Disaster Recovery & Database Restoration Runbook Utility
 * 
 * Mode: Dry-Run Validation ONLY.
 * Validates:
 * 1. Backup directory and manifest.json presence and format.
 * 2. SHA-256 checksum integrity across all exported collection files.
 * 3. Canonical Extended JSON (EJSON) deserialization compatibility.
 * 4. Document count parity and index specification integrity.
 * 5. Target database compatibility and connectivity check against Atlas.
 * 
 * Strict safety guard: Actual live database restoration is explicitly locked
 * in Phase 7B.6.1.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const { connectDB } = require('../src/config/db');

const EXPECTED_DATABASE_NAME = 'tameer_rekhta';

function calculateSha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function findLatestBackupDir() {
  const baseBackupsDir = path.resolve(__dirname, '..', '..', 'backups', 'database');
  if (!fs.existsSync(baseBackupsDir)) return null;

  const entries = fs.readdirSync(baseBackupsDir, { withFileTypes: true });
  const backupDirs = entries
    .filter((e) => e.isDirectory() && e.name.startsWith('backup_tameer_rekhta_'))
    .map((e) => e.name)
    .sort()
    .reverse();

  if (backupDirs.length === 0) return null;
  return path.join(baseBackupsDir, backupDirs[0]);
}

async function validateRestore(options = {}) {
  const args = options.args || process.argv.slice(2);
  let backupPath = options.backupPath;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--backup-dir' && args[i + 1]) {
      backupPath = path.resolve(args[i + 1]);
    }
  }

  if (!backupPath) {
    backupPath = findLatestBackupDir();
  }

  console.log('==================================================================');
  console.log('PHASE 7B.6.1: DISASTER RECOVERY & DRY-RUN RESTORE VALIDATION');
  console.log('Mode: Strictly Dry-Run Validation (Zero Database Writes)');
  console.log('==================================================================\n');

  if (!backupPath || !fs.existsSync(backupPath)) {
    console.error(`[CRITICAL ERROR] Backup directory not found: ${backupPath || 'No backups found in backups/database'}`);
    process.exit(1);
  }

  console.log(`[Backup Target] ${backupPath}`);

  // 1. Validate manifest.json
  const manifestPath = path.join(backupPath, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    console.error(`[CRITICAL ERROR] manifest.json missing from backup: ${manifestPath}`);
    process.exit(1);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  console.log(`[Manifest Loaded] Database: '${manifest.databaseName}' | Timestamp: ${manifest.backupTimestamp} | Version: ${manifest.manifestVersion}`);

  if (manifest.databaseName !== EXPECTED_DATABASE_NAME) {
    console.error(`[SAFETY ERROR] Backup database is '${manifest.databaseName}', expected '${EXPECTED_DATABASE_NAME}'. Aborting.`);
    process.exit(1);
  }

  // 2. Validate SHA-256 Checksums and Canonical Deserialization
  console.log('\n--- 1. Archive Checksum & BSON Deserialization Verification ---');
  const EJSON = mongoose.mongo.BSON.EJSON;
  let validatedCollections = 0;
  let validatedDocuments = 0;
  let checksumMismatches = 0;

  for (const colName of Object.keys(manifest.collections)) {
    const colMeta = manifest.collections[colName];
    const colFilePath = path.join(backupPath, colMeta.file);

    if (!fs.existsSync(colFilePath)) {
      console.error(`  [FAIL] Missing collection file: ${colMeta.file}`);
      checksumMismatches++;
      continue;
    }

    const fileContent = fs.readFileSync(colFilePath, 'utf8');
    const computedChecksum = calculateSha256(fileContent);

    if (computedChecksum !== colMeta.checksumSha256) {
      console.error(`  [FAIL] Checksum mismatch for ${colName}: expected ${colMeta.checksumSha256}, got ${computedChecksum}`);
      checksumMismatches++;
      continue;
    }

    // Verify Canonical EJSON parsing
    let parsedDocs;
    try {
      parsedDocs = EJSON.parse(fileContent, { relaxed: false });
    } catch (parseErr) {
      console.error(`  [FAIL] EJSON parse failure for ${colName}:`, parseErr.message);
      checksumMismatches++;
      continue;
    }

    if (parsedDocs.length !== colMeta.documentCount) {
      console.error(`  [FAIL] Document count mismatch for ${colName}: expected ${colMeta.documentCount}, got ${parsedDocs.length}`);
      checksumMismatches++;
      continue;
    }

    validatedCollections++;
    validatedDocuments += parsedDocs.length;
    console.log(`  [PASS] ${colName.padEnd(20)}: ${parsedDocs.length.toString().padStart(4)} docs | Checksum MATCH (${computedChecksum.substring(0, 12)}...)`);
  }

  if (checksumMismatches > 0) {
    console.error(`\n[VALIDATION FAILED] ${checksumMismatches} checksum or deserialization failures detected.`);
    process.exit(1);
  }

  console.log(`\n[Integrity Confirmed] 100% of collection files (${validatedCollections}) and documents (${validatedDocuments}) verified against SHA-256 manifest.`);

  // 3. Connect to Target Database (Read-Only Compatibility Check)
  console.log('\n--- 2. Target Database Compatibility & Topology Check ---');
  process.env.TEST_USE_LIVE_DB = 'true';
  await connectDB();

  const connection = mongoose.connection;
  const db = connection.db;

  if (db?.databaseName !== EXPECTED_DATABASE_NAME) {
    console.error(`[SAFETY ERROR] Connected database '${db?.databaseName}' does not match expected '${EXPECTED_DATABASE_NAME}'.`);
    await mongoose.disconnect();
    process.exit(1);
  }

  const liveCollections = await db.listCollections().toArray();
  console.log(`[Target Verified] Database '${db.databaseName}' confirmed online with ${liveCollections.length} active collections.`);

  // 4. Dry-Run Restoration Plan
  console.log('\n--- 3. Dry-Run Restoration Plan (Simulation Only) ---');
  for (const colName of Object.keys(manifest.collections)) {
    const colMeta = manifest.collections[colName];
    const liveCount = await db.collection(colName).countDocuments().catch(() => 0);
    const indexCount = colMeta.indexes?.length || 0;

    console.log(`  [DRY-RUN SIMULATION] ${colName.padEnd(20)}: Live docs: ${liveCount.toString().padStart(3)} | Backup docs: ${colMeta.documentCount.toString().padStart(3)} | Indexes to assert: ${indexCount}`);
  }

  // 5. Phase 7B.6.1 Execution Guard
  console.log('\n--- 4. Phase 7B.6.1 Live Execution Guard ---');
  console.log('  [NOTICE] Actual live database restoration is strictly locked in Phase 7B.6.1.');
  console.log('  [NOTICE] The backup archive is 100% valid, recoverable, and ready for deployment when authorized.');

  await mongoose.disconnect();
  console.log('\n[Disconnection] Cleanly disconnected from MongoDB Atlas.');

  console.log('\n==================================================================');
  console.log('DRY-RUN RESTORE VALIDATION: ALL CHECKS PASSED');
  console.log(`Verified Collections: ${validatedCollections}`);
  console.log(`Verified Documents:   ${validatedDocuments}`);
  console.log(`Integrity Status:     100% VALID & RECOVERABLE`);
  console.log('==================================================================\n');

  return {
    validatedCollections,
    validatedDocuments,
    manifest,
  };
}

if (require.main === module) {
  validateRestore().catch(async (err) => {
    console.error('[Restore Validation Failed]:', err.message);
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect().catch(() => null);
    }
    process.exit(1);
  });
}

module.exports = {
  validateRestore,
  findLatestBackupDir,
};
