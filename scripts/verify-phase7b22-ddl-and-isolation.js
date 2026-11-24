/**
 * Verification script for Phase 7B.2.2:
 * 1. Automatic DDL Prevention (autoIndex and autoCreate disabled globally)
 * 2. Test Environment Isolation (No Atlas connection in test mode unless TEST_USE_LIVE_DB=true)
 */

process.env.NODE_ENV = 'test';
delete process.env.TEST_USE_LIVE_DB;

const mongoose = require('mongoose');
const { connectDB, getConnectionStatus } = require('../src/config/db');
const models = require('../src/models');
const app = require('../src/server');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${message}`);
    failed++;
  }
}

async function runVerification() {
  console.log('==================================================================');
  console.log('PHASE 7B.2.2: AUTOMATIC DDL PREVENTION & TEST ISOLATION VERIFICATION');
  console.log('==================================================================\n');

  // Check 1: Mongoose global autoIndex setting
  assert(mongoose.get('autoIndex') === false, 'Check 1: mongoose.get("autoIndex") is strictly false');

  // Check 2: Mongoose global autoCreate setting
  assert(mongoose.get('autoCreate') === false, 'Check 2: mongoose.get("autoCreate") is strictly false');

  // Check 3: Schema options on registered models
  const modelNames = Object.keys(models);
  assert(modelNames.length === 16, `Check 3: All 16 models loaded (${modelNames.length} models)`);

  // Check 4: Server startup in test mode does NOT connect to Atlas
  assert(mongoose.connection.readyState === 0, 'Check 4: Mongoose connection readyState is 0 (Disconnected) after loading server');

  // Check 5: Direct connectDB() call in test mode is blocked and returns null
  const connResult = await connectDB();
  assert(connResult === null, 'Check 5: connectDB() in test mode without TEST_USE_LIVE_DB returns null');
  assert(mongoose.connection.readyState === 0, 'Check 5b: Mongoose connection readyState remains 0 (Disconnected) after connectDB() call');

  // Check 6: getConnectionStatus() reports offline_controlled_mode
  const status = getConnectionStatus();
  assert(status.isConnected === false, 'Check 6: status.isConnected is strictly false');
  assert(status.mode === 'offline_controlled_mode', `Check 6b: status.mode is offline_controlled_mode (got: ${status.mode})`);

  console.log('\n==================================================================');
  console.log(`VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log('==================================================================');

  process.exit(failed > 0 ? 1 : 0);
}

runVerification();
