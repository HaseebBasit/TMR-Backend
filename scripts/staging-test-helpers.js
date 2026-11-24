/**
 * Phase 7B.6.4D.2.1 — Staging E2E Test Helper Utilities
 * 
 * Target: tameer_rekhta_staging ONLY
 * Mode: Staging Test Suite Support
 */

const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

// Load staging configuration
const stagingEnvPath = path.join(__dirname, '..', '.env.staging');
const stagingEnv = dotenv.config({ path: stagingEnvPath, override: true }).parsed;

const {
  validateDatabaseTarget,
  parseMongoUri,
  STAGING_DB_NAME,
  PRODUCTION_DB_NAME,
} = require('../src/config/db');

/**
 * Asserts that the runtime environment is strictly staging.
 * Throws fatal exception if production or non-staging is detected.
 */
function assertStagingEnvironment() {
  if (process.env.NODE_ENV !== 'staging' && stagingEnv.NODE_ENV !== 'staging') {
    throw new Error(`[FATAL ISOLATION EXCEPTION]: Attempted test execution in non-staging environment: ${process.env.NODE_ENV || stagingEnv.NODE_ENV}`);
  }

  const uri = process.env.MONGODB_URI || stagingEnv.MONGODB_URI;
  const parsed = parseMongoUri(uri);
  if (!parsed.valid || parsed.dbName !== STAGING_DB_NAME) {
    throw new Error(`[FATAL ISOLATION EXCEPTION]: Target DB is '${parsed.dbName}'. Expected '${STAGING_DB_NAME}'.`);
  }

  // Active rejection check of production database
  validateDatabaseTarget(uri, { NODE_ENV: 'staging' });

  return {
    isStaging: true,
    dbName: parsed.dbName,
    port: process.env.PORT || stagingEnv.PORT || 5001,
  };
}

/**
 * Loads the active test run credentials securely from local gitignored store.
 */
function loadLocalTestCredentials() {
  assertStagingEnvironment();
  const credentialsPath = path.join(__dirname, '..', '.env.staging.credentials.local.json');
  if (!fs.existsSync(credentialsPath)) {
    throw new Error(`[CREDENTIAL ERROR]: Local test credentials file not found: ${credentialsPath}. Run provision-staging-personas.js first.`);
  }

  try {
    const raw = fs.readFileSync(credentialsPath, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.testRunId || !parsed.personas) {
      throw new Error('Malformed test credentials JSON structure.');
    }
    return parsed;
  } catch (err) {
    throw new Error(`[CREDENTIAL PARSE ERROR]: ${err.message}`);
  }
}

module.exports = {
  assertStagingEnvironment,
  loadLocalTestCredentials,
  STAGING_DB_NAME,
  PRODUCTION_DB_NAME,
};
