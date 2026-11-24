const mongoose = require('mongoose');

// Global DDL Safety & Connection Hardening:
// Prevent automatic index and collection creation across all connections and models
mongoose.set('autoIndex', false);
mongoose.set('autoCreate', false);
// Disable command buffering when disconnected so operations fail fast instead of hanging
mongoose.set('bufferCommands', false);

const PRODUCTION_DB_NAME = 'tameer_rekhta';
const STAGING_DB_NAME = 'tameer_rekhta_staging';

let isConnected = false;
let databaseMode = 'offline_controlled_mode';

/**
 * Sanitizes a MongoDB connection URI to prevent credential leakage in logs.
 */
const sanitizeUri = (uri) => {
  if (!uri || typeof uri !== 'string') return '';
  return uri.replace(/\/\/[^@]+@/, '//***:***@');
};

/**
 * Robustly parses a MongoDB connection URI to extract the scheme, database name, and query options.
 * Does not rely on fragile substring matching.
 * 
 * Supported formats:
 * - mongodb://[user:pass@]host1[:port1][,...hostN[:portN]][/[database][?options]]
 * - mongodb+srv://[user:pass@]host[/[database][?options]]
 */
function parseMongoUri(uri) {
  if (!uri || typeof uri !== 'string' || uri.trim() === '') {
    return {
      valid: false,
      error: 'URI is empty or not a string.',
      scheme: null,
      dbName: null,
      hasExplicitDb: false,
    };
  }

  const trimmed = uri.trim();
  const schemeMatch = trimmed.match(/^mongodb(\+srv)?:\/\//i);
  if (!schemeMatch) {
    return {
      valid: false,
      error: 'Invalid connection scheme. Must begin with mongodb:// or mongodb+srv://',
      scheme: null,
      dbName: null,
      hasExplicitDb: false,
    };
  }

  const scheme = schemeMatch[0].toLowerCase();
  const withoutScheme = trimmed.slice(schemeMatch[0].length);

  // Split hosts from path and query string at the first '/'
  const slashIndex = withoutScheme.indexOf('/');
  const authorityAndHosts = slashIndex === -1 ? withoutScheme : withoutScheme.slice(0, slashIndex);

  // Check for multiple unencoded '@' characters in authority/host segment
  const atMatches = authorityAndHosts.match(/@/g);
  if (atMatches && atMatches.length > 1) {
    return {
      valid: false,
      error: 'Malformed URI: multiple unencoded "@" characters detected in userinfo/host segment. Special characters in passwords (such as "@") must be percent-encoded as "%40".',
      scheme,
      dbName: null,
      hasExplicitDb: false,
    };
  }

  if (slashIndex === -1) {
    return {
      valid: true,
      scheme,
      dbName: null,
      hasExplicitDb: false,
      query: '',
    };
  }

  const pathAndQuery = withoutScheme.slice(slashIndex + 1);
  const questionIndex = pathAndQuery.indexOf('?');

  const rawPath = questionIndex === -1 ? pathAndQuery : pathAndQuery.slice(0, questionIndex);
  const rawQuery = questionIndex === -1 ? '' : pathAndQuery.slice(questionIndex + 1);

  let decodedDb = '';
  try {
    decodedDb = decodeURIComponent(rawPath.trim());
  } catch {
    return {
      valid: false,
      error: 'Malformed URL encoding in database name path.',
      scheme,
      dbName: null,
      hasExplicitDb: false,
    };
  }

  // Database names cannot contain slashes or backslashes
  if (decodedDb.includes('/') || decodedDb.includes('\\')) {
    return {
      valid: false,
      error: 'Malformed database name: path contains invalid slash characters.',
      scheme,
      dbName: null,
      hasExplicitDb: false,
    };
  }

  const hasExplicitDb = decodedDb.length > 0;
  return {
    valid: true,
    scheme,
    dbName: hasExplicitDb ? decodedDb : null,
    hasExplicitDb,
    query: rawQuery,
  };
}

/**
 * Validates the target database against production and staging isolation policies.
 * Throws fatal security / isolation exceptions if invariants are violated.
 */
function validateDatabaseTarget(uri, env = process.env) {
  const nodeEnv = (env.NODE_ENV || 'development').toLowerCase().trim();
  const isProduction = nodeEnv === 'production';
  const isStaging = nodeEnv === 'staging';
  const isTest = nodeEnv === 'test';
  const testUseLiveDb = env.TEST_USE_LIVE_DB === 'true';

  const parsed = parseMongoUri(uri);
  if (!parsed.valid) {
    const sanitizedMsg = sanitizeUri(uri);
    throw new Error(`[CRITICAL DATABASE ERROR] Invalid MONGODB_URI: ${parsed.error} (URI: ${sanitizedMsg})`);
  }

  const targetDb = parsed.dbName;

  // 1. ISOLATION GUARD: Staging or Test Mode MUST NEVER target the production database
  if (isStaging || isTest) {
    if (targetDb === PRODUCTION_DB_NAME) {
      const sanitized = sanitizeUri(uri);
      const fatalMsg = `[FATAL ISOLATION EXCEPTION]: Connection to production database "${PRODUCTION_DB_NAME}" is strictly forbidden in ${nodeEnv.toUpperCase()} environment! Execution immediately aborted. (Target: ${sanitized})`;
      console.error(fatalMsg);
      throw new Error(fatalMsg);
    }
  }

  // 2. STAGING INTEGRITY GUARD: Staging MUST explicitly target "tameer_rekhta_staging"
  if (isStaging) {
    if (!parsed.hasExplicitDb || targetDb !== STAGING_DB_NAME) {
      const fatalMsg = `[FATAL ISOLATION EXCEPTION]: Staging environment requires database name to be exactly "${STAGING_DB_NAME}". Provided target: "${targetDb || 'MISSING'}".`;
      console.error(fatalMsg);
      throw new Error(fatalMsg);
    }
  }

  // 3. PRODUCTION INTEGRITY GUARD: Production MUST explicitly target "tameer_rekhta"
  if (isProduction) {
    if (!parsed.hasExplicitDb || targetDb !== PRODUCTION_DB_NAME) {
      const fatalMsg = `[CRITICAL DATABASE ERROR]: Production environment requires database name to be exactly "${PRODUCTION_DB_NAME}". Provided target: "${targetDb || 'MISSING'}".`;
      console.error(fatalMsg);
      throw new Error(fatalMsg);
    }
  }

  // 4. TEST LIVE OVERRIDE GUARD: When running live DB in test mode, protect against unintended DBs
  if (isTest && testUseLiveDb) {
    if (targetDb !== STAGING_DB_NAME && targetDb !== 'tameer_rekhta_test') {
      const fatalMsg = `[FATAL ISOLATION EXCEPTION]: TEST_USE_LIVE_DB=true is permitted ONLY for isolated test/staging databases ("${STAGING_DB_NAME}" or "tameer_rekhta_test"). Provided: "${targetDb || 'MISSING'}".`;
      console.error(fatalMsg);
      throw new Error(fatalMsg);
    }
  }

  return {
    valid: true,
    dbName: targetDb,
    environment: nodeEnv,
    scheme: parsed.scheme,
  };
}

const getConnectionStatus = () => {
  const states = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  const currentState = states[mongoose.connection.readyState] || 'unknown';

  return {
    isConnected: mongoose.connection.readyState === 1,
    readyState: mongoose.connection.readyState,
    state: currentState,
    mode: databaseMode,
    host: mongoose.connection.host || null,
    dbName: mongoose.connection.name || null,
  };
};

/**
 * Close active Mongoose connection cleanly during graceful shutdown or tests.
 */
const closeDB = async (force = false) => {
  if (mongoose.connection.readyState !== 0) {
    try {
      await mongoose.connection.close(force);
      isConnected = false;
      databaseMode = 'disconnected';
    } catch (err) {
      console.error('[Backend DB Error] Error during connection close:', err.message);
      throw err;
    }
  }
};

const connectDB = async () => {
  const uri = process.env.MONGODB_URI;
  const isProduction = process.env.NODE_ENV === 'production';
  const isStaging = process.env.NODE_ENV === 'staging';
  const isTest = process.env.NODE_ENV === 'test';
  const useLiveDBInTest = process.env.TEST_USE_LIVE_DB === 'true';

  // 1. Test Isolation Guard: Block live database connection during test mode unless TEST_USE_LIVE_DB === 'true'
  if (isTest && !useLiveDBInTest) {
    databaseMode = 'offline_controlled_mode';
    mongoose.set('bufferCommands', false);
    console.log('[Backend DB] Test environment isolated: live database connection blocked by default (offline_controlled_mode).');
    return null;
  }

  // 2. Missing URI Check
  if (!uri || uri.trim() === '') {
    if (isProduction || isStaging) {
      databaseMode = isProduction ? 'production_misconfigured' : 'staging_misconfigured';
      const fatalMsg = `[CRITICAL DATABASE ERROR] MONGODB_URI is required in ${process.env.NODE_ENV} environment. Application refusing to start in unsafe in-memory mode.`;
      console.error(fatalMsg);
      throw new Error(fatalMsg);
    }

    databaseMode = 'offline_controlled_mode';
    mongoose.set('bufferCommands', false);
    console.log(
      '------------------------------------------------------------------\n' +
      '[Backend DB Notice] MONGODB_URI is not configured in .env.\n' +
      'Application is starting in CONTROLLED CONFIGURATION-CHECK MODE.\n' +
      'All public endpoints, health checks, and server services remain active.\n' +
      'To connect MongoDB Atlas, set MONGODB_URI in backend/.env.\n' +
      '------------------------------------------------------------------'
    );
    return null;
  }

  // 3. Enforce Strict Database Isolation & Scheme Validation
  validateDatabaseTarget(uri, process.env);

  // 4. Attempt Connection (with autoIndex and autoCreate strictly disabled)
  try {
    const conn = await mongoose.connect(uri, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      autoIndex: false,
      autoCreate: false,
    });

    isConnected = true;
    databaseMode = 'online';
    console.log(`[Backend DB] MongoDB Connected: ${conn.connection.host} / ${conn.connection.name}`);
    return conn;
  } catch (err) {
    isConnected = false;
    if (isProduction || isStaging) {
      databaseMode = isProduction ? 'production_connection_failed' : 'staging_connection_failed';
      const fatalErr = `[CRITICAL DATABASE ERROR] ${process.env.NODE_ENV.toUpperCase()} MongoDB Connection Failed: ${err.message}`;
      console.error(fatalErr);
      throw new Error(fatalErr);
    }

    databaseMode = 'offline_connection_failed';
    console.error(`[Backend DB Error] MongoDB Connection Failed: ${err.message}`);
    console.warn('[Backend DB Notice] Operating in controlled fallback mode. Verify credentials and network access in Atlas.');
    return null;
  }
};

// Mongoose Connection Event Listeners
mongoose.connection.on('disconnected', () => {
  isConnected = false;
  console.warn('[Backend DB] Mongoose connection disconnected.');
});

mongoose.connection.on('reconnected', () => {
  isConnected = true;
  databaseMode = 'online';
  console.log('[Backend DB] Mongoose connection re-established.');
});

mongoose.connection.on('error', (err) => {
  console.error('[Backend DB Event Error]:', err.message);
});

module.exports = {
  connectDB,
  getConnectionStatus,
  closeDB,
  sanitizeUri,
  parseMongoUri,
  validateDatabaseTarget,
  PRODUCTION_DB_NAME,
  STAGING_DB_NAME,
};
