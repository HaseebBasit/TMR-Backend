/**
 * Phase 7B.6.2 — Cryptographic Secret Generation & Verification Utility
 * 
 * Generates cryptographically secure, independent, high-entropy secrets (256-bit / 64-char hex)
 * suitable for production JWT_SECRET and JWT_REFRESH_SECRET.
 * 
 * Usage:
 *   node scripts/generate-secrets.js            # Generate new pair of independent production secrets
 *   node scripts/generate-secrets.js --verify   # Audit current environment secrets without leaking values
 */

const crypto = require('crypto');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const { validateProductionSecrets, MIN_SECRET_LENGTH } = require('../src/config/secrets');

function generateSecureSecret(byteLength = 32) {
  return crypto.randomBytes(byteLength).toString('hex');
}

function runSecretUtility() {
  const args = process.argv.slice(2);

  if (args.includes('--verify')) {
    console.log('==================================================================');
    console.log('PRODUCTION JWT SECRET VERIFICATION AUDIT');
    console.log('==================================================================\n');

    try {
      const testEnv = {
        NODE_ENV: 'production',
        JWT_SECRET: process.env.JWT_SECRET,
        JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
      };

      validateProductionSecrets(testEnv);

      console.log('  [PASS] JWT_SECRET: Present, high-entropy (>= 32 chars), non-default.');
      console.log('  [PASS] JWT_REFRESH_SECRET: Present, high-entropy (>= 32 chars), non-default.');
      console.log('  [PASS] Distinctness: Access and Refresh secrets are strictly distinct.');
      console.log('\n[Result] Current environment secrets meet all production invariants.\n');
      process.exit(0);
    } catch (err) {
      console.error(`  [FAIL] Production Secret Audit Failed: ${err.message}`);
      console.error('\n[Action Required] Generate new secrets using: node scripts/generate-secrets.js\n');
      process.exit(1);
    }
  }

  // Generate new secret pair
  const accessSecret = generateSecureSecret(32); // 64 hex characters
  const refreshSecret = generateSecureSecret(32); // 64 hex characters

  console.log('==================================================================');
  console.log('SECURE PRODUCTION JWT SECRET GENERATOR');
  console.log('==================================================================\n');
  console.log('Generated two independent 256-bit cryptographic secrets:');
  console.log('Length: 64 hex characters each (meets >= 32 char policy requirement).\n');

  console.log('Copy the following into your private backend/.env or hosting secret manager:');
  console.log('------------------------------------------------------------------');
  console.log(`JWT_SECRET=${accessSecret}`);
  console.log(`JWT_REFRESH_SECRET=${refreshSecret}`);
  console.log('------------------------------------------------------------------\n');
  console.log('[SECURITY REMINDER]:');
  console.log('- Do not commit these values to Git.');
  console.log('- Do not share these values in public chat or unencrypted communications.');
  console.log('- In production, inject them as environment variables on your hosting provider.');
  console.log('==================================================================\n');
}

if (require.main === module) {
  runSecretUtility();
}

module.exports = {
  generateSecureSecret,
};
