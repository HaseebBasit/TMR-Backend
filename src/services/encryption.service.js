/**
 * Phase 10M.R — Production Encryption at Rest Service
 * 
 * Provides authenticated, tamper-evident symmetric encryption for sensitive secrets at rest
 * using AES-256-GCM with distinct initialization vectors (IV) and authentication tags.
 */

const crypto = require('crypto');
const { validateProductionSecrets } = require('../config/secrets');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits for AES-GCM
const PREFIX = 'enc:v1:';

/**
 * Derives ordered candidate keys for encryption and decryption.
 * Primary: Dedicated EMERGENCY_ENCRYPTION_KEY or production MONGODB_URI.
 * Secondary: Validated access secret fallback (for testing and staging environments).
 */
function getCandidateKeys() {
  const keys = [];

  // 1. Explicit production emergency encryption key
  const customKey = process.env.EMERGENCY_ENCRYPTION_KEY || process.env.DATABASE_ENCRYPTION_KEY;
  if (customKey && typeof customKey === 'string' && customKey.trim().length >= 16) {
    keys.push(crypto.createHash('sha256').update(customKey.trim()).digest());
  }

  // 2. Production infrastructure credential key (shared securely across Render and provisioning scripts)
  const infraSecret = process.env.MONGODB_URI;
  if (infraSecret && typeof infraSecret === 'string' && infraSecret.length >= 20) {
    keys.push(crypto.createHash('sha256').update(`rekhta_at_rest_encryption_salt_2026:${infraSecret}`).digest());
  }

  // 3. Environment access secret fallback (for test isolation and staging)
  const validated = validateProductionSecrets();
  const sourceSecret = validated.accessSecret || 'rekhta_default_encryption_source_secret_2026';
  keys.push(crypto.createHash('sha256').update(`rekhta_at_rest_encryption_salt_2026:${sourceSecret}`).digest());

  return keys;
}

/**
 * Get primary 256-bit encryption key.
 */
function getEncryptionKey() {
  const candidates = getCandidateKeys();
  return candidates[0];
}

/**
 * Encrypt plaintext string at rest using AES-256-GCM.
 * Format: enc:v1:<iv_hex>:<auth_tag_hex>:<ciphertext_hex>
 */
function encryptAtRest(plaintext) {
  if (!plaintext || typeof plaintext !== 'string') {
    return plaintext;
  }

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getEncryptionKey(), iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');
  return `${PREFIX}${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypt ciphertext string at rest using AES-256-GCM.
 * Iterates through candidate keys with tamper-evident authentication tag verification.
 */
function decryptAtRest(cipherPayload) {
  if (!cipherPayload || typeof cipherPayload !== 'string') {
    return cipherPayload;
  }

  // If not encrypted with enc:v1 prefix, return as-is (backward-compatible fallback)
  if (!cipherPayload.startsWith(PREFIX)) {
    return cipherPayload;
  }

  const raw = cipherPayload.slice(PREFIX.length);
  const parts = raw.split(':');
  if (parts.length !== 3) {
    throw new Error('[EncryptionService] Malformed encrypted payload structure.');
  }

  const [ivHex, tagHex, encryptedHex] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(tagHex, 'hex');

  const candidates = getCandidateKeys();
  let lastErr = null;

  for (const key of candidates) {
    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);
      let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (err) {
      lastErr = err;
    }
  }

  throw new Error(`[EncryptionService] Decryption failed across candidate keys: ${lastErr?.message}`);
}

module.exports = {
  encryptAtRest,
  decryptAtRest,
  getEncryptionKey,
  getCandidateKeys,
  PREFIX,
};
