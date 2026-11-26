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
 * Derive a 256-bit key from EMERGENCY_ENCRYPTION_KEY or validated JWT_SECRET.
 */
function getEncryptionKey() {
  const customKey = process.env.EMERGENCY_ENCRYPTION_KEY;
  if (customKey && typeof customKey === 'string' && customKey.trim().length >= 32) {
    return crypto.createHash('sha256').update(customKey.trim()).digest();
  }

  const validated = validateProductionSecrets();
  const sourceSecret = validated.accessSecret || 'rekhta_default_encryption_source_secret_2026';
  // Salt-hardened SHA-256 derivation to isolate encryption key from token signing
  return crypto.createHash('sha256').update(`rekhta_at_rest_encryption_salt_2026:${sourceSecret}`).digest();
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

  const decipher = crypto.createDecipheriv(ALGORITHM, getEncryptionKey(), iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

module.exports = {
  encryptAtRest,
  decryptAtRest,
  getEncryptionKey,
  PREFIX,
};
