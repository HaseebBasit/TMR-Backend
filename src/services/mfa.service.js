/**
 * Multi-Factor Authentication (MFA) & TOTP Service
 * RFC 6238 Time-Based One-Time Password Implementation
 * 
 * Built exclusively using Node.js built-in `crypto` module (zero third-party dependencies).
 * Fully compatible with Google Authenticator, Microsoft Authenticator, Authy, and 1Password.
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encodes a buffer into standard RFC 4648 Base32 string (unpadded)
 */
function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * Decodes a Base32 string back to Buffer
 */
function base32Decode(input) {
  if (!input || typeof input !== 'string') return Buffer.alloc(0);
  const cleaned = input.toUpperCase().replace(/=+$/, '').replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/**
 * Generates a new cryptographically secure 20-byte (160-bit) Base32 secret
 */
function generateSecret() {
  const buffer = crypto.randomBytes(20);
  return base32Encode(buffer);
}

/**
 * Generates 6-digit TOTP code for a given secret and timestamp
 */
function generateTotp(secret, time = Date.now(), step = 30) {
  const key = base32Decode(secret);
  const counter = Math.floor(time / 1000 / step);
  const buffer = Buffer.alloc(8);
  buffer.writeBigInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = code % 1000000;
  return otp.toString().padStart(6, '0');
}

/**
 * Verifies a 6-digit TOTP code against a secret within a tolerance window (default +/- 1 step = 30s)
 */
function verifyTotp(inputCode, secret, window = 1) {
  if (!inputCode || typeof inputCode !== 'string') return false;
  const trimmed = inputCode.trim();
  if (trimmed.length !== 6 || !/^\d{6}$/.test(trimmed)) return false;

  const now = Date.now();
  for (let error = -window; error <= window; error++) {
    const time = now + error * 30 * 1000;
    if (generateTotp(secret, time) === trimmed) {
      return true;
    }
  }
  return false;
}

/**
 * Formats standard otpauth:// URI for QR code generation
 */
function generateOtpAuthUri({ secret, email, issuer = "Ta'meer-e-Rekhta" }) {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedEmail = encodeURIComponent(email);
  return `otpauth://totp/${encodedIssuer}:${encodedEmail}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}

/**
 * Generates N cryptographically random recovery codes (e.g. "A1B2-C3D4")
 */
function generateRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const p1 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const p2 = crypto.randomBytes(2).toString('hex').toUpperCase();
    codes.push(`${p1}-${p2}`);
  }
  return codes;
}

/**
 * Hashes a recovery code for database storage
 */
async function hashRecoveryCode(code) {
  const normalized = code.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  return bcrypt.hash(normalized, 10);
}

/**
 * Checks if input recovery code matches any hashed recovery code
 * Returns matching index or -1
 */
async function findMatchingRecoveryCode(inputCode, hashedCodes) {
  if (!inputCode || !Array.isArray(hashedCodes)) return -1;
  const normalized = inputCode.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  for (let i = 0; i < hashedCodes.length; i++) {
    const match = await bcrypt.compare(normalized, hashedCodes[i]);
    if (match) return i;
  }
  return -1;
}

module.exports = {
  base32Encode,
  base32Decode,
  generateSecret,
  generateTotp,
  verifyTotp,
  generateOtpAuthUri,
  generateRecoveryCodes,
  hashRecoveryCode,
  findMatchingRecoveryCode,
};
