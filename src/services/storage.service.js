/**
 * Multimedia Storage & Attachment Validation Service
 * Ta'meer-e-Rekhta Management Portal
 * 
 * Provides:
 * 1. MIME type and file extension verification for task submissions & media assets.
 * 2. File size boundary enforcement (videos, screen recordings, voice audio, images, documents).
 * 3. Filename sanitization to protect against directory traversal and malicious payloads.
 * 4. Safe unique filename generation.
 */

const path = require('path');
const crypto = require('crypto');

// Permitted File Type Configurations
const ALLOWED_EXTENSIONS = Object.freeze({
  // Video & Screen Recordings
  video: ['.mp4', '.webm', '.mov'],
  // Audio & Voice Recordings
  audio: ['.mp3', '.wav', '.m4a'],
  // Images
  image: ['.png', '.jpg', '.jpeg', '.webp'],
  // Documents
  document: ['.pdf', '.doc', '.docx'],
});

const ALLOWED_MIME_TYPES = Object.freeze({
  'video/mp4': 'video',
  'video/webm': 'video',
  'video/quicktime': 'video',
  'audio/mpeg': 'audio',
  'audio/mp3': 'audio',
  'audio/wav': 'audio',
  'audio/x-wav': 'audio',
  'audio/mp4': 'audio',
  'audio/x-m4a': 'audio',
  'image/png': 'image',
  'image/jpeg': 'image',
  'image/jpg': 'image',
  'image/webp': 'image',
  'application/pdf': 'document',
  'application/msword': 'document',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'document',
});

// Maximum file size limits in bytes
const SIZE_LIMITS_BYTES = Object.freeze({
  video: 100 * 1024 * 1024,      // 100 MB for video / screen recordings
  audio: 25 * 1024 * 1024,       // 25 MB for voice / audio recordings
  image: 20 * 1024 * 1024,       // 20 MB for high-resolution images
  document: 25 * 1024 * 1024,    // 25 MB for PDF / Office documents
  default: 25 * 1024 * 1024,
});

/**
 * Sanitizes a filename to prevent directory traversal and injection.
 */
function sanitizeFileName(fileName) {
  if (!fileName || typeof fileName !== 'string') {
    return 'unnamed_file';
  }
  // Strip paths and null bytes
  const baseName = path.basename(fileName).replace(/[\x00-\x1f\x80-\x9f]/g, '');
  // Remove special shell characters, preserve alphanumeric, dots, dashes, underscores
  const cleanName = baseName.replace(/[^a-zA-Z0-9._-]/g, '_');
  return cleanName || 'unnamed_file';
}

/**
 * Generates a cryptographically random, collision-resistant filename.
 */
function generateSafeUniqueName(originalName) {
  const clean = sanitizeFileName(originalName);
  const ext = path.extname(clean).toLowerCase();
  const base = path.basename(clean, ext);
  const randomSuffix = crypto.randomBytes(8).toString('hex');
  return `${Date.now()}_${randomSuffix}_${base}${ext}`;
}

/**
 * Determines file category ('video', 'audio', 'image', 'document') from extension or MIME type.
 */
function detectFileCategory(fileName, mimeType) {
  if (mimeType && ALLOWED_MIME_TYPES[mimeType.toLowerCase()]) {
    return ALLOWED_MIME_TYPES[mimeType.toLowerCase()];
  }
  if (fileName) {
    const ext = path.extname(fileName).toLowerCase();
    for (const [category, extensions] of Object.entries(ALLOWED_EXTENSIONS)) {
      if (extensions.includes(ext)) {
        return category;
      }
    }
  }
  return null;
}

/**
 * Validates metadata for an uploaded multimedia deliverable or media asset.
 * 
 * @param {Object} metadata { fileName, fileSize, mimeType, fileUrl }
 * @returns {Object} { valid: boolean, error?: string, sanitizedFileName?: string, category?: string }
 */
function validateAttachmentMetadata(metadata = {}) {
  const { fileName, mimeType } = metadata;
  const fileSize = metadata.fileSize !== undefined ? metadata.fileSize : metadata.size;

  if (!fileName || typeof fileName !== 'string') {
    return { valid: false, error: 'Attachment filename is required.' };
  }

  const cleanName = sanitizeFileName(fileName);
  const ext = path.extname(cleanName).toLowerCase();
  const category = detectFileCategory(cleanName, mimeType);

  if (!category) {
    const allExts = Object.values(ALLOWED_EXTENSIONS).flat().join(', ');
    return {
      valid: false,
      error: `Unsupported file extension or format '${ext || 'unknown'}'. Permitted formats: ${allExts}.`,
    };
  }

  // Size limit validation
  if (fileSize !== undefined && typeof fileSize === 'number') {
    const maxAllowed = SIZE_LIMITS_BYTES[category] || SIZE_LIMITS_BYTES.default;
    if (fileSize <= 0) {
      return { valid: false, error: 'File size must be greater than 0 bytes.' };
    }
    if (fileSize > maxAllowed) {
      const maxMb = Math.round(maxAllowed / (1024 * 1024));
      return {
        valid: false,
        error: `File size exceeds the permitted limit for ${category} (${maxMb}MB / ${maxMb} MB maximum).`,
      };
    }
  }

  return {
    valid: true,
    category,
    sanitizedFileName: cleanName,
    safeStorageName: generateSafeUniqueName(cleanName),
  };
}

module.exports = {
  ALLOWED_EXTENSIONS,
  ALLOWED_MIME_TYPES,
  SIZE_LIMITS_BYTES,
  SIZE_LIMITS: SIZE_LIMITS_BYTES,
  sanitizeFileName,
  generateSafeUniqueName,
  generateSafeFileName: generateSafeUniqueName,
  detectFileCategory,
  validateAttachmentMetadata,
};
