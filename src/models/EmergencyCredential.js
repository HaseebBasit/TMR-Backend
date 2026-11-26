const mongoose = require('mongoose');
const { encryptAtRest, decryptAtRest } = require('../services/encryption.service');

const EmergencyCredentialSchema = new mongoose.Schema(
  {
    keyId: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      default: 'EMERGENCY-OPERATOR-KEY-01',
    },
    keyHash: {
      type: String,
      required: true,
    },
    operatorEmail: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      default: 'emergency-operator@system.rekhta.org',
    },
    operatorName: {
      type: String,
      required: true,
      trim: true,
      default: 'Authorized Emergency Operator',
    },
    mfaSecret: {
      type: String,
      required: true,
      // Stored encrypted at rest using AES-256-GCM
    },
    mfaRecoveryCodes: [{ type: String }],
    status: {
      type: String,
      enum: ['active', 'revoked', 'suspended'],
      default: 'active',
      index: true,
    },
    revokedAt: { type: Date },
    revokedReason: { type: String, trim: true },
    revokedBy: { type: String, trim: true },
    lastUsedAt: { type: Date },
    usageCount: { type: Number, default: 0 },
    failedAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
  },
  { timestamps: true }
);

EmergencyCredentialSchema.methods.getDecryptedMfaSecret = function () {
  return decryptAtRest(this.mfaSecret);
};

EmergencyCredentialSchema.statics.encryptSecret = encryptAtRest;
EmergencyCredentialSchema.statics.decryptSecret = decryptAtRest;

// In-memory fallback for test isolation and offline resilience
let memoryEmergencyCredential = null;

function setMemoryEmergencyCredential(cred) {
  memoryEmergencyCredential = cred ? { ...cred } : null;
}

function getMemoryEmergencyCredential() {
  return memoryEmergencyCredential;
}

const EmergencyCredential =
  mongoose.models.EmergencyCredential ||
  mongoose.model('EmergencyCredential', EmergencyCredentialSchema);

EmergencyCredential.setMemoryEmergencyCredential = setMemoryEmergencyCredential;
EmergencyCredential.getMemoryEmergencyCredential = getMemoryEmergencyCredential;
EmergencyCredential.encryptSecret = encryptAtRest;
EmergencyCredential.decryptSecret = decryptAtRest;

module.exports = EmergencyCredential;
