const mongoose = require('mongoose');
const { validateRoleDesignation, normalizeDesignation } = require('../constants/roles');

const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: [
        'super_admin',
        'dept_literature',
        'dept_media',
        'dept_marketing',
        'dept_outreach',
        'dept_content',
        'hr',
        'finance',
        'member',
      ],
      default: 'member',
      index: true,
    },
    department: {
      type: String,
      enum: ['Literature', 'Media', 'Marketing', 'Outreach', 'Content Creation', 'HR', 'Finance', null],
      default: null,
    },
    departmentCode: {
      type: String,
      enum: ['LIT', 'MED', 'MKT', 'OUT', 'CON', 'HR', 'FIN', null],
      default: null,
    },
    departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
    status: {
      type: String,
      enum: ['active', 'inactive', 'suspended'],
      default: 'active',
      index: true,
    },
    isPrivilegedHR: {
      type: Boolean,
      default: false,
    },
    isTester: {
      type: Boolean,
      default: false,
      index: true,
    },
    isModerator: {
      type: Boolean,
      default: false,
      index: true,
    },
    capabilities: [{ type: String, trim: true }],
    phoneNumber: { type: String, trim: true },
    designation: {
      type: String,
      trim: true,
      default: null,
      validate: {
        validator: function (v) {
          if (!v) return true; // Legacy backward-compatibility: null/empty allowed without granting elevated privilege
          const { valid } = validateRoleDesignation(this.role || 'member', v);
          return valid;
        },
        message: function (props) {
          return `Invalid designation '${props.value}' for role '${this.role}'.`;
        },
      },
    },
    avatarUrl: { type: String },
    tokenVersion: { type: Number, default: 0 },
    refreshToken: { type: String },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    activationToken: { type: String },
    activationExpires: { type: Date },
    lastLogin: { type: Date },
  },
  { timestamps: true }
);

module.exports = mongoose.models.User || mongoose.model('User', UserSchema);
