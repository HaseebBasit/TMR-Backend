const mongoose = require('mongoose');
const { validateRoleDesignation, normalizeDesignation } = require('../constants/roles');

const MembershipSchema = new mongoose.Schema(
  {
    department: { type: String, required: true, trim: true },
    departmentCode: { type: String, required: true, trim: true, uppercase: true },
    departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
    role: {
      type: String,
      required: true,
      trim: true,
    },
    designation: { type: String, trim: true, default: null },
    region: {
      type: String,
      enum: ['Punjab', 'Sindh', 'National', null],
      default: null,
    },
    isPrimary: { type: Boolean, default: false },
  },
  { _id: false }
);

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
    emailAliases: [{ type: String, lowercase: true, trim: true, index: true }],
    city: { type: String, trim: true, default: null },
    region: {
      type: String,
      enum: ['Punjab', 'Sindh', 'National', null],
      default: null,
    },
    password: {
      type: String,
      required: function () {
        return this.status === 'active';
      },
    },
    role: {
      type: String,
      enum: [
        'super_admin',
        'dept_literature',
        'dept_media',
        'dept_marketing',
        'dept_outreach',
        'dept_oam',
        'dept_content',
        'dept_welfare',
        'hr',
        'finance',
        'member',
      ],
      default: 'member',
      index: true,
    },
    department: {
      type: String,
      enum: [
        'Literature',
        'Media',
        'Marketing',
        'Outreach',
        'Outreach and Marketing',
        'Content Creation',
        'HR',
        'Finance',
        'Welfare',
        null,
      ],
      default: null,
    },
    departmentCode: {
      type: String,
      enum: ['LIT', 'MED', 'MKT', 'OUT', 'OAM', 'CON', 'HR', 'FIN', 'WEL', null],
      default: null,
    },
    departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
    memberships: [MembershipSchema],
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
    activationToken: { type: String, index: true },
    activationExpires: { type: Date },
    activationGeneratedAt: { type: Date },
    activationRevokedAt: { type: Date },
    lastLogin: { type: Date },
  },
  { timestamps: true }
);

module.exports = mongoose.models.User || mongoose.model('User', UserSchema);
