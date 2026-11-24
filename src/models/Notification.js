const mongoose = require('mongoose');

const NotificationSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.Mixed, ref: 'User', required: true, index: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    type: {
      type: String,
      enum: ['info', 'success', 'warning', 'urgent', 'announcement'],
      default: 'info',
    },
    read: { type: Boolean, default: false, index: true },
    link: { type: String },
    category: {
      type: String,
      enum: ['task', 'leave', 'finance', 'recruitment', 'announcement', 'general'],
      default: 'general',
      index: true,
    },
    dedupKey: { type: String, index: true },
  },
  { timestamps: true }
);

// Enforce compound uniqueness for non-empty deduplication keys per user
NotificationSchema.index(
  { userId: 1, dedupKey: 1 },
  {
    unique: true,
    partialFilterExpression: {
      dedupKey: { $type: 'string', $gt: '' },
    },
  }
);

module.exports = mongoose.models.Notification || mongoose.model('Notification', NotificationSchema);
