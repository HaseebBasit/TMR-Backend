const mongoose = require('mongoose');

const AnnouncementSchema = new mongoose.Schema(
  {
    announcementId: { type: String, unique: true, required: true },
    title: { type: String, required: true, trim: true },
    message: { type: String, required: true, trim: true },
    targetDepartment: {
      type: String,
      required: true,
      enum: ['Literature', 'Media', 'Marketing', 'Outreach', 'Content Creation', 'HR', 'Finance'],
      index: true,
    },
    targetDepartmentCode: { type: String, trim: true },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    senderName: { type: String, required: true },
    senderRole: { type: String, required: true },
    senderDesignation: { type: String, required: true, default: 'hr_coordination_incharge' },
    recipientCount: { type: Number, default: 0 },
    readBy: [
      {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        userName: { type: String },
        readAt: { type: Date, default: Date.now },
      },
    ],
    status: {
      type: String,
      enum: ['sent', 'archived'],
      default: 'sent',
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Announcement || mongoose.model('Announcement', AnnouncementSchema);
