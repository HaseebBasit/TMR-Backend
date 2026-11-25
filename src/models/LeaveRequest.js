const mongoose = require('mongoose');

const LeaveRequestSchema = new mongoose.Schema(
  {
    memberId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    memberName: { type: String, required: true },
    memberEmail: { type: String, required: true },
    department: {
      type: String,
      required: true,
      enum: [
        'Literature',
        'Media',
        'Marketing',
        'Outreach',
        'Outreach and Marketing',
        'Content Creation',
        'Welfare',
        'HR',
        'Finance',
      ],
    },
    departmentCode: {
      type: String,
      enum: ['LIT', 'MED', 'MKT', 'OUT', 'OAM', 'CON', 'WEL', 'HR', 'FIN'],
    },
    region: {
      type: String,
      enum: ['Punjab', 'Sindh', 'National', null],
      default: null,
      index: true,
    },
    leaveType: {
      type: String,
      enum: ['Sick', 'Exam', 'Personal', 'Emergency'],
      default: 'Personal',
      required: true,
    },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    reason: { type: String, required: true, trim: true },
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending',
      index: true,
    },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reviewedByName: { type: String },
    reviewedAt: { type: Date },
    reviewNotes: { type: String },
    supportingDoc: { type: String },
    history: [
      {
        status: { type: String, required: true },
        changedBy: { type: String, required: true },
        role: { type: String, required: true },
        notes: { type: String },
        timestamp: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.models.LeaveRequest || mongoose.model('LeaveRequest', LeaveRequestSchema);
