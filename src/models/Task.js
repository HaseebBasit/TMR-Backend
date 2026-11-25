const mongoose = require('mongoose');

const TaskSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    instructions: { type: String, trim: true },
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
        'Administration',
        'HR',
        'Finance',
      ],
      index: true,
    },
    departmentCode: {
      type: String,
      enum: ['LIT', 'MED', 'MKT', 'OUT', 'OAM', 'CON', 'WEL', 'ADM', 'HR', 'FIN'],
      index: true,
    },
    region: {
      type: String,
      enum: ['Punjab', 'Sindh', 'National', null],
      default: null,
      index: true,
    },
    // Original Owning Department (IMMUTABLE across all referrals and reassignments)
    originalDepartment: {
      type: String,
      required: true,
      default: function () {
        return this.department;
      },
      enum: [
        'Literature',
        'Media',
        'Marketing',
        'Outreach',
        'Outreach and Marketing',
        'Content Creation',
        'Welfare',
        'Administration',
        'HR',
        'Finance',
      ],
      index: true,
    },
    originalDepartmentCode: {
      type: String,
      default: function () {
        return this.departmentCode;
      },
      enum: ['LIT', 'MED', 'MKT', 'OUT', 'OAM', 'CON', 'WEL', 'ADM', 'HR', 'FIN'],
      index: true,
    },
    departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    assignedMemberName: { type: String, trim: true },
    assignedMemberEmail: { type: String, lowercase: true, trim: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdByName: { type: String, trim: true },
    createdByRole: { type: String, trim: true },
    priority: {
      type: String,
      enum: ['low', 'medium', 'high', 'urgent'],
      default: 'medium',
      index: true,
    },
    status: {
      type: String,
      enum: [
        'assigned',
        'in_progress',
        'submitted',
        'pending_testing',
        'under_testing',
        'moderation_pending',
        'under_moderation',
        'rechecking_pending',
        'awaiting_final_approval',
        'revision_requested',
        'approved',
        'completed',
        // Backward-compatibility
        'todo',
        'review',
        'under_review',
      ],
      default: 'assigned',
      index: true,
    },
    dueDate: { type: Date },
    deadline: { type: Date },
    completedAt: { type: Date },
    requiredDeliverables: [{ type: String, trim: true }],
    referenceAttachments: [
      {
        fileName: { type: String, required: true },
        fileUrl: { type: String, required: true },
        fileType: { type: String },
        fileSize: { type: Number },
        uploadedAt: { type: Date, default: Date.now },
      },
    ],
    // Versioned Multimedia Submissions (Previous versions are never overwritten or deleted)
    currentVersion: { type: Number, default: 1 },
    submissions: [
      {
        version: { type: Number, required: true },
        submittedBy: {
          id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
          name: { type: String, trim: true },
          email: { type: String, lowercase: true, trim: true },
        },
        submittedAt: { type: Date, default: Date.now },
        notes: { type: String, trim: true },
        attachments: [
          {
            fileName: { type: String, required: true },
            fileUrl: { type: String, required: true },
            fileType: { type: String },
            fileSize: { type: Number },
            mimeType: { type: String },
            uploadedAt: { type: Date, default: Date.now },
          },
        ],
        status: {
          type: String,
          enum: ['pending_testing', 'tested_passed', 'corrections_requested', 'rejected'],
          default: 'pending_testing',
        },
      },
    ],
    // Intermediate Tester Review Details (Tester cannot final approve)
    testingDetails: {
      testerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      testerName: { type: String, trim: true },
      testedAt: { type: Date },
      comments: { type: String, trim: true },
      findings: { type: String, trim: true },
      decision: {
        type: String,
        enum: ['passed', 'corrections_requested', 'rejected'],
      },
      forwardedToModerator: { type: Boolean, default: false },
    },
    // Intermediate Moderator Review & Content Editing Details (Moderator cannot final approve)
    moderationDetails: {
      moderatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      moderatorName: { type: String, trim: true },
      moderatedAt: { type: Date },
      feedback: { type: String, trim: true },
      editedAttachments: [
        {
          fileName: { type: String },
          fileUrl: { type: String },
          fileType: { type: String },
          fileSize: { type: Number },
          uploadedAt: { type: Date, default: Date.now },
        },
      ],
      decision: {
        type: String,
        enum: ['returned_to_department', 'forwarded_for_approval'],
      },
      returnDetails: {
        returnReason: { type: String, trim: true },
        requiredChanges: { type: String, trim: true },
        recheckingDeadline: { type: Date },
        recommendedMember: { type: String, trim: true },
      },
    },
    // Inter-Department Referral Tracking (Original department ownership is preserved)
    referrals: [
      {
        referralId: { type: String, required: true },
        originalDepartment: { type: String, required: true },
        sendingDepartment: { type: String, required: true },
        receivingDepartment: { type: String, required: true },
        referringUser: {
          id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
          name: { type: String },
          role: { type: String },
          designation: { type: String },
        },
        receivingUser: {
          id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
          name: { type: String },
        },
        reason: { type: String, trim: true },
        instructions: { type: String, trim: true },
        status: {
          type: String,
          enum: ['pending', 'accepted', 'in_progress', 'completed', 'returned', 'rejected'],
          default: 'pending',
        },
        responseNotes: { type: String, trim: true },
        referredAt: { type: Date, default: Date.now },
        respondedAt: { type: Date },
      },
    ],
    activeReferral: {
      referralId: { type: String },
      originalDepartment: { type: String },
      sendingDepartment: { type: String },
      receivingDepartment: { type: String },
      referringUserName: { type: String },
      reason: { type: String },
      status: { type: String },
      referredAt: { type: Date },
    },
    // Final Departmental Approval Details (Strictly original department Head or Director ONLY)
    finalApprovalDetails: {
      approvedBy: {
        id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        name: { type: String },
        role: { type: String },
        designation: { type: String },
      },
      approvedAt: { type: Date },
      approvalNotes: { type: String, trim: true },
      originalDepartment: { type: String },
    },
    // Backward-compatible Legacy Work Submission Details
    submissionDetails: {
      notes: { type: String, trim: true },
      links: [{ type: String, trim: true }],
      submittedAt: { type: Date },
    },
    // Backward-compatible Legacy Review Details
    reviewDetails: {
      reviewerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      reviewerName: { type: String, trim: true },
      feedback: { type: String, trim: true },
      revisionNotes: { type: String, trim: true },
      reviewedAt: { type: Date },
    },
    // Historical Audit Trail of Task Status Transitions
    history: [
      {
        status: { type: String, required: true },
        updatedBy: { type: String, required: true },
        role: { type: String },
        notes: { type: String },
        timestamp: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.models.Task || mongoose.model('Task', TaskSchema);
