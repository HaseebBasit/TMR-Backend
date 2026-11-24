const mongoose = require('mongoose');

const ApplicationSchema = new mongoose.Schema(
  {
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign' },
    departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
    department: { type: String, trim: true },
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, lowercase: true, trim: true },
    phoneNumber: { type: String, required: true, trim: true },
    instagramId: { type: String, trim: true },
    city: { type: String, trim: true },
    age: { type: String, trim: true },
    areaOfInterest: { type: String, trim: true },
    motivation: { type: String },
    coverLetter: { type: String },
    resumeUrl: { type: String },
    portfolioUrl: { type: String },
    submissionId: { type: String, unique: true, sparse: true },
    source: {
      type: String,
      enum: ['website_volunteer_form', 'official_website', 'portal_recruitment'],
      default: 'website_volunteer_form',
    },
    status: {
      type: String,
      enum: [
        'submitted',
        'pending',
        'under_review',
        'shortlisted',
        'interview_scheduled',
        'selected',
        'rejected',
        'not_selected',
      ],
      default: 'submitted',
    },
    interviewDetails: {
      scheduledAt: { type: Date },
      interviewers: [{ type: String }],
      interviewerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      interviewerName: { type: String, trim: true },
      mode: { type: String, enum: ['Online', 'In-Person', 'Phone'], default: 'Online' },
      meetingLink: { type: String, trim: true },
      notes: { type: String, trim: true },
      feedback: { type: String, trim: true },
      recommendation: {
        type: String,
        enum: ['pending', 'selected', 'not_selected', 'shortlist', 'further_interview'],
        default: 'pending',
      },
      submittedAt: { type: Date },
    },
    decisionDetails: {
      decision: { type: String, enum: ['selected', 'not_selected', 'rejected'] },
      decidedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      decidedByName: { type: String, trim: true },
      decidedByRole: { type: String, trim: true },
      decidedByDesignation: { type: String, trim: true },
      decidedAt: { type: Date },
      decisionNotes: { type: String, trim: true },
    },
    onboardingDetails: {
      onboardedAt: { type: Date },
      assignedRole: { type: String },
      assignedDepartment: { type: String },
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    },
    reviewNotes: { type: String },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reviewedAt: { type: Date },
    statusHistory: [
      {
        status: { type: String, required: true },
        changedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        changedByName: { type: String },
        changedAt: { type: Date, default: Date.now },
        note: { type: String },
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.models.Application || mongoose.model('Application', ApplicationSchema);
