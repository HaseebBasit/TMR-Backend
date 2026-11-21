const mongoose = require('mongoose');

const ApplicationSchema = new mongoose.Schema(
  {
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign' },
    departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
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
      enum: ['website_volunteer_form', 'portal_recruitment'],
      default: 'website_volunteer_form',
    },
    status: {
      type: String,
      enum: ['submitted', 'under_review', 'shortlisted', 'interview_scheduled', 'selected', 'rejected'],
      default: 'submitted',
    },
    statusHistory: [
      {
        status: { type: String, required: true },
        changedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        changedAt: { type: Date, default: Date.now },
        note: { type: String },
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.models.Application || mongoose.model('Application', ApplicationSchema);
