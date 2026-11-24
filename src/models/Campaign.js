const mongoose = require('mongoose');

const CampaignSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    department: {
      type: String,
      enum: ['Literature', 'Media', 'Marketing', 'Outreach', 'Content Creation', 'HR', 'Finance', 'General'],
      default: 'General',
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    requirements: [
      {
        type: String,
        trim: true,
      },
    ],
    openingsCount: {
      type: Number,
      default: 1,
      min: 1,
    },
    deadline: {
      type: Date,
    },
    status: {
      type: String,
      enum: ['draft', 'active', 'closed'],
      default: 'active',
      index: true,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    createdByName: {
      type: String,
      trim: true,
    },
    applicationsCount: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Campaign || mongoose.model('Campaign', CampaignSchema);
