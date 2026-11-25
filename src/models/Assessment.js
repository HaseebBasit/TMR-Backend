const mongoose = require('mongoose');

const AssessmentSchema = new mongoose.Schema(
  {
    memberId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    memberName: { type: String, required: true },
    evaluatorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    evaluatorName: { type: String, required: true },
    evaluatorRole: { type: String, required: true },
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
      index: true,
    },
    departmentCode: {
      type: String,
      required: true,
      enum: ['LIT', 'MED', 'MKT', 'OUT', 'OAM', 'CON', 'WEL', 'HR', 'FIN'],
      index: true,
    },
    period: { type: String, required: true },
    criteriaScores: {
      taskExecution: { type: Number, required: true, min: 1, max: 10 },
      deliverableQuality: { type: Number, required: true, min: 1, max: 10 },
      punctuality: { type: Number, required: true, min: 1, max: 10 },
      teamCollaboration: { type: Number, required: true, min: 1, max: 10 },
    },
    totalScore: { type: Number, required: true, min: 4, max: 40 },
    percentage: { type: Number, required: true },
    qualitativeFeedback: { type: String, trim: true },
    isConfidential: { type: Boolean, default: true },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Assessment || mongoose.model('Assessment', AssessmentSchema);
