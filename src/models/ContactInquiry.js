const mongoose = require('mongoose');

const ContactInquirySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, lowercase: true, trim: true, index: true },
    phone: { type: String, trim: true },
    subject: { type: String, required: true, trim: true },
    message: { type: String, required: true },
    status: {
      type: String,
      enum: ['new', 'in_progress', 'resolved', 'archived'],
      default: 'new',
      index: true,
    },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    notes: { type: String },
    submissionId: { type: String, unique: true, sparse: true },
  },
  { timestamps: true }
);

module.exports = mongoose.models.ContactInquiry || mongoose.model('ContactInquiry', ContactInquirySchema);
