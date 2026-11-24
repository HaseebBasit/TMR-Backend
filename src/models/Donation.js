const mongoose = require('mongoose');

const DonationSchema = new mongoose.Schema(
  {
    receiptNo: { type: String, required: true, unique: true, index: true },
    transactionId: { type: String, trim: true, index: true },
    referenceNumber: { type: String, required: true, index: true },
    donorName: { type: String, required: true, trim: true },
    donorEmail: { type: String, required: true, lowercase: true, trim: true, index: true },
    donorPhone: { type: String, required: true, trim: true },
    amount: { type: Number, required: true, min: 1 },
    currency: { type: String, default: 'PKR' },
    paymentMethod: { type: String, required: true, index: true },
    cause: { type: String, default: 'General Welfare Fund', index: true },
    category: { type: String, default: 'Donation', index: true },
    notes: { type: String },
    verificationStatus: {
      type: String,
      enum: ['Pending', 'Verified', 'Paid', 'Failed', 'Refunded', 'Rejected', 'pending', 'verified', 'rejected'],
      default: 'Pending',
      index: true,
    },
    verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    verifiedByName: { type: String },
    verifiedAt: { type: Date },
    verificationNotes: { type: String },
    submissionId: { type: String, unique: true, sparse: true },
    isAdjusted: { type: Boolean, default: false },
    isArchived: { type: Boolean, default: false, index: true },
    receiptUrl: { type: String },
    history: [
      {
        status: { type: String },
        previousStatus: { type: String },
        changedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        changedByName: { type: String },
        notes: { type: String },
        timestamp: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.models.Donation || mongoose.model('Donation', DonationSchema);
