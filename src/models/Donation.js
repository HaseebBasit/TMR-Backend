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
    notes: { type: String },
    verificationStatus: {
      type: String,
      enum: ['Pending', 'Verified', 'Paid', 'Failed', 'Refunded'],
      default: 'Pending',
      index: true,
    },
    verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    verifiedAt: { type: Date },
    verificationNotes: { type: String },
    submissionId: { type: String, unique: true, sparse: true },
    isAdjusted: { type: Boolean, default: false },
    receiptUrl: { type: String },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Donation || mongoose.model('Donation', DonationSchema);
