const mongoose = require('mongoose');

const EventRegistrationSchema = new mongoose.Schema(
  {
    eventId: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true, index: true },
    eventTitle: { type: String, trim: true },
    participantName: { type: String, required: true, trim: true },
    email: { type: String, required: true, lowercase: true, trim: true },
    phone: { type: String, required: true, trim: true },
    city: { type: String, trim: true },
    registrationDate: { type: Date, default: Date.now },
    status: {
      type: String,
      enum: ['confirmed', 'waitlist', 'cancelled'],
      default: 'confirmed',
    },
    notes: { type: String },
    submissionId: { type: String, unique: true, sparse: true },
  },
  { timestamps: true }
);

module.exports = mongoose.models.EventRegistration || mongoose.model('EventRegistration', EventRegistrationSchema);
