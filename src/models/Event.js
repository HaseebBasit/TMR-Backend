const mongoose = require('mongoose');

const EventSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, index: true },
    description: { type: String, required: true },
    date: { type: String, required: true },
    time: { type: String, required: true },
    venue: { type: String, required: true },
    organizingDepartmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
    budget: { type: Number, default: 0 },
    actualExpenses: { type: Number, default: 0 },
    status: {
      type: String,
      enum: ['upcoming', 'in_progress', 'completed', 'cancelled'],
      default: 'upcoming',
      index: true,
    },
    bannerUrl: { type: String },
    category: { type: String, default: 'General' },
    capacity: { type: Number },
    registeredCount: { type: Number, default: 0 },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Event || mongoose.model('Event', EventSchema);
