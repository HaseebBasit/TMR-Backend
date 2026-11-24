const mongoose = require('mongoose');

const BudgetSchema = new mongoose.Schema(
  {
    budgetId: { type: String, required: true, unique: true, index: true },
    fiscalYear: { type: String, required: true, index: true },
    title: { type: String, required: true, trim: true },
    department: {
      type: String,
      required: true,
      enum: [
        'Literature',
        'Media',
        'Marketing',
        'Outreach',
        'Content Creation',
        'HR',
        'Finance',
        'General',
        'All',
      ],
      index: true,
    },
    category: { type: String, default: 'General Operating' },
    currency: { type: String, default: 'PKR', trim: true },
    isArchived: { type: Boolean, default: false, index: true },
    eventId: { type: mongoose.Schema.Types.ObjectId, ref: 'Event' },
    eventTitle: { type: String },
    allocatedAmount: { type: Number, required: true, min: 0 },
    spentAmount: { type: Number, default: 0, min: 0 },
    remainingAmount: { type: Number, default: 0 },
    status: {
      type: String,
      enum: ['active', 'frozen', 'closed'],
      default: 'active',
      index: true,
    },
    allocatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    allocatedByName: { type: String },
    notes: { type: String },
    history: [
      {
        action: { type: String, required: true },
        amount: { type: Number },
        previousAmount: { type: Number },
        newAmount: { type: Number },
        previousSpent: { type: Number },
        newSpent: { type: Number },
        previousStatus: { type: String },
        newStatus: { type: String },
        changedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        changedByName: { type: String },
        note: { type: String },
        timestamp: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

BudgetSchema.pre('save', function (next) {
  this.remainingAmount = (this.allocatedAmount || 0) - (this.spentAmount || 0);
  next();
});

// Enforce compound uniqueness for active (non-archived) budgets:
// Exactly one active budget per department, fiscal year, and category.
// Supports department budgets, organization-wide ('All') budgets, multiple legitimate allocations
// across distinct categories (e.g. Operating vs Special Events), and allows archived budget revisions.
BudgetSchema.index(
  { department: 1, fiscalYear: 1, category: 1 },
  {
    unique: true,
    partialFilterExpression: {
      isArchived: false,
    },
  }
);

module.exports = mongoose.models.Budget || mongoose.model('Budget', BudgetSchema);
