const mongoose = require('mongoose');

const RegionalLeadSchema = new mongoose.Schema(
  {
    region: { type: String, enum: ['Punjab', 'Sindh', 'National'], required: true },
    leadId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    leadName: { type: String, trim: true },
    leadEmail: { type: String, trim: true },
    designation: { type: String, trim: true },
  },
  { _id: false }
);

const DepartmentSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, unique: true },
    code: { type: String, required: true, trim: true, uppercase: true, unique: true },
    description: { type: String, trim: true },
    leadId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    leadName: { type: String, trim: true },
    leadEmail: { type: String, trim: true },
    regionalLeads: [RegionalLeadSchema],
    memberCount: { type: Number, default: 0 },
    activeTasksCount: { type: Number, default: 0 },
    status: {
      type: String,
      enum: ['active', 'inactive'],
      default: 'active',
    },
    iconName: { type: String, default: 'Users' },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Department || mongoose.model('Department', DepartmentSchema);
