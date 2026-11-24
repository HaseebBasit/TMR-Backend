const mongoose = require('mongoose');

const MediaAssetSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    caption: { type: String, trim: true },
    department: { type: String, default: 'Media', index: true },
    departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
    fileType: {
      type: String,
      enum: ['image', 'video', 'document', 'audio'],
      default: 'image',
    },
    url: { type: String, required: true },
    driveFileId: { type: String, index: true },
    driveFolder: { type: String, default: 'Tameer-e-Rekhta/Gallery' },
    thumbnailUrl: { type: String },
    size: { type: Number, default: 0 },
    tags: [{ type: String, trim: true }],
    // Internal Management Portal Publication Status (Standalone - No Public Sync)
    publicationStatus: {
      type: String,
      enum: ['draft', 'pending_review', 'published', 'archived'],
      default: 'draft',
      index: true,
    },
    publishedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    publishedByName: { type: String, trim: true },
    publishedAt: { type: Date },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    uploadedByName: { type: String, trim: true },
    // Backward-compatibility fields
    approvalStatus: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending',
      index: true,
    },
    publishedToWebsite: { type: Boolean, default: false, index: true },
    archived: { type: Boolean, default: false, index: true },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reviewedAt: { type: Date },
  },
  { timestamps: true }
);

module.exports = mongoose.models.MediaAsset || mongoose.model('MediaAsset', MediaAssetSchema);
