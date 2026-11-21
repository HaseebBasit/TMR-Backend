const express = require('express');
const router = express.Router();
const { MediaAsset, AuditLog } = require('../models');
const { uploadFileToDrive } = require('../services/googleDrive.service');
const { protect, authorize } = require('../middleware/auth');

router.get('/', async (req, res) => {
  try {
    const { folder, approvalStatus, published } = req.query;
    const query = { archived: { $ne: true } };
    if (folder) query.driveFolder = folder;
    if (approvalStatus) query.approvalStatus = approvalStatus;
    if (published !== undefined) query.publishedToWebsite = published === 'true';

    const media = await MediaAsset.find(query).sort({ createdAt: -1 });
    return res.json({ success: true, count: media.length, media });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch media assets.' });
  }
});

router.post('/', protect, async (req, res) => {
  try {
    const { title, description, fileType, url, driveFileId, driveFolder, tags } = req.body;
    if (!title) {
      return res.status(400).json({ success: false, error: 'Media title is required.' });
    }

    const media = await MediaAsset.create({
      title,
      description: description || '',
      fileType: fileType || 'image',
      url: url || '/images/hero_sprout.jpg',
      driveFileId: driveFileId || '',
      driveFolder: driveFolder || 'Tameer-e-Rekhta/Gallery/Events',
      tags: tags || [],
      approvalStatus: 'pending',
      publishedToWebsite: false,
      archived: false,
      uploadedBy: req.user?.id,
    });

    await AuditLog.create({
      actorId: req.user?.id,
      actorName: req.user?.name || 'Media Team Member',
      actorRole: req.user?.role || 'media_lead',
      action: 'MEDIA_UPLOADED',
      module: 'MEDIA_MANAGEMENT',
      targetId: media._id.toString(),
      targetModel: 'MediaAsset',
      description: `Uploaded media "${title}". Pending approval.`,
    }).catch(() => null);

    return res.json({ success: true, media });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to create media record.' });
  }
});

router.patch('/:id/status', protect, authorize('super_admin', 'hr', 'dept_lead'), async (req, res) => {
  try {
    const { status } = req.body;
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status.' });
    }

    const media = await MediaAsset.findByIdAndUpdate(
      req.params.id,
      {
        approvalStatus: status,
        reviewedBy: req.user?.id,
        reviewedAt: new Date(),
        ...(status === 'rejected' ? { publishedToWebsite: false } : {}),
      },
      { new: true }
    );

    return res.json({ success: true, media });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Status update failed.' });
  }
});

router.patch('/:id/publish', protect, authorize('super_admin', 'dept_lead'), async (req, res) => {
  try {
    const { publish } = req.body;
    const media = await MediaAsset.findById(req.params.id);
    if (!media) return res.status(404).json({ success: false, error: 'Media not found.' });

    if (publish && media.approvalStatus !== 'approved') {
      return res.status(400).json({
        success: false,
        error: 'Security Gate: Cannot publish media that has not been approved.',
      });
    }

    media.publishedToWebsite = Boolean(publish);
    await media.save();

    return res.json({ success: true, media });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Publish failed.' });
  }
});

router.delete('/:id', protect, authorize('super_admin', 'dept_lead'), async (req, res) => {
  try {
    // Soft archive: Never delete original files
    const media = await MediaAsset.findByIdAndUpdate(
      req.params.id,
      { archived: true, publishedToWebsite: false },
      { new: true }
    );
    return res.json({ success: true, message: 'Media archived safely.', media });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Archive failed.' });
  }
});

module.exports = router;
