const express = require('express');
const router = express.Router();
const { MediaAsset } = require('../models');

router.get('/', async (req, res) => {
  try {
    // Return only approved, published, non-archived media
    const publishedMedia = await MediaAsset.find({
      approvalStatus: 'approved',
      publishedToWebsite: true,
      archived: { $ne: true },
    }).sort({ createdAt: -1 });

    const formatted = publishedMedia.map((m) => ({
      id: m._id.toString(),
      title: m.title,
      description: m.description || '',
      category: m.tags?.[0] || 'Initiative',
      image: m.url,
      driveFileId: m.driveFileId,
    }));

    return res.json({ success: true, count: formatted.length, items: formatted });
  } catch (err) {
    return res.json({ success: true, count: 0, items: [] });
  }
});

module.exports = router;
