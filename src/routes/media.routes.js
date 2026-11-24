const express = require('express');
const router = express.Router();
const { MediaAsset, AuditLog } = require('../models');
const {
  protect,
  authorize,
  requireMediaHead,
  normalizeDesignation,
} = require('../middleware/auth');
const { validateAttachmentMetadata } = require('../services/storage.service');

// In-Memory store for offline / mock testing mode
const memoryMediaAssets = new Map();
const getMemoryMediaList = () => Array.from(memoryMediaAssets.values());
const setMemoryMedia = (asset) => {
  if (asset._id) memoryMediaAssets.set(asset._id.toString(), asset);
  if (asset.id) memoryMediaAssets.set(asset.id.toString(), asset);
};

/**
 * @route   GET /api/media
 * @desc    Fetch internal portal gallery assets with filters
 * @access  Protected (All authenticated portal users)
 */
router.get('/', protect, async (req, res) => {
  try {
    const { status, fileType, category } = req.query;
    const query = { archived: { $ne: true } };

    if (status && status !== 'all') {
      query.publicationStatus = status;
    }
    if (fileType && fileType !== 'all') {
      query.fileType = fileType;
    }
    if (category && category !== 'all') {
      query.tags = category;
    }

    let media = [];
    try {
      media = await MediaAsset.find(query).sort({ createdAt: -1 });
    } catch {}

    if (!media || media.length === 0) {
      media = getMemoryMediaList().filter((m) => !m.archived);
      if (status && status !== 'all') media = media.filter((m) => m.publicationStatus === status);
      if (fileType && fileType !== 'all') media = media.filter((m) => m.fileType === fileType);
      if (category && category !== 'all') media = media.filter((m) => m.tags?.includes(category));
    }

    return res.json({ success: true, count: media.length, media });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch media assets.' });
  }
});

/**
 * @route   POST /api/media
 * @desc    Upload media asset for internal review (Media Team or Super Admin)
 * @access  Protected (Media Department or Super Admin)
 */
router.post(
  '/',
  protect,
  authorize('super_admin', 'dept_media'),
  async (req, res) => {
    try {
      const { title, description, caption, fileType, url, driveFileId, tags, size } = req.body;

      if (!title) {
        return res.status(400).json({ success: false, error: 'Media title is required.' });
      }

      // Metadata validation via storage service
      if (url) {
        const validation = validateAttachmentMetadata({
          fileName: title + (fileType === 'video' ? '.mp4' : '.jpg'),
          fileType: fileType || 'image',
          fileSize: size || 1024,
        });
        if (!validation.valid) {
          return res.status(400).json({ success: false, error: validation.error });
        }
      }

      const isHead = req.user.role === 'dept_media' && normalizeDesignation(req.user.designation) === 'head';
      // Members upload as 'pending_review' or 'draft'; only Head can create directly as 'published'
      const initialStatus = req.body.publicationStatus === 'published' && isHead ? 'published' : 'pending_review';

      const newAsset = {
        _id: 'media_' + Date.now(),
        id: 'media_' + Date.now(),
        title: title.trim(),
        description: description?.trim() || '',
        caption: caption?.trim() || '',
        department: 'Media',
        fileType: fileType || 'image',
        url: url || '/images/hero_sprout.jpg',
        driveFileId: driveFileId || '',
        driveFolder: 'Tameer-e-Rekhta/Gallery/Internal',
        thumbnailUrl: url || '/images/hero_sprout.jpg',
        size: size || 0,
        tags: Array.isArray(tags) ? tags : tags ? [tags] : ['Gallery'],
        publicationStatus: initialStatus,
        approvalStatus: initialStatus === 'published' ? 'approved' : 'pending',
        publishedToWebsite: false, // Invariant: internal gallery only, never synced to public website
        archived: false,
        uploadedBy: req.user.id || req.user._id,
        uploadedByName: req.user.name,
        publishedBy: initialStatus === 'published' ? (req.user.id || req.user._id) : null,
        publishedByName: initialStatus === 'published' ? req.user.name : null,
        publishedAt: initialStatus === 'published' ? new Date() : null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      let media = null;
      try {
        media = await MediaAsset.create(newAsset);
      } catch {
        setMemoryMedia(newAsset);
        media = newAsset;
      }

      await AuditLog.create({
        actorId: req.user.id || req.user._id,
        actorName: req.user.name,
        actorRole: req.user.role,
        action: 'MEDIA_ASSET_UPLOADED',
        module: 'MEDIA_GALLERY',
        targetId: (media._id || media.id)?.toString(),
        targetModel: 'MediaAsset',
        description: `${req.user.name} uploaded media asset '${title}' (Status: ${initialStatus}).`,
      }).catch(() => null);

      return res.status(201).json({
        success: true,
        message: `Media asset '${title}' uploaded successfully (${initialStatus}).`,
        media,
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Failed to upload media asset.' });
    }
  }
);

/**
 * @route   PATCH /api/media/:id/publish
 * @desc    Publish a media asset to the internal gallery
 * @access  Protected (STRICTLY Media Department Head ONLY)
 */
router.patch('/:id/publish', protect, requireMediaHead, async (req, res) => {
  try {
    const { id } = req.params;
    let media = null;
    try {
      media = await MediaAsset.findById(id);
    } catch {}
    if (!media) media = memoryMediaAssets.get(id);

    if (!media) {
      return res.status(404).json({ success: false, error: 'Media asset not found.' });
    }

    media.publicationStatus = 'published';
    media.publishedBy = req.user.id || req.user._id;
    media.publishedByName = req.user.name;
    media.publishedAt = new Date();
    media.approvalStatus = 'approved';
    media.publishedToWebsite = false; // Strictly standalone management portal gallery

    try {
      if (media.save) await media.save();
      else setMemoryMedia(media);
    } catch {
      setMemoryMedia(media);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'MEDIA_GALLERY_PUBLISHED',
      module: 'MEDIA_GALLERY',
      targetId: id,
      targetModel: 'MediaAsset',
      description: `Media Head ${req.user.name} published asset '${media.title}' to the internal gallery.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Media asset '${media.title}' published successfully to internal gallery.`,
      media,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to publish media asset.' });
  }
});

/**
 * @route   PATCH /api/media/:id/unpublish
 * @desc    Unpublish a media asset from the internal gallery
 * @access  Protected (STRICTLY Media Department Head ONLY)
 */
router.patch('/:id/unpublish', protect, requireMediaHead, async (req, res) => {
  try {
    const { id } = req.params;
    let media = null;
    try {
      media = await MediaAsset.findById(id);
    } catch {}
    if (!media) media = memoryMediaAssets.get(id);

    if (!media) {
      return res.status(404).json({ success: false, error: 'Media asset not found.' });
    }

    media.publicationStatus = 'draft';
    media.publishedAt = null;

    try {
      if (media.save) await media.save();
      else setMemoryMedia(media);
    } catch {
      setMemoryMedia(media);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'MEDIA_GALLERY_UNPUBLISHED',
      module: 'MEDIA_GALLERY',
      targetId: id,
      targetModel: 'MediaAsset',
      description: `Media Head ${req.user.name} unpublished asset '${media.title}'.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Media asset '${media.title}' unpublished and set to draft.`,
      media,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to unpublish media asset.' });
  }
});

/**
 * @route   PATCH /api/media/:id
 * @desc    Update gallery asset metadata (Title, description, caption, tags)
 * @access  Protected (Media Head if published, or Uploader if draft)
 */
router.patch('/:id', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, caption, tags } = req.body;

    let media = null;
    try {
      media = await MediaAsset.findById(id);
    } catch {}
    if (!media) media = memoryMediaAssets.get(id);

    if (!media) {
      return res.status(404).json({ success: false, error: 'Media asset not found.' });
    }

    const isMediaHead =
      req.user.role === 'dept_media' && normalizeDesignation(req.user.designation) === 'head';
    const isUploader =
      (media.uploadedBy?.toString() || media.uploadedBy) === (req.user.id || req.user._id)?.toString();
    const isSuperAdmin = req.user.role === 'super_admin';

    // If published, only Media Head or Super Admin can edit
    if (media.publicationStatus === 'published' && !isMediaHead && !isSuperAdmin) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: Published gallery items can only be edited by the Media Department Head.',
      });
    }

    // If draft, uploader, Media Head, or Super Admin can edit
    if (!isUploader && !isMediaHead && !isSuperAdmin) {
      return res.status(403).json({ success: false, error: 'Forbidden: You cannot edit this media asset.' });
    }

    if (title) media.title = title.trim();
    if (description !== undefined) media.description = description.trim();
    if (caption !== undefined) media.caption = caption.trim();
    if (tags) media.tags = Array.isArray(tags) ? tags : [tags];

    try {
      if (media.save) await media.save();
      else setMemoryMedia(media);
    } catch {
      setMemoryMedia(media);
    }

    return res.json({ success: true, message: 'Media asset updated successfully.', media });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to update media asset.' });
  }
});

/**
 * @route   DELETE /api/media/:id
 * @desc    Soft-archive a media asset (Never permanently deletes original files)
 * @access  Protected (Media Head or Super Admin Only)
 */
router.delete('/:id', protect, async (req, res) => {
  try {
    const isMediaHead =
      req.user.role === 'dept_media' && normalizeDesignation(req.user.designation) === 'head';
    const isSuperAdmin = req.user.role === 'super_admin';

    if (!isMediaHead && !isSuperAdmin) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: Only the Media Department Head or Super Admin can archive gallery assets.',
      });
    }

    const { id } = req.params;
    let media = null;
    try {
      media = await MediaAsset.findById(id);
    } catch {}
    if (!media) media = memoryMediaAssets.get(id);

    if (!media) {
      return res.status(404).json({ success: false, error: 'Media asset not found.' });
    }

    media.archived = true;
    media.publicationStatus = 'archived';

    try {
      if (media.save) await media.save();
      else setMemoryMedia(media);
    } catch {
      setMemoryMedia(media);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'MEDIA_ASSET_ARCHIVED',
      module: 'MEDIA_GALLERY',
      targetId: id,
      targetModel: 'MediaAsset',
      description: `${req.user.name} archived media asset '${media.title}'.`,
    }).catch(() => null);

    return res.json({ success: true, message: 'Media asset safely archived.', media });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to archive media asset.' });
  }
});

router.router = router;
router.getMemoryMediaList = getMemoryMediaList;
router.setMemoryMedia = setMemoryMedia;

module.exports = router;
