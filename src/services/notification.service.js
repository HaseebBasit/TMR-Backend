const { Notification } = require('../models');

// In-memory store for offline, test, and controlled configuration-check mode
const memoryNotifications = new Map();

const getMemoryNotificationsList = () => Array.from(memoryNotifications.values());

const setMemoryNotification = (notif) => {
  if (!notif) return;
  const id = (notif._id || notif.id)?.toString();
  if (id) memoryNotifications.set(id, notif);
};

const clearMemoryNotifications = () => {
  memoryNotifications.clear();
};

/**
 * Send / dispatch an internal notification with deduplication support
 */
async function sendNotification({
  userId,
  title,
  message,
  type = 'info',
  link = '',
  category = 'general',
  dedupKey = null,
}) {
  if (!userId || !title || !message) {
    return null;
  }

  const normalizedUserId = userId.toString();

  // Deduplication guard: prevent identical event notifications if dedupKey provided
  if (dedupKey) {
    // Check in-memory store
    const existingMemory = getMemoryNotificationsList().find(
      (n) => n.userId?.toString() === normalizedUserId && n.dedupKey === dedupKey
    );
    if (existingMemory) {
      return existingMemory;
    }

    // Check database if connected
    try {
      const existingDb = await Notification.findOne({
        userId: normalizedUserId,
        dedupKey,
      });
      if (existingDb) {
        setMemoryNotification(existingDb);
        return existingDb;
      }
    } catch {}
  }

  const notifId = 'notif_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
  const newNotifData = {
    _id: notifId,
    id: notifId,
    userId: normalizedUserId,
    title: title.trim(),
    message: message.trim(),
    type,
    read: false,
    link: link || '',
    category,
    dedupKey: dedupKey || null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  let created = null;
  try {
    created = await Notification.create(newNotifData);
  } catch (err) {
    // Graceful handling of MongoDB duplicate-key conflict (E11000)
    if (err && (err.code === 11000 || err.name === 'MongoServerError')) {
      try {
        const existingDb = await Notification.findOne({
          userId: normalizedUserId,
          dedupKey,
        });
        if (existingDb) {
          setMemoryNotification(existingDb);
          return existingDb;
        }
      } catch {}
    }
    // In-memory fallback
    created = newNotifData;
  }

  setMemoryNotification(created || newNotifData);
  return created || newNotifData;
}

/**
 * Retrieve notifications for a specific user with strict ownership isolation
 */
async function getNotificationsForUser(userId, query = {}) {
  const normalizedUserId = userId?.toString();
  if (!normalizedUserId) {
    return { success: false, error: 'User ID is required.', notifications: [], count: 0, unreadCount: 0 };
  }

  let dbNotifications = [];
  try {
    const filter = { userId: normalizedUserId };
    if (query.read !== undefined) {
      filter.read = query.read === 'true' || query.read === true;
    }
    if (query.category) {
      filter.category = query.category;
    }
    dbNotifications = await Notification.find(filter).sort({ createdAt: -1 });
  } catch {}

  let list = dbNotifications;
  if (!list || list.length === 0) {
    list = getMemoryNotificationsList().filter(
      (n) => n.userId?.toString() === normalizedUserId
    );
    if (query.read !== undefined) {
      const isRead = query.read === 'true' || query.read === true;
      list = list.filter((n) => Boolean(n.read) === isRead);
    }
    if (query.category) {
      list = list.filter((n) => n.category === query.category);
    }
    list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  const allUserNotifications = getMemoryNotificationsList().filter(
    (n) => n.userId?.toString() === normalizedUserId
  );
  const unreadCount = allUserNotifications.filter((n) => !n.read).length;

  return {
    success: true,
    count: list.length,
    unreadCount,
    notifications: list,
  };
}

/**
 * Mark a notification as read with strict ownership validation
 */
async function markNotificationRead(notificationId, userId) {
  const notifId = notificationId?.toString();
  const normalizedUserId = userId?.toString();

  let notif = null;
  try {
    notif = await Notification.findById(notifId);
  } catch {}

  if (!notif) {
    notif = memoryNotifications.get(notifId);
  }

  if (!notif) {
    return { success: false, statusCode: 404, error: 'Notification not found.' };
  }

  // Strict ownership check
  if (notif.userId?.toString() !== normalizedUserId) {
    return {
      success: false,
      statusCode: 403,
      error: 'Access denied: You are not authorized to access another user’s notification.',
    };
  }

  notif.read = true;
  notif.updatedAt = new Date();

  try {
    if (typeof notif.save === 'function') {
      await notif.save();
    }
  } catch {}

  setMemoryNotification(notif);
  return { success: true, notification: notif };
}

/**
 * Mark all notifications for a user as read
 */
async function markAllNotificationsRead(userId) {
  const normalizedUserId = userId?.toString();
  if (!normalizedUserId) {
    return { success: false, statusCode: 400, error: 'User ID required.' };
  }

  try {
    await Notification.updateMany({ userId: normalizedUserId, read: false }, { $set: { read: true } });
  } catch {}

  // Update in-memory records
  for (const notif of memoryNotifications.values()) {
    if (notif.userId?.toString() === normalizedUserId) {
      notif.read = true;
      notif.updatedAt = new Date();
    }
  }

  return { success: true, message: 'All notifications marked as read.' };
}

/**
 * Delete / dismiss a notification with ownership validation
 */
async function deleteNotification(notificationId, userId) {
  const notifId = notificationId?.toString();
  const normalizedUserId = userId?.toString();

  let notif = null;
  try {
    notif = await Notification.findById(notifId);
  } catch {}

  if (!notif) {
    notif = memoryNotifications.get(notifId);
  }

  if (!notif) {
    return { success: false, statusCode: 404, error: 'Notification not found.' };
  }

  if (notif.userId?.toString() !== normalizedUserId) {
    return {
      success: false,
      statusCode: 403,
      error: 'Access denied: You cannot delete another user’s notification.',
    };
  }

  try {
    await Notification.deleteOne({ _id: notifId });
  } catch {}

  memoryNotifications.delete(notifId);
  return { success: true, message: 'Notification removed successfully.' };
}

module.exports = {
  sendNotification,
  getNotificationsForUser,
  markNotificationRead,
  markAllNotificationsRead,
  deleteNotification,
  getMemoryNotificationsList,
  setMemoryNotification,
  clearMemoryNotifications,
};
