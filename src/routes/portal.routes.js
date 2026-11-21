const express = require('express');
const router = express.Router();
const { Department, Task, Notification, Donation, AuditLog, Application } = require('../models');
const { protect } = require('../middleware/auth');

// Departments
router.get('/departments', async (req, res) => {
  const departments = await Department.find().sort({ name: 1 }).catch(() => []);
  return res.json({ success: true, departments });
});

// Tasks
router.get('/tasks', protect, async (req, res) => {
  const { departmentId, status } = req.query;
  const q = {};
  if (departmentId) q.departmentId = departmentId;
  if (status) q.status = status;
  const tasks = await Task.find(q).sort({ createdAt: -1 }).catch(() => []);
  return res.json({ success: true, tasks });
});

router.post('/tasks', protect, async (req, res) => {
  const task = await Task.create({
    ...req.body,
    createdBy: req.user?.id,
  }).catch(() => null);
  return res.json({ success: Boolean(task), task });
});

// Notifications
router.get('/notifications', protect, async (req, res) => {
  const notifications = await Notification.find({ userId: req.user?.id }).sort({ createdAt: -1 }).catch(() => []);
  return res.json({ success: true, notifications });
});

// Finance
router.get('/finance/income', protect, async (req, res) => {
  const donations = await Donation.find().sort({ createdAt: -1 }).limit(100).catch(() => []);
  return res.json({ success: true, income: donations });
});

router.patch('/finance/income/:id/verify', protect, async (req, res) => {
  const { status, notes } = req.body;
  const donation = await Donation.findByIdAndUpdate(
    req.params.id,
    {
      verificationStatus: status,
      verificationNotes: notes,
      verifiedBy: req.user?.id,
      verifiedAt: new Date(),
    },
    { new: true }
  ).catch(() => null);
  return res.json({ success: Boolean(donation), donation });
});

// Recruitment / Applications
router.get('/recruitment/applications', protect, async (req, res) => {
  const applications = await Application.find().sort({ createdAt: -1 }).catch(() => []);
  return res.json({ success: true, applications });
});

// Super Admin Audit Logs
router.get('/super-admin/audit-logs', protect, async (req, res) => {
  const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(100).catch(() => []);
  return res.json({ success: true, logs });
});

module.exports = router;
