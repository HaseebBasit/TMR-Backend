const mongoose = require('mongoose');

// Global DDL Prevention & Connection Hardening:
// Disable automatic index and collection creation before model loading
mongoose.set('autoIndex', false);
mongoose.set('autoCreate', false);
// Disable command buffering when disconnected so operations fail fast instead of hanging
mongoose.set('bufferCommands', false);

const User = require('./User');
const Application = require('./Application');
const Campaign = require('./Campaign');
const Donation = require('./Donation');
const ContactInquiry = require('./ContactInquiry');
const Event = require('./Event');
const EventRegistration = require('./EventRegistration');
const MediaAsset = require('./MediaAsset');
const AuditLog = require('./AuditLog');
const Department = require('./Department');
const Task = require('./Task');
const Notification = require('./Notification');
const Assessment = require('./Assessment');
const LeaveRequest = require('./LeaveRequest');
const Expense = require('./Expense');
const Budget = require('./Budget');
const Announcement = require('./Announcement');
const EmergencyCredential = require('./EmergencyCredential');

module.exports = {
  User,
  Application,
  Campaign,
  Donation,
  ContactInquiry,
  Event,
  EventRegistration,
  MediaAsset,
  AuditLog,
  Department,
  Task,
  Notification,
  Assessment,
  LeaveRequest,
  Expense,
  Budget,
  Announcement,
  EmergencyCredential,
};
