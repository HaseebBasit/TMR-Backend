const express = require('express');
const router = express.Router();
const { Event, EventRegistration, AuditLog } = require('../models');
const { sendEmail } = require('../services/email.service');

router.get('/', async (req, res) => {
  try {
    const events = await Event.find().sort({ createdAt: -1 });
    return res.json({ success: true, events });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch events.' });
  }
});

router.post('/register', async (req, res) => {
  try {
    const { eventId, participantName, email, phone, city, notes } = req.body;
    if (!eventId || !participantName || !email || !phone) {
      return res.status(400).json({ success: false, error: 'Missing required registration fields.' });
    }

    let eventRecord = await Event.findById(eventId).catch(() => null);
    if (!eventRecord) {
      eventRecord = await Event.findOne({ title: eventId });
      if (!eventRecord) {
        eventRecord = await Event.create({
          title: String(eventId),
          description: 'Flagship Community Event',
          date: new Date().toISOString().split('T')[0],
          time: '6:00 PM',
          venue: 'Bahawalpur / Hybrid',
          status: 'upcoming',
          registeredCount: 0,
        }).catch(() => null);
      }
    }

    const resolvedEventId = eventRecord?._id;
    const eventTitle = eventRecord?.title || 'Community Event';

    // Duplicate check
    const existing = await EventRegistration.findOne({
      eventId: resolvedEventId,
      email: email.toLowerCase().trim(),
    });

    if (existing) {
      return res.json({
        success: true,
        message: 'You are already registered for this event.',
        registration: existing,
      });
    }

    const submissionId = `EVT_REG_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const reg = await EventRegistration.create({
      eventId: resolvedEventId,
      eventTitle,
      participantName,
      email: email.toLowerCase().trim(),
      phone: phone.trim(),
      city: city || '',
      notes: notes || '',
      status: 'confirmed',
      submissionId,
    });

    if (resolvedEventId) {
      await Event.findByIdAndUpdate(resolvedEventId, { $inc: { registeredCount: 1 } }).catch(() => null);
    }

    await AuditLog.create({
      actorName: participantName,
      actorRole: 'public_attendee',
      action: 'EVENT_REGISTRATION_CREATED',
      module: 'EVENTS_REGISTRATION',
      targetId: reg?._id?.toString() || submissionId,
      targetModel: 'EventRegistration',
      description: `Registration confirmed for ${participantName} (${email}) for event: "${eventTitle}".`,
    }).catch(() => null);

    sendEmail({
      to: email,
      subject: `Registration Confirmed: ${eventTitle} — Pass #${submissionId}`,
      text: `Dear ${participantName},\n\nYour registration pass for "${eventTitle}" is confirmed.\nPass ID: ${submissionId}`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Registration confirmed.',
      registration: reg,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Registration failed.' });
  }
});

module.exports = router;
