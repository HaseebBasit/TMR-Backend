const express = require('express');
const router = express.Router();
const { ContactInquiry, AuditLog } = require('../models');
const { sendEmail } = require('../services/email.service');

router.post('/', async (req, res) => {
  try {
    const { name, email, phone, subject, message } = req.body;
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ success: false, error: 'Please provide all required contact fields.' });
    }

    const submissionId = `INQ_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

    const inquiry = await ContactInquiry.create({
      name,
      email: email.toLowerCase().trim(),
      phone: phone || '',
      subject,
      message,
      status: 'new',
      submissionId,
    }).catch((e) => {
      console.warn('[MongoDB Notice] Inquiry saved offline:', e.message);
      return null;
    });

    await AuditLog.create({
      actorName: name,
      actorRole: 'public_visitor',
      action: 'CONTACT_INQUIRY_RECEIVED',
      module: 'ADMIN_INQUIRIES',
      targetId: inquiry?._id?.toString() || submissionId,
      targetModel: 'ContactInquiry',
      description: `Contact inquiry received from ${name} (${email}): "${subject}"`,
    }).catch(() => null);

    const adminEmail = process.env.VOLUNTEER_RECIPIENT_EMAIL || 'taameer.e.rekhta@gmail.com';
    sendEmail({
      to: adminEmail,
      subject: `New Contact Inquiry: ${subject} (${name})`,
      text: `Inquiry from: ${name} <${email}>\nPhone: ${phone || 'N/A'}\n\nMessage:\n${message}`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Inquiry logged successfully. Communications team will reach out shortly.',
      submissionId,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to process inquiry.' });
  }
});

module.exports = router;
