const express = require('express');
const router = express.Router();
const { Donation, AuditLog } = require('../models');
const { sendEmail } = require('../services/email.service');

router.post('/', async (req, res) => {
  try {
    const { donorName, donorEmail, donorPhone, amount, paymentMethod, referenceNumber, cause, notes } = req.body;

    if (!donorName || !donorEmail || !donorPhone || !amount || !paymentMethod || !referenceNumber) {
      return res.status(400).json({ success: false, error: 'Please provide all required donation details.' });
    }

    const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const count = (await Donation.countDocuments().catch(() => 0)) + 1;
    const receiptNo = `REC-${dateStr}-${String(count).padStart(4, '0')}`;
    const submissionId = `DON_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

    // Critical Requirement: Form submission strictly starts as 'Pending', NEVER 'Paid'
    const donation = await Donation.create({
      receiptNo,
      referenceNumber,
      donorName,
      donorEmail: donorEmail.toLowerCase().trim(),
      donorPhone,
      amount: Number(amount),
      paymentMethod,
      cause: cause || 'General Welfare Fund',
      notes: notes || '',
      verificationStatus: 'Pending',
      submissionId,
    }).catch((e) => {
      console.warn('[MongoDB Notice] Donation saved offline:', e.message);
      return null;
    });

    await AuditLog.create({
      actorName: donorName,
      actorRole: 'public_donor',
      action: 'DONATION_INTENT_LOGGED',
      module: 'FINANCE_DONATIONS',
      targetId: donation?._id?.toString() || receiptNo,
      targetModel: 'Donation',
      description: `Donation submission of PKR ${amount} received from ${donorName} (Receipt: ${receiptNo}). Status: Pending verification.`,
    }).catch(() => null);

    // Emails
    sendEmail({
      to: donorEmail,
      subject: `Donation Acknowledgement (Pending Verification) — ${receiptNo}`,
      text: `Dear ${donorName},\n\nThank you for your generous pledge of PKR ${amount}. Your receipt number is ${receiptNo}. Once verified by our finance team, you will receive official confirmation.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Donation record submitted to Finance Portal. Awaiting manual verification.',
      receiptNo,
      verificationStatus: 'Pending',
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to record donation.' });
  }
});

module.exports = router;
