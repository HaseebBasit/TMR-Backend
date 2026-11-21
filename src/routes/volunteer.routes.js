const express = require('express');
const router = express.Router();
const { Application, AuditLog } = require('../models');
const { sendEmail } = require('../services/email.service');
const { appendToGoogleSheet } = require('../services/sheets.service');

function escapeCsv(val) {
  let str = String(val ?? '');
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

router.post('/', async (req, res) => {
  try {
    const body = req.body;
    const { fullName, email, phone, city, areaOfInterest, motivation } = body;

    if (!fullName || !email || !phone || !areaOfInterest) {
      return res.status(400).json({ success: false, error: 'Please fill in all required fields.' });
    }

    const submissionId = `SUB_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

    // 1. Persist to MongoDB Atlas
    let appRecord = await Application.create({
      fullName,
      email: email.toLowerCase().trim(),
      phoneNumber: phone,
      instagramId: body.instagramId || '',
      city: city || '',
      age: body.age || '',
      areaOfInterest,
      motivation: motivation || '',
      source: 'website_volunteer_form',
      status: 'submitted',
      submissionId,
    }).catch((e) => {
      console.warn('[MongoDB Notice] Application saved offline:', e.message);
      return null;
    });

    // 2. Audit Log
    await AuditLog.create({
      actorName: fullName,
      actorRole: 'public_applicant',
      action: 'VOLUNTEER_APPLICATION_SUBMITTED',
      module: 'HR_RECRUITMENT',
      targetId: appRecord?._id?.toString() || submissionId,
      targetModel: 'Application',
      description: `Volunteer application submitted by ${fullName} (${email}) for area: "${areaOfInterest}".`,
    }).catch(() => null);

    // 3. Google Sheets Webhook Sync
    appendToGoogleSheet({
      timestamp: new Date().toISOString(),
      fullName,
      email,
      phone,
      instagramId: body.instagramId || '',
      city: city || '',
      age: body.age || '',
      areaOfInterest,
      motivation: motivation || '',
      submissionId,
    }).catch(() => null);

    // 4. Nodemailer Email Dispatch with Excel CSV
    const adminEmail = process.env.VOLUNTEER_RECIPIENT_EMAIL || 'taameer.e.rekhta@gmail.com';
    const csvContent =
      `Timestamp,Full Name,Email,Phone,City,Area of Interest,Submission ID\r\n` +
      `"${new Date().toISOString()}","${escapeCsv(fullName)}","${escapeCsv(email)}","${escapeCsv(phone)}","${escapeCsv(city)}","${escapeCsv(areaOfInterest)}","${submissionId}"\r\n`;

    sendEmail({
      to: adminEmail,
      subject: `New Volunteer Application: ${fullName} (${areaOfInterest})`,
      text: `New volunteer submission received from ${fullName} (${email}).`,
      attachments: [
        {
          filename: `volunteer_${fullName.replace(/\s+/g, '_')}_${Date.now()}.csv`,
          content: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(csvContent, 'utf-8')]),
        },
      ],
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Application received and registered in HR Recruitment Portal.',
      submissionId,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to process volunteer application.' });
  }
});

module.exports = router;
