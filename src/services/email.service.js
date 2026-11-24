const nodemailer = require('nodemailer');

function getTransporter() {
  if (process.env.EMAIL_DISABLED === 'true') {
    return null;
  }

  const host = process.env.SMTP_HOST || 'smtp.gmail.com';
  const port = Number(process.env.SMTP_PORT) || 587;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!user || !pass) {
    return null;
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
  });
}

async function sendEmail({ to, subject, text, html, attachments }) {
  if (process.env.EMAIL_DISABLED === 'true') {
    console.log(`[Email Service Sink] Email disabled via EMAIL_DISABLED=true. Suppressed outbound email for: ${to} (Subject: "${subject}")`);
    return { success: true, mode: 'disabled_sink', messageId: `mock-sink-${Date.now()}` };
  }

  const transporter = getTransporter();
  const from = process.env.SMTP_FROM || `"Ta'meer-e-Rekhta" <${process.env.SMTP_USER || 'no-reply@rekhta.org'}>`;

  if (!transporter) {
    console.warn(`[Email Service Notice] SMTP not fully configured. Email skipped for: ${to} (Subject: "${subject}")`);
    return { success: false, mode: 'mock' };
  }

  try {
    const info = await transporter.sendMail({
      from,
      to,
      subject,
      text,
      html,
      attachments,
    });
    console.log(`[Email Service] Dispatched email to ${to} (MessageId: ${info.messageId})`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error(`[Email Service Error] Failed to send email to ${to}:`, error.message);
    return { success: false, error: error.message };
  }
}

module.exports = { sendEmail, getTransporter };
