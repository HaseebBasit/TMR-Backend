const https = require('https');
const http = require('http');

async function appendToGoogleSheet(data) {
  const webhookUrl = process.env.GOOGLE_SHEETS_WEBHOOK_URL;
  if (!webhookUrl) {
    return { success: false, reason: 'GOOGLE_SHEETS_WEBHOOK_URL not configured' };
  }

  return new Promise((resolve) => {
    try {
      const url = new URL(webhookUrl);
      const isHttps = url.protocol === 'https:';
      const client = isHttps ? https : http;

      const payload = JSON.stringify(data);
      const req = client.request(
        url,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          },
          timeout: 4000,
        },
        (res) => {
          resolve({ success: res.statusCode >= 200 && res.statusCode < 400 });
        }
      );

      req.on('error', (err) => {
        console.warn('[Google Sheets Sync Notice] Webhook failed:', err.message);
        resolve({ success: false, error: err.message });
      });

      req.write(payload);
      req.end();
    } catch (e) {
      resolve({ success: false, error: e.message });
    }
  });
}

module.exports = { appendToGoogleSheet };
