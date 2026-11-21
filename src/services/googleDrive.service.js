const { google } = require('googleapis');
const stream = require('stream');

const GOOGLE_DRIVE_FOLDER_ID = process.env.GOOGLE_DRIVE_FOLDER_ID || '1MockDriveFolderIdRekhta2026';

function getDriveClient() {
  const clientEmail = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const privateKey = process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY?.replace(/\\n/g, '\n');

  if (!clientEmail || !privateKey) {
    return null;
  }

  const auth = new google.auth.JWT(clientEmail, null, privateKey, [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.file',
  ]);

  return google.drive({ version: 'v3', auth });
}

async function uploadFileToDrive({ buffer, fileName, mimeType, folderId }) {
  const drive = getDriveClient();
  const targetFolder = folderId || GOOGLE_DRIVE_FOLDER_ID;

  if (!drive) {
    console.warn('[Google Drive Notice] Google credentials not provided. Using offline mock storage.');
    const mockId = `mock_drive_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    return {
      fileId: mockId,
      url: `/images/gallery/${fileName}`,
      thumbnailUrl: `/images/gallery/${fileName}`,
      isMock: true,
    };
  }

  const bufferStream = new stream.PassThrough();
  bufferStream.end(buffer);

  const fileMetadata = {
    name: fileName,
    parents: [targetFolder],
  };

  const media = {
    mimeType,
    body: bufferStream,
  };

  const response = await drive.files.create({
    resource: fileMetadata,
    media,
    fields: 'id, name, webViewLink, webContentLink',
  });

  const fileId = response.data.id;
  await drive.permissions
    .create({
      fileId,
      requestBody: { role: 'reader', type: 'anyone' },
    })
    .catch(() => null);

  const directUrl = `https://lh3.googleusercontent.com/d/${fileId}`;

  return {
    fileId,
    url: directUrl,
    thumbnailUrl: directUrl,
    isMock: false,
  };
}

module.exports = { uploadFileToDrive, getDriveClient };
