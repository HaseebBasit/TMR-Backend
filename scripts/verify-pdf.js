const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env') });
const { User } = require('../src/models');

async function verifyStrictNoInternalIds(filePath) {
  await mongoose.connect(process.env.MONGODB_URI);
  const users = await User.find().lean();
  const userIds = users.map((u) => u._id.toString());
  const tokenHashes = users.map((u) => u.activationToken).filter(Boolean);

  await mongoose.disconnect();

  const buf = fs.readFileSync(filePath);
  const str = buf.toString('latin1');

  // Decompress all streams and decode hex text
  let decodedText = str;
  const streamRegex = /stream[\r\n]+([\s\S]*?)[\r\n]+endstream/g;
  let match;
  while ((match = streamRegex.exec(str)) !== null) {
    try {
      const d = zlib.inflateSync(Buffer.from(match[1], 'latin1')).toString('latin1');
      // Replace hex chunks <...> with their ascii characters
      const ascii = d.replace(/<([0-9a-fA-F]+)>/g, (_, hex) => {
        try {
          return Buffer.from(hex, 'hex').toString('latin1');
        } catch {
          return '';
        }
      });
      decodedText += '\n' + ascii;
    } catch {}
  }

  // 1. Check if ANY user ObjectId appears in the PDF
  const exposedUserIds = userIds.filter((id) => decodedText.includes(id));
  console.log(`[Check 1: ObjectIds] Exposed User ObjectIds in PDF: ${exposedUserIds.length}`);

  // 2. Check if ANY activation token hash appears in the PDF
  const exposedTokenHashes = tokenHashes.filter((h) => decodedText.includes(h) || decodedText.includes(h.substring(0, 12)));
  console.log(`[Check 2: Token Hashes] Exposed Token Hashes in PDF: ${exposedTokenHashes.length}`);

  // 3. Check for technical labels
  const technicalTerms = ['ObjectId', 'activationToken', 'tokenVersion', 'SHA-256', 'tameer_rekhta'];
  const exposedTerms = technicalTerms.filter((term) => decodedText.includes(term));
  console.log(`[Check 3: Technical Terms] Exposed Technical Terms: ${exposedTerms.join(', ') || 'None (Clean)'}`);

  // 4. Check for PKT
  const hasPkt = decodedText.includes('PKT');
  console.log(`[Check 4: PKT Timestamp] Contains Pakistan Standard Time: ${hasPkt}`);

  console.log(`\nVerification Result: ${exposedUserIds.length === 0 && exposedTokenHashes.length === 0 && exposedTerms.length === 0 && hasPkt ? '100% CLEAN & VERIFIED' : 'NEEDS ATTENTION'}`);
}

verifyStrictNoInternalIds(path.join(__dirname, '..', '..', 'TAMEER_E_REKHTA_ORGANIZATIONAL_ACTIVATION_LINKS_FINAL.pdf')).catch(console.error);
