const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env') });
const { User } = require('../src/models');

const ARTIFACT_DIR = 'C:/Users/hasee/.gemini/antigravity-cli/brain/83e545b1-f4df-4dc2-b9b4-f6bb6718c4bf';
const WORKSPACE_ROOT = path.join(__dirname, '..', '..');

const EXPECTED_FILES = [
  { code: 'LIT', filename: 'LITERATURE_ACTIVATION_LINKS.pdf', expectedEntries: 15 },
  { code: 'CON', filename: 'CONTENT_CREATION_ACTIVATION_LINKS.pdf', expectedEntries: 7 },
  { code: 'OAM', filename: 'OUTREACH_MARKETING_ACTIVATION_LINKS.pdf', expectedEntries: 5 },
  { code: 'MED', filename: 'MEDIA_ACTIVATION_LINKS.pdf', expectedEntries: 5 },
  { code: 'HR',  filename: 'HR_ACTIVATION_LINKS.pdf', expectedEntries: 7 },
  { code: 'WEL', filename: 'WELFARE_ACTIVATION_LINKS.pdf', expectedEntries: 10 },
];

async function verifySixPdfs() {
  await mongoose.connect(process.env.MONGODB_URI);
  const users = await User.find().lean();
  const userIds = users.map((u) => u._id.toString());
  const tokenHashes = users.map((u) => u.activationToken).filter(Boolean);
  await mongoose.disconnect();

  console.log('========================================================================');
  console.log('VERIFYING SIX DEPARTMENT ACTIVATION PDFS');
  console.log('========================================================================\n');

  let allClean = true;

  for (const f of EXPECTED_FILES) {
    const rootPath = path.join(WORKSPACE_ROOT, f.filename);
    const artifactPath = path.join(ARTIFACT_DIR, f.filename);

    if (!fs.existsSync(rootPath)) throw new Error(`Missing root file: ${rootPath}`);
    if (!fs.existsSync(artifactPath)) throw new Error(`Missing artifact file: ${artifactPath}`);

    const buf = fs.readFileSync(rootPath);
    const str = buf.toString('latin1');
    const pageMatches = str.match(/\/Type\s*\/Page\b/g);
    const pages = pageMatches ? pageMatches.length : 0;

    // Decode streams
    let decodedText = str;
    const streamRegex = /stream[\r\n]+([\s\S]*?)[\r\n]+endstream/g;
    let match;
    while ((match = streamRegex.exec(str)) !== null) {
      try {
        const d = zlib.inflateSync(Buffer.from(match[1], 'latin1')).toString('latin1');
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

    // Check forbidden internal exposures
    const exposedIds = userIds.filter((id) => decodedText.includes(id));
    const exposedHashes = tokenHashes.filter((h) => decodedText.includes(h) || decodedText.includes(h.substring(0, 16)));
    const technicalTerms = ['ObjectId', 'activationToken', 'tokenVersion', 'SHA-256', 'tameer_rekhta'].filter((t) => decodedText.includes(t));

    const isClean = exposedIds.length === 0 && exposedHashes.length === 0 && technicalTerms.length === 0;
    if (!isClean) allClean = false;

    console.log(`[${f.code}] ${f.filename.padEnd(42)} | Pages: ${pages} | Size: ${(buf.length / 1024).toFixed(2).padStart(5)} KB | Clean: ${isClean ? 'YES' : 'NO'} | PKT: ${decodedText.includes('PKT') ? 'YES' : 'NO'}`);
  }

  console.log(`\nAll 6 Department PDFs Verified: ${allClean ? '100% CLEAN & COMPLIANT' : 'FAILURES DETECTED'}\n`);
}

verifySixPdfs().catch(console.error);
