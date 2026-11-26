const fs = require('fs');
const path = require('path');

const WORKSPACE_ROOT = path.join(__dirname, '..', '..');
const BRAIN_DIR = 'C:/Users/hasee/.gemini/antigravity-cli/brain/83e545b1-f4df-4dc2-b9b4-f6bb6718c4bf';

// Files to delete according to Phase 10E.R:
// - TAMEER_E_REKHTA_ORGANIZATIONAL_ACTIVATION_LINKS.pdf
// - TAMEER_E_REKHTA_ORGANIZATIONAL_DIRECTORY_ORGANIZED.pdf
// - Any previous six department-wise activation PDF exports from earlier attempts.
// - TAMEER_E_REKHTA_ORGANIZATIONAL_ACTIVATION_LINKS_FINAL.pdf
// - Obsolete temporary PDF files

const TARGET_FILENAMES = [
  'TAMEER_E_REKHTA_ORGANIZATIONAL_ACTIVATION_LINKS.pdf',
  'TAMEER_E_REKHTA_ORGANIZATIONAL_DIRECTORY_ORGANIZED.pdf',
  'TAMEER_E_REKHTA_ORGANIZATIONAL_ACTIVATION_LINKS_FINAL.pdf',
  'LITERATURE_ACTIVATION_LINKS.pdf',
  'CONTENT_CREATION_ACTIVATION_LINKS.pdf',
  'OUTREACH_MARKETING_ACTIVATION_LINKS.pdf',
  'MEDIA_ACTIVATION_LINKS.pdf',
  'HR_ACTIVATION_LINKS.pdf',
  'WELFARE_ACTIVATION_LINKS.pdf',
  'test.pdf',
];

console.log('--- FINDING AND REMOVING OLD PDF EXPORTS ---');
const deletedFiles = [];

function checkAndDelete(dir) {
  if (!fs.existsSync(dir)) return;
  const items = fs.readdirSync(dir);
  for (const item of items) {
    if (TARGET_FILENAMES.includes(item)) {
      const fullPath = path.join(dir, item);
      try {
        const stats = fs.statSync(fullPath);
        fs.unlinkSync(fullPath);
        deletedFiles.push({ filename: item, path: fullPath, size: stats.size });
        console.log(`[DELETED] ${item} (${(stats.size / 1024).toFixed(2)} KB) at ${fullPath}`);
      } catch (err) {
        console.error(`[ERROR DELETING] ${fullPath}:`, err.message);
      }
    }
  }
}

// 1. Check workspace root
checkAndDelete(WORKSPACE_ROOT);

// 2. Check backend directory
checkAndDelete(path.join(__dirname, '..'));

// 3. Check brain directory
checkAndDelete(BRAIN_DIR);

console.log(`\nTotal old PDF exports deleted: ${deletedFiles.length}`);

// Output summary as JSON for reporting
fs.writeFileSync(path.join(__dirname, 'deleted-files.json'), JSON.stringify(deletedFiles, null, 2));
