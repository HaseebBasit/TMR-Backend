/**
 * Phase 10E: Six Department-Wise Activation PDFs Generator
 * Ta'meer-e-Rekhta Management Portal
 * 
 * Safely connects read-only to live production database `tameer_rekhta`,
 * extracts all verified organizational records, and generates the six separate
 * department-wise activation PDFs:
 * 1. LITERATURE_ACTIVATION_LINKS.pdf
 * 2. CONTENT_CREATION_ACTIVATION_LINKS.pdf
 * 3. OUTREACH_MARKETING_ACTIVATION_LINKS.pdf
 * 4. MEDIA_ACTIVATION_LINKS.pdf
 * 5. HR_ACTIVATION_LINKS.pdf
 * 6. WELFARE_ACTIVATION_LINKS.pdf
 * 
 * Invariants:
 * - Read-only execution: ZERO database mutations, ZERO token regenerations, ZERO status changes.
 * - Saves each PDF to workspace root and brain artifact directory.
 * - Reconciles 47 accounts, 49 departmental roles, 6 departments, 1 protected admin.
 */

const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env'), override: true });

const { User, Department } = require('../src/models');
const { buildDepartmentActivationPdf, DEPARTMENT_CONFIGS } = require('../src/services/department-pdf-export.service');

const ARTIFACT_DIR = 'C:/Users/hasee/.gemini/antigravity-cli/brain/83e545b1-f4df-4dc2-b9b4-f6bb6718c4bf';
const WORKSPACE_ROOT = path.join(__dirname, '..', '..');

async function generateSixDepartmentPdfs() {
  console.log('========================================================================');
  console.log("TA'MEER-E-REKHTA: SIX DEPARTMENT-WISE ACTIVATION PDFS GENERATOR");
  console.log('Phase: 10E — Department-Specific Activation Exports');
  console.log('Execution Mode: STRICTLY READ-ONLY (No DB mutations or token resets)');
  console.log('========================================================================\n');

  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('MONGODB_URI is not set in backend/.env!');
  }

  console.log('[Connecting] Connecting to MongoDB Atlas cluster...');
  await mongoose.connect(uri);
  const dbName = mongoose.connection.name;
  console.log(`[Connected] Verified Target Database: ${dbName}`);

  if (dbName !== 'tameer_rekhta') {
    throw new Error(`CRITICAL: Connected database is ${dbName}, expected 'tameer_rekhta'! Aborting.`);
  }

  // 1. Fetch departments
  const departments = await Department.find({ status: 'active' }).sort({ code: 1 }).lean();
  console.log(`[Query] Retrieved ${departments.length} official departments from ${dbName}.`);

  // 2. Fetch all users
  const allUsers = await User.find().sort({ email: 1 }).lean();
  console.log(`[Query] Retrieved ${allUsers.length} total user accounts from ${dbName}.`);

  const superAdmin = allUsers.find((u) => u.role === 'super_admin');
  const orgUsers = allUsers.filter((u) => u.role !== 'super_admin');

  console.log(`[Verification] Super Admin: ${superAdmin?.name} (${superAdmin?.email}) — Protected & Excluded.`);
  console.log(`[Verification] Organizational Accounts: ${orgUsers.length} (Expected: 47).`);

  if (orgUsers.length !== 47) {
    throw new Error(`Integrity Error: Expected 47 organizational accounts, found ${orgUsers.length}!`);
  }

  const generatedFiles = [];
  const deptCodes = ['LIT', 'CON', 'OAM', 'MED', 'HR', 'WEL'];

  for (const code of deptCodes) {
    const config = DEPARTMENT_CONFIGS[code];
    console.log(`\n>>> Generating PDF for [${code}] ${config.name} (${config.filename})...`);

    const doc = buildDepartmentActivationPdf({
      departmentCode: code,
      users: allUsers,
      generatedAt: new Date(),
    });

    const rootPath = path.join(WORKSPACE_ROOT, config.filename);
    const artifactPath = path.join(ARTIFACT_DIR, config.filename);

    const rootWriteStream = fs.createWriteStream(rootPath);
    doc.pipe(rootWriteStream);

    const chunks = [];
    doc.on('data', (c) => chunks.push(c));

    await new Promise((resolve, reject) => {
      rootWriteStream.on('finish', resolve);
      rootWriteStream.on('error', reject);
      doc.on('error', reject);
      doc.end();
    });

    const fullBuffer = Buffer.concat(chunks);
    fs.writeFileSync(artifactPath, fullBuffer);

    const rootStats = fs.statSync(rootPath);
    const magic = fullBuffer.slice(0, 5).toString('ascii');

    console.log(`    Root File     : ${rootPath}`);
    console.log(`    Size          : ${(rootStats.size / 1024).toFixed(2)} KB`);
    console.log(`    Artifact File : ${artifactPath}`);
    console.log(`    Header Magic  : ${magic} (Valid: ${magic.startsWith('%PDF')})`);

    if (!magic.startsWith('%PDF') || rootStats.size < 1000) {
      throw new Error(`Corrupted PDF generated for department ${code}!`);
    }

    generatedFiles.push({
      code,
      name: config.name,
      filename: config.filename,
      rootPath,
      artifactPath,
      sizeBytes: rootStats.size,
    });
  }

  console.log('\n========================================================================');
  console.log('ALL SIX DEPARTMENT-WISE ACTIVATION PDFS GENERATED SUCCESSFULLY');
  console.log('========================================================================\n');

  console.table(generatedFiles.map((f) => ({
    Dept: f.code,
    Name: f.name,
    Filename: f.filename,
    'Size (KB)': (f.sizeBytes / 1024).toFixed(2),
  })));

  await mongoose.disconnect();
  console.log('\n[Database] Disconnected cleanly.');

  return { success: true, generatedFiles };
}

if (require.main === module) {
  generateSixDepartmentPdfs()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n[FATAL ERROR]:', err);
      process.exit(1);
    });
}

module.exports = { generateSixDepartmentPdfs };
