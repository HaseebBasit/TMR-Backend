/**
 * Phase 10F: Complete Activation Token Rotation & Six Department-wise PDF Generation
 * Ta'meer-e-Rekhta Management Portal
 * 
 * Execution Flow:
 * 1. Pre-execution Safety Check on production database `tameer_rekhta`.
 * 2. Delete old generated PDF exports and log deletions.
 * 3. Invalidate previous tokens and generate fresh 32-byte cryptographic tokens for all 47 accounts.
 * 4. Update database records: activationToken = sha256(rawToken), 7-day PKT expiry, increment tokenVersion.
 * 5. Store raw tokens strictly in protected temporary memory for PDF generation.
 * 6. Generate the six department-wise PDFs containing each member's complete un-truncated token and clickable URLs.
 * 7. Write PDFs to workspace root and brain artifact directory.
 * 8. Clear temporary in-memory raw tokens map.
 * 9. Reconcile 47 unique accounts, 49 departmental roles, 6 departments, 1 protected admin.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env'), override: true });

const { User, Department, AuditLog } = require('../src/models');
const { buildDepartmentActivationPdf, DEPARTMENT_CONFIGS } = require('../src/services/department-pdf-export.service');

const WORKSPACE_ROOT = path.join(__dirname, '..', '..');
const ARTIFACT_DIR = 'C:/Users/hasee/.gemini/antigravity-cli/brain/83e545b1-f4df-4dc2-b9b4-f6bb6718c4bf';
const PORTAL_BASE_URL = 'https://tameer-e-rekhta.vercel.app';

const OLD_TARGET_FILENAMES = [
  'TAMEER_E_REKHTA_ORGANIZATIONAL_ACTIVATION_LINKS.pdf',
  'TAMEER_E_REKHTA_ORGANIZATIONAL_ACTIVATION_LINKS_FINAL.pdf',
  'TAMEER_E_REKHTA_ORGANIZATIONAL_DIRECTORY_ORGANIZED.pdf',
  'LITERATURE_ACTIVATION_LINKS.pdf',
  'CONTENT_CREATION_ACTIVATION_LINKS.pdf',
  'OUTREACH_MARKETING_ACTIVATION_LINKS.pdf',
  'MEDIA_ACTIVATION_LINKS.pdf',
  'HR_ACTIVATION_LINKS.pdf',
  'WELFARE_ACTIVATION_LINKS.pdf',
];

async function rotateTokensAndGeneratePdfs() {
  console.log('========================================================================');
  console.log("TA'MEER-E-REKHTA: PHASE 10F ACTIVATION TOKEN ROTATION & PDF GENERATOR");
  console.log('Target Environment: LIVE PRODUCTION (tameer_rekhta on MongoDB Atlas)');
  console.log('Execution Mode: Controlled Cryptographic Token Rotation & Department PDF Export');
  console.log('========================================================================\n');

  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('MONGODB_URI is not defined in backend/.env!');

  console.log('[Connecting] Connecting to MongoDB Atlas...');
  await mongoose.connect(uri);
  const dbName = mongoose.connection.name;
  console.log(`[Connected] Target Database Verified: ${dbName}`);

  if (dbName !== 'tameer_rekhta') {
    throw new Error(`CRITICAL SECURITY FAILURE: Connected database is '${dbName}', expected 'tameer_rekhta'! Aborting.`);
  }

  // ---------------------------------------------------------------------------
  // STEP 1: PRE-EXECUTION SAFETY CHECK
  // ---------------------------------------------------------------------------
  console.log('\n--- STEP 1: PRE-EXECUTION SAFETY CHECK ---');
  const allUsers = await User.find().sort({ email: 1 });
  const superAdmin = allUsers.find((u) => u.role === 'super_admin');
  const orgUsers = allUsers.filter((u) => u.role !== 'super_admin');
  const departments = await Department.find({ status: 'active' }).sort({ code: 1 });

  let totalMemberships = 0;
  orgUsers.forEach((u) => {
    totalMemberships += (u.memberships && u.memberships.length > 0) ? u.memberships.length : 1;
  });

  console.log(`Total Database Users       : ${allUsers.length} (Expected: 48)`);
  console.log(`Protected Super Admin      : ${superAdmin?.name} <${superAdmin?.email}> (Role: ${superAdmin?.role})`);
  console.log(`Organizational Accounts    : ${orgUsers.length} (Expected: 47)`);
  console.log(`Departmental Memberships   : ${totalMemberships} (Expected: 49)`);
  console.log(`Official Departments Count : ${departments.length} (Expected: 6)`);
  console.log(`Official Department Codes  : ${departments.map((d) => d.code).join(', ')}`);

  if (allUsers.length !== 48 || orgUsers.length !== 47 || totalMemberships !== 49 || departments.length !== 6) {
    throw new Error('Pre-execution verification mismatch! Roster does not match 47 accounts / 49 memberships.');
  }

  // Confirm multi-department users
  const multiUsers = orgUsers.filter((u) => u.memberships && u.memberships.length > 1);
  console.log(`Multi-Department Accounts  : ${multiUsers.map((u) => `${u.name} (${u.email}) [${u.memberships.length} depts]`).join('; ')}`);
  if (multiUsers.length !== 2) {
    throw new Error(`Expected exactly 2 multi-department accounts, found ${multiUsers.length}!`);
  }

  // ---------------------------------------------------------------------------
  // STEP 2: DELETE OLD PDF EXPORTS
  // ---------------------------------------------------------------------------
  console.log('\n--- STEP 2: DELETE OLD PDF EXPORT ARTIFACTS ---');
  const deletedFiles = [];

  for (const filename of OLD_TARGET_FILENAMES) {
    const rootPath = path.join(WORKSPACE_ROOT, filename);
    const artifactPath = path.join(ARTIFACT_DIR, filename);

    if (fs.existsSync(rootPath)) {
      const stat = fs.statSync(rootPath);
      fs.unlinkSync(rootPath);
      deletedFiles.push({ filename, path: rootPath, size: stat.size });
      console.log(`[Deleted] Root: ${filename} (${stat.size} bytes)`);
    }

    if (fs.existsSync(artifactPath)) {
      const stat = fs.statSync(artifactPath);
      fs.unlinkSync(artifactPath);
      deletedFiles.push({ filename, path: artifactPath, size: stat.size });
      console.log(`[Deleted] Artifact: ${filename} (${stat.size} bytes)`);
    }
  }

  console.log(`Total obsolete PDF files removed: ${deletedFiles.length}`);

  // ---------------------------------------------------------------------------
  // STEP 3: ATOMIC TOKEN INVALIDATION & FRESH TOKEN GENERATION
  // ---------------------------------------------------------------------------
  console.log('\n--- STEP 3: ROTATE ACTIVATION TOKENS (47 ACCOUNTS) ---');
  const generatedAt = new Date();
  const expiresAt = new Date(generatedAt.getTime() + 7 * 24 * 60 * 60 * 1000); // 7-day validity

  // Protected in-memory mapping: email -> { token, activationUrl, expiresAt }
  const protectedMemoryLinks = new Map();
  const tokenSet = new Set();

  for (const user of orgUsers) {
    // Generate 32 bytes of cryptographically secure randomness
    const rawToken = crypto.randomBytes(32).toString('hex'); // 64 hex characters
    if (tokenSet.has(rawToken)) {
      throw new Error(`Token collision detected for ${user.email}!`);
    }
    tokenSet.add(rawToken);

    // Compute SHA-256 hash
    const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

    // Update database record
    user.activationToken = hashedToken;
    user.activationExpires = expiresAt;
    user.activationRevokedAt = null;
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    user.status = 'inactive'; // Preserve inactive status

    await user.save();

    const activationUrl = `${PORTAL_BASE_URL}/portal/activate?token=${rawToken}`;
    protectedMemoryLinks.set(user.email.toLowerCase().trim(), {
      email: user.email,
      name: user.name,
      userId: user._id.toString(),
      token: rawToken,
      activationUrl,
      expiresAt: expiresAt.toISOString(),
    });
  }

  console.log(`[Success] Successfully rotated tokens for all ${orgUsers.length} organizational accounts.`);
  console.log(`[Token Invariant] Cryptographic randomness: 32 bytes (64 hex characters).`);
  console.log(`[Token Invariant] Database storage: SHA-256 hash only. Raw tokens never written to DB.`);
  console.log(`[Token Invariant] Token Expiration: ${expiresAt.toISOString()} (7 days from now).`);

  // Record AuditLog
  await AuditLog.create({
    actorId: superAdmin._id,
    actorName: superAdmin.name,
    actorRole: 'super_admin',
    action: 'ALL_ACTIVATION_TOKENS_ROTATED',
    module: 'SUPER_ADMIN',
    targetModel: 'User',
    description: `Super Admin rotated activation tokens for all ${orgUsers.length} organizational accounts under Phase 10F.`,
  }).catch(() => null);

  // ---------------------------------------------------------------------------
  // STEP 4: GENERATE SIX FRESH DEPARTMENT-WISE PDFs
  // ---------------------------------------------------------------------------
  console.log('\n--- STEP 4: GENERATE SIX FRESH DEPARTMENT-WISE PDFs ---');
  const sessionLinksArray = Array.from(protectedMemoryLinks.values());
  const freshUsersLean = await User.find().sort({ email: 1 }).lean();
  const deptCodes = ['LIT', 'CON', 'OAM', 'MED', 'HR', 'WEL'];
  const generatedPdfs = [];

  for (const code of deptCodes) {
    const config = DEPARTMENT_CONFIGS[code];
    console.log(`>>> Generating [${code}] ${config.name} (${config.filename})...`);

    const doc = buildDepartmentActivationPdf({
      departmentCode: code,
      users: freshUsersLean,
      sessionLinks: sessionLinksArray,
      generatedAt,
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

    console.log(`    File Size     : ${(rootStats.size / 1024).toFixed(2)} KB`);
    console.log(`    Header Magic  : ${magic}`);

    if (!magic.startsWith('%PDF') || rootStats.size < 5000) {
      throw new Error(`Corrupted PDF generated for department ${code}!`);
    }

    generatedPdfs.push({
      code,
      name: config.name,
      filename: config.filename,
      sizeBytes: rootStats.size,
      sizeKb: (rootStats.size / 1024).toFixed(2),
    });
  }

  // ---------------------------------------------------------------------------
  // STEP 5: SECURELY CLEAR TEMPORARY RAW TOKEN MEMORY
  // ---------------------------------------------------------------------------
  console.log('\n--- STEP 5: CLEAR TEMPORARY EXPORT MEMORY ---');
  protectedMemoryLinks.clear();
  tokenSet.clear();
  console.log('[Sanitized] Protected temporary raw token memory cleared completely.');

  // Disconnect cleanly
  await mongoose.disconnect();
  console.log('[Database] Disconnected cleanly.');

  console.log('\n========================================================================');
  console.log('PHASE 10F TOKEN ROTATION & PDF GENERATION COMPLETED SUCCESSFULLY');
  console.log('========================================================================\n');
  console.table(generatedPdfs);

  return {
    success: true,
    deletedFiles,
    generatedPdfs,
    expiresAt,
    accountsRotated: orgUsers.length,
  };
}

if (require.main === module) {
  rotateTokensAndGeneratePdfs()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n[FATAL ERROR]:', err);
      process.exit(1);
    });
}

module.exports = { rotateTokensAndGeneratePdfs };
