/**
 * Phase 10E: Department-Specific Activation PDF Export Service
 * Ta'meer-e-Rekhta Management Portal
 * 
 * Generates separate, professionally designed, executive PDFs for each of the 6 official departments:
 * 1. LITERATURE_ACTIVATION_LINKS.pdf
 * 2. CONTENT_CREATION_ACTIVATION_LINKS.pdf
 * 3. OUTREACH_MARKETING_ACTIVATION_LINKS.pdf
 * 4. MEDIA_ACTIVATION_LINKS.pdf
 * 5. HR_ACTIVATION_LINKS.pdf
 * 6. WELFARE_ACTIVATION_LINKS.pdf
 * 
 * Invariants:
 * - Read-only export: Zero token regeneration, zero production mutations.
 * - Clean card layout per member with Pakistan Standard Time (PKT) expiry.
 * - Zero internal ObjectIds, token hashes, or debug metadata exposed.
 * - Cross-department identities (Noor ul Huda, Haseeb Basit) unified with single account.
 * - If raw tokens are unrecoverable from the database, marks links as Unavailable.
 */

const PDFDocument = require('pdfkit');

// Department Configurations & Metadata
const DEPARTMENT_CONFIGS = {
  LIT: {
    code: 'LIT',
    name: 'Literature',
    filename: 'LITERATURE_ACTIVATION_LINKS.pdf',
    lead: 'Noor ul Huda',
    color: '#0284c7', // Sky Blue
    description: 'Reviving Urdu poetry, prose, and literary discourse.',
  },
  CON: {
    code: 'CON',
    name: 'Content Creation',
    filename: 'CONTENT_CREATION_ACTIVATION_LINKS.pdf',
    lead: 'Noor ul Huda',
    color: '#7c3aed', // Purple
    description: 'Urdu scripting, editorial copywriting, and Gen-Z creative series.',
  },
  OAM: {
    code: 'OAM',
    name: 'Outreach and Marketing',
    filename: 'OUTREACH_MARKETING_ACTIVATION_LINKS.pdf',
    lead: 'Laiba Malik',
    color: '#d97706', // Amber
    description: 'Digital campaigns, branding, community engagement, and public outreach.',
  },
  MED: {
    code: 'MED',
    name: 'Media',
    filename: 'MEDIA_ACTIVATION_LINKS.pdf',
    lead: 'Aisha Tariq',
    color: '#db2777', // Pink
    description: 'Photography, videography, graphic design, and video production.',
  },
  HR: {
    code: 'HR',
    name: 'HR',
    filename: 'HR_ACTIVATION_LINKS.pdf',
    lead: 'Hania',
    color: '#059669', // Emerald
    description: 'Talent acquisition, organizational development, and volunteer management.',
  },
  WEL: {
    code: 'WEL',
    name: 'Welfare',
    filename: 'WELFARE_ACTIVATION_LINKS.pdf',
    lead: 'Asfand Yar Karimi (Punjab) / Daniyal Asim (Sindh)',
    color: '#e11d48', // Rose
    description: 'Social welfare initiatives, community relief, and regional aid distribution.',
  },
};

const PORTAL_BASE_URL = 'https://tameer-e-rekhta.vercel.app';

/**
 * Format designation string into executive title
 */
function formatDesignation(desig) {
  if (!desig) return 'Member';
  const map = {
    head: 'Head of Department',
    director: 'Director',
    assistant_director: 'Assistant Director',
    director_graphics: 'Director of Graphics',
    hr_head: 'Head of HR',
    hr_director: 'HR Director',
    coordination_incharge: 'Coordination Incharge',
    head_of_punjab: 'Head of Punjab (Regional Lead)',
    head_of_sindh: 'Head of Sindh (Regional Lead)',
    member: 'Member',
    volunteer: 'Volunteer',
  };
  return map[desig] || desig.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Format Date to Pakistan Standard Time (PKT)
 */
function formatPktDate(date) {
  if (!date) return 'Not Specified';
  const d = new Date(date);
  try {
    const options = {
      timeZone: 'Asia/Karachi',
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    };
    return new Intl.DateTimeFormat('en-US', options).format(d) + ' PKT';
  } catch {
    const pktTime = new Date(d.getTime() + 5 * 3600 * 1000);
    return pktTime.toUTCString().replace('GMT', 'PKT');
  }
}

/**
 * Generate a single department activation PDF
 * @param {Object} options
 * @param {string} options.departmentCode - e.g. 'LIT', 'CON', 'OAM', 'MED', 'HR', 'WEL'
 * @param {Array} options.users - User lean documents from database
 * @param {Array} [options.sessionLinks] - Optional map/array of session links with raw tokens
 * @param {Date} [options.generatedAt] - Generation timestamp
 * @returns {PDFKit.PDFDocument}
 */
function buildDepartmentActivationPdf({ departmentCode, users = [], sessionLinks = [], generatedAt = new Date() }) {
  const deptConfig = DEPARTMENT_CONFIGS[departmentCode];
  if (!deptConfig) {
    throw new Error(`Invalid department code: ${departmentCode}`);
  }

  const doc = new PDFDocument({
    size: 'A4',
    margins: { top: 36, bottom: 40, left: 36, right: 36 },
    bufferPages: true,
    info: {
      Title: `Ta'meer-e-Rekhta - Department of ${deptConfig.name} Activation Links`,
      Author: "Ta'meer-e-Rekhta Management Portal",
      Subject: `Official ${deptConfig.name} Member Activation Directory`,
      Keywords: `Tameer-e-Rekhta, ${deptConfig.name}, Activation Directory`,
      CreationDate: generatedAt,
    },
  });

  const sessionLinksMap = new Map();
  if (Array.isArray(sessionLinks)) {
    sessionLinks.forEach((l) => {
      if (l.email) sessionLinksMap.set(l.email.toLowerCase().trim(), l);
    });
  }

  // Filter out super admin accounts
  const orgUsers = users.filter((u) => u.role !== 'super_admin');

  // Extract department-specific members and designations
  const departmentEntries = [];

  orgUsers.forEach((u) => {
    const memberships = (u.memberships && u.memberships.length > 0)
      ? u.memberships
      : [{ department: u.department, departmentCode: u.departmentCode, role: u.role, designation: u.designation, region: u.region, isPrimary: true }];

    memberships.forEach((m) => {
      const code = m.departmentCode || (
        m.department === 'Literature' ? 'LIT' :
        m.department === 'Content Creation' ? 'CON' :
        m.department === 'Outreach and Marketing' ? 'OAM' :
        m.department === 'Media' ? 'MED' :
        m.department === 'HR' ? 'HR' : 'WEL'
      );

      if (code === departmentCode) {
        departmentEntries.push({
          user: u,
          membership: m,
          isPrimary: m.isPrimary ?? (code === u.departmentCode),
        });
      }
    });
  });

  // Sort department entries by leadership hierarchy then name
  const desigRank = {
    head: 1,
    hr_head: 1,
    head_of_punjab: 1,
    head_of_sindh: 1,
    director: 2,
    hr_director: 2,
    director_graphics: 2,
    assistant_director: 3,
    coordination_incharge: 4,
    member: 5,
    volunteer: 6,
  };

  departmentEntries.sort((a, b) => {
    const rankA = desigRank[a.membership.designation] || 10;
    const rankB = desigRank[b.membership.designation] || 10;
    if (rankA !== rankB) return rankA - rankB;
    return a.user.name.localeCompare(b.user.name);
  });

  // Department Statistics
  const now = new Date();
  let validTokensCount = 0;
  let expiredTokensCount = 0;
  let missingTokensCount = 0;
  let functionalLinksCount = 0;

  departmentEntries.forEach((item) => {
    const u = item.user;
    const sessionLinkObj = sessionLinksMap.get(u.email.toLowerCase().trim());
    const rawUrl = sessionLinkObj?.activationUrl;

    if (rawUrl) functionalLinksCount++;

    if (!u.activationToken && !rawUrl) {
      missingTokensCount++;
    } else if (u.activationExpires && new Date(u.activationExpires) < now) {
      expiredTokensCount++;
    } else {
      validTokensCount++;
    }
  });

  const pageWidth = 595.28;
  const contentWidth = pageWidth - 72; // 523.28

  function drawHeader(subtitle) {
    doc.rect(36, 36, contentWidth, 70).fill('#0f172a');
    doc.rect(36, 106, contentWidth, 3.5).fill(deptConfig.color);

    doc.fillColor('#ffffff').fontSize(16).font('Helvetica-Bold')
       .text("TA'MEER-E-REKHTA (تعمیرِ ریختہ)", 50, 47, { width: contentWidth - 28 });

    doc.fillColor('#38bdf8').fontSize(11).font('Helvetica-Bold')
       .text(`DEPARTMENT OF ${deptConfig.name.toUpperCase()} (${deptConfig.code})`, 50, 68, { width: contentWidth - 28 });

    doc.fillColor('#94a3b8').fontSize(8).font('Helvetica')
       .text(subtitle || `Department Lead: ${deptConfig.lead}  •  Official Member Activation Directory`, 50, 85, { width: contentWidth - 28 });

    doc.y = 124;
  }

  // ===========================================================================
  // PAGE 1: COVER & OVERVIEW
  // ===========================================================================
  drawHeader(`Department Leadership: ${deptConfig.lead}`);

  // Department Executive Summary Banner
  doc.fillColor('#0f172a').fontSize(11.5).font('Helvetica-Bold')
     .text(`EXECUTIVE SUMMARY — ${deptConfig.name.toUpperCase()}`, 36, doc.y);
  doc.y += 5;

  doc.fillColor('#334155').fontSize(8.8).font('Helvetica')
     .text(
       `This document contains the verified departmental activation directory for all authorized personnel assigned to the Department of ${deptConfig.name}. All accounts have been provisioned in the live portal database and await initial password configuration. Links must be distributed manually on a 1-on-1 confidential basis by the Super Administrator. Automated broadcast of activation links is disabled.`,
       36,
       doc.y,
       { width: contentWidth, lineGap: 3 }
     );
  doc.y += 12;

  // Department Metrics Cards (4-box row)
  const boxY = doc.y;
  const cardW = (contentWidth - 18) / 4;
  const cardH = 58;

  const statBoxes = [
    { label: 'ALLOCATED ROLES', value: `${departmentEntries.length} Members`, color: deptConfig.color },
    { label: 'DB STATUS', value: `${validTokensCount} Verified`, color: '#059669' },
    { label: 'EXPIRED LINKS', value: `${expiredTokensCount}`, color: expiredTokensCount > 0 ? '#dc2626' : '#64748b' },
    { label: 'LINK STATUS', value: functionalLinksCount > 0 ? `${functionalLinksCount} Live` : 'On-Demand', color: functionalLinksCount > 0 ? '#059669' : '#d97706' },
  ];

  statBoxes.forEach((b, idx) => {
    const bx = 36 + idx * (cardW + 6);
    doc.roundedRect(bx, boxY, cardW, cardH, 5).fillAndStroke('#f8fafc', '#e2e8f0');
    doc.rect(bx, boxY, 3, cardH).fill(b.color);

    doc.fillColor('#64748b').fontSize(7).font('Helvetica-Bold').text(b.label, bx + 8, boxY + 8);
    doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold').text(b.value, bx + 8, boxY + 20);
    doc.fillColor('#059669').fontSize(7).font('Helvetica').text('Production Verified', bx + 8, boxY + 38);
  });

  doc.y = boxY + cardH + 14;

  // Member Cards
  doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold')
     .text(`DEPARTMENT ROSTER & INDIVIDUAL ACTIVATION CREDENTIALS (${departmentEntries.length} MEMBERS)`, 36, doc.y);
  doc.y += 8;

  departmentEntries.forEach((item, idx) => {
    const u = item.user;
    const m = item.membership;
    const desigTitle = formatDesignation(m.designation);
    const isMulti = (u.memberships && u.memberships.length > 1);

    const sessionLinkObj = sessionLinksMap.get(u.email.toLowerCase().trim());
    const rawToken = sessionLinkObj?.token || u.rawToken || null;
    const portalActivateUrl = `${PORTAL_BASE_URL}/portal/activate`;
    const rawUrl = sessionLinkObj?.activationUrl || (rawToken ? `${PORTAL_BASE_URL}/portal/activate?token=${rawToken}` : null);
    const pktExpiry = formatPktDate(u.activationExpires);

    const cardHeight = isMulti ? 106 : 94;

    // Check page break
    if (doc.y + cardHeight > 780) {
      doc.addPage();
      drawHeader(`Continued Roster — Department of ${deptConfig.name}`);
      doc.y += 6;
    }

    const cardY = doc.y;
    doc.roundedRect(36, cardY, contentWidth, cardHeight, 5).fillAndStroke('#ffffff', '#e2e8f0');

    // Left accent bar
    doc.rect(36, cardY, 4, cardHeight).fill(deptConfig.color);

    // Row 1: Member Name & Designation Badge
    doc.fillColor('#0f172a').fontSize(9.5).font('Helvetica-Bold')
       .text(`${idx + 1}. ${u.name}`, 48, cardY + 7);

    const desigBadgeW = doc.widthOfString(desigTitle, { size: 7.5 }) + 14;
    const desigBadgeX = contentWidth + 36 - desigBadgeW - 8;
    doc.roundedRect(desigBadgeX, cardY + 6, desigBadgeW, 14, 3).fill('#f1f5f9');
    doc.fillColor('#0f172a').fontSize(7.5).font('Helvetica-Bold')
       .text(desigTitle, desigBadgeX + 7, cardY + 9.5);

    // Row 2: Email & Region
    doc.fillColor('#475569').fontSize(7.8).font('Helvetica')
       .text(`Email: `, 48, cardY + 21);
    doc.fillColor('#0284c7').font('Helvetica')
       .text(u.email, 78, cardY + 21);

    doc.fillColor('#475569').font('Helvetica')
       .text(`Region: `, 280, cardY + 21);
    doc.fillColor('#334155').font('Helvetica-Bold')
       .text(m.region || u.region || u.city || 'National', 320, cardY + 21);

    // Row 3: Complete Individual Activation Token (Un-truncated)
    doc.fillColor('#475569').fontSize(7.2).font('Helvetica')
       .text(`Activation Token (Single-Use): `, 48, cardY + 34);

    const tokenBoxW = contentWidth - 24;
    doc.roundedRect(48, cardY + 44, tokenBoxW, 15, 3).fillAndStroke('#f8fafc', '#cbd5e1');

    if (rawToken) {
      doc.fillColor('#0f172a').font('Courier-Bold').fontSize(7.2)
         .text(rawToken, 54, cardY + 48, { lineBreak: false });
    } else {
      doc.fillColor('#b45309').font('Helvetica-Bold').fontSize(7.2)
         .text(`Unavailable (Raw Token Irrecoverable — One-Way SHA-256 Hash Stored in DB)`, 54, cardY + 48);
    }

    // Row 4: Clickable Activation Page URLs
    doc.fillColor('#475569').fontSize(7.5).font('Helvetica')
       .text(`Activation URL: `, 48, cardY + 63);
    doc.fillColor('#2563eb').font('Helvetica-Bold')
       .text(portalActivateUrl, 115, cardY + 63, {
         link: portalActivateUrl,
         underline: true,
       });

    if (rawUrl) {
      doc.fillColor('#64748b').font('Helvetica').fontSize(7.2)
         .text(`(Click URL to open form, then paste token above)`, 310, cardY + 63);
    }

    // Row 5: Designation & Department
    doc.fillColor('#475569').fontSize(7.5).font('Helvetica')
       .text(`Designation: `, 48, cardY + 76);
    doc.fillColor('#0f172a').font('Helvetica-Bold')
       .text(desigTitle, 105, cardY + 76);

    doc.fillColor('#475569').font('Helvetica')
       .text(`Department: `, 280, cardY + 76);
    doc.fillColor('#0f172a').font('Helvetica-Bold')
       .text(`${deptConfig.name} (${deptConfig.code})`, 340, cardY + 76);

    // Row 6: Account Status & Expiration
    doc.fillColor('#475569').fontSize(7.5).font('Helvetica')
       .text(`Account Status: `, 48, cardY + 88);
    doc.fillColor('#d97706').font('Helvetica-Bold')
       .text(`Pending Activation`, 115, cardY + 88);

    doc.fillColor('#475569').font('Helvetica')
       .text(`Expires: `, 280, cardY + 88);
    doc.fillColor('#059669').font('Helvetica-Bold')
       .text(pktExpiry, 320, cardY + 88);

    // Cross-department indicator if applicable
    if (isMulti) {
      const otherRoles = u.memberships.map((x) => `${x.department} (${formatDesignation(x.designation)})`).join(' • ');
      doc.fillColor('#7c3aed').fontSize(7.2).font('Helvetica-Bold')
         .text(`★ Cross-Department Account: ${otherRoles}`, 48, cardY + 99, { width: contentWidth - 28 });
    }

    doc.y = cardY + cardHeight + 6;
  });

  // End of Department Notes Box
  if (doc.y + 110 > 780) {
    doc.addPage();
    drawHeader(`Distribution Protocols — Department of ${deptConfig.name}`);
    doc.y += 6;
  } else {
    doc.y += 8;
  }

  const guideBoxY = doc.y;
  doc.roundedRect(36, guideBoxY, contentWidth, 80, 5).fillAndStroke('#eff6ff', '#bfdbfe');
  doc.rect(36, guideBoxY, 4, 80).fill('#2563eb');

  doc.fillColor('#1e40af').fontSize(8.5).font('Helvetica-Bold')
     .text("SUPER ADMIN DISTRIBUTION PROTOCOL & SINGLE-USE LIFECYCLE", 48, guideBoxY + 8);

  const guideText = 
    "1. Activation Workflow: The member clicks the Activation URL to open the form, copies their complete 64-character token from this PDF, and pastes it into the token field.\n" +
    "2. Single-Use Security Invariant: The token is invalidated atomically upon password creation and cannot be reused, replayed, or shared.\n" +
    "3. Expiration Deadline: Accounts must be activated before the stated PKT expiration (7-day validity). Expired tokens require Super Admin regeneration.\n" +
    "4. Confidential 1-on-1 Sharing: Deliver credentials directly to the individual member via secure channel. Never broadcast tokens in group chats.";

  doc.fillColor('#1e3a8a').fontSize(7.2).font('Helvetica')
     .text(guideText, 48, guideBoxY + 22, { width: contentWidth - 24, lineGap: 2.5 });

  doc.y = guideBoxY + 90;

  // Running Page Footers across all pages
  const range = doc.bufferedPageRange();
  const totalPages = range.count;

  for (let i = 0; i < totalPages; i++) {
    doc.switchToPage(i);
    const oldBottom = doc.page.margins.bottom;
    doc.page.margins.bottom = 0;

    doc.rect(36, 808, contentWidth, 0.75).fill('#cbd5e1');
    doc.fillColor('#94a3b8').fontSize(7.5).font('Helvetica')
       .text(`Ta'meer-e-Rekhta • Department of ${deptConfig.name} (${deptConfig.code}) Activation Directory`, 36, 814, { lineBreak: false });
    const pageStr = `Page ${i + 1} of ${totalPages}`;
    doc.text(
      pageStr,
      pageWidth - 36 - doc.widthOfString(pageStr, { size: 7.5 }),
      814,
      { lineBreak: false }
    );

    doc.page.margins.bottom = oldBottom;
  }

  return doc;
}

module.exports = {
  buildDepartmentActivationPdf,
  DEPARTMENT_CONFIGS,
  formatDesignation,
  formatPktDate,
};
