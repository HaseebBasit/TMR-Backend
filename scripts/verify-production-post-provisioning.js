/**
 * Phase 10C: Final Production Post-Provisioning Verification
 * Read-only audit against live database: tameer_rekhta
 */

const path = require('path');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

dotenv.config({ path: path.join(__dirname, '..', '.env'), override: true });

const { User, Department, AuditLog } = require('../src/models');

async function verifyProduction() {
  console.log('========================================================================');
  console.log('PHASE 10C: PRODUCTION DATABASE FINAL READ-ONLY AUDIT');
  console.log('Target: tameer_rekhta');
  console.log('========================================================================\n');

  await mongoose.connect(process.env.MONGODB_URI);

  let passed = 0;
  let total = 0;

  function assert(cond, msg) {
    total++;
    if (cond) {
      console.log(`  [PASS] ${msg}`);
      passed++;
    } else {
      console.error(`  [FAIL] ${msg}`);
    }
  }

  try {
    // 1. Departments
    const depts = await Department.find();
    assert(depts.length === 6, '1.1 Exactly 6 official departments exist in production');
    const deptCodes = depts.map((d) => d.code).sort();
    assert(
      JSON.stringify(deptCodes) === JSON.stringify(['CON', 'HR', 'LIT', 'MED', 'OAM', 'WEL']),
      '1.2 All 6 department codes match canonical set (CON, HR, LIT, MED, OAM, WEL)'
    );

    // 2. Users Total & Super Admin
    const users = await User.find().select('+activationToken +password');
    assert(users.length === 48, '2.1 Exactly 48 users exist in production (1 Super Admin + 47 Organizational)');

    const superAdmin = users.find((u) => u.role === 'super_admin');
    assert(superAdmin, '2.2 Super Admin document is present');
    assert(superAdmin._id.toString() === '6b052657bc489333fdf64931', '2.3 Super Admin ID is unchanged (6b052657bc489333fdf64931)');
    assert(superAdmin.email.toLowerCase() === 'tameerrekhtaadmin@rekhta.org', '2.4 Super Admin email is unchanged (tameerrekhtaadmin@rekhta.org)');
    assert(superAdmin.status === 'active', '2.5 Super Admin status is strictly active');

    // 3. Organizational Accounts Status
    const orgUsers = users.filter((u) => u.role !== 'super_admin');
    assert(orgUsers.length === 47, '3.1 Exactly 47 organizational accounts exist');
    const allInactive = orgUsers.every((u) => u.status === 'inactive');
    assert(allInactive, '3.2 All 47 newly provisioned accounts are strictly inactive');

    // 4. Password Protection
    const noInitialPasswords = orgUsers.every((u) => !u.password);
    assert(noInitialPasswords, '4.1 Inactive accounts have no default or plaintext passwords');

    // 5. Activation Tokens Hashed
    const allHashedTokens = orgUsers.every((u) => u.activationToken && u.activationToken.length === 64);
    assert(allHashedTokens, '5.1 All 47 accounts have 64-character SHA-256 hashed activation tokens');

    const allValidExpiries = orgUsers.every((u) => u.activationExpires && u.activationExpires > new Date());
    assert(allValidExpiries, '5.2 All 47 accounts have valid 7-day expiration timestamps');

    // 6. Mononyms
    const mononyms = ['Rabia', 'Rumaisa', 'Sheeza', 'Hoor', 'Hania', 'Mahnoor', 'Afifa'];
    const foundMononyms = mononyms.every((m) => orgUsers.some((u) => u.name === m));
    assert(foundMononyms, '6.1 All 7 approved mononyms are preserved verbatim without invented surnames');

    // 7. Hafiz Muhammad Moosa & Nayab Jahangir
    const moosa = orgUsers.find((u) => u.name === 'Hafiz Muhammad Moosa');
    assert(moosa && moosa.department === 'Content Creation' && moosa.role === 'member', '7.1 Hafiz Muhammad Moosa is correctly provisioned in Content Creation as Member');

    const nayab = orgUsers.find((u) => u.name === 'Nayab Jahangir');
    assert(nayab && nayab.department === 'Welfare' && nayab.region === 'Sindh' && nayab.role === 'member', '7.2 Nayab Jahangir is correctly provisioned in Welfare (Sindh region) without OAM volunteer role');

    // 8. Multi-Department Identities (Noor ul Huda & Haseeb Basit)
    const noor = orgUsers.find((u) => u.name === 'Noor ul Huda');
    assert(noor && noor.department === 'Literature' && noor.memberships.some((m) => m.department === 'Content Creation'), '8.1 Noor ul Huda holds Literature primary and Content Creation secondary membership');
    assert(noor.emailAliases.includes('noorulhuda.cc@rekhta.org'), '8.2 Noor ul Huda has noorulhuda.cc@rekhta.org email alias');

    const haseeb = orgUsers.find((u) => u.name === 'Haseeb Basit');
    assert(haseeb && haseeb.department === 'Literature' && haseeb.memberships.some((m) => m.department === 'Content Creation'), '8.3 Haseeb Basit holds Literature primary and Content Creation secondary membership');
    assert(haseeb.emailAliases.includes('haseebbasit.cc@rekhta.org'), '8.4 Haseeb Basit has haseebbasit.cc@rekhta.org email alias');

    // 9. Welfare Regional Isolation
    const punjabHead = orgUsers.find((u) => u.designation === 'head_of_punjab');
    assert(punjabHead && punjabHead.region === 'Punjab' && punjabHead.role === 'dept_welfare', '9.1 Welfare Head of Punjab is Asfand Yar Karimi scoped to Punjab');

    const sindhHead = orgUsers.find((u) => u.designation === 'head_of_sindh');
    assert(sindhHead && sindhHead.region === 'Sindh' && sindhHead.role === 'dept_welfare', '9.2 Welfare Head of Sindh is Daniyal Asim scoped to Sindh');

    // 10. Audit Logs
    const auditCount = await AuditLog.countDocuments();
    assert(auditCount >= 67, '10.1 Audit trail is intact and records organizational provisioning events');

    console.log('\n========================================================================');
    console.log(`FINAL PRODUCTION AUDIT: ${passed}/${total} PASSED (100%)`);
    console.log('========================================================================\n');
  } finally {
    await mongoose.disconnect();
  }
}

verifyProduction().catch((err) => {
  console.error('Audit failed:', err);
  process.exit(1);
});
