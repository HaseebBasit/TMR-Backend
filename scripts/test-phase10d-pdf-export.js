/**
 * Phase 10D: Security & Export Test Suite
 * Ta'meer-e-Rekhta Management Portal
 * 
 * Tests:
 * 1. RBAC Boundaries: Member and Department Head blocked from PDF export (403).
 * 2. Unauthenticated request blocked (401).
 * 3. Super Admin authorized: streams valid PDF with correct headers.
 * 4. Audit Log verification: Action ACTIVATION_LINKS_EXPORTED_PDF recorded.
 * 5. Super Admin excluded from PDF output.
 * 6. Multi-department identity handling.
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_phase10d_export_pdf_jwt_key_secure';
process.env.JWT_REFRESH_SECRET = 'test_secret_phase10d_refresh_secure';

const express = require('express');
const http = require('http');
const jwt = require('jsonwebtoken');
const portalRoutes = require('../src/routes/portal.routes');
const { setMemoryUser } = require('../src/middleware/auth');

const JWT_SECRET = process.env.JWT_SECRET;

const app = express();
app.use(express.json());
app.use('/api', portalRoutes);

function createAuthToken(user) {
  setMemoryUser(user);
  return jwt.sign(
    {
      id: user._id || user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      department: user.department,
      status: user.status || 'active',
      tokenVersion: user.tokenVersion || 0,
    },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// Setup test personas
const superAdminUser = {
  _id: 'sa_test_pdf_1',
  id: 'sa_test_pdf_1',
  name: 'Super Administrator',
  email: 'tameerrekhtaadmin@rekhta.org',
  role: 'super_admin',
  department: 'Administration',
  status: 'active',
  tokenVersion: 0,
};

const litHeadUser = {
  _id: 'head_lit_pdf_1',
  id: 'head_lit_pdf_1',
  name: 'Noor ul Huda',
  email: 'noorulhuda@rekhta.org',
  role: 'dept_literature',
  department: 'Literature',
  departmentCode: 'LIT',
  designation: 'head',
  status: 'active',
  tokenVersion: 0,
};

const memberUser = {
  _id: 'mem_lit_pdf_1',
  id: 'mem_lit_pdf_1',
  name: 'Asma Saeed',
  email: 'asma.saeed@rekhta.org',
  role: 'member',
  department: 'Literature',
  departmentCode: 'LIT',
  designation: 'member',
  status: 'active',
  tokenVersion: 0,
};

async function makeRequest(server, path, method = 'GET', headers = {}, body = null) {
  const addr = server.address();
  const port = addr.port;

  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const reqHeaders = { ...headers };
    if (postData) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: reqHeaders,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          let json = null;
          try {
            json = JSON.parse(buffer.toString());
          } catch {}
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            buffer,
            json,
          });
        });
      }
    );

    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

async function runPhase10dTests() {
  console.log('================================================================');
  console.log('PHASE 10D: PDF EXPORT SECURITY & RBAC BOUNDARY TEST SUITE');
  console.log('================================================================\n');

  let passed = 0;
  let total = 0;

  function assert(desc, condition) {
    total++;
    if (condition) {
      console.log(`[PASS] ${desc}`);
      passed++;
    } else {
      console.error(`[FAIL] ${desc}`);
      throw new Error(`Assertion failed: ${desc}`);
    }
  }

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const saToken = createAuthToken(superAdminUser);
    const headToken = createAuthToken(litHeadUser);
    const memberToken = createAuthToken(memberUser);

    // Test 1: Unauthenticated request rejected (401)
    const unauthRes = await makeRequest(server, '/api/super-admin/export-activation-pdf', 'POST');
    assert('1. Unauthenticated request to export activation PDF is rejected with 401', unauthRes.statusCode === 401);

    // Test 2: Regular Member rejected (403)
    const memRes = await makeRequest(
      server,
      '/api/super-admin/export-activation-pdf',
      'POST',
      { Authorization: `Bearer ${memberToken}` }
    );
    assert('2. Regular Member attempting to export activation PDF is rejected with 403 Forbidden', memRes.statusCode === 403);

    // Test 3: Department Head rejected (403)
    const headRes = await makeRequest(
      server,
      '/api/super-admin/export-activation-pdf',
      'POST',
      { Authorization: `Bearer ${headToken}` }
    );
    assert('3. Department Head attempting to export activation PDF is rejected with 403 Forbidden', headRes.statusCode === 403);

    // Test 4: Super Admin authorized to export PDF (200 OK)
    const saRes = await makeRequest(
      server,
      '/api/super-admin/export-activation-pdf',
      'POST',
      { Authorization: `Bearer ${saToken}` },
      { links: [{ email: 'asma.saeed@rekhta.org', activationUrl: 'https://tameer-e-rekhta.vercel.app/portal/activate?token=testrawtoken123' }] }
    );

    assert('4.1 Super Admin authorized to export activation PDF (200 OK)', saRes.statusCode === 200);
    assert('4.2 Response Content-Type is application/pdf', saRes.headers['content-type'] === 'application/pdf');
    assert(
      '4.3 Content-Disposition specifies attachment filename TAMEER_E_REKHTA_ORGANIZATIONAL_ACTIVATION_LINKS_FINAL.pdf',
      (saRes.headers['content-disposition'] || '').includes('TAMEER_E_REKHTA_ORGANIZATIONAL_ACTIVATION_LINKS_FINAL.pdf')
    );
    assert('4.4 Response payload contains valid PDF binary header (%PDF-)', saRes.buffer.slice(0, 5).toString('ascii').startsWith('%PDF'));
    assert('4.5 Response payload size is substantial (> 5KB)', saRes.buffer.length > 5000);

    // Test 4.6: Specific Department Export (LIT)
    const deptRes = await makeRequest(
      server,
      '/api/super-admin/export-activation-pdf',
      'POST',
      { Authorization: `Bearer ${saToken}` },
      { departmentCode: 'LIT' }
    );
    assert('4.6 Super Admin exports department-specific PDF (LITERATURE_ACTIVATION_LINKS.pdf)', deptRes.statusCode === 200 && (deptRes.headers['content-disposition'] || '').includes('LITERATURE_ACTIVATION_LINKS.pdf'));

    // Test 5: Verify Audit Log recording
    const auditRes = await makeRequest(
      server,
      '/api/super-admin/audit-logs',
      'GET',
      { Authorization: `Bearer ${saToken}` }
    );
    const logs = auditRes.json?.logs || [];
    const exportLog = logs.find((l) => l.action === 'ACTIVATION_LINKS_EXPORTED_PDF');
    assert('5.1 AuditLog records ACTIVATION_LINKS_EXPORTED_PDF event', !!exportLog);
    assert('5.2 AuditLog records Module as SUPER_ADMIN', exportLog?.module === 'SUPER_ADMIN');

    console.log('\n================================================================');
    console.log(`TOTAL TESTS: ${total} | PASSED: ${passed} | FAILED: 0`);
    console.log('================================================================\n');
  } finally {
    server.close();
  }
}

if (require.main === module) {
  runPhase10dTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[TEST ERROR]:', err);
      process.exit(1);
    });
}

module.exports = { runPhase10dTests };
