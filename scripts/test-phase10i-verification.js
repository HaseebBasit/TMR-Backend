/**
 * Phase 10I Verification Test Suite:
 * - Authentication Lifecycle, Session Restoration & Cookie Security
 * - Media Department Workspace & Gallery Authorization Boundaries
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_jwt_secret_phase10i_verification_2026';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_phase10i_verification_2026';

const http = require('http');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = require('../src/server');
const { setMemoryUser } = require('../src/middleware/auth');

const TEST_PORT = 5008;
let server;
let passed = 0;
let failed = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName} ${details ? '- ' + details : ''}`);
    failed++;
  }
}

function makeRequest({ method = 'GET', path, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const reqHeaders = { ...headers };

    if (postData) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(
      {
        hostname: 'localhost',
        port: TEST_PORT,
        path,
        method,
        headers: reqHeaders,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(data);
          } catch {
            json = { raw: data };
          }
          resolve({ status: res.statusCode, headers: res.headers, data: json });
        });
      }
    );

    req.on('error', (err) => reject(err));
    if (postData) req.write(postData);
    req.end();
  });
}

function extractCookie(headers, cookieName) {
  const setCookie = headers['set-cookie'];
  if (!setCookie) return null;
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const c of cookies) {
    if (c.startsWith(`${cookieName}=`)) {
      return c.split(';')[0].split('=')[1];
    }
  }
  return null;
}

function parseCookieAttributes(headers, cookieName) {
  const setCookie = headers['set-cookie'];
  if (!setCookie) return {};
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const c of cookies) {
    if (c.startsWith(`${cookieName}=`)) {
      const parts = c.split(';').map((p) => p.trim());
      const attrs = { raw: c };
      for (const p of parts) {
        const [k, v] = p.split('=');
        if (k.toLowerCase() === 'httponly') attrs.httpOnly = true;
        if (k.toLowerCase() === 'secure') attrs.secure = true;
        if (k.toLowerCase() === 'samesite') attrs.sameSite = v?.toLowerCase();
        if (k.toLowerCase() === 'path') attrs.path = v;
        if (k.toLowerCase() === 'max-age') attrs.maxAge = parseInt(v, 10);
      }
      return attrs;
    }
  }
  return {};
}

async function runTests() {
  console.log('========================================================================');
  console.log('PHASE 10I: AUTHENTICATION & MEDIA DEPARTMENT PORTAL VERIFICATION');
  console.log('========================================================================\n');

  await new Promise((resolve) => {
    server = app.listen(TEST_PORT, () => resolve());
  });

  const password = 'TestSecurePassword123!';
  const hashedPassword = await bcrypt.hash(password, 10);

  // Setup test personas
  const personas = {
    mediaHead: {
      _id: '607f191e810c19729de89001',
      id: '607f191e810c19729de89001',
      name: 'Aisha Tariq',
      email: 'aishatariq@rekhta.org',
      password: hashedPassword,
      role: 'dept_media',
      department: 'Media',
      departmentCode: 'MED',
      designation: 'head',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        { department: 'Media', departmentCode: 'MED', role: 'dept_media', designation: 'head', isPrimary: true },
      ],
    },
    mediaDirector: {
      _id: '607f191e810c19729de89002',
      id: '607f191e810c19729de89002',
      name: 'Sarmad Waseem',
      email: 'sarmadwaseem@rekhta.org',
      password: hashedPassword,
      role: 'dept_media',
      department: 'Media',
      departmentCode: 'MED',
      designation: 'director_graphics',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        { department: 'Media', departmentCode: 'MED', role: 'dept_media', designation: 'director_graphics', isPrimary: true },
      ],
    },
    mediaMember: {
      _id: '607f191e810c19729de89003',
      id: '607f191e810c19729de89003',
      name: 'Inshal Sheikh',
      email: 'inshalsheikh@rekhta.org',
      password: hashedPassword,
      role: 'member',
      department: 'Media',
      departmentCode: 'MED',
      designation: 'member',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        { department: 'Media', departmentCode: 'MED', role: 'member', designation: 'member', isPrimary: true },
      ],
    },
    litHead: {
      _id: '607f191e810c19729de89004',
      id: '607f191e810c19729de89004',
      name: 'Noor ul Huda',
      email: 'noorulhuda@rekhta.org',
      password: hashedPassword,
      role: 'dept_literature',
      department: 'Literature',
      departmentCode: 'LIT',
      designation: 'head',
      status: 'active',
      tokenVersion: 0,
      memberships: [
        { department: 'Literature', departmentCode: 'LIT', role: 'dept_literature', designation: 'head', isPrimary: true },
      ],
    },
  };

  Object.values(personas).forEach((p) => setMemoryUser(p));

  try {
    // -------------------------------------------------------------------------
    // SECTION 1: Login & Cookie Attributes Verification
    // -------------------------------------------------------------------------
    console.log('--- SECTION 1: Login & Cookie Attributes Verification ---');

    const loginRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      body: { email: 'aishatariq@rekhta.org', password },
    });

    assert(loginRes.status === 200, '1.1 Login succeeds with 200 OK');
    assert(loginRes.data.success === true, '1.2 Login response indicates success');
    assert(Boolean(loginRes.data.token), '1.3 In-memory session token provided in login response');

    const accessToken = loginRes.data.token;
    const accessCookie = extractCookie(loginRes.headers, 'rekhta_access_token');
    const refreshCookie = extractCookie(loginRes.headers, 'rekhta_refresh_token');

    assert(Boolean(accessCookie), '1.4 rekhta_access_token cookie issued on login');
    assert(Boolean(refreshCookie), '1.5 rekhta_refresh_token cookie issued on login');

    const accessAttrs = parseCookieAttributes(loginRes.headers, 'rekhta_access_token');
    const refreshAttrs = parseCookieAttributes(loginRes.headers, 'rekhta_refresh_token');

    assert(accessAttrs.httpOnly === true, '1.6 access cookie has HttpOnly flag');
    assert(accessAttrs.sameSite === 'lax', '1.7 access cookie has SameSite=lax for first-party persistence');
    assert(refreshAttrs.httpOnly === true, '1.8 refresh cookie has HttpOnly flag');
    assert(refreshAttrs.sameSite === 'lax', '1.9 refresh cookie has SameSite=lax for first-party persistence');

    // -------------------------------------------------------------------------
    // SECTION 2: /api/auth/me & Seamless Session Restoration Verification
    // -------------------------------------------------------------------------
    console.log('\n--- SECTION 2: /api/auth/me & Seamless Session Restoration ---');

    // 2.1 Authenticated with Bearer token
    const meBearerRes = await makeRequest({
      method: 'GET',
      path: '/api/auth/me',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(meBearerRes.status === 200, '2.1 /api/auth/me succeeds with Bearer token (200 OK)');
    assert(meBearerRes.data.user.email === 'aishatariq@rekhta.org', '2.2 Profile email matches authenticated user');

    // 2.2 Cold Mount / Reload Simulation: No Bearer token, but valid refresh cookie present!
    // This is the EXACT scenario that previously returned 401 in production!
    const meRefreshRestoreRes = await makeRequest({
      method: 'GET',
      path: '/api/auth/me',
      headers: {
        Cookie: `rekhta_refresh_token=${refreshCookie}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(
      meRefreshRestoreRes.status === 200,
      '2.3 /api/auth/me restores session seamlessly on reload via refresh cookie (200 OK, NO 401!)'
    );
    assert(
      Boolean(meRefreshRestoreRes.data.token),
      '2.4 /api/auth/me provides fresh in-memory access token to hydrate client'
    );
    const newRefreshCookie = extractCookie(meRefreshRestoreRes.headers, 'rekhta_refresh_token') || refreshCookie;

    // 2.3 Unauthenticated Visitor: No bearer token, no cookies -> Strictly 401
    const meUnauthRes = await makeRequest({
      method: 'GET',
      path: '/api/auth/me',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert(meUnauthRes.status === 401, '2.5 Unauthenticated request without tokens strictly rejected (401)');
    assert(
      meUnauthRes.data.error === 'Authentication required. No session token provided.',
      '2.6 Exact expected unauthenticated error message returned'
    );

    // -------------------------------------------------------------------------
    // SECTION 3: Token Refresh & Single-Use Replay Attack Defense
    // -------------------------------------------------------------------------
    console.log('\n--- SECTION 3: Token Refresh & Replay Defense ---');

    const refreshEndpointRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/refresh',
      headers: {
        Cookie: `rekhta_refresh_token=${newRefreshCookie}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(refreshEndpointRes.status === 200, '3.1 /api/auth/refresh rotates tokens successfully (200 OK)');
    assert(Boolean(refreshEndpointRes.data.token), '3.2 Refresh returns new access token');

    const secondRefreshCookie = extractCookie(refreshEndpointRes.headers, 'rekhta_refresh_token');
    assert(Boolean(secondRefreshCookie), '3.3 Refresh issues fresh rotated refresh cookie');

    // Replay Attack Test: Attempting to reuse the PREVIOUS refresh token
    const replayRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/refresh',
      headers: {
        Cookie: `rekhta_refresh_token=${newRefreshCookie}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(replayRes.status === 401, '3.4 Replayed/stolen refresh token rejected (401)');
    assert(replayRes.data.code === 'TOKEN_REUSE_DETECTED', '3.5 Security alert TOKEN_REUSE_DETECTED raised');

    // -------------------------------------------------------------------------
    // SECTION 4: Media Department Workspace & Route Authorization Boundaries
    // -------------------------------------------------------------------------
    console.log('\n--- SECTION 4: Media Department Workspace Boundaries ---');

    // Login fresh as Media Head
    const freshLogin = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      body: { email: 'aishatariq@rekhta.org', password },
    });
    const mediaHeadToken = freshLogin.data.token;

    // Login as Literature Head
    const litLogin = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      body: { email: 'noorulhuda@rekhta.org', password },
    });
    const litHeadToken = litLogin.data.token;

    // 4.1 Media Head accesses Media Department Overview
    const mediaOverviewRes = await makeRequest({
      method: 'GET',
      path: '/api/department/Media/overview',
      headers: {
        Authorization: `Bearer ${mediaHeadToken}`,
        'X-Department-Context': 'Media',
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(mediaOverviewRes.status === 200, '4.1 Media Head accesses Media department overview (200 OK)');
    assert(mediaOverviewRes.data.success === true, '4.2 Media overview returns success');

    // 4.2 Literature Head BLOCKED from Media Department Overview (Cross-department isolation)
    const crossDeptRes = await makeRequest({
      method: 'GET',
      path: '/api/department/Media/overview',
      headers: {
        Authorization: `Bearer ${litHeadToken}`,
        'X-Department-Context': 'Media',
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(crossDeptRes.status === 403, '4.3 Literature Head strictly BLOCKED from Media overview (403 Forbidden)');

    // -------------------------------------------------------------------------
    // SECTION 5: Media Gallery / Media Bank Permissions
    // -------------------------------------------------------------------------
    console.log('\n--- SECTION 5: Media Gallery Bank Permissions ---');

    // 5.1 Media Head uploads and publishes asset directly
    const headUploadRes = await makeRequest({
      method: 'POST',
      path: '/api/media',
      headers: {
        Authorization: `Bearer ${mediaHeadToken}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: {
        title: 'Rekhta Calligraphy Vector 2026',
        fileType: 'image',
        url: 'https://images.unsplash.com/photo-1541701494587-cb58502866ab',
        publicationStatus: 'published',
        tags: ['calligraphy', 'nastaliq'],
      },
    });
    assert(headUploadRes.status === 201 || headUploadRes.status === 200, '5.1 Media Head can create media assets (201 Created)');
    assert(headUploadRes.data.media.publicationStatus === 'published', '5.2 Media Head can publish assets directly');

    // 5.2 Literature Head BLOCKED from creating media assets
    const litUploadRes = await makeRequest({
      method: 'POST',
      path: '/api/media',
      headers: {
        Authorization: `Bearer ${litHeadToken}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: {
        title: 'Unauthorized Asset',
        fileType: 'image',
        url: 'https://example.com/test.jpg',
      },
    });
    assert(litUploadRes.status === 403, '5.3 Non-media user strictly BLOCKED from media uploads (403 Forbidden)');

    // 5.3 Fetch Media Bank assets
    const galleryRes = await makeRequest({
      method: 'GET',
      path: '/api/media',
      headers: {
        Authorization: `Bearer ${mediaHeadToken}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(galleryRes.status === 200, '5.4 /api/media gallery assets fetchable (200 OK)');
    assert(galleryRes.data.media.length > 0, '5.5 Gallery assets list populated');

    // -------------------------------------------------------------------------
    // SECTION 6: Logout Verification
    // -------------------------------------------------------------------------
    console.log('\n--- SECTION 6: Logout Verification ---');

    const logoutRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/logout',
      headers: {
        Authorization: `Bearer ${mediaHeadToken}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(logoutRes.status === 200, '6.1 Logout succeeds with 200 OK');

    // Verify cookies cleared on logout
    const clearedAccess = extractCookie(logoutRes.headers, 'rekhta_access_token');
    assert(clearedAccess === '' || clearedAccess === null, '6.2 rekhta_access_token cookie cleared on logout');

    // Post-logout request strictly rejected
    const postLogoutRes = await makeRequest({
      method: 'GET',
      path: '/api/auth/me',
      headers: {
        Authorization: `Bearer ${mediaHeadToken}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    assert(postLogoutRes.status === 401, '6.3 Post-logout request strictly rejected (401)');
  } finally {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  }

  console.log('\n========================================================================');
  console.log(`PHASE 10I TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('========================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('[FATAL TEST RUN ERROR]:', err);
  process.exit(1);
});
