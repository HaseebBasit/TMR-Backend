/**
 * Phase 7B.5.2C — Offline Validation for First-Login Verification Script
 * Mode: Strictly Offline Mock Validation (Zero Live Writes)
 */

const { parseCookies } = require('./verify-first-login');
const fs = require('fs');
const path = require('path');

let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passedTests++;
  } else {
    console.error(`  [FAIL] ${message}`);
    failedTests++;
  }
}

console.log('==================================================================');
console.log('PHASE 7B.5.2C: OFFLINE VALIDATION FOR VERIFY-FIRST-LOGIN SCRIPT');
console.log('==================================================================\n');

// 1. Verify parseCookies handles empty / missing Set-Cookie without error
const emptyCookies = parseCookies({});
assert(typeof emptyCookies === 'object' && Object.keys(emptyCookies).length === 0, 'Test 1.1: parseCookies({}) returns empty object');

const nullCookies = parseCookies({ 'set-cookie': null });
assert(typeof nullCookies === 'object' && Object.keys(nullCookies).length === 0, 'Test 1.2: parseCookies({ set-cookie: null }) returns empty object');

// 2. Verify defensive access to empty cookies does not throw
let threwException = false;
try {
  const hasRefreshedAccess = Boolean(emptyCookies['rekhta_access_token']?.value);
  const hasRefreshedRefresh = Boolean(emptyCookies['rekhta_refresh_token']?.value);
  assert(hasRefreshedAccess === false, 'Test 2.1: Defensive check correctly evaluates empty access token as false');
  assert(hasRefreshedRefresh === false, 'Test 2.2: Defensive check correctly evaluates empty refresh token as false');
} catch (err) {
  threwException = true;
}
assert(!threwException, 'Test 2.3: Dereferencing properties on empty cookies does NOT throw unhandled exception');

// 3. Verify parseCookies correctly extracts cookie attributes when present
const sampleSetCookie = [
  'rekhta_access_token=sample_acc_tok; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600',
  'rekhta_refresh_token=sample_ref_tok; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800',
];
const parsedSample = parseCookies({ 'set-cookie': sampleSetCookie });
assert(parsedSample['rekhta_access_token']?.value === 'sample_acc_tok', 'Test 3.1: Access token value extracted');
assert(parsedSample['rekhta_access_token']?.httpOnly === true, 'Test 3.2: Access token HttpOnly flag detected');
assert(parsedSample['rekhta_access_token']?.sameSite === 'Lax', 'Test 3.3: Access token SameSite=Lax detected');
assert(parsedSample['rekhta_refresh_token']?.value === 'sample_ref_tok', 'Test 3.4: Refresh token value extracted');
assert(parsedSample['rekhta_refresh_token']?.httpOnly === true, 'Test 3.5: Refresh token HttpOnly flag detected');

// 4. Verify verify-first-login.js static source code includes required CSRF headers
const scriptContent = fs.readFileSync(path.join(__dirname, 'verify-first-login.js'), 'utf8');

const hasOriginOnRefresh = scriptContent.includes("Origin: 'http://localhost:3000'");
assert(hasOriginOnRefresh, "Test 4.1: verify-first-login.js sets Origin: 'http://localhost:3000'");

const hasRequestedWith = scriptContent.includes("'X-Requested-With': 'XMLHttpRequest'");
assert(hasRequestedWith, "Test 4.2: verify-first-login.js sets 'X-Requested-With': 'XMLHttpRequest'");

const hasDefensiveLoginCheck = scriptContent.includes("if (!loginCookies['rekhta_access_token']?.value");
assert(hasDefensiveLoginCheck, 'Test 4.3: verify-first-login.js contains defensive check on initial login cookies');

const hasDefensiveRefreshCheck = scriptContent.includes('const hasRefreshedAccess = Boolean(refreshedCookies');
assert(hasDefensiveRefreshCheck, 'Test 4.4: verify-first-login.js contains defensive check on refreshed cookies before logout');

console.log('\n==================================================================');
console.log(`PHASE 7B.5.2C TEST SUMMARY: ${passedTests} PASSED, ${failedTests} FAILED`);
console.log('==================================================================\n');

process.exit(failedTests > 0 ? 1 : 0);
