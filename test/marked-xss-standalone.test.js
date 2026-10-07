#!/usr/bin/env node
/**
 * Standalone test runner for marked XSS vulnerability mitigation
 * This runs without requiring npm test or authentication
 */

const marked = require('marked');

// Configure marked the same way as the application
marked.setOptions({
  headerIds: false,
  mangle: false,
  sanitize: true
});

let passed = 0;
let failed = 0;
let total = 0;

function test(name, fn) {
  total++;
  try {
    fn();
    passed++;
    console.log(`✓ ${name}`);
  } catch (err) {
    failed++;
    console.log(`✗ ${name}`);
    console.log(`  ${err.message}`);
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertNotMatch(str, regex, message) {
  if (regex.test(str)) {
    throw new Error(message || `Expected string not to match ${regex}`);
  }
}

function assertMatch(str, regex, message) {
  if (!regex.test(str)) {
    throw new Error(message || `Expected string to match ${regex}`);
  }
}

console.log('\n=== Testing marked XSS vulnerability mitigation ===\n');

// Test 1: Block javascript: protocol in links
test('should block javascript: protocol in links', () => {
  const maliciousInput = '[Click me](javascript:alert(1))';
  const output = marked.parse(maliciousInput);
  assertNotMatch(output, /javascript:/i, 'output should not contain javascript: protocol');
  assertNotMatch(output, /href="javascript:/i, 'href should not contain javascript: protocol');
});

// Test 2: Block javascript: protocol with HTML entity encoding
test('should block javascript: protocol with HTML entity encoding', () => {
  const maliciousInput = '[Click me](javascript&#58;alert(1))';
  const output = marked.parse(maliciousInput);
  assertNotMatch(output, /javascript/i, 'output should not contain javascript protocol');
  assertNotMatch(output, /&#58;/i, 'output should not contain encoded colon');
});

// Test 3: Block javascript: protocol with "this" bypass (CVE-2016-10531)
test('should block javascript: protocol with "this" bypass (CVE-2016-10531)', () => {
  const maliciousInput = '[Gotcha](javascript&#58this;alert(1))';
  const output = marked.parse(maliciousInput);
  assertNotMatch(output, /javascript/i, 'output should not contain javascript protocol');
  assertNotMatch(output, /href="javascript/i, 'href should not have javascript protocol');
  assertNotMatch(output, /&#58/i, 'output should not contain encoded colon');
});

// Test 4: Block javascript: protocol with full exploit payload
test('should block javascript: protocol with full exploit payload', () => {
  const maliciousInput = '[Gotcha](javascript&#58this;alert(\'marked exploit successful\'))';
  const output = marked.parse(maliciousInput);
  assertNotMatch(output, /javascript/i, 'output should not contain javascript protocol');
  assertNotMatch(output, /alert/i, 'output should not contain alert function');
});

// Test 5: Block data: URI protocol
test('should block data: URI protocol', () => {
  const maliciousInput = '[Click me](data:text/html,<script>alert(1)</script>)';
  const output = marked.parse(maliciousInput);
  assertNotMatch(output, /data:text\/html/i, 'output should not contain data: URI');
  assertNotMatch(output, /href="data:/i, 'href should not contain data: protocol');
});

// Test 6: Block vbscript: protocol
test('should block vbscript: protocol', () => {
  const maliciousInput = '[Click me](vbscript:msgbox(1))';
  const output = marked.parse(maliciousInput);
  assertNotMatch(output, /vbscript:/i, 'output should not contain vbscript: protocol');
});

// Test 7: Allow safe HTTPS links
test('should allow safe HTTPS links', () => {
  const safeInput = '[Snyk](https://snyk.io/)';
  const output = marked.parse(safeInput);
  assertMatch(output, /href="https:\/\/snyk\.io\/"/, 'should contain safe HTTPS link');
  assertMatch(output, /<a/, 'should contain anchor tag');
  assertMatch(output, />Snyk</, 'should contain link text');
});

// Test 8: Allow safe HTTP links
test('should allow safe HTTP links', () => {
  const safeInput = '[Example](http://example.com)';
  const output = marked.parse(safeInput);
  assertMatch(output, /href="http:\/\/example\.com"/, 'should contain safe HTTP link');
});

// Test 9: Render markdown formatting safely
test('should render markdown formatting safely', () => {
  const safeInput = 'This is **markdown** with _emphasis_';
  const output = marked.parse(safeInput);
  assertMatch(output, /<strong>markdown<\/strong>/, 'should render bold text');
  assertMatch(output, /<em>emphasis<\/em>/, 'should render italic text');
});

// Test 10: Handle plain text safely
test('should handle plain text safely', () => {
  const plainInput = 'Just plain text';
  const output = marked.parse(plainInput);
  assertMatch(output, /<p>Just plain text<\/p>/, 'should wrap plain text in paragraph');
});

// Test 11: Block javascript: with various encodings
test('should block javascript: with various encodings', () => {
  const encodings = [
    '[test](javascript:alert(1))',
    '[test](javascript&#58;alert(1))',
    '[test](javascript&#x3A;alert(1))',
    '[test](javascript&#58this;alert(1))',
    '[test](JaVaScRiPt:alert(1))',
  ];
  
  encodings.forEach((input) => {
    const output = marked.parse(input);
    assertNotMatch(output, /javascript/i, `should block: ${input}`);
  });
});

// Test 12: Verify marked version
test('marked version should be 4.x or higher', () => {
  const markedVersion = require('marked/package.json').version;
  const majorVersion = parseInt(markedVersion.split('.')[0], 10);
  assert(majorVersion >= 4, `marked version should be 4.x or higher, got ${markedVersion}`);
});

// Test 13: Verify sanitize option is enabled
test('marked sanitize option should be enabled', () => {
  const options = marked.getDefaults();
  assert(options.hasOwnProperty('sanitize'), 'sanitize option should exist in marked 4.x');
  assert(options.sanitize === true, 'sanitize should be enabled to block dangerous protocols');
});

// Integration tests
console.log('\n=== Integration tests ===\n');

// Test 14: Safely render todo content with malicious markdown
test('should safely render todo content with malicious markdown', () => {
  const todoContent = '[Click for prize](javascript&#58this;alert(document.cookie))';
  const rendered = marked.parse(new String(todoContent));
  assertNotMatch(rendered, /javascript/i, 'rendered output should not contain javascript protocol');
  assertNotMatch(rendered, /alert/i, 'rendered output should not contain alert function');
  assertNotMatch(rendered, /document\.cookie/i, 'rendered output should not contain cookie access');
});

// Test 15: Safely render multiple todo items
test('should safely render multiple todo items', () => {
  const todos = [
    { content: 'Buy groceries' },
    { content: '[Malicious](javascript:alert(1))' },
    { content: 'This is **safe** markdown' },
    { content: '[Evil](javascript&#58this;alert("xss"))' },
  ];
  
  todos.forEach((todo) => {
    const rendered = marked.parse(new String(todo.content));
    assertNotMatch(rendered, /javascript:/i, `should be safe: ${todo.content}`);
  });
});

// Test 16: Handle edge cases safely
test('should handle edge cases safely', () => {
  const edgeCases = [
    '',  // empty string
    ' ',  // whitespace
    '[](javascript:void(0))',  // empty link text
    '[](<javascript:alert(1)>)',  // angle brackets
  ];
  
  edgeCases.forEach((input) => {
    const rendered = marked.parse(String(input || ''));
    assert(typeof rendered === 'string', `should handle: ${JSON.stringify(input)}`);
    assertNotMatch(rendered, /javascript:/i, `should be safe: ${JSON.stringify(input)}`);
  });
});

// Summary
console.log('\n=== Test Summary ===\n');
console.log(`Total: ${total}`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
  console.log('\n❌ Some tests failed\n');
  process.exit(1);
} else {
  console.log('\n✅ All tests passed\n');
  process.exit(0);
}
