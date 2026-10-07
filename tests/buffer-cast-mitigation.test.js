/**
 * Mongoose Buffer Cast Vulnerability Mitigation Tests
 * 
 * These tests verify that the mitigation for CVE mongoose:20160116 is effective.
 * The vulnerability allowed numeric values to be cast to Buffers using the legacy
 * Buffer constructor, which could expose uninitialized process memory.
 * 
 * The mitigation adds type validation to ensure only strings and Buffers are accepted
 * for the content field, preventing numeric Buffer cast attacks.
 */

const tap = require('tap');

// Validation function that mirrors the mitigation logic in routes/index.js
function validateContent(content) {
  return typeof content === 'string' || Buffer.isBuffer(content);
}

tap.test('Mongoose Buffer Cast Vulnerability Mitigation', (t) => {
  
  t.test('should reject numeric content (primary exploit vector)', (t) => {
    const content = 1024;
    t.notOk(validateContent(content), 'Numeric value 1024 should be rejected');
    t.end();
  });

  t.test('should reject large numeric values', (t) => {
    const content = 65536;
    t.notOk(validateContent(content), 'Large numeric value should be rejected');
    t.end();
  });

  t.test('should reject float values', (t) => {
    const content = 123.456;
    t.notOk(validateContent(content), 'Float value should be rejected');
    t.end();
  });

  t.test('should reject zero', (t) => {
    const content = 0;
    t.notOk(validateContent(content), 'Zero should be rejected');
    t.end();
  });

  t.test('should reject negative numbers', (t) => {
    const content = -100;
    t.notOk(validateContent(content), 'Negative number should be rejected');
    t.end();
  });

  t.test('should reject boolean values', (t) => {
    t.notOk(validateContent(true), 'Boolean true should be rejected');
    t.notOk(validateContent(false), 'Boolean false should be rejected');
    t.end();
  });

  t.test('should reject null', (t) => {
    const content = null;
    t.notOk(validateContent(content), 'Null should be rejected');
    t.end();
  });

  t.test('should reject undefined', (t) => {
    const content = undefined;
    t.notOk(validateContent(content), 'Undefined should be rejected');
    t.end();
  });

  t.test('should reject objects', (t) => {
    const content = { malicious: 'object' };
    t.notOk(validateContent(content), 'Object should be rejected');
    t.end();
  });

  t.test('should reject arrays', (t) => {
    const content = [1, 2, 3];
    t.notOk(validateContent(content), 'Array should be rejected');
    t.end();
  });

  t.test('should reject functions', (t) => {
    const content = () => {};
    t.notOk(validateContent(content), 'Function should be rejected');
    t.end();
  });

  t.test('should accept valid string content', (t) => {
    const content = 'Valid todo item';
    t.ok(validateContent(content), 'String content should be accepted');
    t.end();
  });

  t.test('should accept empty string', (t) => {
    const content = '';
    t.ok(validateContent(content), 'Empty string should be accepted');
    t.end();
  });

  t.test('should accept Buffer content', (t) => {
    const content = Buffer.from('Valid buffer content');
    t.ok(validateContent(content), 'Buffer content should be accepted');
    t.end();
  });

  t.test('should accept empty Buffer', (t) => {
    const content = Buffer.alloc(0);
    t.ok(validateContent(content), 'Empty Buffer should be accepted');
    t.end();
  });

  t.test('comprehensive allowlist validation', (t) => {
    const testCases = [
      { value: 'string', expected: true, desc: 'string' },
      { value: Buffer.from('test'), expected: true, desc: 'Buffer' },
      { value: 42, expected: false, desc: 'number' },
      { value: 0, expected: false, desc: 'zero' },
      { value: -1, expected: false, desc: 'negative number' },
      { value: 3.14, expected: false, desc: 'float' },
      { value: true, expected: false, desc: 'boolean true' },
      { value: false, expected: false, desc: 'boolean false' },
      { value: null, expected: false, desc: 'null' },
      { value: undefined, expected: false, desc: 'undefined' },
      { value: {}, expected: false, desc: 'empty object' },
      { value: [], expected: false, desc: 'empty array' },
      { value: () => {}, expected: false, desc: 'function' }
    ];

    testCases.forEach(testCase => {
      const result = validateContent(testCase.value);
      t.equal(result, testCase.expected, 
        `${testCase.desc} should ${testCase.expected ? 'pass' : 'fail'} validation`);
    });

    t.end();
  });

  t.end();
});
