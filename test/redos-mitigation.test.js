/**
 * Unit tests for ReDoS mitigation in todo reminder duration parsing
 * 
 * These tests verify that the mitigation for CVE-2015-8315 and CVE-2017-16137
 * (ReDoS in ms package) is effective by ensuring that:
 * 1. Legitimate duration strings are parsed correctly
 * 2. Excessively long duration strings are rejected before reaching the vulnerable parser
 * 3. The application returns the original content when duration string is too long
 */

const tap = require('tap');
const fs = require('fs');
const path = require('path');

// Read and extract the parse function from routes/index.js
const routesPath = path.join(__dirname, '../routes/index.js');
const routesContent = fs.readFileSync(routesPath, 'utf8');

// Extract the parse function - it's defined as: function parse(todo) { ... }
// The function spans from line 130 to line 159
const parseFunctionRegex = /function parse\(todo\) \{[\s\S]*?^}/m;
const parseFunctionMatch = routesContent.match(parseFunctionRegex);
if (!parseFunctionMatch) {
  throw new Error('Could not extract parse function from routes/index.js');
}

// Mock the dependencies - use the actual libraries but with safety checks
const actualHms = require('humanize-ms');
const actualMs = require('ms');

const mockHms = function(time) {
  // Add safety check to verify mitigation is working
  if (time.length > 100) {
    throw new Error('Should not reach vulnerable parser with long strings');
  }
  // Use actual library for realistic testing
  try {
    return actualHms(time);
  } catch (e) {
    return undefined;
  }
};

const mockMs = function(period) {
  try {
    return actualMs(period);
  } catch (e) {
    return period + 'ms';
  }
};

// Create the parse function with mocked dependencies
const hms = mockHms;
const ms = mockMs;
const console = { log: () => {} }; // Mock console.log to suppress output
const parse = eval('(' + parseFunctionMatch[0] + ')');

tap.test('ReDoS Mitigation - Legitimate duration strings', (t) => {
  t.test('should parse valid short duration strings correctly', (t) => {
    const input = 'Call mom in 5 minutes';
    const result = parse(input);
    
    t.ok(result.includes('Call mom'), 'Should contain the todo text');
    // The actual output format depends on the ms library
    t.ok(result !== input, 'Should process and modify the input');
    t.end();
  });

  t.test('should parse duration strings with "in" keyword', (t) => {
    const input = 'Buy milk in 1 hour';
    const result = parse(input);
    
    t.ok(result.includes('Buy milk'), 'Should contain the todo text');
    t.ok(result !== input, 'Should process and modify the input');
    t.end();
  });

  t.test('should handle todos without duration strings', (t) => {
    const input = 'Just a regular todo item';
    const result = parse(input);
    
    t.equal(result, input, 'Should return original content unchanged');
    t.end();
  });

  t.test('should handle duration strings at exactly 100 characters', (t) => {
    const duration = '5 minutes' + ' '.repeat(91); // 9 + 91 = 100 chars
    const input = 'Task in ' + duration;
    const result = parse(input);
    
    t.ok(result.includes('Task'), 'Should contain the todo text');
    t.end();
  });

  t.end();
});

tap.test('ReDoS Mitigation - Attack prevention', (t) => {
  t.test('should reject duration strings longer than 100 characters', (t) => {
    const longDuration = '5'.repeat(200) + ' minutes';
    const input = 'Buy milk in ' + longDuration;
    const result = parse(input);
    
    t.equal(result, input, 'Should return original content when duration is too long');
    t.end();
  });

  t.test('should prevent ReDoS with extremely long malformed duration (exploit scenario)', (t) => {
    // Simulate the actual exploit: long string with malformed duration
    // This would cause catastrophic backtracking in vulnerable ms parser
    const maliciousDuration = '5'.repeat(60000) + ' minutea'; // Note the typo 'minutea'
    const input = 'Buy milk in ' + maliciousDuration;
    
    const startTime = Date.now();
    const result = parse(input);
    const endTime = Date.now();
    const executionTime = endTime - startTime;
    
    t.equal(result, input, 'Should return original content for malicious payload');
    t.ok(executionTime < 100, `Should complete in under 100ms, took ${executionTime}ms`);
    t.end();
  });

  t.test('should handle duration string of exactly 101 characters (just over limit)', (t) => {
    const duration = '5 minutes' + ' '.repeat(92); // 9 + 92 = 101 chars
    const input = 'Task in ' + duration;
    const result = parse(input);
    
    t.equal(result, input, 'Should return original content when duration exceeds 100 chars');
    t.end();
  });

  t.test('should prevent multiple ReDoS attempts in sequence', (t) => {
    const maliciousDuration = '5'.repeat(10000) + ' minutea';
    const input = 'Task in ' + maliciousDuration;
    
    const startTime = Date.now();
    
    for (let i = 0; i < 5; i++) {
      const result = parse(input);
      t.equal(result, input, `Attempt ${i + 1}: Should return original content`);
    }
    
    const endTime = Date.now();
    const totalTime = endTime - startTime;
    
    t.ok(totalTime < 500, `5 attempts should complete in under 500ms, took ${totalTime}ms`);
    t.end();
  });

  t.end();
});

tap.test('ReDoS Mitigation - Edge cases and boundary conditions', (t) => {
  t.test('should handle empty duration string after "in" keyword', (t) => {
    const input = 'Task in ';
    const result = parse(input);
    
    t.ok(result !== undefined, 'Should return a result');
    t.end();
  });

  t.test('should handle duration with newline characters', (t) => {
    const input = 'Task in 5 minutes\n';
    const result = parse(input);
    
    t.ok(result.includes('Task'), 'Should process the task');
    t.end();
  });

  t.test('should handle special characters in duration string within limit', (t) => {
    const duration = '5 min!@#$%^&*()';
    const input = 'Task in ' + duration;
    const result = parse(input);
    
    t.ok(result !== undefined, 'Should return a result');
    t.end();
  });

  t.test('should handle Unicode characters in duration string', (t) => {
    const duration = '5 минут'; // "minutes" in Russian
    const input = 'Task in ' + duration;
    const result = parse(input);
    
    t.ok(result !== undefined, 'Should return a result');
    t.end();
  });

  t.test('should handle multiple "in" keywords (only first should be processed)', (t) => {
    const input = 'Task in 5 minutes in the morning';
    const result = parse(input);
    
    t.ok(result.includes('Task'), 'Should contain the todo text');
    t.end();
  });

  t.end();
});

tap.test('ReDoS Mitigation - Security properties validation', (t) => {
  t.test('should enforce MAX_DURATION_LENGTH constant', (t) => {
    const MAX_DURATION_LENGTH = 100;
    
    const atLimit = 'Task in ' + 'x'.repeat(MAX_DURATION_LENGTH);
    const resultAtLimit = parse(atLimit);
    t.ok(resultAtLimit !== undefined, 'Should handle duration at limit');
    
    const overLimit = 'Task in ' + 'x'.repeat(MAX_DURATION_LENGTH + 1);
    const resultOverLimit = parse(overLimit);
    t.equal(resultOverLimit, overLimit, 'Should reject duration over limit');
    t.end();
  });

  t.test('should not call vulnerable parser with long strings', (t) => {
    const longDuration = 'x'.repeat(200);
    const input = 'Task in ' + longDuration;
    
    // If this doesn't throw, the mitigation is working
    t.doesNotThrow(() => {
      parse(input);
    }, 'Should not reach vulnerable parser with long duration strings');
    t.end();
  });

  t.test('should maintain original content integrity when rejecting', (t) => {
    const longDuration = '5'.repeat(200) + ' minutes';
    const input = 'Important task in ' + longDuration;
    const result = parse(input);
    
    t.equal(result, input, 'Should preserve exact original content');
    t.equal(result.length, input.length, 'Should preserve content length');
    t.end();
  });

  t.end();
});
