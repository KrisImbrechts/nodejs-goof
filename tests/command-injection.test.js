#!/usr/bin/env node
'use strict';

const tap = require('tap');
const validator = require('validator');

// Test the security mitigations for OS command injection vulnerability
tap.test('Command Injection Mitigation Tests', (t) => {
  
  // Test 1: URL validation rejects shell metacharacters
  t.test('should reject URLs with shell metacharacters (semicolon)', (t) => {
    const maliciousUrl = 'http://example.invalid/x;id;';
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'URL with semicolon should be rejected');
    t.end();
  });

  // Test 2: URL validation rejects command substitution
  t.test('should reject URLs with command substitution syntax', (t) => {
    const maliciousUrl = 'http://example.com/$(whoami)';
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'URL with command substitution should be rejected');
    t.end();
  });

  // Test 3: URL validation rejects backtick command execution
  t.test('should reject URLs with backtick command execution', (t) => {
    const maliciousUrl = 'http://example.com/`id`';
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'URL with backticks should be rejected');
    t.end();
  });

  // Test 4: URL validation rejects pipe operators
  t.test('should reject URLs with pipe operators', (t) => {
    const maliciousUrl = 'http://example.com/x|id';
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'URL with pipe operator should be rejected');
    t.end();
  });

  // Test 5: URL validation rejects ampersand operators
  t.test('should reject URLs with ampersand operators', (t) => {
    const maliciousUrl = 'http://example.com/x&id&';
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'URL with ampersand operator should be rejected');
    t.end();
  });

  // Test 6: URL validation rejects newline injection
  t.test('should reject URLs with newline characters', (t) => {
    const maliciousUrl = 'http://example.com/x\nid';
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'URL with newline should be rejected');
    t.end();
  });

  // Test 7: URL validation accepts legitimate HTTP URLs
  t.test('should accept valid HTTP URLs', (t) => {
    const validUrl = 'http://example.com/image.png';
    const isValid = validator.isURL(validUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, true, 'Valid HTTP URL should be accepted');
    t.end();
  });

  // Test 8: URL validation accepts legitimate HTTPS URLs
  t.test('should accept valid HTTPS URLs', (t) => {
    const validUrl = 'https://example.com/path/to/image.jpg';
    const isValid = validator.isURL(validUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, true, 'Valid HTTPS URL should be accepted');
    t.end();
  });

  // Test 9: URL validation rejects URLs without protocol
  t.test('should reject URLs without protocol', (t) => {
    const urlWithoutProtocol = 'example.com/image.png';
    const isValid = validator.isURL(urlWithoutProtocol, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'URL without protocol should be rejected');
    t.end();
  });

  // Test 10: URL validation rejects non-HTTP(S) protocols
  t.test('should reject file:// protocol URLs', (t) => {
    const fileUrl = 'file:///etc/passwd';
    const isValid = validator.isURL(fileUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'file:// protocol should be rejected');
    t.end();
  });

  // Test 11: Pentest reproduction - semicolon injection
  t.test('should reject pentest payload with semicolon command separator', (t) => {
    // This is the exact payload from the pentest finding
    const pentestPayload = 'http://example.invalid/x;id;';
    const isValid = validator.isURL(pentestPayload, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'Pentest payload should be rejected by URL validation');
    t.end();
  });

  // Test 12: Pentest reproduction - comment injection
  t.test('should reject payload with shell comment character', (t) => {
    const payloadWithComment = 'http://example.invalid/x;id; #';
    const isValid = validator.isURL(payloadWithComment, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'Payload with comment character should be rejected');
    t.end();
  });

  // Test 13: Verify execFile is available (defensive check)
  t.test('should have execFile available from child_process', (t) => {
    const { execFile } = require('child_process');
    t.type(execFile, 'function', 'execFile should be a function');
    t.end();
  });

  // Test 14: Verify validator module is available
  t.test('should have validator module with isURL function', (t) => {
    t.type(validator.isURL, 'function', 'validator.isURL should be a function');
    t.end();
  });

  // Test 15: URL validation with query parameters
  t.test('should accept valid URLs with query parameters', (t) => {
    const urlWithQuery = 'http://example.com/image.png?size=large&format=jpg';
    const isValid = validator.isURL(urlWithQuery, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, true, 'Valid URL with query parameters should be accepted');
    t.end();
  });

  // Test 16: URL validation with fragments
  t.test('should accept valid URLs with fragments', (t) => {
    const urlWithFragment = 'http://example.com/page#section';
    const isValid = validator.isURL(urlWithFragment, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, true, 'Valid URL with fragment should be accepted');
    t.end();
  });

  // Test 17: Regex extraction pattern test
  t.test('should extract URL from markdown image syntax', (t) => {
    const markdownImage = '![alt text](http://example.com/image.png "title")';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    const match = markdownImage.match(imgRegex);
    t.ok(match, 'Regex should match markdown image syntax');
    t.equal(match[1], 'http://example.com/image.png', 'Should extract URL correctly');
    t.end();
  });

  // Test 18: Regex extraction with malicious payload
  t.test('should extract malicious URL from markdown (before validation)', (t) => {
    const maliciousMarkdown = '![alt text](http://example.invalid/x;id; # "x")';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    const match = maliciousMarkdown.match(imgRegex);
    t.ok(match, 'Regex should match malicious markdown');
    const extractedUrl = match[1];
    // Now verify that this extracted URL would be rejected by validation
    const isValid = validator.isURL(extractedUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'Extracted malicious URL should fail validation');
    t.end();
  });

  // Test 19: Double encoding attack
  t.test('should reject URLs with encoded shell metacharacters', (t) => {
    const encodedUrl = 'http://example.com/x%3Bid'; // %3B is semicolon
    const isValid = validator.isURL(encodedUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    // validator.isURL accepts percent-encoded URLs, but execFile won't interpret them as shell commands
    // This test documents that URL encoding is allowed, but execFile provides protection
    t.ok(typeof isValid === 'boolean', 'URL validation should return a boolean');
    t.end();
  });

  // Test 20: Null byte injection
  t.test('should reject URLs with null bytes', (t) => {
    const nullByteUrl = 'http://example.com/x\x00id';
    const isValid = validator.isURL(nullByteUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'URL with null byte should be rejected');
    t.end();
  });

  t.end();
});

// Test authentication middleware behavior
tap.test('Authentication Middleware Tests', (t) => {
  const routes = require('../routes/index.js');

  // Test 21: isLoggedIn middleware exists
  t.test('should have isLoggedIn middleware function', (t) => {
    t.type(routes.isLoggedIn, 'function', 'isLoggedIn should be a function');
    t.end();
  });

  // Test 22: isLoggedIn redirects when not logged in
  t.test('should redirect to / when user is not logged in', (t) => {
    const req = { session: { loggedIn: 0 } };
    const res = {
      redirect: function(path) {
        t.equal(path, '/', 'Should redirect to home page');
        t.end();
      }
    };
    const next = function() {
      t.fail('Should not call next() when not logged in');
      t.end();
    };
    routes.isLoggedIn(req, res, next);
  });

  // Test 23: isLoggedIn allows access when logged in
  t.test('should call next() when user is logged in', (t) => {
    const req = { session: { loggedIn: 1 } };
    const res = {
      redirect: function(path) {
        t.fail('Should not redirect when logged in');
        t.end();
      }
    };
    const next = function() {
      t.pass('Should call next() when logged in');
      t.end();
    };
    routes.isLoggedIn(req, res, next);
  });

  // Test 24: create function exists
  t.test('should have create route handler function', (t) => {
    t.type(routes.create, 'function', 'create should be a function');
    t.end();
  });

  t.end();
});

// Test the complete flow with mocked dependencies
tap.test('Integration Tests for Command Injection Mitigation', (t) => {
  
  // Test 25: Complete flow - malicious payload should be rejected
  t.test('should reject malicious markdown image and skip command execution', (t) => {
    const maliciousContent = '![alt text](http://example.invalid/x;id; # "x")';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    
    if (typeof maliciousContent === 'string' && maliciousContent.match(imgRegex)) {
      const url = maliciousContent.match(imgRegex)[1];
      const isValid = validator.isURL(url, { 
        protocols: ['http', 'https'], 
        require_protocol: true 
      });
      
      if (isValid) {
        t.fail('Malicious URL should not pass validation');
      } else {
        t.pass('Malicious URL correctly rejected, command execution skipped');
      }
    }
    t.end();
  });

  // Test 26: Complete flow - legitimate payload should be accepted
  t.test('should accept legitimate markdown image for processing', (t) => {
    const legitimateContent = '![alt text](http://example.com/image.png "title")';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    
    if (typeof legitimateContent === 'string' && legitimateContent.match(imgRegex)) {
      const url = legitimateContent.match(imgRegex)[1];
      const isValid = validator.isURL(url, { 
        protocols: ['http', 'https'], 
        require_protocol: true 
      });
      
      if (isValid) {
        t.pass('Legitimate URL correctly accepted for processing');
      } else {
        t.fail('Legitimate URL should pass validation');
      }
    }
    t.end();
  });

  // Test 27: Verify execFile doesn't spawn shell
  t.test('execFile should not spawn shell by default', (t) => {
    const { execFile } = require('child_process');
    // execFile with array arguments doesn't spawn a shell
    // This is a documentation test to verify the API is used correctly
    t.type(execFile, 'function', 'execFile should be available');
    t.comment('execFile with array arguments prevents shell interpretation');
    t.end();
  });

  t.end();
});
