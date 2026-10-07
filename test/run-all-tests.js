#!/usr/bin/env node
/**
 * Standalone test runner for security tests
 * Runs tests without requiring npm test or snyk authentication
 */

console.log('='.repeat(70));
console.log('Security Tests for Import Endpoint');
console.log('='.repeat(70));
console.log('');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

// Run the unit tests
console.log('Running unit tests...\n');
try {
  require('./import-security.test.js');
  console.log('\n✓ Unit tests completed\n');
} catch (e) {
  console.error('✗ Unit tests failed:', e.message);
  process.exitCode = 1;
}

// Run the integration tests
console.log('Running integration tests...\n');
try {
  require('./import-integration.test.js');
  console.log('\n✓ Integration tests completed\n');
} catch (e) {
  console.error('✗ Integration tests failed:', e.message);
  process.exitCode = 1;
}

console.log('='.repeat(70));
console.log('Test run complete');
console.log('='.repeat(70));

if (process.exitCode) {
  console.log('\n⚠ Some tests failed\n');
} else {
  console.log('\n✓ All tests passed\n');
}
