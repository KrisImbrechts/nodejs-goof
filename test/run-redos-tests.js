#!/usr/bin/env node
/**
 * Standalone test runner for ReDoS mitigation tests
 * This can be run directly with: node test/run-redos-tests.js
 */

const path = require('path');
const { spawn } = require('child_process');

// Run tap directly
const tap = spawn(path.join(__dirname, '../node_modules/.bin/tap'), [
  path.join(__dirname, 'redos-mitigation.test.js'),
  '--no-coverage'
], {
  stdio: 'inherit',
  shell: true
});

tap.on('close', (code) => {
  process.exit(code);
});
