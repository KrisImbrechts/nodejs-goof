#!/usr/bin/env node
// Simple test runner that bypasses npm test script
const { spawn } = require('child_process');
const path = require('path');

const tapBin = path.join(__dirname, '..', 'node_modules', '.bin', 'tap');
const testFile = path.join(__dirname, 'import-security.test.js');

const tap = spawn(tapBin, [testFile], {
  stdio: 'inherit',
  cwd: path.join(__dirname, '..')
});

tap.on('close', (code) => {
  process.exit(code);
});
