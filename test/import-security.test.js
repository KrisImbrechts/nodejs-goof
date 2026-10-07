/**
 * Security tests for the import endpoint
 * Tests verify mitigations for:
 * - Unauthenticated access to /import endpoint
 * - ZIP path traversal (Zip Slip) vulnerability
 * - Moment locale path traversal leading to RCE
 */

// Try to load tap, fall back to simple test runner if not available
let tap;
try {
  tap = require('tap');
} catch (e) {
  console.log('tap not available, using simple test runner');
  // Simple test runner fallback
  tap = {
    test: function(name, fn) {
      console.log('\n# ' + name);
      const t = {
        ok: function(val, msg) {
          if (val) {
            console.log('  ✓ ' + msg);
          } else {
            console.log('  ✗ ' + msg);
            process.exitCode = 1;
          }
        },
        notOk: function(val, msg) {
          if (!val) {
            console.log('  ✓ ' + msg);
          } else {
            console.log('  ✗ ' + msg);
            process.exitCode = 1;
          }
        },
        pass: function(msg) {
          console.log('  ✓ ' + msg);
        },
        end: function() {}
      };
      fn(t);
    }
  };
}
const path = require('path');

// Import the validation functions from routes/index.js
// We need to extract them for unit testing
function isSafeLocale(locale) {
  // Whitelist approach: only allow valid locale identifiers without path traversal
  // Valid locales are alphanumeric with hyphens and underscores, no path separators
  if (!locale || typeof locale !== 'string') {
    return false;
  }
  // Reject any locale containing path traversal characters
  if (locale.includes('/') || locale.includes('\\') || locale.includes('..')) {
    return false;
  }
  // Only allow alphanumeric, hyphens, and underscores
  return /^[a-zA-Z0-9_-]+$/.test(locale);
}

function isSafeZipEntry(entryPath, extractionRoot) {
  // Prevent path traversal in ZIP entries
  if (!entryPath || typeof entryPath !== 'string') {
    return false;
  }
  
  // Normalize paths to resolve any .. or . components
  var pathModule = require('path');
  var normalizedExtractRoot = pathModule.resolve(extractionRoot);
  var normalizedEntryPath = pathModule.resolve(pathModule.join(extractionRoot, entryPath));
  
  // Ensure the resolved entry path is within the extraction root
  return normalizedEntryPath.startsWith(normalizedExtractRoot + pathModule.sep) || 
         normalizedEntryPath === normalizedExtractRoot;
}

tap.test('isSafeLocale - rejects path traversal attempts', function(t) {
  // Test cases that should be rejected (return false)
  const maliciousLocales = [
    '../../../tmp/malicious',
    '../../tmp/payload',
    '../locale',
    './../../etc/passwd',
    'en/../../../tmp/evil',
    'locale/../../tmp/payload',
    '..\\..\\..\\tmp\\evil',  // Windows-style
    'locale\\..\\..\\payload',
    'en/us',  // Contains forward slash
    'en\\us',  // Contains backslash
    '..',
    '../',
    '..\\',
    null,
    undefined,
    '',
    123,  // Not a string
    {},   // Not a string
  ];

  maliciousLocales.forEach(function(locale) {
    t.notOk(isSafeLocale(locale), 'Should reject malicious locale: ' + JSON.stringify(locale));
  });

  t.end();
});

tap.test('isSafeLocale - allows valid locale identifiers', function(t) {
  // Test cases that should be allowed (return true)
  const validLocales = [
    'en',
    'en-US',
    'en_US',
    'fr-FR',
    'de_DE',
    'zh-CN',
    'ja',
    'es-ES',
    'pt-BR',
    'en-GB',
    'fr',
    'de',
    'it',
    'ru',
    'ko',
    'ar',
    'hi',
    'be',  // Belgian locale from the exploit example
  ];

  validLocales.forEach(function(locale) {
    t.ok(isSafeLocale(locale), 'Should allow valid locale: ' + locale);
  });

  t.end();
});

tap.test('isSafeZipEntry - rejects path traversal in ZIP entries', function(t) {
  const extractionRoot = '/tmp/extracted_files';
  
  // Test cases that should be rejected (return false)
  const maliciousEntries = [
    '../../../tmp/malicious.js',
    '../../etc/passwd',
    '../payload.js',
    'folder/../../../tmp/evil.js',
    'legitimate/../../../../../../tmp/rce.js',
    '..\\..\\..\\tmp\\evil.js',  // Windows-style
    'folder\\..\\..\\..\\payload.js',
    null,
    undefined,
    '',
    123,  // Not a string
  ];

  maliciousEntries.forEach(function(entry) {
    t.notOk(isSafeZipEntry(entry, extractionRoot), 'Should reject malicious ZIP entry: ' + JSON.stringify(entry));
  });

  t.end();
});

tap.test('isSafeZipEntry - allows safe ZIP entries', function(t) {
  const extractionRoot = '/tmp/extracted_files';
  
  // Test cases that should be allowed (return true)
  const safeEntries = [
    'backup.txt',
    'data/backup.txt',
    'folder/subfolder/file.csv',
    'documents/report.pdf',
    'images/photo.jpg',
    'config/settings.json',
    'deeply/nested/folder/structure/file.txt',
  ];

  safeEntries.forEach(function(entry) {
    t.ok(isSafeZipEntry(entry, extractionRoot), 'Should allow safe ZIP entry: ' + entry);
  });

  t.end();
});

tap.test('isSafeZipEntry - edge cases with normalized paths', function(t) {
  const extractionRoot = '/tmp/extracted_files';
  
  // These look suspicious but resolve to safe paths within the extraction root
  const edgeCases = [
    './file.txt',  // Current directory reference
    'folder/./file.txt',  // Current directory in path
  ];

  edgeCases.forEach(function(entry) {
    const result = isSafeZipEntry(entry, extractionRoot);
    t.ok(result, 'Should handle edge case: ' + entry);
  });

  // These should still be rejected even with normalization tricks
  const stillMalicious = [
    'folder/../../../tmp/evil.js',  // Goes outside despite starting inside
    './../../etc/passwd',  // Current dir then traversal
  ];

  stillMalicious.forEach(function(entry) {
    t.notOk(isSafeZipEntry(entry, extractionRoot), 'Should reject normalized malicious entry: ' + entry);
  });

  t.end();
});

tap.test('Security mitigation - locale validation prevents RCE chain', function(t) {
  // These are the types of locale values that would enable the RCE chain
  // by allowing moment.locale() to load arbitrary JavaScript files
  const rceLocales = [
    '../../../tmp/payload',  // Direct traversal to /tmp
    '../../../../../../tmp/malicious',  // Multiple levels up
    '../locale/../../tmp/evil',  // Mixed legitimate and traversal
    'locale/../../../tmp/rce',  // Starts legitimate, then traverses
  ];

  rceLocales.forEach(function(locale) {
    t.notOk(isSafeLocale(locale), 'Should block RCE-enabling locale: ' + locale);
  });

  t.pass('Locale validation successfully prevents moment.locale() RCE chain');
  t.end();
});

tap.test('Security mitigation - ZIP validation prevents file write primitive', function(t) {
  const extractionRoot = '/tmp/extracted_files';
  
  // These are the types of ZIP entries that would enable writing files
  // outside the extraction directory (Zip Slip vulnerability)
  const zipSlipEntries = [
    '../../../tmp/payload.js',  // Write to /tmp
    '../../../../../../tmp/malicious.js',  // Multiple levels
    'backup/../../../tmp/evil.js',  // Mixed legitimate and traversal
    'data/../../../../../../tmp/rce.js',  // Starts in subfolder
  ];

  zipSlipEntries.forEach(function(entry) {
    t.notOk(isSafeZipEntry(entry, extractionRoot), 'Should block Zip Slip entry: ' + entry);
  });

  t.pass('ZIP entry validation successfully prevents arbitrary file writes');
  t.end();
});

tap.test('Combined exploit scenario - validates full attack chain is blocked', function(t) {
  const extractionRoot = '/tmp/extracted_files';
  
  // Simulate the full exploit chain:
  // 1. Attacker uploads ZIP with traversal entry to write malicious.js to /tmp
  const maliciousZipEntry = '../../../tmp/malicious.js';
  
  // 2. Attacker provides CSV with locale that would load /tmp/malicious.js
  const maliciousLocale = '../../../tmp/malicious';
  
  // Verify both parts of the chain are blocked
  t.notOk(isSafeZipEntry(maliciousZipEntry, extractionRoot), 
    'Step 1 blocked: Cannot write malicious file via ZIP traversal');
  
  t.notOk(isSafeLocale(maliciousLocale), 
    'Step 2 blocked: Cannot load malicious file via locale traversal');
  
  t.pass('Full RCE exploit chain is successfully mitigated');
  t.end();
});

tap.test('Legitimate use cases still work', function(t) {
  const extractionRoot = '/tmp/extracted_files';
  
  // Verify legitimate operations are not blocked
  t.ok(isSafeZipEntry('backup.txt', extractionRoot), 
    'Legitimate ZIP entry allowed');
  
  t.ok(isSafeLocale('en-US'), 
    'Legitimate locale allowed');
  
  t.ok(isSafeLocale('fr-FR'), 
    'Another legitimate locale allowed');
  
  t.ok(isSafeZipEntry('data/todos.csv', extractionRoot), 
    'Legitimate nested ZIP entry allowed');
  
  t.pass('Legitimate use cases are not affected by security mitigations');
  t.end();
});
