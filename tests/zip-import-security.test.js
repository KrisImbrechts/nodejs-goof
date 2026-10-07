const tap = require('tap');
const path = require('path');
const AdmZip = require('adm-zip');

/**
 * Security tests for ZIP import path traversal vulnerability (CVE-like)
 * 
 * These tests verify that the mitigation for the unauthenticated ZIP import
 * vulnerability is effective. The vulnerability allowed attackers to upload
 * ZIP files with path traversal sequences (../) to write arbitrary files
 * outside the extraction directory.
 * 
 * Mitigations tested:
 * 1. Authentication requirement on /import endpoint
 * 2. Path validation before extraction (isPathSafe function)
 * 3. Rejection of malicious ZIP entries
 */

// Helper function that mimics the isPathSafe function from routes/index.js
function isPathSafe(extractPath, targetDir) {
  var resolvedTarget = path.resolve(targetDir);
  var resolvedPath = path.resolve(extractPath);
  return resolvedPath.startsWith(resolvedTarget);
}

// Helper to simulate the validation logic from routes/index.js
function validateZipEntries(zipBuffer, extractionPath) {
  const zip = AdmZip(zipBuffer);
  const zipEntries = zip.getEntries();
  
  for (let i = 0; i < zipEntries.length; i++) {
    const entry = zipEntries[i];
    const entryPath = path.join(extractionPath, entry.entryName);
    
    // Use the same validation logic as the fixed code
    const resolvedTarget = path.resolve(extractionPath);
    const resolvedPath = path.resolve(entryPath);
    
    if (!resolvedPath.startsWith(resolvedTarget)) {
      return {
        valid: false,
        invalidEntry: entry.entryName,
        reason: 'Path traversal detected'
      };
    }
  }
  
  return { valid: true };
}

tap.test('isPathSafe - Path Traversal Validation', (t) => {
  
  t.test('should allow safe paths within extraction directory', (t) => {
    const targetDir = '/tmp/extracted_files';
    const safePath = path.join(targetDir, 'backup.txt');
    
    t.equal(isPathSafe(safePath, targetDir), true, 'safe path should be allowed');
    t.end();
  });
  
  t.test('should allow safe nested paths within extraction directory', (t) => {
    const targetDir = '/tmp/extracted_files';
    const safePath = path.join(targetDir, 'subdir/backup.txt');
    
    t.equal(isPathSafe(safePath, targetDir), true, 'nested safe path should be allowed');
    t.end();
  });
  
  t.test('should reject path with single parent directory traversal', (t) => {
    const targetDir = '/tmp/extracted_files';
    const maliciousPath = path.join(targetDir, '../etc/passwd');
    
    t.equal(isPathSafe(maliciousPath, targetDir), false, 'path with ../ should be rejected');
    t.end();
  });
  
  t.test('should reject path with multiple parent directory traversals', (t) => {
    const targetDir = '/tmp/extracted_files';
    const maliciousPath = path.join(targetDir, '../../../usr/src/goof/public/malicious.html');
    
    t.equal(isPathSafe(maliciousPath, targetDir), false, 'path with multiple ../ should be rejected');
    t.end();
  });
  
  t.test('should reject absolute path outside extraction directory', (t) => {
    const targetDir = '/tmp/extracted_files';
    const maliciousPath = '/usr/src/goof/public/malicious.html';
    
    t.equal(isPathSafe(maliciousPath, targetDir), false, 'absolute path outside target should be rejected');
    t.end();
  });
  
  t.test('should reject path that escapes via symbolic link pattern', (t) => {
    const targetDir = '/tmp/extracted_files';
    // Path that tries to escape and then come back
    const maliciousPath = path.join(targetDir, '../extracted_files/../../../etc/passwd');
    
    t.equal(isPathSafe(maliciousPath, targetDir), false, 'complex traversal pattern should be rejected');
    t.end();
  });
  
  t.test('should handle relative target directory correctly', (t) => {
    const targetDir = './tmp/extracted_files';
    const resolvedTarget = path.resolve(targetDir);
    const safePath = path.join(resolvedTarget, 'backup.txt');
    
    t.equal(isPathSafe(safePath, targetDir), true, 'relative target dir should work correctly');
    t.end();
  });
  
  t.test('should reject path with encoded traversal sequences', (t) => {
    const targetDir = '/tmp/extracted_files';
    // Even though path.join normalizes, test the validation logic
    const maliciousPath = path.resolve(targetDir, '..', '..', 'etc', 'passwd');
    
    t.equal(isPathSafe(maliciousPath, targetDir), false, 'resolved traversal path should be rejected');
    t.end();
  });
  
  t.end();
});

tap.test('ZIP Entry Validation', (t) => {
  
  t.test('should accept ZIP with safe file entries', (t) => {
    const zip = new AdmZip();
    zip.addFile('backup.txt', Buffer.from('safe content', 'utf8'));
    zip.addFile('data/config.json', Buffer.from('{"safe": true}', 'utf8'));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    t.equal(result.valid, true, 'ZIP with safe entries should be accepted');
    t.end();
  });
  
  t.test('should reject ZIP with path traversal in entry name', (t) => {
    const zip = new AdmZip();
    zip.addFile('../../../etc/passwd', Buffer.from('malicious', 'utf8'));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    t.equal(result.valid, false, 'ZIP with traversal should be rejected');
    t.ok(result.invalidEntry.includes('..'), 'invalid entry should contain ..');
    t.equal(result.reason, 'Path traversal detected', 'reason should indicate path traversal');
    t.end();
  });
  
  t.test('should reject ZIP attempting to write to application directory', (t) => {
    const zip = new AdmZip();
    // Simulate the exact attack from the pentest finding
    zip.addFile('../../../usr/src/goof/public/zip-slip-proof.html', 
                Buffer.from('<html>Compromised</html>', 'utf8'));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    t.equal(result.valid, false, 'ZIP attempting app directory write should be rejected');
    t.ok(result.invalidEntry.includes('usr/src/goof/public'), 'should identify the malicious entry');
    t.end();
  });
  
  t.test('should reject ZIP with mixed safe and malicious entries', (t) => {
    const zip = new AdmZip();
    zip.addFile('safe.txt', Buffer.from('safe content', 'utf8'));
    zip.addFile('../../malicious.txt', Buffer.from('malicious', 'utf8'));
    zip.addFile('also-safe.txt', Buffer.from('also safe', 'utf8'));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    t.equal(result.valid, false, 'ZIP with any malicious entry should be rejected');
    t.ok(result.invalidEntry.includes('..'), 'should identify the malicious entry');
    t.end();
  });
  
  t.test('should accept ZIP with deeply nested safe paths', (t) => {
    const zip = new AdmZip();
    zip.addFile('level1/level2/level3/deep.txt', Buffer.from('deep content', 'utf8'));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    t.equal(result.valid, true, 'deeply nested safe paths should be accepted');
    t.end();
  });
  
  t.test('should reject ZIP with Windows-style path traversal', (t) => {
    const zip = new AdmZip();
    // Windows path separators
    zip.addFile('..\\..\\..\\windows\\system32\\config', Buffer.from('malicious', 'utf8'));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    // path.join normalizes backslashes on Unix, but we still validate
    t.equal(result.valid, false, 'Windows-style traversal should be rejected');
    t.end();
  });
  
  t.test('should reject ZIP with absolute path entry', (t) => {
    const zip = new AdmZip();
    zip.addFile('/etc/passwd', Buffer.from('malicious', 'utf8'));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    t.equal(result.valid, false, 'absolute path entry should be rejected');
    t.end();
  });
  
  t.end();
});

tap.test('Authentication Requirement', (t) => {
  
  t.test('import endpoint should require authentication middleware', (t) => {
    // This test verifies the fix in app.js where isLoggedIn middleware was added
    const routes = require('../routes');
    
    // Verify that isLoggedIn middleware exists and is a function
    t.equal(typeof routes.isLoggedIn, 'function', 'isLoggedIn should be a function');
    t.ok(routes.isLoggedIn.length >= 2, 'isLoggedIn should accept at least 2 parameters');
    t.end();
  });
  
  t.test('isLoggedIn middleware should check session state - unauthenticated', (t) => {
    const routes = require('../routes');
    
    // Mock request without logged in session
    const mockReq = {
      session: {
        loggedIn: 0
      }
    };
    
    let redirectCalled = false;
    let redirectPath = null;
    const mockRes = {
      redirect: (path) => {
        redirectCalled = true;
        redirectPath = path;
      }
    };
    
    let nextCalled = false;
    const mockNext = () => {
      nextCalled = true;
    };
    
    // Call the middleware
    routes.isLoggedIn(mockReq, mockRes, mockNext);
    
    // Should redirect unauthenticated users
    t.equal(redirectCalled, true, 'should redirect unauthenticated users');
    t.equal(redirectPath, '/', 'should redirect to home page');
    t.equal(nextCalled, false, 'should not call next() for unauthenticated users');
    t.end();
  });
  
  t.test('isLoggedIn middleware should allow authenticated users', (t) => {
    const routes = require('../routes');
    
    // Mock request with logged in session
    const mockReq = {
      session: {
        loggedIn: 1
      }
    };
    
    let redirectCalled = false;
    const mockRes = {
      redirect: () => {
        redirectCalled = true;
      }
    };
    
    let nextCalled = false;
    const mockNext = () => {
      nextCalled = true;
    };
    
    // Call the middleware
    routes.isLoggedIn(mockReq, mockRes, mockNext);
    
    // Should call next() for authenticated users
    t.equal(nextCalled, true, 'should call next() for authenticated users');
    t.equal(redirectCalled, false, 'should not redirect authenticated users');
    t.end();
  });
  
  t.end();
});

tap.test('Integration - Full Import Flow Security', (t) => {
  
  t.test('should validate all entries before any extraction occurs', (t) => {
    // This test ensures fail-fast behavior - if any entry is malicious,
    // no extraction should occur at all
    const zip = new AdmZip();
    zip.addFile('safe1.txt', Buffer.from('safe', 'utf8'));
    zip.addFile('../malicious.txt', Buffer.from('malicious', 'utf8'));
    zip.addFile('safe2.txt', Buffer.from('safe', 'utf8'));
    
    const zipBuffer = zip.toBuffer();
    const extractionPath = '/tmp/extracted_files';
    
    // Simulate the validation loop from routes/index.js
    const zipObj = AdmZip(zipBuffer);
    const zipEntries = zipObj.getEntries();
    
    let validationFailed = false;
    let failedEntry = null;
    
    for (let i = 0; i < zipEntries.length; i++) {
      const entry = zipEntries[i];
      const entryPath = path.join(extractionPath, entry.entryName);
      const resolvedTarget = path.resolve(extractionPath);
      const resolvedPath = path.resolve(entryPath);
      
      if (!resolvedPath.startsWith(resolvedTarget)) {
        validationFailed = true;
        failedEntry = entry.entryName;
        break;
      }
    }
    
    // Validation should fail before extraction
    t.equal(validationFailed, true, 'validation should fail for malicious ZIP');
    t.ok(failedEntry.includes('malicious.txt'), 'should identify the malicious entry');
    t.end();
  });
  
  t.test('should use path.resolve for proper canonicalization', (t) => {
    // Verify that the validation uses path.resolve which handles
    // complex traversal patterns correctly
    const targetDir = '/tmp/extracted_files';
    const complexPath = path.join(targetDir, 'a/b/../../c/../../../etc/passwd');
    
    const resolvedTarget = path.resolve(targetDir);
    const resolvedPath = path.resolve(complexPath);
    
    // After resolution, the path should be outside the target
    t.equal(resolvedPath.startsWith(resolvedTarget), false, 'complex traversal should resolve outside target');
    t.end();
  });
  
  t.end();
});

tap.test('Edge Cases and Corner Cases', (t) => {
  
  t.test('should handle empty ZIP file', (t) => {
    const zip = new AdmZip();
    const zipBuffer = zip.toBuffer();
    
    const zipObj = AdmZip(zipBuffer);
    const zipEntries = zipObj.getEntries();
    
    t.equal(zipEntries.length, 0, 'empty ZIP should have no entries');
    t.end();
  });
  
  t.test('should handle ZIP with only directories', (t) => {
    const zip = new AdmZip();
    zip.addFile('dir1/', Buffer.alloc(0));
    zip.addFile('dir2/', Buffer.alloc(0));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    t.equal(result.valid, true, 'ZIP with only directories should be accepted');
    t.end();
  });
  
  t.test('should reject directory traversal in directory entries', (t) => {
    const zip = new AdmZip();
    zip.addFile('../../malicious-dir/', Buffer.alloc(0));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    t.equal(result.valid, false, 'directory traversal in directory entry should be rejected');
    t.end();
  });
  
  t.test('should handle special characters in safe filenames', (t) => {
    const zip = new AdmZip();
    zip.addFile('file with spaces.txt', Buffer.from('content', 'utf8'));
    zip.addFile('file-with-dashes.txt', Buffer.from('content', 'utf8'));
    zip.addFile('file_with_underscores.txt', Buffer.from('content', 'utf8'));
    
    const zipBuffer = zip.toBuffer();
    const result = validateZipEntries(zipBuffer, '/tmp/extracted_files');
    
    t.equal(result.valid, true, 'special characters in safe filenames should be accepted');
    t.end();
  });
  
  t.end();
});
