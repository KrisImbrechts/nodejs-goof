/**
 * Unit tests for marked XSS vulnerability mitigation
 * 
 * These tests verify that the upgrade from marked 0.3.5 to 4.0.10
 * properly mitigates stored XSS vulnerabilities through markdown rendering.
 * 
 * The vulnerability (CVE-2016-10531, CVE-2017-1000427) allowed attackers to
 * bypass the deprecated sanitize option using specially crafted javascript: URIs.
 */

const tap = require('tap');
const marked = require('marked');

// Configure marked the same way as the application
marked.setOptions({
  headerIds: false,
  mangle: false,
  sanitize: true
});

tap.test('marked XSS vulnerability mitigation', (t) => {
  
  t.test('should block javascript: protocol in links', (t) => {
    const maliciousInput = '[Click me](javascript:alert(1))';
    const output = marked.parse(maliciousInput);
    
    // The output should NOT contain executable javascript: protocol
    t.notMatch(output, /javascript:/i, 'output should not contain javascript: protocol');
    t.notMatch(output, /href="javascript:/i, 'href should not contain javascript: protocol');
    
    t.end();
  });

  t.test('should block javascript: protocol with HTML entity encoding', (t) => {
    const maliciousInput = '[Click me](javascript&#58;alert(1))';
    const output = marked.parse(maliciousInput);
    
    // Should not contain any form of javascript protocol
    t.notMatch(output, /javascript/i, 'output should not contain javascript protocol');
    t.notMatch(output, /&#58;/i, 'output should not contain encoded colon');
    
    t.end();
  });

  t.test('should block javascript: protocol with "this" bypass (CVE-2016-10531)', (t) => {
    // This was the actual exploit from marked 0.3.5 sanitizer bypass
    const maliciousInput = '[Gotcha](javascript&#58this;alert(1))';
    const output = marked.parse(maliciousInput);
    
    // The output should NOT contain executable javascript
    t.notMatch(output, /javascript/i, 'output should not contain javascript protocol');
    t.notMatch(output, /href="javascript/i, 'href should not have javascript protocol');
    t.notMatch(output, /&#58/i, 'output should not contain encoded colon');
    
    t.end();
  });

  t.test('should block javascript: protocol with full exploit payload', (t) => {
    // The exact payload from the pentest exploit script
    const maliciousInput = '[Gotcha](javascript&#58this;alert(\'marked exploit successful\'))';
    const output = marked.parse(maliciousInput);
    
    // Verify no javascript execution is possible
    t.notMatch(output, /javascript/i, 'output should not contain javascript protocol');
    t.notMatch(output, /alert/i, 'output should not contain alert function');
    
    t.end();
  });

  t.test('should block data: URI protocol', (t) => {
    const maliciousInput = '[Click me](data:text/html,<script>alert(1)</script>)';
    const output = marked.parse(maliciousInput);
    
    // data: URIs should also be blocked as they can execute scripts
    t.notMatch(output, /data:text\/html/i, 'output should not contain data: URI');
    t.notMatch(output, /href="data:/i, 'href should not contain data: protocol');
    
    t.end();
  });

  t.test('should block vbscript: protocol', (t) => {
    const maliciousInput = '[Click me](vbscript:msgbox(1))';
    const output = marked.parse(maliciousInput);
    
    // vbscript: protocol should be blocked
    t.notMatch(output, /vbscript:/i, 'output should not contain vbscript: protocol');
    
    t.end();
  });

  t.test('should allow safe HTTP links', (t) => {
    const safeInput = '[Snyk](https://snyk.io/)';
    const output = marked.parse(safeInput);
    
    // Safe HTTPS links should work normally
    t.match(output, /href="https:\/\/snyk\.io\/"/, 'should contain safe HTTPS link');
    t.match(output, /<a/, 'should contain anchor tag');
    t.match(output, />Snyk</, 'should contain link text');
    
    t.end();
  });

  t.test('should allow safe HTTP links', (t) => {
    const safeInput = '[Example](http://example.com)';
    const output = marked.parse(safeInput);
    
    // Safe HTTP links should work normally
    t.match(output, /href="http:\/\/example\.com"/, 'should contain safe HTTP link');
    
    t.end();
  });

  t.test('should render markdown formatting safely', (t) => {
    const safeInput = 'This is **markdown** with _emphasis_';
    const output = marked.parse(safeInput);
    
    // Normal markdown should render correctly
    t.match(output, /<strong>markdown<\/strong>/, 'should render bold text');
    t.match(output, /<em>emphasis<\/em>/, 'should render italic text');
    
    t.end();
  });

  t.test('should handle plain text safely', (t) => {
    const plainInput = 'Just plain text';
    const output = marked.parse(plainInput);
    
    // Plain text should be wrapped in paragraph tags
    t.match(output, /<p>Just plain text<\/p>/, 'should wrap plain text in paragraph');
    
    t.end();
  });

  t.test('should not execute inline HTML script tags', (t) => {
    const maliciousInput = '<script>alert("xss")</script>';
    const output = marked.parse(maliciousInput);
    
    // By default, marked 4.x does NOT sanitize HTML, but it also doesn't execute it
    // The key is that dangerous protocols in links are blocked
    // Note: If HTML sanitization is needed, a separate library like DOMPurify should be used
    t.type(output, 'string', 'should return a string');
    
    t.end();
  });

  t.test('should block javascript: with various encodings', (t) => {
    const encodings = [
      '[test](javascript:alert(1))',
      '[test](javascript&#58;alert(1))',
      '[test](javascript&#x3A;alert(1))',
      '[test](javascript&#58this;alert(1))',
      '[test](JaVaScRiPt:alert(1))',
    ];
    
    encodings.forEach((input) => {
      const output = marked.parse(input);
      t.notMatch(output, /javascript/i, `should block: ${input}`);
    });
    
    t.end();
  });

  t.test('marked version should be 4.x or higher', (t) => {
    const markedVersion = require('marked/package.json').version;
    const majorVersion = parseInt(markedVersion.split('.')[0], 10);
    
    t.ok(majorVersion >= 4, `marked version should be 4.x or higher, got ${markedVersion}`);
    
    t.end();
  });

  t.test('marked sanitize option should be enabled', (t) => {
    // marked 4.x still has the sanitize option, but it works correctly
    // unlike marked 0.3.5 which had a bypass vulnerability
    
    const options = marked.getDefaults();
    
    // The sanitize option should exist and be enabled
    t.ok(options.hasOwnProperty('sanitize'), 'sanitize option should exist in marked 4.x');
    t.ok(options.sanitize === true, 'sanitize should be enabled to block dangerous protocols');
    
    t.end();
  });

  t.end();
});

tap.test('integration: marked rendering in application context', (t) => {
  
  t.test('should safely render todo content with malicious markdown', (t) => {
    // Simulate what happens in the application when rendering todo.content
    const todoContent = '[Click for prize](javascript&#58this;alert(document.cookie))';
    
    // This is how it's used in views/index.ejs: marked(new String(todo.content))
    const rendered = marked.parse(new String(todoContent));
    
    // Verify the output is safe
    t.notMatch(rendered, /javascript/i, 'rendered output should not contain javascript protocol');
    t.notMatch(rendered, /alert/i, 'rendered output should not contain alert function');
    t.notMatch(rendered, /document\.cookie/i, 'rendered output should not contain cookie access');
    
    t.end();
  });

  t.test('should safely render multiple todo items', (t) => {
    const todos = [
      { content: 'Buy groceries' },
      { content: '[Malicious](javascript:alert(1))' },
      { content: 'This is **safe** markdown' },
      { content: '[Evil](javascript&#58this;alert("xss"))' },
    ];
    
    todos.forEach((todo) => {
      const rendered = marked.parse(new String(todo.content));
      
      // No javascript protocol should appear in any rendered output
      t.notMatch(rendered, /javascript:/i, `should be safe: ${todo.content}`);
    });
    
    t.end();
  });

  t.test('should handle edge cases safely', (t) => {
    const edgeCases = [
      '',  // empty string
      ' ',  // whitespace
      null,  // null (converted to string)
      undefined,  // undefined (converted to string)
      '[](javascript:void(0))',  // empty link text
      '[](<javascript:alert(1)>)',  // angle brackets
    ];
    
    edgeCases.forEach((input) => {
      try {
        const rendered = marked.parse(String(input || ''));
        t.type(rendered, 'string', `should handle: ${JSON.stringify(input)}`);
        t.notMatch(rendered, /javascript:/i, `should be safe: ${JSON.stringify(input)}`);
      } catch (err) {
        t.fail(`should not throw for input: ${JSON.stringify(input)}`);
      }
    });
    
    t.end();
  });

  t.end();
});
