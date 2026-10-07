const tap = require('tap');
const routes = require('../routes/index');

tap.test('about_new route - Dust.js code injection mitigation', (t) => {
  
  t.test('should sanitize array values to prevent eval() exploitation', (t) => {
    // This tests the primary exploit vector: device[]=payload
    const req = {
      query: {
        device: ['malicious', 'code']  // Array value that would bypass escaping in dustjs-linkedin 2.5.0
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Array values should be rejected and replaced with empty string
    t.equal(renderedContext.device, '', 'Array values should be sanitized to empty string');
    t.end();
  });
  
  t.test('should sanitize array with injection payload', (t) => {
    // Simulates Express bracket notation: device[]=require('child_process').execSync('whoami')
    const req = {
      query: {
        device: ["require('child_process').execSync('whoami')"]
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Injection payload in array should be rejected
    t.equal(renderedContext.device, '', 'Injection payload in array should be sanitized to empty string');
    t.end();
  });
  
  t.test('should remove special characters from string values', (t) => {
    // Test that special characters that could be used for injection are removed
    const req = {
      query: {
        device: "Desktop'; require('fs')"
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Special characters should be stripped, leaving only alphanumeric
    t.equal(renderedContext.device, 'Desktop requirefs', 'Special characters should be removed');
    t.notMatch(renderedContext.device, /['";()]/g, 'No injection characters should remain');
    t.end();
  });
  
  t.test('should allow legitimate device strings', (t) => {
    const req = {
      query: {
        device: 'Desktop'
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Legitimate device string should pass through
    t.equal(renderedContext.device, 'Desktop', 'Legitimate device string should be preserved');
    t.end();
  });
  
  t.test('should allow alphanumeric with spaces, hyphens, and underscores', (t) => {
    const req = {
      query: {
        device: 'iPhone 12-Pro_Max'
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Alphanumeric with allowed characters should pass through
    t.equal(renderedContext.device, 'iPhone 12-Pro_Max', 'Alphanumeric with spaces, hyphens, underscores should be preserved');
    t.end();
  });
  
  t.test('should handle undefined device parameter', (t) => {
    const req = {
      query: {}
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Undefined should result in empty string
    t.equal(renderedContext.device, '', 'Undefined device should result in empty string');
    t.end();
  });
  
  t.test('should handle null device parameter', (t) => {
    const req = {
      query: {
        device: null
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Null should result in empty string
    t.equal(renderedContext.device, '', 'Null device should result in empty string');
    t.end();
  });
  
  t.test('should reject non-string, non-array values', (t) => {
    const req = {
      query: {
        device: { malicious: 'object' }
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Object values should be rejected
    t.equal(renderedContext.device, '', 'Object values should be sanitized to empty string');
    t.end();
  });
  
  t.test('should reject numeric values', (t) => {
    const req = {
      query: {
        device: 12345
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Numeric values should be rejected
    t.equal(renderedContext.device, '', 'Numeric values should be sanitized to empty string');
    t.end();
  });
  
  t.test('should strip eval-dangerous characters', (t) => {
    // Test various characters that could be used in eval() context
    const dangerousChars = [
      { input: "Desktop'||1==1", desc: 'single quotes' },
      { input: 'Desktop"||1==1', desc: 'double quotes' },
      { input: 'Desktop()', desc: 'parentheses' },
      { input: 'Desktop{}', desc: 'curly braces' },
      { input: 'Desktop[]', desc: 'square brackets' },
      { input: 'Desktop;alert(1)', desc: 'semicolons' },
      { input: 'Desktop\\x00', desc: 'null bytes' },
      { input: 'Desktop<script>', desc: 'angle brackets' },
      { input: 'Desktop$var', desc: 'dollar signs' },
      { input: 'Desktop`cmd`', desc: 'backticks' }
    ];
    
    dangerousChars.forEach(({ input, desc }) => {
      const req = {
        query: { device: input }
      };
      
      let renderedContext = null;
      const res = {
        render: (template, context) => {
          renderedContext = context;
        }
      };
      
      routes.about_new(req, res, null);
      
      // All dangerous characters should be stripped
      t.notMatch(renderedContext.device, /['"`(){}[\];<>$\\]/g, `Dangerous characters (${desc}) should be removed`);
    });
    
    t.end();
  });
  
  t.test('should ensure device value is safe for Dust @if conditional', (t) => {
    // The vulnerability is in the @if cond="'{device}'=='Desktop'" context
    // Test that the sanitized value cannot break out of the string context
    const req = {
      query: {
        device: "Desktop'+'malicious"
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // The sanitized value should not contain quotes or operators
    t.equal(renderedContext.device, 'Desktopmalicious', 'String concatenation operators should be removed');
    t.notMatch(renderedContext.device, /['+]/g, 'No quotes or plus operators should remain');
    t.end();
  });
  
  t.test('should verify render is called with correct template', (t) => {
    const req = {
      query: {
        device: 'Mobile'
      }
    };
    
    let templateName = null;
    const res = {
      render: (template, context) => {
        templateName = template;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Verify the correct template is used
    t.equal(templateName, 'about_new.dust', 'Should render about_new.dust template');
    t.end();
  });
  
  t.test('should verify all context properties are set', (t) => {
    const req = {
      query: {
        device: 'Tablet'
      }
    };
    
    let renderedContext = null;
    const res = {
      render: (template, context) => {
        renderedContext = context;
      }
    };
    
    routes.about_new(req, res, null);
    
    // Verify all expected properties are present
    t.ok(renderedContext.hasOwnProperty('title'), 'Context should have title property');
    t.ok(renderedContext.hasOwnProperty('subhead'), 'Context should have subhead property');
    t.ok(renderedContext.hasOwnProperty('device'), 'Context should have device property');
    t.equal(renderedContext.title, 'Patch TODO List', 'Title should be correct');
    t.equal(renderedContext.subhead, 'Vulnerabilities at their best', 'Subhead should be correct');
    t.end();
  });
  
  t.end();
});
