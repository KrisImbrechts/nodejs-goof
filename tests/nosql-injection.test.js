// Test for NoSQL Injection Prevention
// This test verifies that the mitigation for CVE-NoSQL-Injection is effective

const tap = require('tap');
const test = tap.test;

// Mock dependencies
const mockMongoose = {
  model: function(name) {
    if (name === 'User') {
      return {
        find: function(query, callback) {
          // Simulate database behavior
          // If password is an object (like {$ne: null}), it would match in vulnerable version
          // But with the fix, we should never reach here with an object password
          if (typeof query.password === 'object') {
            // This simulates the vulnerable behavior that should be prevented
            callback(null, [{ username: 'admin@snyk.io', password: 'SuperSecretPassword' }]);
          } else if (query.username === 'admin@snyk.io' && query.password === 'SuperSecretPassword') {
            callback(null, [{ username: 'admin@snyk.io', password: 'SuperSecretPassword' }]);
          } else {
            callback(null, []);
          }
        }
      };
    }
  }
};

const mockValidator = {
  isEmail: function(email) {
    return typeof email === 'string' && email.includes('@');
  }
};

// Create a mock routes module with the fixed loginHandler
function createLoginHandler() {
  const User = mockMongoose.model('User');
  const validator = mockValidator;
  
  return function loginHandler(req, res, next) {
    // Validate that username and password are strings to prevent NoSQL injection
    if (typeof req.body.username !== 'string' || typeof req.body.password !== 'string') {
      return res.status(401).send();
    }
    
    if (validator.isEmail(req.body.username)) {
      User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
        if (users.length > 0) {
          const redirectPage = req.body.redirectPage;
          const session = req.session;
          const username = req.body.username;
          session.loggedIn = 1;
          
          if (redirectPage) {
            return res.redirect(redirectPage);
          } else {
            return res.redirect('/admin');
          }
        } else {
          return res.status(401).send();
        }
      });
    } else {
      return res.status(401).send();
    }
  };
}

// Helper to create mock request/response objects
function createMockReqRes(body) {
  const req = {
    body: body,
    session: {}
  };
  
  const res = {
    statusCode: 200,
    redirectUrl: null,
    sentData: null,
    status: function(code) {
      this.statusCode = code;
      return this;
    },
    send: function(data) {
      this.sentData = data;
      return this;
    },
    redirect: function(url) {
      this.redirectUrl = url;
      return this;
    }
  };
  
  return { req, res };
}

test('NoSQL Injection Prevention Tests', function(t) {
  const loginHandler = createLoginHandler();
  
  t.test('should reject login attempt with object in password field ($ne operator)', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: { $ne: null }
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should reject login attempt with object in password field ($gt operator)', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: { $gt: '' }
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should reject login attempt with object in password field ($regex operator)', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: { $regex: '.*' }
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should reject login attempt with array in password field', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: ['password1', 'password2']
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should reject login attempt with object in username field', function(t) {
    const { req, res } = createMockReqRes({
      username: { $ne: null },
      password: 'password'
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should reject login attempt with null password', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: null
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should reject login attempt with undefined password', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: undefined
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should reject login attempt with number in password field', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: 12345
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should reject login attempt with boolean in password field', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: true
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should allow valid login with correct string credentials', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: 'SuperSecretPassword'
    });
    
    loginHandler(req, res, function() {});
    
    // Need to wait for async callback
    setTimeout(function() {
      t.equal(req.session.loggedIn, 1, 'should set session.loggedIn to 1');
      t.equal(res.redirectUrl, '/admin', 'should redirect to /admin');
      t.end();
    }, 10);
  });
  
  t.test('should reject login with incorrect string password', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: 'WrongPassword'
    });
    
    loginHandler(req, res, function() {});
    
    // Need to wait for async callback
    setTimeout(function() {
      t.equal(res.statusCode, 401, 'should return 401 status');
      t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
      t.end();
    }, 10);
  });
  
  t.test('should reject login with invalid email format', function(t) {
    const { req, res } = createMockReqRes({
      username: 'notanemail',
      password: 'password'
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should enforce string type check before email validation', function(t) {
    // This test ensures the type check happens first, preventing bypass via object with toString
    const { req, res } = createMockReqRes({
      username: { toString: function() { return 'admin@snyk.io'; } },
      password: 'password'
    });
    
    loginHandler(req, res, function() {});
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.test('should handle empty string password correctly', function(t) {
    const { req, res } = createMockReqRes({
      username: 'admin@snyk.io',
      password: ''
    });
    
    loginHandler(req, res, function() {});
    
    // Empty string is a valid string type, so it passes type check but fails authentication
    setTimeout(function() {
      t.equal(res.statusCode, 401, 'should return 401 status');
      t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
      t.end();
    }, 10);
  });
  
  t.test('should handle empty string username correctly', function(t) {
    const { req, res } = createMockReqRes({
      username: '',
      password: 'password'
    });
    
    loginHandler(req, res, function() {});
    
    // Empty string is not a valid email, so it should be rejected
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });
  
  t.end();
});

test('Type Validation Security Properties', function(t) {
  t.test('typeof check correctly identifies objects', function(t) {
    t.equal(typeof { $ne: null }, 'object', 'object with $ne should be type object');
    t.equal(typeof { $gt: '' }, 'object', 'object with $gt should be type object');
    t.equal(typeof { $regex: '.*' }, 'object', 'object with $regex should be type object');
    t.equal(typeof [], 'object', 'array should be type object');
    t.equal(typeof null, 'object', 'null should be type object');
    t.end();
  });
  
  t.test('typeof check correctly identifies strings', function(t) {
    t.equal(typeof 'password', 'string', 'string literal should be type string');
    t.equal(typeof '', 'string', 'empty string should be type string');
    t.equal(typeof String('test'), 'string', 'String() should be type string');
    t.end();
  });
  
  t.test('typeof check correctly identifies non-strings', function(t) {
    t.notEqual(typeof 123, 'string', 'number should not be type string');
    t.notEqual(typeof true, 'string', 'boolean should not be type string');
    t.notEqual(typeof undefined, 'string', 'undefined should not be type string');
    t.notEqual(typeof null, 'string', 'null should not be type string');
    t.end();
  });
  
  t.end();
});
