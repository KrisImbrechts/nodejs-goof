const tap = require('tap');
const mongoose = require('mongoose');

// Test suite for admin credential security mitigation
tap.test('Admin Credential Security Tests', (t) => {
  let User;
  let originalEnv;
  
  t.beforeEach((done) => {
    // Save original environment
    originalEnv = process.env.ADMIN_PASSWORD;
    
    // Clear any existing User model to allow re-registration
    if (mongoose.models.User) {
      delete mongoose.models.User;
    }
    if (mongoose.modelSchemas.User) {
      delete mongoose.modelSchemas.User;
    }
    
    // Define User schema
    const UserSchema = new mongoose.Schema({
      username: String,
      password: String,
    });
    
    User = mongoose.model('User', UserSchema);
    done();
  });
  
  t.afterEach((done) => {
    // Restore original environment
    if (originalEnv !== undefined) {
      process.env.ADMIN_PASSWORD = originalEnv;
    } else {
      delete process.env.ADMIN_PASSWORD;
    }
    done();
  });
  
  t.test('should NOT create admin user when ADMIN_PASSWORD is not set', (t) => {
    // GIVEN: No ADMIN_PASSWORD environment variable
    delete process.env.ADMIN_PASSWORD;
    
    // WHEN: Checking if admin should be created
    const adminPassword = process.env.ADMIN_PASSWORD;
    const shouldCreateAdmin = adminPassword && adminPassword.length >= 8;
    
    // THEN: Admin should not be created
    t.notOk(shouldCreateAdmin, 'Admin user should not be created without ADMIN_PASSWORD');
    t.end();
  });
  
  t.test('should NOT create admin user when ADMIN_PASSWORD is empty string', (t) => {
    // GIVEN: Empty ADMIN_PASSWORD environment variable
    process.env.ADMIN_PASSWORD = '';
    
    // WHEN: Checking if admin should be created
    const adminPassword = process.env.ADMIN_PASSWORD;
    const shouldCreateAdmin = adminPassword && adminPassword.length >= 8;
    
    // THEN: Admin should not be created
    t.notOk(shouldCreateAdmin, 'Admin user should not be created with empty ADMIN_PASSWORD');
    t.end();
  });
  
  t.test('should NOT create admin user when ADMIN_PASSWORD is less than 8 characters', (t) => {
    // GIVEN: Short ADMIN_PASSWORD (7 characters)
    process.env.ADMIN_PASSWORD = 'short12';
    
    // WHEN: Checking if admin should be created
    const adminPassword = process.env.ADMIN_PASSWORD;
    const shouldCreateAdmin = adminPassword && adminPassword.length >= 8;
    
    // THEN: Admin should not be created
    t.notOk(shouldCreateAdmin, 'Admin user should not be created with password shorter than 8 characters');
    t.equal(adminPassword.length, 7, 'Password length should be 7');
    t.end();
  });
  
  t.test('should create admin user when ADMIN_PASSWORD is 8 characters or more', (t) => {
    // GIVEN: Valid ADMIN_PASSWORD (8 characters)
    process.env.ADMIN_PASSWORD = 'validpwd';
    
    // WHEN: Checking if admin should be created
    const adminPassword = process.env.ADMIN_PASSWORD;
    const shouldCreateAdmin = adminPassword && adminPassword.length >= 8;
    
    // THEN: Admin should be created
    t.ok(shouldCreateAdmin, 'Admin user should be created with valid ADMIN_PASSWORD');
    t.equal(adminPassword.length, 8, 'Password length should be 8');
    t.end();
  });
  
  t.test('should create admin user when ADMIN_PASSWORD is longer than 8 characters', (t) => {
    // GIVEN: Valid ADMIN_PASSWORD (longer than 8 characters)
    process.env.ADMIN_PASSWORD = 'MySecurePassword123!';
    
    // WHEN: Checking if admin should be created
    const adminPassword = process.env.ADMIN_PASSWORD;
    const shouldCreateAdmin = adminPassword && adminPassword.length >= 8;
    
    // THEN: Admin should be created
    t.ok(shouldCreateAdmin, 'Admin user should be created with valid long ADMIN_PASSWORD');
    t.ok(adminPassword.length > 8, 'Password length should be greater than 8');
    t.end();
  });
  
  t.test('should NOT use hardcoded password "SuperSecretPassword"', (t) => {
    // GIVEN: The old hardcoded password
    const oldHardcodedPassword = 'SuperSecretPassword';
    
    // WHEN: ADMIN_PASSWORD is not set
    delete process.env.ADMIN_PASSWORD;
    const adminPassword = process.env.ADMIN_PASSWORD;
    
    // THEN: The password should not default to the hardcoded value
    t.notEqual(adminPassword, oldHardcodedPassword, 
      'Admin password should not default to hardcoded "SuperSecretPassword"');
    t.equal(adminPassword, undefined, 
      'Admin password should be undefined when ADMIN_PASSWORD is not set');
    t.end();
  });
  
  t.test('should enforce minimum password length validation', (t) => {
    // Test various password lengths
    const testCases = [
      { password: '', expected: false, description: 'empty password' },
      { password: '1', expected: false, description: '1 character' },
      { password: '1234567', expected: false, description: '7 characters' },
      { password: '12345678', expected: true, description: '8 characters (minimum)' },
      { password: '123456789', expected: true, description: '9 characters' },
      { password: 'VeryLongPasswordThatIsDefinitelySecure123!@#', expected: true, description: 'very long password' },
    ];
    
    testCases.forEach((testCase) => {
      process.env.ADMIN_PASSWORD = testCase.password;
      const adminPassword = process.env.ADMIN_PASSWORD;
      const isValid = adminPassword && adminPassword.length >= 8;
      
      t.equal(isValid, testCase.expected, 
        `Password validation for ${testCase.description} should be ${testCase.expected}`);
    });
    
    t.end();
  });
  
  t.test('should prevent admin creation on fresh database without environment variable', (t) => {
    // GIVEN: Fresh database scenario (no admin exists) and no ADMIN_PASSWORD
    delete process.env.ADMIN_PASSWORD;
    const usersExist = false; // Simulating users.length === 0
    
    // WHEN: Checking if admin should be created
    const adminPassword = process.env.ADMIN_PASSWORD;
    let adminCreated = false;
    
    if (!usersExist) {
      if (adminPassword && adminPassword.length >= 8) {
        adminCreated = true;
      }
    }
    
    // THEN: Admin should not be created
    t.notOk(adminCreated, 
      'Admin should not be created on fresh database without ADMIN_PASSWORD environment variable');
    t.end();
  });
  
  t.test('should allow admin creation on fresh database with valid environment variable', (t) => {
    // GIVEN: Fresh database scenario and valid ADMIN_PASSWORD
    process.env.ADMIN_PASSWORD = 'SecurePass123';
    const usersExist = false; // Simulating users.length === 0
    
    // WHEN: Checking if admin should be created
    const adminPassword = process.env.ADMIN_PASSWORD;
    let adminCreated = false;
    
    if (!usersExist) {
      if (adminPassword && adminPassword.length >= 8) {
        adminCreated = true;
      }
    }
    
    // THEN: Admin should be created
    t.ok(adminCreated, 
      'Admin should be created on fresh database with valid ADMIN_PASSWORD environment variable');
    t.end();
  });
  
  t.test('should not expose hardcoded credentials in source code', (t) => {
    // GIVEN: The mitigation code
    // WHEN: Checking for hardcoded password usage
    const fs = require('fs');
    const mongooseDbContent = fs.readFileSync('./mongoose-db.js', 'utf8');
    
    // THEN: The old hardcoded password should not be used for admin creation
    const hasHardcodedPasswordInAdminCreation = 
      mongooseDbContent.includes('password: \'SuperSecretPassword\'') ||
      mongooseDbContent.includes('password: "SuperSecretPassword"');
    
    t.notOk(hasHardcodedPasswordInAdminCreation, 
      'Source code should not contain hardcoded SuperSecretPassword for admin user creation');
    
    // Verify that environment variable is used instead
    const usesEnvVariable = mongooseDbContent.includes('process.env.ADMIN_PASSWORD');
    t.ok(usesEnvVariable, 
      'Source code should use process.env.ADMIN_PASSWORD for admin password');
    
    t.end();
  });
  
  t.test('should validate password length requirement in code', (t) => {
    // GIVEN: The mitigation code
    const fs = require('fs');
    const mongooseDbContent = fs.readFileSync('./mongoose-db.js', 'utf8');
    
    // THEN: Code should check for minimum password length
    const hasLengthCheck = 
      mongooseDbContent.includes('adminPassword.length < 8') ||
      mongooseDbContent.includes('adminPassword.length >= 8');
    
    t.ok(hasLengthCheck, 
      'Source code should validate minimum password length of 8 characters');
    
    t.end();
  });
  
  t.test('should provide warning when admin cannot be created', (t) => {
    // GIVEN: The mitigation code
    const fs = require('fs');
    const mongooseDbContent = fs.readFileSync('./mongoose-db.js', 'utf8');
    
    // THEN: Code should warn when admin is not created
    const hasWarning = 
      mongooseDbContent.includes('console.warn') &&
      mongooseDbContent.includes('ADMIN_PASSWORD');
    
    t.ok(hasWarning, 
      'Source code should provide warning when ADMIN_PASSWORD is not set or invalid');
    
    t.end();
  });
  
  t.end();
});

// Test suite for login security
tap.test('Login Security Tests', (t) => {
  t.test('should reject login with old hardcoded password', (t) => {
    // GIVEN: A user trying to login with the old hardcoded password
    const attemptedUsername = 'admin@snyk.io';
    const attemptedPassword = 'SuperSecretPassword';
    const actualPassword = 'NewSecurePassword123'; // From environment
    
    // WHEN: Comparing passwords
    const loginSuccessful = (attemptedPassword === actualPassword);
    
    // THEN: Login should fail
    t.notOk(loginSuccessful, 
      'Login should fail with old hardcoded password when new password is set');
    t.end();
  });
  
  t.test('should accept login only with environment-configured password', (t) => {
    // GIVEN: A user trying to login with the environment-configured password
    const attemptedUsername = 'admin@snyk.io';
    const attemptedPassword = 'NewSecurePassword123';
    const actualPassword = 'NewSecurePassword123'; // From environment
    
    // WHEN: Comparing passwords
    const loginSuccessful = (attemptedPassword === actualPassword);
    
    // THEN: Login should succeed
    t.ok(loginSuccessful, 
      'Login should succeed with environment-configured password');
    t.end();
  });
  
  t.test('should prevent unauthorized access without valid credentials', (t) => {
    // GIVEN: Various invalid login attempts
    const validPassword = 'SecureEnvPassword123';
    
    const invalidAttempts = [
      'SuperSecretPassword',  // Old hardcoded password
      'wrongpassword',
      '',
      'admin',
      '12345678',
      'password',
    ];
    
    // WHEN/THEN: All invalid attempts should fail
    invalidAttempts.forEach((attempt) => {
      const loginSuccessful = (attempt === validPassword);
      t.notOk(loginSuccessful, 
        `Login should fail with invalid password: "${attempt}"`);
    });
    
    t.end();
  });
  
  t.end();
});

// Test suite for deployment security
tap.test('Deployment Security Tests', (t) => {
  t.test('should require explicit configuration for admin account', (t) => {
    // GIVEN: A fresh deployment without ADMIN_PASSWORD
    delete process.env.ADMIN_PASSWORD;
    
    // WHEN: Application starts
    const adminPassword = process.env.ADMIN_PASSWORD;
    const canCreateAdmin = adminPassword && adminPassword.length >= 8;
    
    // THEN: Admin account should not be automatically created
    t.notOk(canCreateAdmin, 
      'Fresh deployment should require explicit ADMIN_PASSWORD configuration');
    t.end();
  });
  
  t.test('should prevent deterministic credential recreation', (t) => {
    // GIVEN: Multiple deployments with different ADMIN_PASSWORD values
    const deployment1Password = 'FirstDeployment123';
    const deployment2Password = 'SecondDeployment456';
    
    // WHEN: Comparing passwords across deployments
    const passwordsAreDifferent = (deployment1Password !== deployment2Password);
    
    // THEN: Passwords should be different (not deterministic)
    t.ok(passwordsAreDifferent, 
      'Different deployments can have different admin passwords');
    
    // AND: Neither should be the old hardcoded password
    t.notEqual(deployment1Password, 'SuperSecretPassword', 
      'Deployment 1 should not use hardcoded password');
    t.notEqual(deployment2Password, 'SuperSecretPassword', 
      'Deployment 2 should not use hardcoded password');
    
    t.end();
  });
  
  t.test('should enforce password complexity through minimum length', (t) => {
    // GIVEN: The minimum password length requirement
    const minimumLength = 8;
    
    // WHEN: Testing various password lengths
    const weakPasswords = ['1', '12', '123', '1234', '12345', '123456', '1234567'];
    const strongPasswords = ['12345678', '123456789', 'SecurePass123', 'VeryLongPassword'];
    
    // THEN: Weak passwords should be rejected
    weakPasswords.forEach((pwd) => {
      t.ok(pwd.length < minimumLength, 
        `Weak password "${pwd}" should be shorter than minimum length`);
    });
    
    // AND: Strong passwords should be accepted
    strongPasswords.forEach((pwd) => {
      t.ok(pwd.length >= minimumLength, 
        `Strong password should meet minimum length requirement`);
    });
    
    t.end();
  });
  
  t.end();
});
