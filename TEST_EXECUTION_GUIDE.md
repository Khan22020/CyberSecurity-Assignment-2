# Test Execution Guide

## Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Application**
   ```bash
   python app.py
   ```

3. **Access the Application**
   - Open browser: `http://127.0.0.1:5000`
   - Register a new account
   - Start testing!

## Detailed Test Cases

### Test 1: SQL Injection Attack
**Objective**: Test if application prevents SQL injection
**Steps**:
1. Navigate to login page
2. In username field, enter: `'OR 1=1--`
3. Enter any password
4. Click Login
5. **Expected**: Error message displayed, login fails
6. **Screenshot**: Capture error message

### Test 2: Weak Password Validation
**Objective**: Verify password strength requirements
**Steps**:
1. Go to registration page
2. Enter username and email
3. Enter weak password: `12345`
4. Click Register
5. **Expected**: Password strength error message
6. **Screenshot**: Capture validation error

### Test 3: XSS (Cross-Site Scripting) Prevention
**Objective**: Test input sanitization
**Steps**:
1. Go to registration page
2. Enter username: `<script>alert('XSS')</script>`
3. Fill other required fields
4. Submit form
5. **Expected**: Input sanitized, script tags escaped
6. **Screenshot**: Show registered username (sanitized)

### Test 4: Unauthorized Access Prevention
**Objective**: Verify access control
**Steps**:
1. Logout or clear browser cookies
2. Try to access: `http://127.0.0.1:5000/dashboard`
3. **Expected**: Redirected to login page
4. **Screenshot**: Show redirect

### Test 5: Session Expiry
**Objective**: Test session timeout
**Steps**:
1. Login to application
2. Wait 30+ minutes OR modify session timeout in code temporarily
3. Try to access dashboard
4. **Expected**: Session expired, redirected to login
5. **Screenshot**: Show login page

### Test 6: Logout Functionality
**Objective**: Verify secure logout
**Steps**:
1. Login to application
2. Click Logout button
3. Try to access dashboard URL
4. **Expected**: Redirected to login, session cleared
5. **Screenshot**: Show login page after logout

### Test 7: Password Hashing Verification
**Objective**: Verify passwords are hashed
**Steps**:
1. Register a new user with password: `Test1234!`
2. Open database file `fintech_app.db` with SQLite browser
3. Check `users` table
4. **Expected**: Password is hashed, not plaintext
5. **Screenshot**: Show database entry

### Test 8: File Upload Validation
**Objective**: Test file type restrictions
**Steps**:
1. Login to application
2. Go to Upload File page
3. Try to upload `.exe` file
4. **Expected**: File rejected, error message
5. **Screenshot**: Show error message

### Test 9: Error Message Security
**Objective**: Verify no sensitive info leakage
**Steps**:
1. Access invalid URL: `http://127.0.0.1:5000/invalid`
2. **Expected**: Generic error message, no stack trace
3. **Screenshot**: Show error page

### Test 10: Input Length Validation
**Objective**: Test input length limits
**Steps**:
1. Login and go to Add Transaction
2. Enter 5000+ characters in description
3. Submit form
4. **Expected**: Length validation error
5. **Screenshot**: Show validation message

### Test 11: Duplicate User Registration
**Objective**: Verify duplicate prevention
**Steps**:
1. Register user with username: `testuser`
2. Logout
3. Try to register again with same username
4. **Expected**: Error message
5. **Screenshot**: Show duplicate error

### Test 12: Numeric Field Validation
**Objective**: Test numeric input validation
**Steps**:
1. Login and go to Add Transaction
2. Enter letters in amount field: `abc`
3. Submit form
4. **Expected**: Validation error
5. **Screenshot**: Show error message

### Test 13: Password Match Validation
**Objective**: Verify password confirmation
**Steps**:
1. Go to registration
2. Enter password: `Test1234!`
3. Enter different confirm password: `Test5678!`
4. Submit form
5. **Expected**: Password mismatch error
6. **Screenshot**: Show error message

### Test 14: Access Control
**Objective**: Test unauthorized data access
**Steps**:
1. Login as user A
2. Note user A's transaction ID (e.g., 1)
3. Logout
4. Login as user B
5. Try to access: `/transaction?id=1` (if endpoint exists)
6. **Expected**: Access denied or 404
7. **Screenshot**: Show access denied message

### Test 15: Email Validation
**Objective**: Test email format validation
**Steps**:
1. Go to registration
2. Enter invalid email: `abc@`
3. Fill other fields
4. Submit form
5. **Expected**: Email validation error
6. **Screenshot**: Show error message

### Test 16: Account Lockout
**Objective**: Test brute force protection
**Steps**:
1. Go to login page
2. Enter correct username but wrong password
3. Repeat 5 times
4. **Expected**: Account locked message
5. Try to login again
6. **Expected**: Lockout message
7. **Screenshot**: Show lockout message

### Test 17: Secure Error Handling
**Objective**: Verify app doesn't crash on errors
**Steps**:
1. Login to application
2. Try to perform invalid operations
3. **Expected**: Generic error message, app continues
4. **Screenshot**: Show error handling

### Test 18: Data Encryption
**Objective**: Verify sensitive data encryption
**Steps**:
1. Login and go to Profile
2. Enter account number: `123456789`
3. Save profile
4. Open database and check `user_profiles` table
5. **Expected**: Account number encrypted
6. **Screenshot**: Show encrypted data in database

### Test 19: Unicode Input Handling
**Objective**: Test special character handling
**Steps**:
1. Go to registration or profile update
2. Enter emoji or Unicode: `Test👤🎉`
3. Submit form
4. **Expected**: Handled gracefully, no corruption
5. **Screenshot**: Show successful submission

### Test 20: Required Field Validation
**Objective**: Test form validation
**Steps**:
1. Go to registration
2. Leave username empty
3. Fill other fields
4. Submit form
5. **Expected**: Validation error for empty field
6. **Screenshot**: Show validation message

## Additional Tests (21-25)

### Test 21: XSS in Description Field
**Steps**:
1. Login and add transaction
2. Enter description: `<img src=x onerror=alert(1)>`
3. Submit
4. **Expected**: Sanitized, no alert shown
5. **Screenshot**: Show sanitized output

### Test 22: File Size Limit
**Steps**:
1. Try to upload file larger than 5MB
2. **Expected**: Size limit error
3. **Screenshot**: Show error

### Test 23: SQL Injection in Amount Field
**Steps**:
1. Add transaction with amount: `'; DROP TABLE users;--`
2. **Expected**: Validation error
3. **Screenshot**: Show error

### Test 24: Session Security
**Steps**:
1. Login and capture session cookie
2. Logout
3. Try to use old session cookie
4. **Expected**: Session invalid
5. **Screenshot**: Show access denied

### Test 25: Audit Logging
**Steps**:
1. Perform various actions (login, transactions, etc.)
2. Check Audit Logs page
3. **Expected**: All actions logged
4. **Screenshot**: Show audit logs

## Documentation Requirements

For each test case:
1. Take screenshot showing the test action
2. Take screenshot showing the result
3. Document in Excel/Word table
4. Note actual behavior vs expected
5. Mark Pass/Fail

## Tips

- Use different browsers for testing
- Clear cookies between tests
- Take screenshots in PNG or JPG format
- Save screenshots in a dedicated folder
- Update the CSV/Excel file with results
- Note any deviations from expected behavior

