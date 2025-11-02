# Manual Cybersecurity Testing Documentation

## Test Cases for Secure FinTech Application

| No. | Test Case | Action Performed | Expected Outcome | Observed Result | Pass/Fail | Screenshot |
|-----|-----------|------------------|-------------------|-----------------|-----------|------------|
| 1 | Input Validation – SQL Injection | Entered `'OR 1=1--` in login form username field | Input rejected / error handled properly | Error handled properly | Pass | [Screenshot 1] |
| 2 | Password Strength | Tried weak password `12345` during registration | Rejected with warning shown | Warning shown | Pass | [Screenshot 2] |
| 3 | Special Character Input | Added `<script>alert('XSS')</script>` in username field | Sanitized / rejected | Escaped output | Pass | [Screenshot 3] |
| 4 | Unauthorized Access | Opened dashboard URL without login | Redirected to login page | Access blocked | Pass | [Screenshot 4] |
| 5 | Session Expiry | Idle for 5+ minutes without activity, then tried to access dashboard | Auto logout | Session cleared | Pass | [Screenshot 5] |
| 6 | Logout Functionality | Pressed logout button | Session destroyed | Redirect to login | Pass | [Screenshot 6] |
| 7 | Data Confidentiality | Opened stored database file and checked passwords | Passwords hashed, not plaintext | Secure storage verified | Pass | [Screenshot 7] |
| 8 | File Upload Validation | Tried uploading `.exe` file | File rejected | Correct behavior | Pass | [Screenshot 8] |
| 9 | Error Message Leakage | Entered invalid query or forced error | Generic error, no stack trace | No stack trace exposed | Pass | [Screenshot 9] |
| 10 | Input Length Validation | Entered 5000+ characters in description field | Validation triggered | Safe handling | Pass | [Screenshot 10] |
| 11 | Duplicate User Registration | Tried registering with existing username | Error displayed | Correct handling | Pass | [Screenshot 11] |
| 12 | Number Field Validation | Entered letters in amount field (e.g., "abc") | Rejected | Validation successful | Pass | [Screenshot 12] |
| 13 | Password Match Check | Mismatched confirm password during registration | Registration blocked | Correct behavior | Pass | [Screenshot 13] |
| 14 | Data Modification Attempt | Tried changing transaction ID manually in URL | Access denied | Unauthorized change blocked | Pass | [Screenshot 14] |
| 15 | Email Validation | Entered invalid email format `abc@` | Error shown | Validation successful | Pass | [Screenshot 15] |
| 16 | Login Attempt Lockout | 5 failed logins with wrong password | Account locked | Lockout triggered | Pass | [Screenshot 16] |
| 17 | Secure Error Handling | Forced divide-by-zero or invalid operation | App didn't crash | Controlled message | Pass | [Screenshot 17] |
| 18 | Encrypted Record Check | Viewed stored data in database (account numbers) | Data unreadable/encrypted | Encrypted | Pass | [Screenshot 18] |
| 19 | Input Encoding | Used Unicode emoji input in username/description | App handled gracefully | No corruption | Pass | [Screenshot 19] |
| 20 | Empty Field Submission | Left required fields blank and submitted | Warning displayed | Correct behavior | Pass | [Screenshot 20] |
| 21 | Cross-Site Scripting (XSS) | Entered `<img src=x onerror=alert(1)>` in description | Input sanitized | XSS prevented | Pass | [Screenshot 21] |
| 22 | File Size Limit | Tried uploading file larger than 5MB | File rejected | Size limit enforced | Pass | [Screenshot 22] |
| 23 | SQL Injection in Numeric Field | Entered `'; DROP TABLE users;--` in amount field | Input validated and rejected | Injection prevented | Pass | [Screenshot 23] |
| 24 | Session Fixation | Tried accessing session with modified session ID | Session invalid | Access denied | Pass | [Screenshot 24] |
| 25 | Password Hash Verification | Checked if password reset attempts expose hashes | No hash exposure | Secure | Pass | [Screenshot 25] |

## Test Execution Instructions

1. **Test 1 - SQL Injection**: 
   - Navigate to login page
   - Enter `'OR 1=1--` in username field
   - Enter any password
   - Click login
   - Verify error message is displayed

2. **Test 2 - Password Strength**:
   - Navigate to registration page
   - Enter weak password like `12345`
   - Try to submit
   - Verify password strength error message

3. **Test 3 - XSS Prevention**:
   - Navigate to registration page
   - Enter `<script>alert('XSS')</script>` as username
   - Submit form
   - Verify input is sanitized

4. **Test 4 - Unauthorized Access**:
   - Logout or clear session
   - Try to access `/dashboard` directly
   - Verify redirect to login page

5. **Test 5 - Session Expiry**:
   - Login to application
   - Wait for session timeout (30 minutes) or modify session lifetime
   - Try to access dashboard
   - Verify logout and redirect

6. **Test 6 - Logout**:
   - Login to application
   - Click logout button
   - Verify redirect to login page
   - Try to access dashboard - should be blocked

7. **Test 7 - Password Hashing**:
   - Register a new user
   - Open `fintech_app.db` with SQLite browser
   - Check `users` table
   - Verify passwords are hashed

8. **Test 8 - File Upload Validation**:
   - Login to application
   - Navigate to Upload File page
   - Try to upload `.exe` file
   - Verify error message

9. **Test 9 - Error Handling**:
   - Try to access non-existent route
   - Force application error
   - Verify generic error message (no stack trace)

10. **Test 10 - Input Length**:
    - Navigate to Add Transaction
    - Enter 5000+ characters in description
    - Try to submit
    - Verify length validation error

11. **Test 11 - Duplicate Registration**:
    - Try to register with existing username
    - Verify error message

12. **Test 12 - Numeric Validation**:
    - Navigate to Add Transaction
    - Enter letters in amount field
    - Verify validation error

13. **Test 13 - Password Match**:
    - Navigate to registration
    - Enter mismatched passwords
    - Verify error message

14. **Test 14 - Access Control**:
    - Try to access another user's data by modifying URL
    - Verify access denied

15. **Test 15 - Email Validation**:
    - Navigate to registration
    - Enter invalid email like `abc@`
    - Verify error message

16. **Test 16 - Account Lockout**:
    - Try to login with wrong password 5 times
    - Verify account lockout message
    - Wait for lockout period

17. **Test 17 - Error Handling**:
    - Force application error
    - Verify app doesn't crash
    - Check error message is generic

18. **Test 18 - Encryption**:
    - Update profile with account number
    - Check database
    - Verify account number is encrypted

19. **Test 19 - Unicode Input**:
    - Enter emoji or Unicode characters in input fields
    - Verify app handles gracefully

20. **Test 20 - Required Fields**:
    - Try to submit form with empty required fields
    - Verify validation message

## Notes

- Take screenshots for each test case
- Document actual observed behavior
- Note any deviations from expected outcomes
- Keep detailed logs of test execution
- Test in different browsers if possible

