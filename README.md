# Secure FinTech Application

A comprehensive banking/transaction application with security-aware features designed for cybersecurity testing.

## Features

### Security Features Implemented

1. **User Registration & Login**
   - Secure password hashing using PBKDF2-SHA256
   - Account lockout after 5 failed login attempts
   - Session management with timeout (30 minutes)
   - Password strength validation

2. **Password Validation**
   - Minimum 8 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one digit
   - At least one special character

3. **Input Validation**
   - SQL Injection prevention using parameterized queries
   - XSS prevention through input sanitization
   - Input length validation
   - Email format validation
   - Numeric field validation

4. **Session Management**
   - Secure session handling with Flask sessions
   - Automatic logout after idle time
   - Protected routes requiring authentication
   - Secure logout functionality

5. **Data Storage Layer**
   - Passwords stored as hashes (never plaintext)
   - Sensitive data encrypted using Fernet (symmetric encryption)
   - SQLite database with proper schema

6. **Error Handling**
   - Generic error messages (no sensitive information leakage)
   - Proper exception handling
   - Custom error pages

7. **Encryption/Decryption**
   - AES encryption for sensitive fields
   - Encrypt/Decrypt tool for testing

8. **Audit Logging**
   - Comprehensive activity logs
   - Tracks user actions, IP addresses, and timestamps
   - Secure logging without exposing sensitive data

9. **Profile Update Page**
   - User profile management
   - Input validation on all fields
   - Access control (users can only update their own profile)

10. **File Upload Validation**
    - File type restrictions (txt, pdf, png, jpg, jpeg, gif, csv)
    - File size limits (5MB maximum)
    - Secure filename handling

## Installation

1. **Clone or download this repository**

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python app.py
   ```

4. **Access the application:**
   - Open your browser and navigate to: `http://127.0.0.1:5000`
   - Register a new account or use existing credentials

## Project Structure

```
Assignment 2/
│
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── .gitignore            # Git ignore file
├── templates/            # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── profile.html
│   ├── encrypt_decrypt.html
│   ├── upload.html
│   ├── audit_logs.html
│   └── error.html
├── uploads/              # Uploaded files directory (created on first run)
└── fintech_app.db        # SQLite database (created on first run)
```

## Database Schema

- **users**: User accounts with hashed passwords
- **transactions**: Financial transactions with optional encryption
- **audit_logs**: Activity logs for security auditing
- **user_profiles**: User profile information with encrypted fields

## Security Testing

This application is designed to support comprehensive security testing including:

- SQL Injection testing
- XSS (Cross-Site Scripting) testing
- Authentication bypass attempts
- Session hijacking tests
- Input validation testing
- File upload security
- Error message leakage tests
- Encryption/Decryption verification
- Access control testing

## Manual Testing Checklist

See `TEST_DOCUMENTATION.md` or `Test_Cases.xlsx` for detailed test cases.

## Notes

- **Development Mode**: The app runs with `debug=False` for production-like security
- **Encryption Key**: A new encryption key is generated on first run and stored in `.encryption_key`
- **Database**: SQLite database is created automatically on first run
- **File Uploads**: Uploaded files are stored in the `uploads/` directory

## Security Best Practices Implemented

1. ✅ Password hashing (never store plaintext passwords)
2. ✅ Parameterized queries (prevents SQL injection)
3. ✅ Input sanitization (prevents XSS)
4. ✅ Session security (timeout and secure handling)
5. ✅ Error handling (no information leakage)
6. ✅ Account lockout (prevents brute force)
7. ✅ File upload validation (type and size restrictions)
8. ✅ Data encryption (sensitive fields encrypted)
9. ✅ Audit logging (comprehensive activity tracking)
10. ✅ Access control (protected routes)

## Testing Instructions

1. Start the application: `python app.py`
2. Register a new account with a strong password
3. Perform the manual security tests as documented
4. Check audit logs for activity tracking
5. Test various security features and vulnerabilities

## Author

Created for Cybersecurity Assignment 2

## License

This project is created for educational purposes.

