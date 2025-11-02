# Assignment Deliverables Checklist

## Required Deliverables

### ✅ 1. Source Code
- [x] Main application file (`app.py`)
- [x] HTML templates (in `templates/` folder)
- [x] Requirements file (`requirements.txt`)
- [x] README.md file
- [x] Setup scripts

### ✅ 2. GitHub Repository
- [ ] Create GitHub account (if needed)
- [ ] Create repository on GitHub
- [ ] Push code to GitHub
- [ ] Add GitHub link to README.md
- [ ] Verify all files are pushed correctly

### ✅ 3. Test Documentation
- [x] Test case template (`Test_Cases_Template.csv`)
- [x] Test documentation markdown (`TEST_DOCUMENTATION.md`)
- [x] Test execution guide (`TEST_EXECUTION_GUIDE.md`)
- [ ] Complete test table with 20+ tests
- [ ] Add screenshots for each test (20+ screenshots)
- [ ] Export to Excel/Word format

### ✅ 4. Application Features
All required features implemented:
- [x] User Registration & Login with password hashing
- [x] Password Validation (strong password rules)
- [x] Input Forms with validation
- [x] Session Management
- [x] Data Storage Layer (encrypted/hashed)
- [x] Error Handling (no sensitive info exposure)
- [x] Encryption/Decryption Option
- [x] Audit/Activity Logs
- [x] Profile Update Page
- [x] File Upload Validation

## Steps to Complete Assignment

### Step 1: Setup Application
1. Install Python 3.7+
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python app.py`
4. Verify application starts successfully
5. Test basic functionality (register, login)

### Step 2: Create GitHub Repository
1. Follow instructions in `GITHUB_SETUP.md`
2. Create repository on GitHub
3. Push all code files
4. Update README.md with GitHub link

### Step 3: Perform Manual Security Tests
1. Use `TEST_EXECUTION_GUIDE.md` for detailed steps
2. Perform all 20+ test cases
3. Take screenshots for each test
4. Document results in test table

### Step 4: Create Test Documentation
1. Open `Test_Cases_Template.csv` in Excel
2. Fill in "Observed Result" column
3. Mark Pass/Fail for each test
4. Add screenshot paths/names
5. Export to Word or Excel format
6. Include screenshots folder

### Step 5: Prepare Final Submission
1. Create a folder named: `Assignment2_YourName`
2. Include:
   - Source code folder (all .py files, templates, etc.)
   - README.md (with GitHub link)
   - Test documentation (Excel/Word with screenshots)
   - Screenshots folder (if separate)
3. Compress to .zip file
4. Verify all files are included

## File Structure for Submission

```
Assignment2_YourName.zip
├── Source Code/
│   ├── app.py
│   ├── setup.py
│   ├── requirements.txt
│   ├── README.md
│   ├── .gitignore
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── dashboard.html
│   │   ├── profile.html
│   │   ├── encrypt_decrypt.html
│   │   ├── upload.html
│   │   ├── audit_logs.html
│   │   └── error.html
│   └── (other supporting files)
├── Test Documentation/
│   ├── Test_Cases.xlsx (or .docx)
│   └── Screenshots/
│       ├── Test1_SQL_Injection.png
│       ├── Test2_Password_Strength.png
│       ├── ... (all 20+ screenshots)
│       └── Test25_Audit_Logs.png
└── README.md (main README with GitHub link)
```

## Notes

- **DO NOT** include:
  - Database files (.db)
  - Encryption keys (.encryption_key)
  - Uploaded files (uploads/ folder contents)
  - Python cache files (__pycache__/)
  - Virtual environment (venv/, env/)

- **DO** include:
  - All source code files
  - Templates
  - Documentation files
  - Test cases with screenshots
  - README with GitHub link

## Quick Verification

Before submitting, verify:
- [ ] Application runs without errors
- [ ] All features work correctly
- [ ] GitHub repository is accessible
- [ ] All test cases are documented
- [ ] All screenshots are included
- [ ] Test table is complete (20+ tests)
- [ ] README contains GitHub link
- [ ] All required features are implemented

