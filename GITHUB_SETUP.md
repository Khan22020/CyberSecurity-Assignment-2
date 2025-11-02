# GitHub Setup Guide

## Steps to Create GitHub Repository

1. **Create a GitHub Account** (if you don't have one)
   - Go to https://github.com
   - Sign up for a new account

2. **Create a New Repository**
   - Click the "+" icon in the top right corner
   - Select "New repository"
   - Repository name: `Secure-FinTech-App` (or your preferred name)
   - Description: "Secure FinTech application with comprehensive security features for cybersecurity testing"
   - Set visibility: Public or Private
   - **DO NOT** initialize with README, .gitignore, or license (we already have these)
   - Click "Create repository"

3. **Initialize Git in Your Project**
   Open terminal/command prompt in your project directory:
   ```bash
   cd "c:\Users\Mohaddis Khan\Desktop\Cypersecurity\Assignment 2"
   git init
   ```

4. **Add All Files**
   ```bash
   git add .
   ```

5. **Commit Files**
   ```bash
   git commit -m "Initial commit: Secure FinTech Application with security features"
   ```

6. **Add Remote Repository**
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
   ```
   (Replace YOUR_USERNAME and YOUR_REPO_NAME with your actual GitHub username and repository name)

7. **Push to GitHub**
   ```bash
   git branch -M main
   git push -u origin main
   ```

8. **Copy Repository URL**
   - Go to your GitHub repository page
   - Click the green "Code" button
   - Copy the HTTPS URL
   - Add this URL to your README.md file

## Updating README with GitHub Link

After creating the repository, update the README.md file:
- Add GitHub repository link at the top or bottom
- Example: `GitHub Repository: https://github.com/YOUR_USERNAME/YOUR_REPO_NAME`

## Notes

- Never commit sensitive files like `.encryption_key` or database files
- Use `.gitignore` to exclude sensitive files
- Commit and push regularly as you make changes
- Keep commit messages clear and descriptive

