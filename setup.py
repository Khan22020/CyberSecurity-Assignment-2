"""
Setup script for Secure FinTech Application
Run this script to initialize the application
"""

import os
import sys

def setup():
    """Setup the application environment"""
    print("Setting up Secure FinTech Application...")
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required.")
        sys.exit(1)
    
    print("✓ Python version check passed")
    
    # Create uploads directory
    uploads_dir = 'uploads'
    if not os.path.exists(uploads_dir):
        os.makedirs(uploads_dir)
        print(f"✓ Created {uploads_dir} directory")
    else:
        print(f"✓ {uploads_dir} directory already exists")
    
    # Check if requirements.txt exists
    if not os.path.exists('requirements.txt'):
        print("Warning: requirements.txt not found")
    else:
        print("✓ requirements.txt found")
    
    print("\nSetup complete!")
    print("\nNext steps:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Run the application: python app.py")
    print("3. Open browser and navigate to: http://127.0.0.1:5000")

if __name__ == '__main__':
    setup()

