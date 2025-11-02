@echo off
echo Starting Secure FinTech Application...
echo.
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Starting application...
echo Open your browser and navigate to: http://127.0.0.1:5000
echo Press Ctrl+C to stop the application
echo.
python app.py
pause

