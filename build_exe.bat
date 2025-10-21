@echo off
echo Installing PyInstaller...
pip install pyinstaller

echo.
echo Building executable...
pyinstaller --onefile --windowed --name="BTC_Seed_Generator" --icon=NONE main.py

echo.
echo Build complete! Check the 'dist' folder for the executable.
pause

