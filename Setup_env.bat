@echo off

REM Ensure pip is installed and upgraded
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install required packages
echo Installing required packages...
pip install requests
pip install pycryptodome
pip install Pillow
pip install cryptography


REM Notify user of successful setup
echo Required packages installation is complete.

REM Pause to keep the window open
pause
