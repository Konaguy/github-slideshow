@echo off
:: OmniManager Windows build script
:: Usage: build.bat
:: Output: dist\OmniManager.exe

echo =^> Activating virtual environment
call .venv\Scripts\activate.bat

echo =^> Installing build dependencies
pip install pyinstaller pywebview --quiet

echo =^> Cleaning previous build
if exist build rmdir /s /q build
if exist dist  rmdir /s /q dist

echo =^> Building OmniManager.exe
pyinstaller OmniManager.spec

echo.
echo Build complete: dist\OmniManager\OmniManager.exe
echo Run it directly or use Inno Setup to create an installer.
pause
