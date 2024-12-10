@echo off
:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo Requesting administrator privileges...
    powershell Start-Process -FilePath "%~f0" -Verb RunAs
    exit /b
)

:: Run the flash tool
spi_flash_detector.exe
pause 