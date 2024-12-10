@echo off
echo Building SPI Flash Detector...

:: Check for Visual Studio installation
where /q cl.exe
if %ERRORLEVEL% neq 0 (
    echo Visual Studio not found in PATH
    echo Please run this from a Visual Studio Developer Command Prompt
    pause
    exit /b 1
)

:: Create build directory if it doesn't exist
if not exist "build" mkdir build

:: Navigate to build directory
cd build

:: Run CMake for Visual Studio
cmake -G "Visual Studio 17 2022" -A x64 ..

:: Build the project
cmake --build . --config Release

:: Copy executable to parent directory
if exist "bin\Release\spi_flash_detector.exe" (
    copy /Y "bin\Release\spi_flash_detector.exe" "..\spi_flash_detector.exe"
    echo Build successful! Executable created as spi_flash_detector.exe
) else (
    echo Build failed! Executable not found
)

:: Return to original directory
cd ..

pause 