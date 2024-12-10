# SPI Flash Detector

A utility for detecting and analyzing SPI flash chips on Windows systems.

## Requirements

- Windows 10 or later
- Visual Studio 2019 or later with C++ support
- CMake 3.10 or later
- Administrator privileges (for hardware access)

## Building with Visual Studio

### Method 1: Using Developer Command Prompt
1. Open "Developer Command Prompt for VS 2022"
2. Navigate to project directory
3. Run `build.bat`

### Method 2: Using Visual Studio IDE
1. Open Visual Studio 2022
2. Select "Open a local folder" and choose project directory
3. Wait for CMake configuration to complete
4. Select "Release" configuration from dropdown
5. Build -> Build All (F7)

### Troubleshooting
- If CMake fails to find Visual Studio, ensure you have "Desktop development with C++" workload installed
- If build fails, try running Visual Studio as Administrator
- Check Output window for detailed error messages

### Using Command Line (Windows) 