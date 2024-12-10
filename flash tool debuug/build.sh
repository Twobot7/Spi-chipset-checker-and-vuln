#!/bin/bash

echo "Building SPI Flash Detector..."

# Create build directory if it doesn't exist
mkdir -p build

# Navigate to build directory
cd build

# Run CMake
cmake ..

# Build the project
cmake --build . --config Release

# Copy executable to parent directory
cp bin/spi_flash_detector ../spi_flash_detector

# Return to original directory
cd ..

echo "Build complete!" 