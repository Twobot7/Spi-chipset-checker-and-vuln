cmake_minimum_required(VERSION 3.10)
project(spi_flash_detector)

# Enable C++17 features
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add source files
add_executable(spi_flash_detector 
    spi_flash_detector.cpp
)

# Add Windows-specific libraries
target_link_libraries(spi_flash_detector
    setupapi
    cfgmgr32
)

# Set Windows subsystem
if(MSVC)
    set_target_properties(spi_flash_detector PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )
endif() 