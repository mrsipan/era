cmake_minimum_required(VERSION 3.20)
project(era VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# Main executable
add_executable(era
    src/main.cpp
    src/era/base64.cpp
    src/era/bech32.cpp
    src/era/crypto.cpp
    src/era/format.cpp
    src/era/identity.cpp
    src/era/recipient.cpp
    src/era/keys.cpp
)

target_include_directories(era PRIVATE src)
target_link_libraries(era PRIVATE PkgConfig::SODIUM)
target_compile_options(era PRIVATE -Wall -Wextra -Wpedantic -O3)

# Tests
option(BUILD_TESTS "Build tests" OFF)
