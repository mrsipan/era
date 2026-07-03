cmake_minimum_required(VERSION 3.20)
project(era VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(STATIC_LINK "Link libsodium statically" OFF)

# Find libsodium
find_package(PkgConfig REQUIRED)

if(STATIC_LINK)
    # Find static libsodium
    pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)

    # Locate the static library
    find_library(SODIUM_STATIC_LIB
        NAMES libsodium.a sodium
        PATHS ${SODIUM_LIBRARY_DIRS}
        NO_DEFAULT_PATH
    )

    if(NOT SODIUM_STATIC_LIB)
        # Fallback: search system paths
        find_library(SODIUM_STATIC_LIB NAMES libsodium.a sodium)
    endif()

    if(SODIUM_STATIC_LIB)
        message(STATUS "Found static libsodium: ${SODIUM_STATIC_LIB}")

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
        target_include_directories(era SYSTEM PRIVATE ${SODIUM_INCLUDE_DIRS})
        target_link_libraries(era PRIVATE ${SODIUM_STATIC_LIB})

        # On Linux, also set full static linking if the user wants it
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_link_options(era PRIVATE -static-libgcc -static-libstdc++)
        endif()
    else()
        message(FATAL_ERROR "Static libsodium not found. Install libsodium-dev or libsodium-static.")
    endif()
else()
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

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
endif()

target_compile_options(era PRIVATE -Wall -Wextra -Wpedantic -O3)

# Tests
option(BUILD_TESTS "Build tests" OFF)
