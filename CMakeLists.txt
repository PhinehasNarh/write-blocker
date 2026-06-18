cmake_minimum_required(VERSION 3.15)
project(writeblock C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform-neutral sources.
set(WB_SOURCES
    src/main.c
    src/cli.c
    src/core.c
    src/sha256.c
    src/hash.c
    src/audit.c
)

# Select exactly one backend by target OS. Android is detected first because
# CMAKE_SYSTEM_NAME is "Android" (or "Linux" with the ANDROID flag) under the NDK.
if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Android")
    list(APPEND WB_SOURCES src/platform/android.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND WB_SOURCES src/platform/win.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND WB_SOURCES src/platform/linux.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND WB_SOURCES src/platform/macos.c)
else()
    message(FATAL_ERROR "Unsupported target OS: ${CMAKE_SYSTEM_NAME}")
endif()

add_executable(writeblock ${WB_SOURCES})
target_include_directories(writeblock PRIVATE include src)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # advapi32 provides the token/SID functions used by the privilege check.
    # MSVC links it by default; name it explicitly so MinGW builds also link.
    target_link_libraries(writeblock PRIVATE advapi32)
    target_compile_definitions(writeblock PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_library(IOKIT_LIB IOKit REQUIRED)
    find_library(DISKARB_LIB DiskArbitration REQUIRED)
    find_library(COREFOUNDATION_LIB CoreFoundation REQUIRED)
    target_link_libraries(writeblock PRIVATE ${IOKIT_LIB} ${DISKARB_LIB} ${COREFOUNDATION_LIB})
endif()

if(NOT MSVC)
    target_compile_options(writeblock PRIVATE -Wall -Wextra)
endif()
