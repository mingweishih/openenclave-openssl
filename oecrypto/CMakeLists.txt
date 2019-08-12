cmake_minimum_required(VERSION 3.11)
enable_testing()

if (UNIX)
    set(OE_ASM ASM)
elseif (WIN32)
    set(OE_ASM ASM_MASM)
endif ()

project(OECrypto LANGUAGES C CXX ${OE_ASM})

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

set(OEOpenSSL_INCLUDE_DIR $ENV{OEOpenSSL_INCLUDE_DIR})
set(OEOpenSSL_LIB_DIR $ENV{OEOpenSSL_LIB_DIR})

if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
    # TODO: Right now assume it's Intel+SGX for x86_64 processors
    set(OE_SGX 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm.*|ARM.*|aarch64.*|AARCH64.*")
    set(OE_TRUSTZONE 1)
else()
    message(FATAL_ERROR "Unknown processor. Only Intel SGX and ARM TrustZone are supported")
endif()

if (OE_SGX)
    if (WIN32)
        # Building enclaves on windows is on by default but can be disabled for enclaves pre-compiled under linux
        option(BUILD_ENCLAVES "Build ELF enclaves" ON)
    else()
        set(BUILD_ENCLAVES ON)
    endif()

    if (BUILD_ENCLAVES AND WIN32)
        # Search for prerequisites
        find_program(CLANG clang)
    if (NOT CLANG)
        message(FATAL_ERROR "Clang is required to build ELF enclaves on Windows")
    endif ()

    # Get the list of clang specific defines and search for __clang_major__
    execute_process(
        COMMAND cmd.exe /c " clang -dM -E -x c nul | findstr __clang_major__ "
        RESULT_VARIABLE HAD_ERROR
        OUTPUT_VARIABLE CONFIG_OUTPUT
    )
    if (HAD_ERROR)
        message(FATAL_ERROR "Could not parse clang major version")
    endif ()

    # Format the output for a list
    string(REPLACE " " ";" CONFIG_OUTPUT ${CONFIG_OUTPUT})
    # Get the major version for clang
    list(GET CONFIG_OUTPUT 2 MAJOR_VERSION)
    if (MAJOR_VERSION VERSION_LESS 7)
        message(FATAL_ERROR "Clang version 7.0 or higher is required")
    endif ()

    set(USE_CLANGW ON)
endif()
else() # NOT OE_SGX
    # On non-sgx enclaves are built by default on Unix
    if (UNIX)
        set(BUILD_ENCLAVES ON)
    endif()
endif()

if (WIN32)
    # NOTE: On Windows we have found that we must use Git Bash, not the
    # Bash from the Windows Subsystem for Linux. Hence this is
    # explicitly searching only for Git Bash. See #1302 for more.
    find_program(GIT git)
    get_filename_component(GIT_DIR ${GIT} DIRECTORY)
    find_program(BASH bash
    PATHS "C:/Program Files/Git/bin" "${GIT_DIR}/../bin"
    NO_DEFAULT_PATH) # Do not find WSL bash.

    if (NOT BASH)
        message(FATAL_ERROR "Git Bash not found!")
    endif ()
else ()
    find_program(BASH bash)
    if (NOT BASH)
        message(FATAL_ERROR "Bash not found!")
    endif ()
endif ()

include(package_settings)

find_package(OpenEnclave CONFIG REQUIRED)

add_subdirectory(src)
add_subdirectory(include)
add_subdirectory(test)
