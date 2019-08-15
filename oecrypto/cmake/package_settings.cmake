if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/opt/oecrypto")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
find_package(PkgConfig)

pkg_check_modules(OEOpenSSL openssl_oe_enclave)

# Generate CMake config files

configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/OECryptoConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/OECryptoConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/oecrypto/cmake
    PATH_VARS CMAKE_INSTALL_LIBDIR)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/OECryptoConfigVersion.cmake
    COMPATIBILITY SameMajorVersion)

# Generate pkg-config files

set(DEST_DIR "${CMAKE_INSTALL_PREFIX}")
set(PRIVATE_LIBS "-L/opt/oe-openssl/lib -lssl -lcrypto")

CONFIGURE_FILE("cmake/oecrypto.pc.in" "oecrypto.pc" @ONLY)

# Install

install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/OECryptoConfig.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/OECryptoConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/oecrypto/cmake)
install(FILES
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/oecryptorc
        DESTINATION ${CMAKE_INSTALL_DATADIR}/oecrypto)
install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/oecrypto.pc
        DESTINATION ${CMAKE_INSTALL_DATADIR}/pkgconfig)
install(EXPORT OECryptoTargets
        NAMESPACE oecrypto::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/oecrypto/cmake)
