if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/opt/oecrypto")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/OECryptoConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/OECryptoConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/OECrypto/cmake
    PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_INCLUDEDIR)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/OECryptoConfig.cmake ${CMAKE_CURRENT_SOURCE_DIR}/cmake/oecryptorc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/OECrypto/cmake)
install(EXPORT OECryptoTargets
        NAMESPACE oecrypto::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/OECrypto/cmake)
