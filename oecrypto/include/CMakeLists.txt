add_library(oecrypto_includes INTERFACE)
target_include_directories(oecrypto_includes INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>)
install(TARGETS oecrypto_includes EXPORT OECryptoTargets)
