add_library(oecrypto_includes INTERFACE)
target_include_directories(oecrypto_includes INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
install(TARGETS oecrypto_includes EXPORT OECryptoTargets)
