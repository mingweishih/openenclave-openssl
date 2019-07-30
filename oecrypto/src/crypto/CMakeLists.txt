add_library(oecrypto STATIC
    ../../common/asn1.c
    ../../common/cert.c
    ../../common/kdf.c
    asn1.c)

target_include_directories(oecrypto PRIVATE ${OEOpenSSL_INCLUDE_DIR})
target_link_libraries(oecrypto PUBLIC oecrypto_includes)
target_link_libraries(oecrypto PUBLIC openenclave::oeenclave openenclave::oelibc -L${OEOpenSSL_LIB_DIR} -lssl -lcrypto)

install(
    TARGETS oecrypto
    EXPORT OECryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/oecrypto)
