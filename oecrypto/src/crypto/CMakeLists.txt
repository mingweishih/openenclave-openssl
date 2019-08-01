add_library(oecrypto STATIC
    ../../common/asn1.c
    ../../common/cert.c
    ../../common/kdf.c
    asn1.c
    cert.c
    cmac.c
    crl.c
    ec.c
    hmac.c
    init.c
    key.c
    random.c
    rsa.c
    sha.c)

target_include_directories(oecrypto PRIVATE ${OEOpenSSL_INCLUDE_DIR})
target_link_libraries(oecrypto PUBLIC oecrypto_includes)
target_link_libraries(oecrypto PUBLIC openenclave::oeenclave openenclave::oelibc -L${OEOpenSSL_LIB_DIR} -lssl -lcrypto)

install(
    TARGETS oecrypto
    EXPORT OECryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/oecrypto)
