set(OECRYPTO_SRC
    ${OE_SRC_DIR}/common/asn1.c
    ${OE_SRC_DIR}/common/cert.c
    ${OE_SRC_DIR}/common/kdf.c
    asn1.c
    cert.c
    cmac.c
    crl.c
    ec.c
    hmac.c
    init.c
    key.c
    sha.c
    rsa.c)

if (TEST_CRYPTO)
    list(APPEND OECRYPTO_SRC random.c)
endif ()

add_library(oecrypto STATIC ${OECRYPTO_SRC})

target_include_directories(oecrypto PRIVATE ${OEOpenSSL_INCLUDEDIR} ${OE_INTERNAL_INCLUDEDIR})
target_link_libraries(oecrypto PUBLIC openenclave::oe_includes)
target_link_libraries(oecrypto PRIVATE openenclave::oecore openenclave::oelibc ${OEOpenSSL_LDFLAGS})

install(
    TARGETS oecrypto
    EXPORT OECryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/oecrypto)
