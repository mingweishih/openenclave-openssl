add_library(oecrypto STATIC
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
    random.c
    rsa.c
    sha.c)

target_include_directories(oecrypto PRIVATE ${OEOpenSSL_INCLUDEDIR} ${OE_INTERNAL_INCLUDEDIR})
target_link_libraries(oecrypto PUBLIC openenclave::oe_includes)
target_link_libraries(oecrypto PRIVATE openenclave::oecore openenclave::oelibc ${OEOpenSSL_LDFLAGS})

install(
    TARGETS oecrypto
    EXPORT OECryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/oecrypto)
