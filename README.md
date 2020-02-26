# Prototype for using the OpenSSL libraries with the Open Enclave SDK

This OECrypto package is built on OpenSSL crypto library and serves as an optional plug-in library to the Mbed TLS crypto library used in Open Enclave.

To start using the package, link to this library before the mbedtls library is linked to.

For example, with CMake, add `set(oeenclave-openssl openenclave::oeenclave oecrypto::oecrypto)` in the top-level `CMakeFiles.txt` of your project,
and link the enclave target to the libraries with `target_link_libraries(enc ${oeenclave-openssl} <other libraries>)`.

## Build and install Open Enclave

Follow instructions [here](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Contributors/building_oe_sdk.md).

## Build and install the same version of MUSL used in Open Enclave

```bash
$ wget http://www.musl-libc.org/releases/musl-1.1.21.tar.gz
$ tar zxvf musl-1.1.21.tar.gz
$ cd musl-1.1.21
$ ./configure CFLAGS=-fPIC --prefix=/opt/musl --disable-shared
$ make
$ sudo make install
```

## Clone the repo

```bash
$ git clone https://github.com/openenclave/openenclave-openssl --recursive
```

## Build and install openssl for Open Enclave

```bash
$ cd ~/openenclave-openssl/openssl
$ git am  ../0001-Get-openssl-to-build-against-MUSL-headers.-Use-SGX-r.patch
$ ./config --with-rand-seed=none no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ssl3 no-md2 no-md4 no-afalgeng -D_FORTIFY_SOURCE=2 -DGETPID_IS_MEANINGLESS --prefix=/opt/oe-openssl CC=/opt/musl/bin/musl-gcc
$ sudo make all install
```

## Build and install OECrypto

```bash
$ cd ~/openenclave-openssl/oecrypto
$ . ~/openenclave-openssl/oecrypto/cmake/oecryptorc
$ mkdir build && cd build
$ cmake ..
$ sudo make install
```

> ## Test OECrypto
>
> ```bash
> $ cmake .. -DTEST_CRYPTO=ON
> $ make
> $ ctest
> ```

## Build the sample

```bash
$ . /opt/oecrypto/share/oecrypto/oecryptorc
```

#### `openssl_server`

```bash
$ cd ~/openenclave-openssl/sample/openssl_server
$ mkdir build && cd build
$ cmake ..
$ make
```

###### Run the sample which is a TLS server running inside an enclave

```bash
$ host/openssl_server_host enclave/enclave.signed
```

###### Connect to the server running inside an enclave. Run the following from a different terminal

```bash
$ openssl s_client -connect localhost:4433
```

#### `attested_tls`

```bash
$ cd ~/openenclave-openssl/sample/attested_tls
$ mkdir build && cd build
$ cmake ..
$ make
```

###### Run server app

```bash
$ ./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12341
```

###### Run client app

Enclave client app:

```bash
$ ./client/host/tls_client_host ./client/enc/tls_client_enc.signed -server:localhost -port:12341
```

Non-enclave client app:

```bash
$ ./non_enc_client/tls_non_enc_client -server:localhost -port:12341
```
Contributing
------------

This project welcomes contributions and suggestions. All contributions to the Open Enclave SDK
must adhere to the terms of the [Developer Certificate of Origin (DCO)](https://developercertificate.org/).
For details, see [Contributing to Open Enclave](https://github.com/openenclave/openenclave/docs/Contributing.md).

This project follows a [Code of Conduct](https://github.com/openenclave/openenclave/docs/CodeOfConduct.md) adapted from the
[Contributor Covenant v1.4](https://www.contributor-covenant.org).

