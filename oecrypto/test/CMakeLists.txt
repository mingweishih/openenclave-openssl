set(CMAKE_CXX_STANDARD 11)

include(add_enclave_test)
include(add_enclave)
include(oeedl_file)

add_subdirectory(data)
add_subdirectory(enclave)
add_subdirectory(host)
