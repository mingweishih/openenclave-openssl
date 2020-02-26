// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "openssl_server_u.h"

bool check_simulate_opt(int* argc, const char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            fprintf(stdout, "Running in simulation mode\n");
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
       perror("getcwd() error");
       return 1;
    }

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if ((result = oe_create_openssl_server_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        fprintf(stderr, "oe_create_crypto_enclave(): result=%u", result);
        return 1;
    }
    
    if ((result = run_server(enclave, cwd)) != OE_OK)
    {
        fprintf(stderr, "sample failed: result=%u", result);
        return 1;
    }

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        fprintf(stderr, "oe_terminate_enclave() failed: %u\n", result);
        return 1;
    }

    return 0;
}
