// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "tests.h"

void TestAll()
{
#if !defined(_WIN32)
    TestASN1();
    TestCRL();
    TestEC();
    TestRSA();
#endif
    TestRandom();
    TestRdrand();
    TestHMAC();
    TestKDF();
    TestSHA();
}
