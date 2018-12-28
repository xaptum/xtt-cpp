#include <iostream>
#include <vector>
#include <string>

#include "test-utils.h"

#include <xtt.hpp>

void swap_moves_pointers();

int main()
{
    swap_moves_pointers();
}

void swap_moves_pointers()
{
    // Default ctor
    xtt::server_certificate_context_ecdsap256 cert_ctx_1;
    unsigned char* serialized_ptr_1 = (unsigned char*)cert_ctx_1.get()->serialized_certificate;
    TEST_ASSERT(serialized_ptr_1 == cert_ctx_1.get()->serialized_certificate_raw);

    // Copy ctor
    xtt::server_certificate_context_ecdsap256 cert_ctx_2(cert_ctx_1);
    unsigned char* serialized_ptr_2 = (unsigned char*)cert_ctx_2.get()->serialized_certificate;
    TEST_ASSERT(serialized_ptr_2 == cert_ctx_2.get()->serialized_certificate_raw);
    TEST_ASSERT((unsigned char*)cert_ctx_1.get()->serialized_certificate == serialized_ptr_1);
    TEST_ASSERT(serialized_ptr_2 != serialized_ptr_1);

    // Copy assignment
    xtt::server_certificate_context_ecdsap256 cert_ctx_3;
    cert_ctx_3 = cert_ctx_1;
    unsigned char* serialized_ptr_3 = (unsigned char*)cert_ctx_3.get()->serialized_certificate;
    TEST_ASSERT(serialized_ptr_3 == cert_ctx_3.get()->serialized_certificate_raw);
    TEST_ASSERT((unsigned char*)cert_ctx_1.get()->serialized_certificate == serialized_ptr_1);
    TEST_ASSERT(serialized_ptr_3 != serialized_ptr_1);

    // Move ctor
    xtt::server_certificate_context_ecdsap256 cert_ctx_4(std::move(cert_ctx_1));
    unsigned char* serialized_ptr_4 = (unsigned char*)cert_ctx_4.get()->serialized_certificate;
    TEST_ASSERT(serialized_ptr_4 == cert_ctx_4.get()->serialized_certificate_raw);
    TEST_ASSERT(serialized_ptr_4 != serialized_ptr_1);
}
