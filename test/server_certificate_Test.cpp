/******************************************************************************
 *
 * Copyright 2019 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

#include "test-utils.h"

#include <xtt.hpp>

#include <xtt.h>

void ecdsap256_clone();
void ecdsap256_swap_moves_pointers();
void ecdsap256_clone_moves_pointers();
void ecdsap256_deserialize_bin_together();
void ecdsap256_deserialize_bin_separate();
void ecdsap256_deserialize_text();

int main()
{
    xtt::initialize_crypto();

    ecdsap256_clone();
    ecdsap256_swap_moves_pointers();
    ecdsap256_clone_moves_pointers();
    ecdsap256_deserialize_bin_together();
    ecdsap256_deserialize_bin_separate();
    ecdsap256_deserialize_text();
}

void ecdsap256_clone()
{
    std::cout << "Starting server_certificate_Test::ecdsap256_clone...\n";

    xtt::server_certificate_context_ecdsap256 ctx;
    TEST_ASSERT(ctx.get());

    xtt_crypto_get_random((unsigned char*)ctx.get(), sizeof(xtt_server_certificate_context));

    auto cloned_ctx = ctx.clone();
    TEST_ASSERT(cloned_ctx->get());

    TEST_ASSERT(ctx.get_certificate() == cloned_ctx->get_certificate());
    TEST_ASSERT(ctx.get_private_key() == cloned_ctx->get_private_key());
    TEST_ASSERT(ctx.get_certificate() != cloned_ctx->get_private_key());
}

void ecdsap256_swap_moves_pointers()
{
    std::cout << "Starting server_certificate_Test::ecdsap256_clone...\n";

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

void ecdsap256_clone_moves_pointers()
{
    std::cout << "Starting server_certificate_Test::ecdsap256_clone_moves_pointers...\n";

    xtt::server_certificate_context_ecdsap256 ctx;
    TEST_ASSERT(ctx.get());

    xtt_crypto_get_random((unsigned char*)ctx.get(), sizeof(xtt_server_certificate_context));
    unsigned char* serialized_ptr = (unsigned char*)ctx.get()->serialized_certificate;

    auto cloned_ctx = ctx.clone();
    TEST_ASSERT(cloned_ctx->get());

    TEST_ASSERT(cloned_ctx->get() != ctx.get());
    TEST_ASSERT(0 != memcmp(cloned_ctx->get(), ctx.get(), sizeof(xtt_server_certificate_context)));

    unsigned char* serialized_ptr_cloned = (unsigned char*)cloned_ctx->get()->serialized_certificate;
    TEST_ASSERT(serialized_ptr == (unsigned char*)ctx.get()->serialized_certificate);
    TEST_ASSERT(serialized_ptr != serialized_ptr_cloned);
}

void ecdsap256_deserialize_bin_together()
{
    std::cout << "Starting server_certificate_Test::ecdsap256_deserialize_bin_together...\n";

    std::vector<unsigned char> certificate_as_bytes(XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH);
    xtt_crypto_get_random(certificate_as_bytes.data(), certificate_as_bytes.size());

    std::vector<unsigned char> private_key_as_bytes(sizeof(xtt_ecdsap256_priv_key));
    xtt_crypto_get_random(private_key_as_bytes.data(), private_key_as_bytes.size());

    std::vector<unsigned char> all_together(certificate_as_bytes);
    all_together.insert(all_together.end(), private_key_as_bytes.begin(), private_key_as_bytes.end());
    auto maybe_ctx = xtt::server_certificate_context_ecdsap256::deserialize(all_together);
    TEST_ASSERT(maybe_ctx);

    TEST_ASSERT(certificate_as_bytes == maybe_ctx->get_certificate());
    TEST_ASSERT(private_key_as_bytes == maybe_ctx->get_private_key());

    auto ctx_serialized = maybe_ctx->serialize();
    TEST_ASSERT(ctx_serialized.size() == private_key_as_bytes.size() + certificate_as_bytes.size());
    TEST_ASSERT(ctx_serialized == all_together);
}

void ecdsap256_deserialize_bin_separate()
{
    std::cout << "Starting server_certificate_Test::ecdsap256_deserialize_bin_separate...\n";

    std::vector<unsigned char> certificate_as_bytes(XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH);
    xtt_crypto_get_random(certificate_as_bytes.data(), certificate_as_bytes.size());

    std::vector<unsigned char> private_key_as_bytes(sizeof(xtt_ecdsap256_priv_key));
    xtt_crypto_get_random(private_key_as_bytes.data(), private_key_as_bytes.size());

    auto maybe_ctx = xtt::server_certificate_context_ecdsap256::from_certificate_and_key(certificate_as_bytes,
            private_key_as_bytes);
    TEST_ASSERT(maybe_ctx);

    TEST_ASSERT(certificate_as_bytes == maybe_ctx->get_certificate());
    TEST_ASSERT(private_key_as_bytes == maybe_ctx->get_private_key());
}

void ecdsap256_deserialize_text()
{
    std::cout << "Starting server_certificate_Test::ecdsap256_deserialize_text_separate...\n";

    std::vector<unsigned char> certificate_as_bytes(XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH);
    xtt_crypto_get_random(certificate_as_bytes.data(), certificate_as_bytes.size());
    std::stringstream ss1;
    ss1 << std::hex;
    for (auto& b: certificate_as_bytes)
        ss1 << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string certificate_as_text = ss1.str();
    TEST_ASSERT(certificate_as_text.length() == 2*XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH);

    std::vector<unsigned char> private_key_as_bytes(sizeof(xtt_ecdsap256_priv_key));
    xtt_crypto_get_random(private_key_as_bytes.data(), private_key_as_bytes.size());
    std::stringstream ss2;
    ss2 << std::hex;
    for (auto& b: private_key_as_bytes)
        ss2 << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string private_key_as_text = ss2.str();
    TEST_ASSERT(private_key_as_text.length() == 2*sizeof(xtt_ecdsap256_priv_key));

    auto maybe_ctx = xtt::server_certificate_context_ecdsap256::from_certificate_and_key(certificate_as_text,
            private_key_as_text);
    TEST_ASSERT(maybe_ctx);

    TEST_ASSERT(certificate_as_text == maybe_ctx->get_certificate_as_text());
    TEST_ASSERT(private_key_as_text == maybe_ctx->get_private_key_as_text());
}
