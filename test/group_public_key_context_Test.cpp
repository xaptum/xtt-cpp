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

#include <cstring>
#include <xtt.h>

void lrsw_clone();
void lrsw_deserialize_bin_together();
void lrsw_deserialize_bins_together_agree();
void lrsw_deserialize_bin_separate();
void lrsw_deserialize_text();
void lrsw_deserialize_basename_too_long();
void lrsw_deserialize_basename_bad_length();

int main()
{
    xtt::initialize_crypto();

    lrsw_clone();
    lrsw_deserialize_bin_together();
    lrsw_deserialize_bins_together_agree();
    lrsw_deserialize_bin_separate();
    lrsw_deserialize_text();
    lrsw_deserialize_basename_too_long();
    lrsw_deserialize_basename_bad_length();
}

void lrsw_clone()
{
    std::cout << "Starting group_public_key_context_Test::lrsw_clone...\n";

    xtt::group_public_key_context_lrsw ctx;
    TEST_ASSERT(ctx.get());

    xtt_crypto_get_random((unsigned char*)ctx.get(), sizeof(xtt_group_public_key_context));

    auto cloned_ctx = ctx.clone();
    TEST_ASSERT(cloned_ctx->get());

    TEST_ASSERT(cloned_ctx->get() != ctx.get());
    TEST_ASSERT(0 == memcmp(cloned_ctx->get(), ctx.get(), sizeof(xtt_group_public_key_context)));
}

void lrsw_deserialize_bin_together()
{
    std::cout << "Starting group_public_key_context_Test::lrsw_deserialize_bin_together...\n";

    std::vector<unsigned char> basename_as_bytes(23);
    xtt_crypto_get_random(basename_as_bytes.data(), basename_as_bytes.size());

    std::vector<unsigned char> gpk_as_bytes(sizeof(xtt_daa_group_pub_key_lrsw));
    xtt_crypto_get_random(gpk_as_bytes.data(), gpk_as_bytes.size());

    std::vector<unsigned char> all_together(gpk_as_bytes);
    all_together.push_back(static_cast<unsigned char>(basename_as_bytes.size()));
    all_together.insert(all_together.end(), basename_as_bytes.begin(), basename_as_bytes.end());
    auto maybe_ctx = xtt::group_public_key_context_lrsw::deserialize(all_together);
    TEST_ASSERT(maybe_ctx);

    TEST_ASSERT(basename_as_bytes == maybe_ctx->get_basename());
    TEST_ASSERT(gpk_as_bytes == maybe_ctx->get_gpk());

    auto ctx_serialized = maybe_ctx->serialize();
    TEST_ASSERT(ctx_serialized.size() == gpk_as_bytes.size() + 1 + basename_as_bytes.size());
    TEST_ASSERT(ctx_serialized == all_together);
}

void lrsw_deserialize_bins_together_agree()
{
    std::cout << "Starting group_public_key_context_Test::lrsw_deserialize_bins_together_agree...\n";

    unsigned char basename_as_bytes[23];
    xtt_crypto_get_random(basename_as_bytes, sizeof(basename_as_bytes));

    unsigned char gpk_as_bytes[sizeof(xtt_daa_group_pub_key_lrsw)];
    xtt_crypto_get_random(gpk_as_bytes, sizeof(gpk_as_bytes));

    unsigned char all_together[sizeof(gpk_as_bytes) + 1 + sizeof(basename_as_bytes)];
    std::copy(gpk_as_bytes, gpk_as_bytes + sizeof(gpk_as_bytes), all_together);
    all_together[sizeof(gpk_as_bytes)] = sizeof(basename_as_bytes);
    std::copy(basename_as_bytes, basename_as_bytes + sizeof(basename_as_bytes), all_together + sizeof(gpk_as_bytes) + 1);
    auto maybe_ctx = xtt::group_public_key_context_lrsw::deserialize(all_together, sizeof(all_together));
    TEST_ASSERT(maybe_ctx);

    TEST_ASSERT(maybe_ctx->get_basename().size() == sizeof(basename_as_bytes));
    TEST_ASSERT(0 == memcmp(basename_as_bytes, maybe_ctx->get_basename().data(), sizeof(basename_as_bytes)));
    TEST_ASSERT(maybe_ctx->get_gpk().size() == sizeof(gpk_as_bytes));
    TEST_ASSERT(0 == memcmp(gpk_as_bytes, maybe_ctx->get_gpk().data(), sizeof(gpk_as_bytes)));

    auto ctx_serialized = maybe_ctx->serialize();
    TEST_ASSERT(ctx_serialized.size() == sizeof(all_together));
    TEST_ASSERT(0 == memcmp(ctx_serialized.data(), all_together, sizeof(all_together)));
}

void lrsw_deserialize_bin_separate()
{
    std::cout << "Starting group_public_key_context_Test::lrsw_deserialize_bin_separate...\n";

    std::vector<unsigned char> basename_as_bytes(23);
    xtt_crypto_get_random(basename_as_bytes.data(), basename_as_bytes.size());

    std::vector<unsigned char> gpk_as_bytes(sizeof(xtt_daa_group_pub_key_lrsw));
    xtt_crypto_get_random(gpk_as_bytes.data(), gpk_as_bytes.size());

    auto maybe_ctx = xtt::group_public_key_context_lrsw::from_gpk_and_basename(gpk_as_bytes,
            basename_as_bytes);
    TEST_ASSERT(maybe_ctx);

    TEST_ASSERT(basename_as_bytes == maybe_ctx->get_basename());
    TEST_ASSERT(gpk_as_bytes == maybe_ctx->get_gpk());
}

void lrsw_deserialize_bins_separate_agree()
{
    std::cout << "Starting group_public_key_context_Test::lrsw_deserialize_bins_separate_agree...\n";

    unsigned char basename_as_bytes[23];
    xtt_crypto_get_random(basename_as_bytes, sizeof(basename_as_bytes));

    unsigned char gpk_as_bytes[sizeof(xtt_daa_group_pub_key_lrsw)];
    xtt_crypto_get_random(gpk_as_bytes, sizeof(gpk_as_bytes));

    auto maybe_ctx = xtt::group_public_key_context_lrsw::from_gpk_and_basename(gpk_as_bytes, sizeof(gpk_as_bytes),
            basename_as_bytes, sizeof(basename_as_bytes));
    TEST_ASSERT(maybe_ctx);

    TEST_ASSERT(maybe_ctx->get_basename().size() == sizeof(basename_as_bytes));
    TEST_ASSERT(0 == memcmp(basename_as_bytes, maybe_ctx->get_basename().data(), sizeof(basename_as_bytes)));
    TEST_ASSERT(maybe_ctx->get_gpk().size() == sizeof(gpk_as_bytes));
    TEST_ASSERT(0 == memcmp(gpk_as_bytes, maybe_ctx->get_gpk().data(), sizeof(gpk_as_bytes)));

    unsigned char all_together[sizeof(gpk_as_bytes) + 1 + sizeof(basename_as_bytes)];
    std::copy(gpk_as_bytes, gpk_as_bytes + sizeof(gpk_as_bytes), all_together);
    all_together[sizeof(gpk_as_bytes)] = sizeof(basename_as_bytes);
    std::copy(basename_as_bytes, basename_as_bytes + sizeof(basename_as_bytes), all_together + sizeof(gpk_as_bytes) + 1);
    auto ctx_serialized = maybe_ctx->serialize();
    TEST_ASSERT(ctx_serialized.size() == sizeof(all_together));
    TEST_ASSERT(0 == memcmp(ctx_serialized.data(), all_together, sizeof(all_together)));
}

void lrsw_deserialize_text()
{
    std::cout << "Starting group_public_key_context_Test::lrsw_deserialize_text...\n";

    std::string basename_as_text = "DEADBEEFCAFE";

    std::vector<unsigned char> gpk_as_bytes(sizeof(xtt_daa_group_pub_key_lrsw));
    xtt_crypto_get_random(gpk_as_bytes.data(), gpk_as_bytes.size());
    std::stringstream ss;
    ss << std::hex;
    for (auto& b: gpk_as_bytes)
        ss << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string gpk_as_text = ss.str();
    TEST_ASSERT(gpk_as_text.length() == 2*sizeof(xtt_daa_group_pub_key_lrsw));

    auto maybe_ctx = xtt::group_public_key_context_lrsw::from_gpk_and_basename(gpk_as_text, basename_as_text);
    TEST_ASSERT(maybe_ctx);

    TEST_ASSERT(basename_as_text == maybe_ctx->get_basename_as_text());
    TEST_ASSERT(gpk_as_text == maybe_ctx->get_gpk_as_text());

    std::cout << "GPK as string is: '" << gpk_as_text << "'\n"
        << "and basename as string is: '" << basename_as_text << "'\n"
        << "which creates a group public key context as: '" << *maybe_ctx << std::endl;
}

void lrsw_deserialize_basename_too_long()
{
    std::cout << "Starting group_public_key_context_Test::lrsw_deserialize_basename_too_long...\n";

    std::vector<unsigned char> basename_as_bytes(MAX_BASENAME_LENGTH+1);
    xtt_crypto_get_random(basename_as_bytes.data(), basename_as_bytes.size());

    std::vector<unsigned char> gpk_as_bytes(sizeof(xtt_daa_group_pub_key_lrsw));
    xtt_crypto_get_random(gpk_as_bytes.data(), gpk_as_bytes.size());

    auto maybe_ctx = xtt::group_public_key_context_lrsw::from_gpk_and_basename(gpk_as_bytes,
            basename_as_bytes);
    TEST_ASSERT(!maybe_ctx);
}

void lrsw_deserialize_basename_bad_length()
{
    std::cout << "Starting group_public_key_context_Test::lrsw_deserialize_basename_bad_length...\n";

    std::vector<unsigned char> basename_as_bytes(23);
    xtt_crypto_get_random(basename_as_bytes.data(), basename_as_bytes.size());

    std::vector<unsigned char> gpk_as_bytes(sizeof(xtt_daa_group_pub_key_lrsw));
    xtt_crypto_get_random(gpk_as_bytes.data(), gpk_as_bytes.size());

    std::vector<unsigned char> all_together(gpk_as_bytes);
    all_together.push_back(static_cast<unsigned char>(basename_as_bytes.size() + 1));   // nb. wrong size
    all_together.insert(all_together.end(), basename_as_bytes.begin(), basename_as_bytes.end());
    auto maybe_ctx = xtt::group_public_key_context_lrsw::deserialize(all_together);
    TEST_ASSERT(!maybe_ctx);
}
