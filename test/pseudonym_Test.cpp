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

void lrsw_length();
void lrsw_clone();
void lrsw_equality();
void lrsw_deserialize_bin();
void lrsw_deserialize_bins_agree();
void lrsw_deserialize_text();

int main()
{
    xtt::initialize_crypto();

    lrsw_length();
    lrsw_clone();
    lrsw_equality();
    lrsw_deserialize_bin();
    lrsw_deserialize_bins_agree();
    lrsw_deserialize_text();
}

void lrsw_length()
{
    std::cout << "Starting pseudonym_Test::length...\n";

    xtt::pseudonym_lrsw nym;

    TEST_ASSERT(nym.length() == sizeof(xtt_daa_pseudonym_lrsw));
}

void lrsw_clone()
{
    std::cout << "Starting pseudonym_Test::lrsw_clone...\n";

    xtt::pseudonym_lrsw nym;
    TEST_ASSERT(nym.get());

    xtt_crypto_get_random(nym.get()->data, sizeof(xtt_daa_pseudonym_lrsw));

    auto cloned_nym = nym.clone();
    TEST_ASSERT(cloned_nym->get());

    TEST_ASSERT(cloned_nym->get() != nym.get());
    TEST_ASSERT(0 == memcmp(cloned_nym->get(), nym.get(), sizeof(xtt_daa_pseudonym_lrsw)));
}

void lrsw_equality()
{
    std::cout << "Starting pseudonym_Test::lrsw_equality...\n";

    xtt::pseudonym_lrsw nym1;
    xtt_crypto_get_random(nym1.get()->data, sizeof(xtt_daa_pseudonym_lrsw));

    xtt::pseudonym_lrsw nym2;
    xtt_crypto_get_random(nym2.get()->data, sizeof(xtt_daa_pseudonym_lrsw));

    TEST_ASSERT(nym1 == nym1);
    TEST_ASSERT(nym2 == nym2);
    TEST_ASSERT(nym1 != nym2);
}

void lrsw_deserialize_bin()
{
    std::cout << "Starting pseudonym_Test::lrsw_deserialize_bin...\n";

    std::vector<unsigned char> nym_as_bytes(sizeof(xtt_daa_pseudonym_lrsw));
    xtt_crypto_get_random(nym_as_bytes.data(), nym_as_bytes.size());

    auto maybe_nym = xtt::pseudonym_lrsw::deserialize(nym_as_bytes);
    TEST_ASSERT(maybe_nym);

    auto nym_serialized = maybe_nym->serialize();
    TEST_ASSERT(nym_serialized.size() == nym_as_bytes.size());
    TEST_ASSERT(nym_serialized == nym_as_bytes);
}

void lrsw_deserialize_bins_agree()
{
    std::cout << "Starting pseudonym_Test::lrsw_deserialize_bins_agree...\n";

    std::vector<unsigned char> nym_as_bytes(sizeof(xtt_daa_pseudonym_lrsw));
    xtt_crypto_get_random(nym_as_bytes.data(), nym_as_bytes.size());

    auto maybe_nym = xtt::pseudonym_lrsw::deserialize(nym_as_bytes);
    TEST_ASSERT(maybe_nym);

    auto nym_serialized = maybe_nym->serialize();

    TEST_ASSERT(nym_serialized.size() == sizeof(xtt_ecdsap256_pub_key));
    TEST_ASSERT(nym_as_bytes == nym_serialized);
}

void lrsw_deserialize_text()
{
    std::cout << "Starting pseudonym_Test::lrsw_deserialize_text...\n";

    std::vector<unsigned char> nym_as_bytes(sizeof(xtt_daa_pseudonym_lrsw));
    xtt_crypto_get_random(nym_as_bytes.data(), nym_as_bytes.size());
    std::stringstream ss;
    ss << std::hex;
    for (auto& b: nym_as_bytes)
        ss << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string nym_as_text = ss.str();

    auto maybe_nym = xtt::pseudonym_lrsw::deserialize(nym_as_text);
    TEST_ASSERT(maybe_nym);

    TEST_ASSERT(nym_as_text == maybe_nym->serialize_to_text());

    std::cout << "Pseudonym as string is: '" << nym_as_text << "'\n"
        << "which serializes as: '" << *maybe_nym << std::endl;
}
