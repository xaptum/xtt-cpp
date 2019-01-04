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

void length();
void equality();
void hash();
void serialize_bin();
void serialize_text();
void string_to_bin();
void serialize_bins_agree();

int main()
{
    xtt::initialize_crypto();

    length();
    equality();
    hash();
    serialize_bin();
    serialize_text();
    string_to_bin();
    serialize_bins_agree();
}

void length()
{
    std::cout << "Starting group_identity_Test::length...\n";

    xtt::group_identity id;

    TEST_ASSERT(id.length() == sizeof(xtt_group_id));
}

void equality()
{
    std::cout << "Starting group_identity_Test::equality...\n";

    xtt::group_identity id1;
    xtt_crypto_get_random(id1.get()->data, sizeof(xtt_group_id));

    xtt::group_identity id2;
    xtt_crypto_get_random(id2.get()->data, sizeof(xtt_group_id));

    TEST_ASSERT(id1 == id1);
    TEST_ASSERT(id1 != id2);
}

void hash()
{
    std::cout << "Starting group_identity_Test::hash...\n";

    xtt::group_identity id1;
    xtt_crypto_get_random(id1.get()->data, sizeof(xtt_group_id));

    xtt::group_identity id2;
    xtt_crypto_get_random(id2.get()->data, sizeof(xtt_group_id));

    auto hash1 = std::hash<xtt::group_identity>()(id1);
    auto hash2 = std::hash<xtt::group_identity>()(id2);
    TEST_ASSERT(hash1 == hash1);
    TEST_ASSERT(hash1 != hash2);
}

void serialize_bin()
{
    std::cout << "Starting group_identity_Test::serialize_bin...\n";

    std::vector<unsigned char> id_as_bytes(sizeof(xtt_group_id));
    xtt_crypto_get_random(id_as_bytes.data(), id_as_bytes.size());

    auto maybe_id = xtt::group_identity::deserialize(id_as_bytes);

    TEST_ASSERT(maybe_id);

    auto id_serialized = (*maybe_id).serialize();

    TEST_ASSERT(id_serialized.size() == sizeof(xtt_group_id));
    TEST_ASSERT(id_as_bytes == id_serialized);
}

void serialize_text()
{
    std::cout << "Starting group_identity_Test::serialize_text...\n";

    std::vector<unsigned char> id_as_bytes(sizeof(xtt_group_id));
    xtt_crypto_get_random(id_as_bytes.data(), id_as_bytes.size());
    std::stringstream ss;
    ss << std::hex;
    for (auto& b: id_as_bytes)
        ss << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string id_as_text = ss.str();
    TEST_ASSERT(id_as_text.length() == 2*sizeof(xtt_group_id));

    auto maybe_id = xtt::group_identity::deserialize(id_as_text);

    TEST_ASSERT(maybe_id);

    auto id_serialized = (*maybe_id).serialize_to_text();

    TEST_ASSERT(id_as_text == id_serialized);

    std::cout << "Group identity as string is: '" << id_as_text << "'"
        << ", which gets serialized as: '" << *maybe_id << std::endl;
}

void string_to_bin()
{
    std::cout << "Starting group_identity_Test::string_to_bin...\n";

    std::vector<unsigned char> id_as_bytes(sizeof(xtt_group_id));
    xtt_crypto_get_random(id_as_bytes.data(), id_as_bytes.size());
    std::stringstream ss;
    ss << std::hex;
    for (auto& b: id_as_bytes)
        ss << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string id_as_text = ss.str();
    TEST_ASSERT(id_as_text.length() == 2*sizeof(xtt_group_id));

    auto maybe_id = xtt::group_identity::deserialize(id_as_text);

    TEST_ASSERT(maybe_id);

    auto id_serialized = (*maybe_id).serialize();

    TEST_ASSERT(id_as_bytes == id_serialized);
}

void serialize_bins_agree()
{
    std::cout << "Starting group_identity_Test::serialize_bins_agree...\n";

    unsigned char id_as_bytes[sizeof(xtt_group_id)];
    xtt_crypto_get_random(id_as_bytes, sizeof(id_as_bytes));

    auto maybe_id = xtt::group_identity::deserialize(id_as_bytes, sizeof(id_as_bytes));

    TEST_ASSERT(maybe_id);

    auto id_serialized = (*maybe_id).serialize();

    TEST_ASSERT(id_serialized.size() == sizeof(xtt_group_id));
    TEST_ASSERT(0 == memcmp(id_as_bytes, id_serialized.data(), id_serialized.size()));
}
