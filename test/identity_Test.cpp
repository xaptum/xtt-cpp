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

#include "test-utils.h"

#include <xtt.hpp>

#include <xtt.h>

void null();
void equality();
void hash();
void serialize_bin();
void serialize_text();
void deserialize_text_handles_noncanon();
void string_to_bin();
void serialize_bins_agree();

int main()
{
    xtt::initialize_crypto();

    null();
    hash();
    equality();
    serialize_bin();
    serialize_text();
    deserialize_text_handles_noncanon();
    string_to_bin();
    serialize_bins_agree();
}

void null()
{
    std::cout << "Starting identity_Test::null...\n";

    xtt::identity id;
    TEST_ASSERT(id.is_null());

    xtt_identity_type null_id = xtt_null_identity;
    TEST_ASSERT(0 == memcmp(null_id.data, id.get(), sizeof(xtt_identity_type)));
}

void equality()
{
    std::cout << "Starting identity_Test::equality...\n";

    xtt::identity id1;
    xtt_crypto_get_random(id1.get()->data, sizeof(xtt_identity_type));
    TEST_ASSERT(!id1.is_null());

    xtt::identity id2;
    xtt_crypto_get_random(id2.get()->data, sizeof(xtt_identity_type));
    TEST_ASSERT(!id2.is_null());

    TEST_ASSERT(id1 == id1);
    TEST_ASSERT(id1 != id2);
}

void hash()
{
    std::cout << "Starting identity_Test::hash...\n";

    xtt::identity id1;
    xtt_crypto_get_random(id1.get()->data, sizeof(xtt_identity_type));
    TEST_ASSERT(!id1.is_null());

    xtt::identity id2;
    xtt_crypto_get_random(id2.get()->data, sizeof(xtt_identity_type));
    TEST_ASSERT(!id2.is_null());

    auto hash1 = std::hash<xtt::identity>()(id1);
    auto hash2 = std::hash<xtt::identity>()(id2);
    TEST_ASSERT(hash1 == hash1);
    TEST_ASSERT(hash1 != hash2);
}

void serialize_bin()
{
    std::cout << "Starting identity_Test::serialize_bin...\n";

    std::vector<unsigned char> id_as_bytes(sizeof(xtt_identity_type));
    xtt_crypto_get_random(id_as_bytes.data(), id_as_bytes.size());

    auto maybe_id = xtt::identity::deserialize(id_as_bytes);

    TEST_ASSERT(maybe_id);

    TEST_ASSERT(!(*maybe_id).is_null());

    auto id_serialized = (*maybe_id).serialize();

    TEST_ASSERT(id_serialized.size() == sizeof(xtt_identity_type));
    TEST_ASSERT(id_as_bytes == id_serialized);
}

void serialize_text()
{
    std::cout << "Starting identity_Test::serialize_text...\n";

    std::string id_as_string = "ff02::1:2";

    auto maybe_id = xtt::identity::deserialize(id_as_string);

    TEST_ASSERT(maybe_id);

    TEST_ASSERT(!(*maybe_id).is_null());

    auto id_serialized = (*maybe_id).serialize_to_text();

    TEST_ASSERT(id_as_string == id_serialized);
}

void deserialize_text_handles_noncanon()
{
    std::cout << "Starting identity_Test::serialize_text_handles_noncanon...\n";

    std::string id_as_string = "ff02:0:0000:0000:0000:0000:1:2";
    std::string id_as_string_canon = "ff02::1:2";

    auto maybe_id = xtt::identity::deserialize(id_as_string);

    TEST_ASSERT(maybe_id);

    TEST_ASSERT(!(*maybe_id).is_null());

    auto id_serialized = (*maybe_id).serialize_to_text();

    TEST_ASSERT(id_as_string_canon == id_serialized);

    std::cout << "Identity as string is: '" << id_as_string << "'"
        << ", which gets serialized as: '" << *maybe_id << std::endl;
}

void string_to_bin()
{
    std::cout << "Starting identity_Test::string_to_bin...\n";

    std::vector<unsigned char> id_as_bytes = {0xFF, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02};
    std::string id_as_string = "ff02::1:2";

    auto maybe_id = xtt::identity::deserialize(id_as_string);

    TEST_ASSERT(maybe_id);

    TEST_ASSERT(!(*maybe_id).is_null());

    auto id_serialized = (*maybe_id).serialize();

    TEST_ASSERT(id_as_bytes == id_serialized);
}

void serialize_bins_agree()
{
    std::cout << "Starting identity_Test::serialize_bins_agree...\n";

    unsigned char id_as_bytes[sizeof(xtt_identity_type)];
    xtt_crypto_get_random(id_as_bytes, sizeof(id_as_bytes));

    auto maybe_id = xtt::identity::deserialize(id_as_bytes, sizeof(id_as_bytes));

    TEST_ASSERT(maybe_id);

    TEST_ASSERT(!(*maybe_id).is_null());

    auto id_serialized = (*maybe_id).serialize();

    TEST_ASSERT(id_serialized.size() == sizeof(xtt_identity_type));
    TEST_ASSERT(0 == memcmp(id_as_bytes, id_serialized.data(), id_serialized.size()));
}
