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

void ecdsap256_length();
void ecdsap256_equality();
void ecdsap256_clone();
void ecdsap256_serialize_bin();
void ecdsap256_serialize_text();
void ecdsap256_string_to_bin();
void ecdsap256_serialize_bins_agree();
void ecdsap256_priv_length();
void ecdsap256_priv_equality();
void ecdsap256_priv_clone();
void ecdsap256_priv_serialize_bin();
void ecdsap256_priv_string_to_bin();
void ecdsap256_priv_serialize_bins_agree();

int main()
{
    xtt::initialize_crypto();

    ecdsap256_length();
    ecdsap256_equality();
    ecdsap256_clone();
    ecdsap256_serialize_bin();
    ecdsap256_serialize_text();
    ecdsap256_string_to_bin();
    ecdsap256_serialize_bins_agree();
    ecdsap256_priv_length();
    ecdsap256_priv_equality();
    ecdsap256_priv_clone();
    ecdsap256_priv_serialize_bin();
    ecdsap256_priv_string_to_bin();
    ecdsap256_priv_serialize_bins_agree();
}

void ecdsap256_length()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_length...\n";

    xtt::longterm_key_ecdsap256 key;

    TEST_ASSERT(key.length() == sizeof(xtt_ecdsap256_pub_key));
}

void ecdsap256_equality()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_equality...\n";

    xtt::longterm_key_ecdsap256 key1;
    xtt_crypto_get_random(key1.get()->data, sizeof(xtt_ecdsap256_pub_key));

    xtt::longterm_key_ecdsap256 key2;
    xtt_crypto_get_random(key2.get()->data, sizeof(xtt_ecdsap256_pub_key));

    TEST_ASSERT(key1 == key1);
    TEST_ASSERT(key2 == key2);
    TEST_ASSERT(key1 != key2);
}

void ecdsap256_clone()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_clone...\n";

    xtt::longterm_key_ecdsap256 key;
    TEST_ASSERT(key.get());

    xtt_crypto_get_random(key.get()->data, sizeof(xtt_ecdsap256_pub_key));

    auto cloned_key = key.clone();
    TEST_ASSERT(cloned_key->get());

    TEST_ASSERT(cloned_key->get() != key.get());
    TEST_ASSERT(0 == memcmp(cloned_key->get(), key.get(), sizeof(xtt_ecdsap256_pub_key)));
}

void ecdsap256_serialize_bin()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_serialize_bin...\n";

    std::vector<unsigned char> key_as_bytes(sizeof(xtt_ecdsap256_pub_key));
    xtt_crypto_get_random(key_as_bytes.data(), key_as_bytes.size());

    auto maybe_key = xtt::longterm_key_ecdsap256::deserialize(key_as_bytes);
    TEST_ASSERT(maybe_key);

    auto key_serialized = maybe_key->serialize();

    TEST_ASSERT(key_serialized.size() == sizeof(xtt_ecdsap256_pub_key));
    TEST_ASSERT(key_as_bytes == key_serialized);
}

void ecdsap256_serialize_text()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_serialize_text...\n";

    std::vector<unsigned char> key_as_bytes(sizeof(xtt_ecdsap256_pub_key));
    xtt_crypto_get_random(key_as_bytes.data(), key_as_bytes.size());
    std::stringstream ss;
    ss << std::hex;
    for (auto& b: key_as_bytes)
        ss << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string key_as_string = ss.str();

    auto maybe_key = xtt::longterm_key_ecdsap256::deserialize(key_as_string);

    TEST_ASSERT(maybe_key);

    auto key_serialized = maybe_key->serialize_to_text();

    TEST_ASSERT(key_as_string == key_serialized);

    std::cout << "Longterm key as string is: '" << key_as_string << "'"
        << ", which gets serialized as: '" << *maybe_key << std::endl;
}

void ecdsap256_string_to_bin()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_string_to_bin...\n";

    std::vector<unsigned char> key_as_bytes(sizeof(xtt_ecdsap256_priv_key));
    xtt_crypto_get_random(key_as_bytes.data(), key_as_bytes.size());
    std::stringstream ss;
    ss << std::hex;
    for (auto& b: key_as_bytes)
        ss << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string key_as_string = ss.str();

    auto maybe_key = xtt::longterm_private_key_ecdsap256::deserialize(key_as_string);
    TEST_ASSERT(maybe_key);

    auto key_serialized = maybe_key->serialize();

    TEST_ASSERT(key_as_bytes == key_serialized);
}

void ecdsap256_serialize_bins_agree()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_serialize_bins_agree...\n";

    unsigned char key_as_bytes[sizeof(xtt_ecdsap256_pub_key)];
    xtt_crypto_get_random(key_as_bytes, sizeof(xtt_ecdsap256_pub_key));

    auto maybe_key = xtt::longterm_key_ecdsap256::deserialize(key_as_bytes, sizeof(key_as_bytes));
    TEST_ASSERT(maybe_key);

    auto key_serialized = maybe_key->serialize();

    TEST_ASSERT(key_serialized.size() == sizeof(xtt_ecdsap256_pub_key));
    TEST_ASSERT(0 == memcmp(key_as_bytes, key_serialized.data(), key_serialized.size()));
}

void ecdsap256_priv_length()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_priv_length...\n";

    xtt::longterm_private_key_ecdsap256 key;

    TEST_ASSERT(key.length() == sizeof(xtt_ecdsap256_priv_key));
}

void ecdsap256_priv_equality()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_priv_equality...\n";

    xtt::longterm_key_ecdsap256 key1;
    xtt_crypto_get_random(key1.get()->data, sizeof(xtt_ecdsap256_pub_key));

    xtt::longterm_key_ecdsap256 key2;
    xtt_crypto_get_random(key2.get()->data, sizeof(xtt_ecdsap256_pub_key));

    TEST_ASSERT(key1 == key1);
    TEST_ASSERT(key2 == key2);
    TEST_ASSERT(key1 != key2);
}

void ecdsap256_priv_clone()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_priv_clone...\n";

    xtt::longterm_private_key_ecdsap256 key;
    TEST_ASSERT(key.get());

    xtt_crypto_get_random(key.get()->data, sizeof(xtt_ecdsap256_priv_key));

    auto cloned_key = key.clone();
    TEST_ASSERT(cloned_key->get());

    TEST_ASSERT(cloned_key->get() != key.get());
    TEST_ASSERT(0 == memcmp(cloned_key->get(), key.get(), sizeof(xtt_ecdsap256_priv_key)));
}

void ecdsap256_priv_serialize_bin()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_priv_serialize_bin...\n";

    std::vector<unsigned char> key_as_bytes(sizeof(xtt_ecdsap256_priv_key));
    xtt_crypto_get_random(key_as_bytes.data(), key_as_bytes.size());

    auto maybe_key = xtt::longterm_private_key_ecdsap256::deserialize(key_as_bytes);
    TEST_ASSERT(maybe_key);

    auto key_serialized = maybe_key->serialize();

    TEST_ASSERT(key_serialized.size() == sizeof(xtt_ecdsap256_priv_key));
    TEST_ASSERT(key_as_bytes == key_serialized);
}

void ecdsap256_priv_serialize_text()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_priv_serialize_text...\n";

    std::vector<unsigned char> key_as_bytes(sizeof(xtt_ecdsap256_pub_key));
    xtt_crypto_get_random(key_as_bytes.data(), key_as_bytes.size());
    std::stringstream ss;
    ss << std::hex;
    for (auto& b: key_as_bytes)
        ss << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string key_as_string = ss.str();

    auto maybe_key = xtt::longterm_key_ecdsap256::deserialize(key_as_string);

    TEST_ASSERT(maybe_key);

    auto key_serialized = maybe_key->serialize_to_text();

    TEST_ASSERT(key_as_string == key_serialized);
}

void ecdsap256_priv_string_to_bin()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_priv_string_to_bin...\n";

    std::vector<unsigned char> key_as_bytes(sizeof(xtt_ecdsap256_priv_key));
    xtt_crypto_get_random(key_as_bytes.data(), key_as_bytes.size());
    std::stringstream ss;
    ss << std::hex;
    for (auto& b: key_as_bytes)
        ss << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string key_as_string = ss.str();

    auto maybe_key = xtt::longterm_private_key_ecdsap256::deserialize(key_as_string);
    TEST_ASSERT(maybe_key);

    auto key_serialized = maybe_key->serialize();

    TEST_ASSERT(key_as_bytes == key_serialized);
}

void ecdsap256_priv_serialize_bins_agree()
{
    std::cout << "Starting longterm_key_Test::ecdsap256_priv_serialize_bins_agree...\n";

    unsigned char key_as_bytes[sizeof(xtt_ecdsap256_priv_key)];
    xtt_crypto_get_random(key_as_bytes, sizeof(xtt_ecdsap256_priv_key));

    auto maybe_key = xtt::longterm_private_key_ecdsap256::deserialize(key_as_bytes, sizeof(key_as_bytes));
    TEST_ASSERT(maybe_key);

    auto key_serialized = maybe_key->serialize();

    TEST_ASSERT(key_serialized.size() == sizeof(xtt_ecdsap256_priv_key));
    TEST_ASSERT(0 == memcmp(key_as_bytes, key_serialized.data(), key_serialized.size()));
}
