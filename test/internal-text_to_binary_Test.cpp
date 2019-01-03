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

#include "text_to_binary.hpp"

#include "test-utils.h"

#include <xtt.hpp>

#include <xtt.h>

void text_to_bin_to_text();
void bin_to_text_to_bin();
void lowercase_ok();

int main()
{
    text_to_bin_to_text();
    bin_to_text_to_bin();
    lowercase_ok();
}

void text_to_bin_to_text()
{
    std::cout << "Starting internal-text_to_binary_Test::text_to_bin_to_text...\n";

    std::vector<unsigned char> as_bytes(1024);
    xtt_crypto_get_random(as_bytes.data(), as_bytes.size());

    std::stringstream ss;
    ss << std::hex;
    for (auto& b: as_bytes)
        ss << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string as_string = ss.str();
    TEST_ASSERT(as_string.length() == 2*as_bytes.size());

    auto conv_to_bin = text_to_binary(as_string);
    TEST_ASSERT(conv_to_bin == as_bytes);

    auto conv_to_text = binary_to_text(conv_to_bin.data(), conv_to_bin.size());
    TEST_ASSERT(conv_to_text == as_string);
}

void bin_to_text_to_bin()
{
    std::cout << "Starting internal-text_to_binary_Test::bin_to_text_to_bin...\n";

    std::vector<unsigned char> as_bytes(1024);
    xtt_crypto_get_random(as_bytes.data(), as_bytes.size());

    auto conv_to_text = binary_to_text(as_bytes.data(), as_bytes.size());
    TEST_ASSERT(conv_to_text.length() == 2*as_bytes.size());

    auto conv_to_bin = text_to_binary(conv_to_text);
    TEST_ASSERT(conv_to_bin == as_bytes);
}

void lowercase_ok()
{
    std::cout << "Starting internal-text_to_binary_Test::lowercase_ok...\n";

    std::vector<unsigned char> as_bytes(255);
    xtt_crypto_get_random(as_bytes.data(), as_bytes.size());

    std::stringstream ss1;
    ss1 << std::hex;
    for (auto& b: as_bytes)
        ss1 << std::nouppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string as_string_lower = ss1.str();
    std::stringstream ss2;
    ss2 << std::hex;
    for (auto& b: as_bytes)
        ss2 << std::uppercase << std::setw(2) << std::setfill('0') << (int)b;
    std::string as_string_upper = ss2.str();

    auto bin_from_lower = text_to_binary(as_string_lower);
    TEST_ASSERT(bin_from_lower == as_bytes);

    auto bin_from_upper = text_to_binary(as_string_upper);
    TEST_ASSERT(bin_from_upper == as_bytes);
}

