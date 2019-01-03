/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
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

#include <xtt/longterm_key.hpp>

#include "internal/text_to_binary.hpp"

#include <xtt/crypto_wrapper.h>

using namespace xtt;

std::ostream& xtt::operator<<(std::ostream& stream, const xtt::longterm_key& key)
{
    return stream << key.serialize_to_text();
}

std::unique_ptr<longterm_key>
longterm_key_ecdsap256::deserialize(const unsigned char* serialized, std::size_t serialized_length)
{
    if (sizeof(xtt_ecdsap256_pub_key) != serialized_length) {
        return {};
    }

    std::unique_ptr<longterm_key> ret = std::make_unique<longterm_key_ecdsap256>();
    if (!ret)
        return {};
    *(ret->get()) = *reinterpret_cast<const xtt_ecdsap256_pub_key*>(serialized);

    return ret;
}

std::unique_ptr<longterm_key>
longterm_key_ecdsap256::deserialize(const std::vector<unsigned char>& serialized)
{
    return deserialize(serialized.data(), serialized.size());
}

std::unique_ptr<longterm_key>
longterm_key_ecdsap256::deserialize(const std::string& serialized)
{
    return longterm_key_ecdsap256::deserialize(text_to_binary(serialized));
}

std::size_t longterm_key_ecdsap256::length() const
{
    return sizeof(xtt_ecdsap256_pub_key);
}

std::unique_ptr<longterm_key> longterm_key_ecdsap256::clone() const
{
    return std::make_unique<longterm_key_ecdsap256>(*this);
}

std::vector<unsigned char> longterm_key_ecdsap256::serialize() const
{
    return std::vector<unsigned char>(raw_.data, raw_.data+sizeof(xtt_ecdsap256_pub_key));
}

std::string longterm_key_ecdsap256::serialize_to_text() const
{
    return binary_to_text(raw_.data, sizeof(xtt_ecdsap256_pub_key));
}

const xtt_ecdsap256_pub_key* longterm_key_ecdsap256::get() const
{
    return &raw_;
}

xtt_ecdsap256_pub_key* longterm_key_ecdsap256::get()
{
    return &raw_;
}

bool longterm_key::operator==(const longterm_key& other) const
{
    if (this->length() != other.length())
        return false;

    return 0 == xtt_crypto_memcmp(this->get()->data,
                                  other.get()->data,
                                  this->length());
}

bool longterm_key::operator!=(const longterm_key& other) const
{
    return !(*this == other);
}

std::unique_ptr<longterm_private_key>
longterm_private_key_ecdsap256::deserialize(const unsigned char* serialized, std::size_t serialized_length)
{
    if (sizeof(xtt_ecdsap256_priv_key) != serialized_length) {
        return {};
    }

    auto ret = std::make_unique<longterm_private_key_ecdsap256>();
    if (!ret)
        return {};

    *(ret->get()) = *reinterpret_cast<const xtt_ecdsap256_priv_key*>(serialized);

    return std::move(ret);
}

std::unique_ptr<longterm_private_key>
longterm_private_key_ecdsap256::deserialize(const std::vector<unsigned char>& serialized)
{
    return deserialize(serialized.data(), serialized.size());
}

std::unique_ptr<longterm_private_key>
longterm_private_key_ecdsap256::deserialize(const std::string& serialized)
{
    return longterm_private_key_ecdsap256::deserialize(text_to_binary(serialized));
}

std::size_t longterm_private_key_ecdsap256::length() const
{
    return sizeof(xtt_ecdsap256_priv_key);
}

std::unique_ptr<longterm_private_key> longterm_private_key_ecdsap256::clone() const
{
    return std::make_unique<longterm_private_key_ecdsap256>(*this);
}

std::vector<unsigned char> longterm_private_key_ecdsap256::serialize() const
{
    return std::vector<unsigned char>(raw_.data, raw_.data+sizeof(xtt_ecdsap256_priv_key));
}

std::string longterm_private_key_ecdsap256::serialize_to_text() const
{
    return binary_to_text(raw_.data, sizeof(xtt_ecdsap256_priv_key));
}

const xtt_ecdsap256_priv_key* longterm_private_key_ecdsap256::get() const
{
    return &raw_;
}

xtt_ecdsap256_priv_key* longterm_private_key_ecdsap256::get()
{
    return &raw_;
}

bool longterm_private_key::operator==(const longterm_private_key& other) const
{
    if (this->length() != other.length())
        return false;

    return 0 == xtt_crypto_memcmp(this->get()->data,
                                  other.get()->data,
                                  this->length());
}

bool longterm_private_key::operator!=(const longterm_private_key& other) const
{
    return !(*this == other);
}
