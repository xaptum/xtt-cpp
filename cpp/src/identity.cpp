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

#include <xtt/identity.hpp>

#include <boost/asio.hpp>

#include <algorithm>

#include "internal/text_to_binary.hpp"

#include <xtt/crypto_wrapper.h>

using namespace xtt;

const identity identity::null;

std::ostream& xtt::operator<<(std::ostream& stream, const xtt::identity& id)
{
    return stream << id.serialize_to_text();
}

OPTIONAL_NS::optional<identity>
identity::deserialize(const unsigned char* serialized, std::size_t serialized_length)
{
    if (sizeof(xtt_identity_type) != serialized_length) {
        return {};
    }

    identity ret;
    ret.raw_ = *reinterpret_cast<const xtt_identity_type*>(serialized);

    return ret;
}

OPTIONAL_NS::optional<identity>
identity::deserialize(const std::vector<unsigned char>& serialized)
{
    return identity::deserialize(serialized.data(), serialized.size());
}

OPTIONAL_NS::optional<identity>
identity::deserialize(const std::string& serialized_as_text)
{
    using boost::asio::ip::make_address_v6;

    auto as_bytes = make_address_v6(serialized_as_text).to_bytes();

    return identity::deserialize(as_bytes.data(), as_bytes.size());
}

identity::identity()
    : raw_(xtt_null_identity)
{
}

std::size_t identity::length() const
{
    return sizeof(xtt_identity_type);
}

std::vector<unsigned char> identity::serialize() const
{
    return std::vector<unsigned char>(raw_.data, raw_.data+sizeof(xtt_identity_type));
}

std::string identity::serialize_to_text() const
{
    using boost::asio::ip::address_v6;
    using boost::asio::ip::make_address_v6;

    address_v6::bytes_type as_bytes;

    auto beg = raw_.data;
    auto end = raw_.data + sizeof(xtt_identity_type);
    std::copy(beg, end, as_bytes.begin());

    return make_address_v6(as_bytes).to_string();
}

bool identity::is_null() const
{
    return *this == identity::null;
}

const xtt_identity_type* identity::get() const
{
    return &raw_;
}

xtt_identity_type* identity::get()
{
    return &raw_;
}

bool identity::operator==(const identity& other) const
{
    return 0 == xtt_crypto_memcmp(raw_.data,
                                  other.raw_.data,
                                  sizeof(xtt_identity_type));
}

bool identity::operator!=(const identity& other) const
{
    return !(*this == other);
}

std::size_t std::hash<xtt::identity>::operator()(const xtt::identity& key) const
{
    return hash<std::string>()(std::string(reinterpret_cast<const char*>(key.get()->data), sizeof(xtt_identity_type)));
}
