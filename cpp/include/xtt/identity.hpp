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

#ifndef XTT_CPP_IDENTITY_HPP
#define XTT_CPP_IDENTITY_HPP
#pragma once

#include <xtt/crypto_types.h>

#include <xtt/config.hpp>

#include <string>
#include <vector>
#include OPTIONAL_H

namespace xtt { class identity; }
namespace std {
    template<>
    struct hash<xtt::identity>
    {
        std::size_t operator()(const xtt::identity& key) const;
    };
}

namespace xtt {

    class identity {
    public:
        static const identity null;

    public:
        static
        OPTIONAL_NS::optional<identity>
        deserialize(const unsigned char* serialized, std::size_t serialized_length);

        static
        OPTIONAL_NS::optional<identity>
        deserialize(const std::vector<unsigned char>& serialized);

        static
        OPTIONAL_NS::optional<identity>
        deserialize(const std::string& serialized);

    public:
        identity();

        std::size_t length() const;

        std::vector<unsigned char> serialize() const;

        std::string serialize_to_text() const;

        bool is_null() const;

        bool operator==(const identity& other) const;

        bool operator!=(const identity& other) const;

        const xtt_identity_type* get() const;
        xtt_identity_type* get();

    private:
        xtt_identity_type raw_;
    };

    std::ostream& operator<<(std::ostream& stream, const xtt::identity& id);


}   // namespace xtt


#endif
