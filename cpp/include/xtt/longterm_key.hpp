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

#ifndef XTT_CPP_LONGTERMKEY_HPP
#define XTT_CPP_LONGTERMKEY_HPP
#pragma once

#include <xtt/crypto_types.h>

#include <xtt/config.hpp>

#include <string>
#include <vector>
#include <memory>

namespace xtt { class longterm_key; }

namespace xtt {

    class longterm_key {
    public:
        virtual ~longterm_key() = default;

        virtual std::size_t length() const = 0;

        virtual std::unique_ptr<longterm_key> clone() const = 0;

        virtual std::vector<unsigned char> serialize() const = 0;

        virtual std::string serialize_to_text() const = 0;

        virtual const xtt_ecdsap256_pub_key* get() const = 0;
        virtual xtt_ecdsap256_pub_key* get() = 0;

        bool operator==(const longterm_key& other) const;

        bool operator!=(const longterm_key& other) const;
    };

    class longterm_key_ecdsap256 : public longterm_key {
    public:
        static
        std::unique_ptr<longterm_key>
        deserialize(const unsigned char* serialized, std::size_t serialized_length);

        static
        std::unique_ptr<longterm_key>
        deserialize(const std::vector<unsigned char>& serialized);

        static
        std::unique_ptr<longterm_key>
        deserialize(const std::string& serialized);

    public:
        longterm_key_ecdsap256() = default;

        std::size_t length() const final;

        std::unique_ptr<longterm_key> clone() const final;

        std::vector<unsigned char> serialize() const final;

        std::string serialize_to_text() const final;

        const xtt_ecdsap256_pub_key* get() const final;
        xtt_ecdsap256_pub_key* get() final;

    private:
        xtt_ecdsap256_pub_key raw_;
    };

    class longterm_private_key {
    public:
        virtual ~longterm_private_key() = default;

        virtual std::size_t length() const = 0;

        virtual std::unique_ptr<longterm_private_key> clone() const = 0;

        virtual std::vector<unsigned char> serialize() const = 0;

        virtual std::string serialize_to_text() const = 0;

        virtual const xtt_ecdsap256_priv_key* get() const = 0;
        virtual xtt_ecdsap256_priv_key* get() = 0;

        bool operator==(const longterm_private_key& other) const;

        bool operator!=(const longterm_private_key& other) const;
    };

    class longterm_private_key_ecdsap256 : public longterm_private_key {
    public:
        static
        std::unique_ptr<longterm_private_key>
        deserialize(const unsigned char* serialized, std::size_t serialized_length);

        static
        std::unique_ptr<longterm_private_key>
        deserialize(const std::vector<unsigned char>& serialized);

        static
        std::unique_ptr<longterm_private_key>
        deserialize(const std::string& serialized);

    public:
        longterm_private_key_ecdsap256() = default;

        std::size_t length() const final;

        std::unique_ptr<longterm_private_key> clone() const final;

        std::vector<unsigned char> serialize() const final;

        std::string serialize_to_text() const final;

        const xtt_ecdsap256_priv_key* get() const final;
        xtt_ecdsap256_priv_key* get() final;

    private:
        xtt_ecdsap256_priv_key raw_;
    };

    std::ostream& operator<<(std::ostream& stream, const xtt::longterm_key& key);

}   // namespace xtt

#endif
