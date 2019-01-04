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

#ifndef XTT_CPP_SERVERCERTIFICATECONTEXT_HPP
#define XTT_CPP_SERVERCERTIFICATECONTEXT_HPP
#pragma once

#include <xtt/context.h>

#include <vector>
#include <string>
#include <utility>
#include <memory>

namespace xtt { class server_certificate_context_ecdsap256; }
void swap(xtt::server_certificate_context_ecdsap256&, xtt::server_certificate_context_ecdsap256&);

namespace xtt {

    class server_certificate_context {
    public:
        virtual ~server_certificate_context() = default;

        virtual std::unique_ptr<server_certificate_context> clone() const = 0;

        /*
         * Serialize to byte stream,
         *  as (certificate | private_key).
         */
        virtual std::vector<unsigned char> serialize() const = 0;

        /*
         * Get server certificate as byte string.
         */
        virtual std::vector<unsigned char> get_certificate() const = 0;

        /*
         * Get private key as byte string.
         */
        virtual std::vector<unsigned char> get_private_key() const = 0;

        /*
         * Get server certificate as ASCII-encoded hexadecimal string
         */
        virtual std::string get_certificate_as_text() const = 0;

        /*
         * Get private key as ASCII-encoded hexadecimal string
         */
        virtual std::string get_private_key_as_text() const = 0;

        virtual struct xtt_server_certificate_context* get() = 0;
        virtual const struct xtt_server_certificate_context* get() const = 0;
    };

    class server_certificate_context_ecdsap256 : public server_certificate_context {
    public:
        /*
         * Build a server_certificate_context_ecdsap256 from
         *  a single byte string,
         *  in the form (certificate | private_key).
         */
        static
        std::unique_ptr<server_certificate_context>
        deserialize(const unsigned char* serialized, std::size_t serialized_length);

        static
        std::unique_ptr<server_certificate_context>
        deserialize(const std::vector<unsigned char>& serialized);

        /*
         * Build a server_certificate_context_ecdsap256 from
         *  two separate byte strings,
         *  one for the certificate and the other for the private_key.
         */
        static
        std::unique_ptr<server_certificate_context>
        from_certificate_and_key(const std::vector<unsigned char>& certificate,
                                 const std::vector<unsigned char>& private_key);

        /*
         * Build a server_certificate_context_ecdsap256 from
         *  two separate ASCII-encoded hexadecimal strings,
         *  one for the certificate and the other for the private_key.
         */
        static
        std::unique_ptr<server_certificate_context>
        from_certificate_and_key(const std::string& certificate,
                                 const std::string& private_key);

    public:
        server_certificate_context_ecdsap256();

        server_certificate_context_ecdsap256(const server_certificate_context_ecdsap256&);

        server_certificate_context_ecdsap256(server_certificate_context_ecdsap256&& other);

        server_certificate_context_ecdsap256& operator=(server_certificate_context_ecdsap256 other);

        std::unique_ptr<server_certificate_context> clone() const final;

        std::vector<unsigned char> serialize() const final;

        std::vector<unsigned char> get_certificate() const final;

        std::vector<unsigned char> get_private_key() const final;

        std::string get_certificate_as_text() const final;

        std::string get_private_key_as_text() const final;

        struct xtt_server_certificate_context* get() final;
        const struct xtt_server_certificate_context* get() const final;

        friend void ::swap(server_certificate_context_ecdsap256& first, server_certificate_context_ecdsap256& second);

    private:
        xtt_server_certificate_context certificate_ctx_;
    };

}   // namespace xtt

#endif
