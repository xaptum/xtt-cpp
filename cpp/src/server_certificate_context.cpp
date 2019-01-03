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

#include <xtt/server_certificate_context.hpp>

#include "internal/text_to_binary.hpp"

#include <cassert>

using namespace xtt;

const unsigned char server_certificate_ecdsap256_dummy[XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH] = {0};
const xtt_ecdsap256_priv_key server_privatekey_ecdsap256_dummy = {{0}};

std::unique_ptr<server_certificate_context>
server_certificate_context_ecdsap256::deserialize(const unsigned char* serialized, std::size_t serialized_length)
{
    size_t cert_len = XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH;
    size_t key_len = sizeof(xtt_ecdsap256_priv_key);

    if (serialized_length < (cert_len + key_len)) {
        return {};
    }

    const unsigned char* cert_begin = serialized;

    const unsigned char* key_begin = serialized + cert_len;

    return from_certificate_and_key(std::vector<unsigned char>(cert_begin, cert_begin + cert_len),
                                    std::vector<unsigned char>(key_begin, key_begin + key_len));
}

std::unique_ptr<server_certificate_context>
server_certificate_context_ecdsap256::deserialize(const std::vector<unsigned char>& serialized)
{
    return deserialize(serialized.data(), serialized.size());
}

std::unique_ptr<server_certificate_context>
server_certificate_context_ecdsap256::from_certificate_and_key(const std::vector<unsigned char>& certificate,
                                                             const std::vector<unsigned char>& private_key)
{
    if (XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH != certificate.size() ||
        sizeof(xtt_ecdsap256_priv_key) != private_key.size())
    {
        return {};
    }

    auto ret = std::make_unique<server_certificate_context_ecdsap256>();
    if (!ret)
        return {};

    xtt_return_code_type ctor_ret =
        xtt_initialize_server_certificate_context_ecdsap256(ret->get(),
                                                          certificate.data(),
                                                          reinterpret_cast<const xtt_ecdsap256_priv_key*>(private_key.data()));
    if (XTT_RETURN_SUCCESS != ctor_ret) {
        return {};
    }

    return std::move(ret);
}

std::unique_ptr<server_certificate_context>
server_certificate_context_ecdsap256::from_certificate_and_key(const std::string& certificate,
                                                             const std::string& private_key)
{
    return server_certificate_context_ecdsap256::from_certificate_and_key(text_to_binary(certificate),
                                                                        text_to_binary(private_key));
}

server_certificate_context_ecdsap256::server_certificate_context_ecdsap256()
{
    xtt_return_code_type ctor_ret =
        xtt_initialize_server_certificate_context_ecdsap256(&certificate_ctx_,
                                                          server_certificate_ecdsap256_dummy,
                                                          &server_privatekey_ecdsap256_dummy);
    (void)ctor_ret;
    assert(XTT_RETURN_SUCCESS == ctor_ret);
}

server_certificate_context_ecdsap256::server_certificate_context_ecdsap256(const server_certificate_context_ecdsap256& other)
    : certificate_ctx_(other.certificate_ctx_)
{
    // Internal buffer pointers must be explicitly reset
    certificate_ctx_.serialized_certificate = (struct xtt_server_certificate_raw_type*)certificate_ctx_.serialized_certificate_raw;
}

server_certificate_context_ecdsap256::server_certificate_context_ecdsap256(server_certificate_context_ecdsap256&& other)
    : server_certificate_context_ecdsap256()
{
    swap(*this, other);
}

server_certificate_context_ecdsap256& server_certificate_context_ecdsap256::operator=(server_certificate_context_ecdsap256 other)
{
    swap(*this, other);

    return *this;
}

std::unique_ptr<server_certificate_context> server_certificate_context_ecdsap256::clone() const
{
    return std::make_unique<server_certificate_context_ecdsap256>(*this);
}

std::vector<unsigned char> server_certificate_context_ecdsap256::serialize() const
{
    std::vector<unsigned char> cert{get_certificate()};
    std::vector<unsigned char> priv_key{get_private_key()};

    std::vector<unsigned char> ret;
    ret.reserve(cert.size() + priv_key.size());

    ret.insert(ret.end(), cert.begin(), cert.end());

    ret.insert(ret.end(), priv_key.begin(), priv_key.end());

    return ret;
}

std::vector<unsigned char> server_certificate_context_ecdsap256::get_certificate() const
{
    size_t cert_len = XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH;

    return std::vector<unsigned char>(certificate_ctx_.serialized_certificate_raw,
                                      certificate_ctx_.serialized_certificate_raw + cert_len);
}

std::vector<unsigned char> server_certificate_context_ecdsap256::get_private_key() const
{
    size_t key_len = sizeof(xtt_ecdsap256_priv_key);

    return std::vector<unsigned char>(certificate_ctx_.private_key.ecdsap256.data,
                                      certificate_ctx_.private_key.ecdsap256.data + key_len);
}

std::string server_certificate_context_ecdsap256::get_certificate_as_text() const
{
    size_t cert_len = XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH;

    return binary_to_text(certificate_ctx_.serialized_certificate_raw, cert_len);
}

std::string server_certificate_context_ecdsap256::get_private_key_as_text() const
{
    size_t key_len = sizeof(xtt_ecdsap256_priv_key);

    return binary_to_text(certificate_ctx_.private_key.ecdsap256.data, key_len);
}

struct xtt_server_certificate_context* server_certificate_context_ecdsap256::get()
{
    return &certificate_ctx_;
}

const struct xtt_server_certificate_context* server_certificate_context_ecdsap256::get() const
{
    return &certificate_ctx_;
}

void swap(server_certificate_context_ecdsap256& first, server_certificate_context_ecdsap256& second)
{
    using std::swap;

    swap(first.certificate_ctx_, second.certificate_ctx_);

    // Internal buffer pointers must be explicitly reset
    first.certificate_ctx_.serialized_certificate = (struct xtt_server_certificate_raw_type*)first.certificate_ctx_.serialized_certificate_raw;
    second.certificate_ctx_.serialized_certificate = (struct xtt_server_certificate_raw_type*)second.certificate_ctx_.serialized_certificate_raw;
}
