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

#ifndef XTT_CPP_TYPES_HPP
#define XTT_CPP_TYPES_HPP
#pragma once

#include <xtt/config.hpp>

#include <xtt/crypto_types.h>

#include <ostream>

namespace xtt {

    enum class version {
        ONE = XTT_VERSION_ONE,
    };

    enum class suite_spec {
        X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512 = XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512,
        X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B = XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B,
        X25519_LRSW_ECDSAP256_AES256GCM_SHA512 = XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512,
        X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B = XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B,
    };

    enum class return_code {
        SUCCESS = XTT_RETURN_SUCCESS,

        // Next-state codes:
        WANT_WRITE = XTT_RETURN_WANT_WRITE,
        WANT_READ = XTT_RETURN_WANT_READ,
        WANT_BUILDSERVERATTEST = XTT_RETURN_WANT_BUILDSERVERATTEST,
        WANT_PREPARSESERVERATTEST = XTT_RETURN_WANT_PREPARSESERVERATTEST,
        WANT_BUILDIDCLIENTATTEST = XTT_RETURN_WANT_BUILDIDCLIENTATTEST,
        WANT_PREPARSEIDCLIENTATTEST = XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST,
        WANT_VERIFYGROUPSIGNATURE = XTT_RETURN_WANT_VERIFYGROUPSIGNATURE,
        WANT_BUILDIDSERVERFINISHED = XTT_RETURN_WANT_BUILDIDSERVERFINISHED,
        WANT_PARSEIDSERVERFINISHED = XTT_RETURN_WANT_PARSEIDSERVERFINISHED,
        HANDSHAKE_FINISHED = XTT_RETURN_HANDSHAKE_FINISHED,

        // Error codes:
        RECEIVED_ERROR_MSG = XTT_RETURN_RECEIVED_ERROR_MSG,

        BAD_INIT = XTT_RETURN_BAD_INIT,
        BAD_IO = XTT_RETURN_BAD_IO,
        BAD_HANDSHAKE_ORDER = XTT_RETURN_BAD_HANDSHAKE_ORDER,
        INSUFFICIENT_ENTROPY = XTT_RETURN_INSUFFICIENT_ENTROPY,
        BAD_IO_LENGTH = XTT_RETURN_BAD_IO_LENGTH,
        UINT16_OVERFLOW = XTT_RETURN_UINT16_OVERFLOW,
        UINT32_OVERFLOW = XTT_RETURN_UINT32_OVERFLOW,
        NULL_BUFFER = XTT_RETURN_NULL_BUFFER,
        INCORRECT_TYPE = XTT_RETURN_INCORRECT_TYPE,
        DIFFIE_HELLMAN = XTT_RETURN_DIFFIE_HELLMAN,
        UNKNOWN_VERSION = XTT_RETURN_UNKNOWN_VERSION,
        UNKNOWN_SUITE_SPEC = XTT_RETURN_UNKNOWN_SUITE_SPEC,
        INCORRECT_LENGTH = XTT_RETURN_INCORRECT_LENGTH,
        BAD_CLIENT_SIGNATURE = XTT_RETURN_BAD_CLIENT_SIGNATURE,
        BAD_SERVER_SIGNATURE = XTT_RETURN_BAD_SERVER_SIGNATURE,
        BAD_ROOT_SIGNATURE = XTT_RETURN_BAD_ROOT_SIGNATURE,
        UNKNOWN_CRYPTO_SPEC = XTT_RETURN_UNKNOWN_CRYPTO_SPEC,
        BAD_CERTIFICATE = XTT_RETURN_BAD_CERTIFICATE,
        UNKNOWN_CERTIFICATE = XTT_RETURN_UNKNOWN_CERTIFICATE,
        UNKNOWN_GID = XTT_RETURN_UNKNOWN_GID,
        BAD_GPK = XTT_RETURN_BAD_GPK,
        BAD_ID = XTT_RETURN_BAD_ID,
        CRYPTO = XTT_RETURN_CRYPTO,
        DAA = XTT_RETURN_DAA,
        BAD_COOKIE = XTT_RETURN_BAD_COOKIE,
        COOKIE_ROTATION = XTT_RETURN_COOKIE_ROTATION,
        RECORD_FAILED_CRYPTO = XTT_RETURN_RECORD_FAILED_CRYPTO,
        BAD_FINISH = XTT_RETURN_BAD_FINISH,
        CONTEXT_BUFFER_OVERFLOW = XTT_RETURN_CONTEXT_BUFFER_OVERFLOW,
    };

    inline
    std::ostream& operator<<(std::ostream& stream, enum xtt::return_code rc)
    {
        return stream << xtt_strerror(static_cast<xtt_return_code_type>(rc));
    }

}   // namespace xtt

namespace std {
    template<>
    struct hash<xtt::suite_spec>
    {
        std::size_t operator()(enum xtt::suite_spec key) const
        {
            return static_cast<std::size_t>(key);
        }
    };
}

#endif
