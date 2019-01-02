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

#include <xtt/server_handshake_context.hpp>

#include <stdexcept>

using namespace xtt;

server_handshake_context::server_handshake_context(unsigned char *in_buffer,
                                                   uint16_t in_buffer_size,
                                                   unsigned char *out_buffer,
                                                   uint16_t out_buffer_size)
{
    if (!in_buffer || !out_buffer)
        return;

    xtt_return_code_type rc;
    rc = xtt_initialize_server_handshake_context(&handshake_ctx_,
                                                 in_buffer,
                                                 in_buffer_size,
                                                 out_buffer,
                                                 out_buffer_size);
    if (XTT_RETURN_SUCCESS != rc) {
        throw std::runtime_error("Error initializing server handshake context");
    }
}

std::experimental::optional<version> server_handshake_context::get_version() const
{
    xtt_version current_version;
    if (XTT_RETURN_SUCCESS != xtt_get_version(&current_version, &handshake_ctx_)) {
        return {};
    }

    return static_cast<version>(current_version);
}

std::experimental::optional<suite_spec> server_handshake_context::get_suite_spec() const
{
    xtt_suite_spec current_suite_spec;
    if (XTT_RETURN_SUCCESS != xtt_get_suite_spec(&current_suite_spec, &handshake_ctx_)) {
        return {};
    }

    return static_cast<suite_spec>(current_suite_spec);
}

std::unique_ptr<pseudonym> server_handshake_context::get_clients_pseudonym() const
{
    auto suite_spec_opt = get_suite_spec();
    if (!suite_spec_opt)
        return {};

    switch (*suite_spec_opt) {
        case suite_spec::X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
        case suite_spec::X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
        case suite_spec::X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
        case suite_spec::X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
            {
                auto ret = std::make_unique<pseudonym_lrsw>();
                if (XTT_RETURN_SUCCESS != xtt_get_clients_pseudonym_lrsw(ret->get(), &handshake_ctx_)) {
                    return {};
                }

                return std::move(ret);
            }
        default:
            return {};
    }
}

std::unique_ptr<longterm_key> server_handshake_context::get_clients_longterm_key() const
{
    auto suite_spec_opt = get_suite_spec();
    if (!suite_spec_opt)
        return {};

    switch (*suite_spec_opt) {
        case suite_spec::X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
        case suite_spec::X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
        case suite_spec::X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
        case suite_spec::X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
            {
                auto ret = std::make_unique<longterm_key_ecdsap256>();
                if (XTT_RETURN_SUCCESS != xtt_get_clients_longterm_key_ecdsap256(ret->get(), &handshake_ctx_)) {
                    return {};
                }

                return std::move(ret);
            }
        default:
            return {};
    }
}

std::experimental::optional<identity> server_handshake_context::get_clients_identity() const
{
    xtt_identity_type assigned_identity;
    if (XTT_RETURN_SUCCESS != xtt_get_clients_identity(&assigned_identity, &handshake_ctx_)) {
        return {};
    }

    return identity::deserialize(std::vector<unsigned char>(assigned_identity.data, assigned_identity.data + sizeof(xtt_identity_type)));
}

const struct xtt_server_handshake_context* server_handshake_context::get() const
{
    return &handshake_ctx_;
}

struct xtt_server_handshake_context* server_handshake_context::get()
{
    return &handshake_ctx_;
}

return_code server_handshake_context::handle_io(uint16_t bytes_written,
                                                uint16_t bytes_read,
                                                io_buffer& io_buf)
{
    xtt_return_code_type ret = xtt_handshake_server_handle_io(bytes_written,
                                                              bytes_read,
                                                              &io_buf.len,
                                                              &io_buf.ptr,
                                                              &handshake_ctx_);

    return static_cast<return_code>(ret);
}

return_code server_handshake_context::handle_connect(io_buffer& io_buf)
{
    xtt_return_code_type ret = xtt_handshake_server_handle_connect(&io_buf.len,
                                                                   &io_buf.ptr,
                                                                   &handshake_ctx_);
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::build_serverattest(io_buffer& io_buf,
                                                         const server_certificate_context& certificate_ctx,
                                                         server_cookie_context& cookie_ctx)
{
    xtt_return_code_type ret = xtt_handshake_server_build_serverattest(&io_buf.len,
                                                                       &io_buf.ptr,
                                                                       &handshake_ctx_,
                                                                       certificate_ctx.get(),
                                                                       cookie_ctx.get());
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::preparse_idclientattest(io_buffer& io_buf,
                                                              identity& requested_client_id_out,
                                                              group_identity& claimed_group_id_out,
                                                              server_cookie_context& cookie_ctx,
                                                              const server_certificate_context& certificate_ctx)
{
    xtt_return_code_type ret = xtt_handshake_server_preparse_idclientattest(&io_buf.len,
                                                                            &io_buf.ptr,
                                                                            requested_client_id_out.get(),
                                                                            claimed_group_id_out.get(),
                                                                            cookie_ctx.get(),
                                                                            certificate_ctx.get(),
                                                                            &handshake_ctx_);
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::verify_groupsignature(io_buffer& io_buf,
                                                            group_public_key_context& group_pub_key_ctx,
                                                            const server_certificate_context& certificate_ctx)
{
xtt_return_code_type ret = xtt_handshake_server_verify_groupsignature(&io_buf.len,
                                                                      &io_buf.ptr,
                                                                      group_pub_key_ctx.get(),
                                                                      certificate_ctx.get(),
                                                                      &handshake_ctx_);
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::build_idserverfinished(io_buffer& io_buf,
                                                             const identity& client_id)
{
    xtt_return_code_type ret = xtt_handshake_server_build_idserverfinished(&io_buf.len,
                                                                           &io_buf.ptr,
                                                                           client_id.get(),
                                                                           &handshake_ctx_);
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::build_error_msg(io_buffer& io_buf)
{
    return static_cast<return_code>(xtt_server_build_error_msg(&io_buf.len, &io_buf.ptr, &handshake_ctx_));
}
