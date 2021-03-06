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

#ifndef XTT_CPP_SERVERCOOKIECONTEXT_HPP
#define XTT_CPP_SERVERCOOKIECONTEXT_HPP
#pragma once

#include <xtt/context.h>

#include <xtt/config.hpp>

namespace xtt {

    class server_cookie_context {
    public:
        const xtt_server_cookie_context* get() const {
            return &raw_;
        }

        xtt_server_cookie_context* get() {
            return &raw_;
        }

    private:
        xtt_server_cookie_context raw_;
    };

}   // namespace xtt

#endif

