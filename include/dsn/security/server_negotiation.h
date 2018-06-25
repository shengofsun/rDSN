/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Microsoft Corporation
 *
 * -=- Robust Distributed System Nucleus (rDSN) -=-
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#pragma once

#include <dsn/security/negotiation_utils.h>

namespace dsn {
namespace security {

class server_negotiation
{
public:
    server_negotiation(rpc_session *session);
    void negotiate();

private:
    error_s do_sasl_server_init();
    void recv_sasl_initiate_msg();
    error_s do_sasl_server_start(const std::string &input, std::string &output);
    error_s do_sasl_step(const std::string &input, std::string &output);
    void handle_response_msg(const negotiation_message &msg);
    void send_challenge_msg(error_s err_s, const std::string &msg);
    void send_auth_fail_msg(const std::string &msg);

private:
    // the lifetime of _session should be longer than client_negotiation
    rpc_session *_session;
    std::unique_ptr<sasl_conn_t, sasl_deleter> _sasl_conn;
};

} // end namespace security
} // end namespace dsn
