#include <dsn/security/server_negotiation.h>

namespace dsn {
namespace security {

server_negotiation::server_negotiation(rpc_session *session) : _session(session) {}

void server_negotiation::negotiate()
{
    ddebug("server_negotiation: start negotiation");
    error_s err_s = do_sasl_server_init();
    if (!err_s.is_ok()) {
        dwarn("server_negotiation: server initialize sasl failed, error = %s, msg = %s",
              err_s.code().to_string(),
              err_s.description().c_str());
        _session->complete_negotiation(false);
        return;
    }

    recv_sasl_initiate_msg();
}

error_s server_negotiation::do_sasl_server_init()
{
    sasl_conn_t *conn = nullptr;
    error_s err_s = call_sasl_func(nullptr, [&]() {
        // TODO: make "pegasus_tst" read from config file
        return sasl_server_new(
            "pegasus_tst", get_server_fqdn().c_str(), nullptr, nullptr, nullptr, nullptr, 0, &conn);
    });
    if (err_s.is_ok()) {
        _sasl_conn.reset(conn);
    }

    return err_s;
}

void server_negotiation::recv_sasl_initiate_msg()
{
    async_recv_negotiation_msg(
        _session, std::bind(&server_negotiation::handle_response_msg, this, std::placeholders::_1));
}

error_s server_negotiation::do_sasl_server_start(const std::string &input, std::string &output)
{
    const char *msg = nullptr;
    unsigned msg_len = 0;
    error_s err_s = call_sasl_func(_sasl_conn.get(), [&]() {
        return sasl_server_start(_sasl_conn.get(),
                                 "GSSAPI" /*now, only support*/,
                                 input.c_str(),
                                 input.length(),
                                 &msg,
                                 &msg_len);
    });

    output.assign(msg, msg_len);
    return err_s;
}

error_s server_negotiation::do_sasl_step(const std::string &input, std::string &output)
{
    const char *msg = nullptr;
    unsigned msg_len = 0;
    error_s err_s = call_sasl_func(_sasl_conn.get(), [&]() {
        return sasl_server_step(_sasl_conn.get(), input.c_str(), input.length(), &msg, &msg_len);
    });

    output.assign(msg, msg_len);
    return err_s;
}

void server_negotiation::handle_response_msg(const negotiation_message &msg)
{
    ddebug("server_negotiation: recv response negotiation message from client, addr = %s",
           _session->remote_address().to_string());
    if (msg.status == negotiation_status::type::SASL_INITIATE ||
        msg.status == negotiation_status::type::SASL_RESPONSE) {
        std::string output;
        error_s err_s;
        if (msg.status == negotiation_status::type::SASL_INITIATE) {
            err_s = do_sasl_server_start(msg.msg, output);
        } else {
            err_s = do_sasl_step(msg.msg, output);
        }

        if (err_s.code() != ERR_OK && err_s.code() != ERR_INCOMPLETE) {
            ddebug("server negotiation: negotiation failed locally, with err = %s, msg = %s, "
                   "remote_addr = %s",
                   err_s.code().to_string(),
                   err_s.description().c_str(),
                   _session->remote_address().to_string());
            send_auth_fail_msg(output);
        } else {
            send_challenge_msg(err_s, output);
            if (err_s.code() == ERR_INCOMPLETE) {
                async_recv_negotiation_msg(_session,
                                           std::bind(&server_negotiation::handle_response_msg,
                                                     this,
                                                     std::placeholders::_1));
            } else {
                ddebug("negotiation: negotiation succ, remote addr = %s",
                       _session->remote_address().to_string());
                _session->complete_negotiation(true);
            }
        }
        return;
    } else { // error msg type
        derror("server_negotiation: recv wrong neogtiation msg, type = %s, msg = %s",
               enum_to_string(msg.status),
               msg.msg.c_str());
        send_auth_fail_msg("invalid response type"); //+ enum_to_string(msg.status));
        return;
    }
    return;
}

void server_negotiation::send_challenge_msg(error_s err_s, const std::string &msg)
{
    const error_code &code = err_s.code();
    dassert(code == ERR_OK || code == ERR_INCOMPLETE, "invalid response message type");
    negotiation_message resp_msg;
    if (code == ERR_OK) {
        // auth succ
        resp_msg.status = negotiation_status::type::SASL_SUCC;
    } else {
        resp_msg.status = negotiation_status::type::SASL_CHALLENGE;
    }
    resp_msg.msg = msg;
    async_send_negotiation_msg(_session, resp_msg);
}

void server_negotiation::send_auth_fail_msg(const std::string &msg)
{
    negotiation_message resp_msg;
    resp_msg.status = negotiation_status::type::SASL_AUTH_FAIL;
    resp_msg.msg = msg;
    async_send_negotiation_msg(_session, resp_msg);

    _session->complete_negotiation(false);
}

} // end namespace security
} // end namespace dsn
