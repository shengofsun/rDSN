#include <dsn/security/client_negotiation.h>

namespace dsn {
namespace security {

client_negotiation::client_negotiation(rpc_session *session) : _session(session) {}

void client_negotiation::negotiate()
{
    ddebug("client_negotiation: start negotiation");
    error_s err_s = do_sasl_client_init();
    if (!err_s.is_ok()) {
        dassert(false,
                "initiaze sasl client failed, error = %s, reason = %s",
                err_s.code().to_string(),
                err_s.description().c_str());
        _session->complete_negotiation(false);
        return;
    }

    err_s = send_sasl_initiate_msg();

    error_code code = err_s.code();
    if (code != ERR_OK && code != ERR_INCOMPLETE) {
        dassert(false,
                "client_negotiation: send sasl_client_start failed, error = %s, reason = %s",
                code.to_string(),
                err_s.description().c_str());
        _session->complete_negotiation(false);
    }

    // then we wait receive chanllenge message from server, see rpc_session::on_recv_msg()

    return;
}

error_s client_negotiation::do_sasl_client_init()
{
    sasl_conn_t *conn = nullptr;
    error_s err_s = call_sasl_func(nullptr, [&]() {
        // TODO: make "pegasus_tst read from config file"
        return sasl_client_new(
            "pegasus_tst", get_server_fqdn().c_str(), nullptr, nullptr, nullptr, 0, &conn);
    });

    if (err_s.is_ok()) {
        _sasl_conn.reset(conn);
    }

    return err_s;
}

error_s client_negotiation::send_sasl_initiate_msg()
{
    const char *msg = nullptr;
    unsigned msg_len = 0;
    const char *client_mech = nullptr;

    error_s err_s = call_sasl_func(_sasl_conn.get(), [&]() {
        return sasl_client_start(_sasl_conn.get(),
                                 "GSSAPI" /*now only support GSSAPI*/,
                                 nullptr,
                                 &msg,
                                 &msg_len,
                                 &client_mech);
    });

    error_code code = err_s.code();
    if (code == ERR_OK || code == ERR_INCOMPLETE) {
        ddebug("client_negotiation: call sasl_client_start succ with msg = {%s}, len = %d",
               msg,
               msg_len);
        negotiation_message neg_msg;
        neg_msg.status = negotiation_status::type::SASL_INITIATE;
        neg_msg.msg.assign(msg, msg_len);
        async_send_negotiation_msg(_session, neg_msg);
    }

    return err_s;
}

error_s client_negotiation::do_sasl_step(const std::string &input, std::string &output)
{
    const char *msg = nullptr;
    unsigned msg_len = 0;
    error_s err_s = call_sasl_func(_sasl_conn.get(), [&]() {
        return sasl_client_step(
            _sasl_conn.get(), input.c_str(), input.length(), nullptr, &msg, &msg_len);
    });

    output.assign(msg, msg_len);
    return err_s;
}

void client_negotiation::handle_chanllenge_msg(message_ex *msg)
{
    if (msg->error() != ERR_OK) {
        derror("client negotiation failed, error = %s", msg->error().to_string());
        _session->complete_negotiation(false);
    } else {
        negotiation_message neg_msg;
        ::dsn::unmarshall(msg, neg_msg);
        handle_challenge_msg(neg_msg);
    }
    msg->add_ref();
    msg->release_ref();
}

void client_negotiation::handle_challenge_msg(const negotiation_message &msg)
{
    ddebug("client_negotiation: client recv negotiation message from server");
    if (msg.status == negotiation_status::type::SASL_AUTH_FAIL) {
        dwarn("client_negotiation: negotiation failed, with msg = %s, remote_addr = %s",
              msg.msg.c_str(),
              _session->remote_address().to_string());
        _session->complete_negotiation(false);
        return;
    } else if (msg.status == negotiation_status::type::SASL_CHALLENGE) {
        std::string response_msg;
        error_s err_s = do_sasl_step(msg.msg, response_msg);
        if (err_s.code() != ERR_OK && err_s.code() != ERR_INCOMPLETE) {
            derror("client_negotiation: negotiation failed locally, reason = %s",
                   err_s.description().c_str());
            _session->complete_negotiation(false);
            return;
        } else {
            negotiation_message resp;
            resp.status = negotiation_status::type::SASL_RESPONSE;
            resp.msg = response_msg;
            async_send_negotiation_msg(_session, resp);
            // wait recv response message from client, see rpc_session::on_recv_message()
            return;
        }
    } else if (msg.status == negotiation_status::type::SASL_SUCC) {
        ddebug("client_negotiation: negotiation succ, remote_addr = %s",
               _session->remote_address().to_string());
        _session->complete_negotiation(true);
        return;
    } else { // wrong msg
        derror(
            "client_negotiation: recv wrong negotiation msg, type = %s, msg = %s, remote_addr = %s",
            enum_to_string(msg.status),
            msg.msg.c_str(),
            _session->remote_address().to_string());
        _session->complete_negotiation(false);
        return;
    }
}

} // end namespace security
} // end namespace dsn
