#include <dsn/security/sasl_utils.h>
#include <dsn/c/api_utilities.h>
#include <dsn/utility/config_api.h>

namespace dsn {
namespace security {

// use anonymous to define client/server callback
namespace {

const char *logger_level_to_string(int level)
{
    switch (level) {
    case SASL_LOG_NONE:
        return "SASL_LOG_NONE";
    case SASL_LOG_ERR:
        return "SASL_LOG_ERR";
    case SASL_LOG_FAIL:
        return "SASL_LOG_FAIL";
    case SASL_LOG_WARN:
        return "SASL_LOG_WARN";
    case SASL_LOG_NOTE:
        return "SASL_LOG_NOTE";
    case SASL_LOG_DEBUG:
        return "SASL_LOG_DEBUG";
    case SASL_LOG_TRACE:
        return "SASL_LOG_TRACE";
    case SASL_LOG_PASS:
        return "SASL_LOG_PASS";
    default:
        return "Unkown SASL log level";
    }
}

static const char *plugins_search_path = nullptr;

int sasl_simple_logger(void *context, int level, const char *msg)
{
    // TODO: we can set a level to print sasl log info
    if (level == SASL_LOG_NONE || msg == nullptr) {
        return SASL_OK;
    }

    ddebug("sasl log info: log level = %s, message = %s", logger_level_to_string(level), msg);
    return SASL_OK;
}

int getpath(void *context, char **path)
{
    if (!path) {
        return SASL_BADPARAM;
    }
    *path = const_cast<char *>(plugins_search_path);
    return SASL_OK;
}

int simple(void *context, int id, const char **result, unsigned *len)
{
    if (!result) {
        return SASL_BADPARAM;
    }
    static std::string username = get_username();
    switch (id) {
    case SASL_CB_USER:
    case SASL_CB_AUTHNAME:
        dinfo("sasl callback for SASL_CB_USER");
        *result = username.c_str();
        if (len != nullptr) {
            *len = username.length();
        }
        return SASL_OK;
    case SASL_CB_LANGUAGE:
        derror("could handle SASL callback type SASL_CB_LANGUAGE");
        return SASL_BADPARAM;
    default:
        dassert(false, "unexpected SASL callback type: %d", id);
        return SASL_BADPARAM;
    }
    return SASL_OK;
}

sasl_callback_t client_callbacks[] = {{SASL_CB_USER, (sasl_callback_ft)&simple, nullptr},
                                      {SASL_CB_GETPATH, (sasl_callback_ft)&getpath, nullptr},
                                      {SASL_CB_AUTHNAME, (sasl_callback_ft)&simple, nullptr},
                                      {SASL_CB_LOG, (sasl_callback_ft)&sasl_simple_logger, nullptr},
                                      {SASL_CB_LIST_END, nullptr, nullptr}};

sasl_callback_t server_callbacks[] = {{SASL_CB_LOG, (sasl_callback_ft)&sasl_simple_logger, nullptr},
                                      {SASL_CB_GETPATH, (sasl_callback_ft)&getpath, nullptr},
                                      {SASL_CB_LIST_END, nullptr, nullptr}};

// provide mutex function for sasl
void *sasl_mutex_alloc_local() { return static_cast<void *>(new utils::ex_lock_nr); }

void sasl_mutex_free_local(void *m) { delete static_cast<utils::ex_lock_nr *>(m); }

int sasl_mutex_lock_local(void *m)
{
    static_cast<utils::ex_lock_nr *>(m)->lock();
    return 0;
}

int sasl_mutex_unlock_local(void *m)
{
    static_cast<utils::ex_lock_nr *>(m)->unlock();
    return 0;
}

void sasl_set_mutex_local()
{
    sasl_set_mutex(&sasl_mutex_alloc_local,
                   &sasl_mutex_lock_local,
                   &sasl_mutex_unlock_local,
                   &sasl_mutex_free_local);
}

const char *sasl_err_desc(int status, sasl_conn_t *conn)
{
    if (conn != nullptr) {
        return sasl_errdetail(conn);
    } else {
        return sasl_errstring(status, nullptr, nullptr);
    }
    return "unknown error";
}

} // end anonymous namespace

error_s call_sasl_func(sasl_conn_t *conn, const std::function<int()> &call)
{
    krb5_cred_lock()->lock_read();
    int err = call();
    krb5_cred_lock()->unlock_read();
    error_s ret;
    switch (err) {
    case SASL_OK:
        return error_s::make(ERR_OK);
    case SASL_CONTINUE:
        return error_s::make(ERR_INCOMPLETE);
    case SASL_FAIL:      // Generic failure (encompasses missing krb5 credentials).
    case SASL_BADAUTH:   // Authentication failure.
    case SASL_BADMAC:    // Decode failure.
    case SASL_NOAUTHZ:   // Authorization failure.
    case SASL_NOUSER:    // User not found.
    case SASL_WRONGMECH: // Server doesn't support requested mechanism.
    case SASL_BADSERV: { // Server failed mutual authentication.
        ret = error_s::make(ERR_AUTH_FAILED);
        ret << "sasl auth failed, error: " << sasl_err_desc(err, conn);
        break;
    }
    default:
        ret = error_s::make(ERR_UNKNOWN);
        break;
    }
    return ret;
}

error_s sasl_init(bool is_server)
{
    plugins_search_path = dsn_config_get_value_string(
        "kerberos", "sasl_plugin_path", "/usr/lib/sasl2", "path to search sasl plugins");
    sasl_set_mutex_local();
    int err = 0;
    err = sasl_client_init(&client_callbacks[0]);
    error_s ret = error_s::make(ERR_OK);
    if (err != SASL_OK) {
        ret = error_s::make(ERR_RUNTIME_ERROR);
        ret << "initialize sasl client failed with error: "
            << sasl_errstring(err, nullptr, nullptr);
        return ret;
    }
    if (is_server) {
        // TODO: find a better saslappname
        err = sasl_server_init(&server_callbacks[0], "pegasus");
        if (err != SASL_OK) {
            ret = error_s::make(ERR_RUNTIME_ERROR);
            ret << "initialize sasl server failed with error: "
                << sasl_errstring(err, nullptr, nullptr);
            return ret;
        }
    }
    return ret;
}

} // end namespace security
} // end namespace dsn
