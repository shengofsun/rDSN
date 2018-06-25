#include <krb5/krb5.h>

#include <dsn/security/init.h>
#include <dsn/c/api_utilities.h>
#include <dsn/utility/scoped_cleanup.h>
#include <dsn/utility/config_api.h>

#include <functional>

namespace dsn {
namespace security {

namespace {

class kinit_context;

static std::unique_ptr<utils::rw_lock_nr> g_kerberos_lock;
static std::unique_ptr<kinit_context> g_kinit_ctx;
static krb5_context g_krb5_context;
static std::string username; // parse from principal

class kinit_context
{
public:
    kinit_context() : _opt(nullptr) {}
    virtual ~kinit_context();
    // implementation of 'kinit -k -t <keytab_file> <principal>'
    error_s kinit(const std::string &keytab_file, const std::string &principal);
    // rountine for update credential(Ticket Granting Ticket)
    error_s renew_cred();

    std::string username() { return _username_str; }

    std::string server_fqdn() { return _server_fqdn; }

private:
    // krb5 structure
    krb5_principal _principal;
    krb5_keytab _keytab; // absolute path
    krb5_ccache _ccache;
    krb5_get_init_creds_opt *_opt;

    // principal and username that logged in as
    std::string _principal_name;
    std::string _username_str;

    std::string _server_fqdn;

    // the timestamp that current cred(TGT) expire
    int64_t _cred_expire_timestamp;
};

void init_krb5_ctx()
{
    static std::once_flag once;
    std::call_once(once, [&]() {
        int64_t err = krb5_init_context(&g_krb5_context);
        if (err != 0) {
            dassert(false,
                    "init kerberos context failed, with kerberos  error_code = %" PRId64 "",
                    err);
        }
    });
}

#undef KRB5_RETURN_NOT_OK
#define KRB5_RETURN_NOT_OK(err, msg)                                                               \
    do {                                                                                           \
        if ((err) != 0) {                                                                          \
            return krb5_call_to_errors(g_krb5_context, (err), (msg));                              \
        }                                                                                          \
    } while (0);

// switch the code of krb5_xxx function to error_s
static error_s krb5_call_to_errors(krb5_context ctx, krb5_error_code code, const char *prefix_msg)
{
    std::unique_ptr<const char, std::function<void(const char *)>> error_msg(
        krb5_get_error_message(ctx, code),
        std::bind(krb5_free_error_message, ctx, std::placeholders::_1));

    std::string msg;
    if (prefix_msg != nullptr) {
        msg = prefix_msg;
        msg += ": ";
    }
    msg += error_msg.get();
    return error_s::make(ERR_RUNTIME_ERROR, msg.c_str());
}

static error_s parse_username_from_principal(krb5_const_principal principal, std::string &username)
{
    // Attention: here we just assume the length of username must be little then 1024
    char buf[1024];
    krb5_error_code err = 0;
    err = krb5_aname_to_localname(g_krb5_context, principal, sizeof(buf), buf);

    if (err == KRB5_LNAME_NOTRANS) {
        if (principal->length > 0) {
            int cnt = 0;
            while (cnt < principal->length) {
                std::string tname;
                tname.assign((const char *)principal->data[cnt].data, principal->data[cnt].length);
                if (!username.empty()) {
                    username += '/';
                }
                username += tname;
                cnt++;
            }
            // username.assign((const char *)principal->data[0].data, principal->data[0].length);
            return error_s::make(ERR_OK);
        }
        return error_s::make(ERR_RUNTIME_ERROR, "parse username from principal failed");
    }

    if (err == KRB5_CONFIG_NOTENUFSPACE) {
        return error_s::make(ERR_RUNTIME_ERROR, "username is larger than 1024");
    }

    KRB5_RETURN_NOT_OK(err, "krb5 parse aname to localname failed");

    if (strlen(buf) <= 0) {
        return error_s::make(ERR_RUNTIME_ERROR, "empty username");
    }
    username.assign((const char *)buf);
    return error_s::make(ERR_OK);
}

// inline implementation of kinit_context
kinit_context::~kinit_context() { krb5_get_init_creds_opt_free(g_krb5_context, _opt); }

error_s kinit_context::kinit(const std::string &keytab_file, const std::string &principal)
{
    if (keytab_file.empty() || principal.empty()) {
        return error_s::make(dsn::ERR_INVALID_PARAMETERS, "invalid keytab or principal");
    }

    init_krb5_ctx();

    KRB5_RETURN_NOT_OK(krb5_parse_name(g_krb5_context, principal.c_str(), &_principal),
                       "couldn't parse principal");

    KRB5_RETURN_NOT_OK(krb5_kt_resolve(g_krb5_context, keytab_file.c_str(), &_keytab),
                       "couldn't resolve keytab file");

    KRB5_RETURN_NOT_OK(krb5_cc_default(g_krb5_context, &_ccache),
                       "couldn't acquire credential cache handle");

    KRB5_RETURN_NOT_OK(krb5_cc_initialize(g_krb5_context, _ccache, _principal),
                       "initialize credential cache failed");

    KRB5_RETURN_NOT_OK(krb5_get_init_creds_opt_alloc(g_krb5_context, &_opt),
                       "alloc get_init_creds_opt structure failed");

    krb5_creds creds;
    KRB5_RETURN_NOT_OK(krb5_get_init_creds_keytab(g_krb5_context,
                                                  &creds,
                                                  _principal,
                                                  _keytab,
                                                  0 /*valid from now*/,
                                                  nullptr /*empty TKT service name*/,
                                                  _opt),
                       "acquire credential from keytab failed");

    auto cleanup_creds =
        kudu::MakeScopedCleanup([&]() { krb5_free_cred_contents(g_krb5_context, &creds); });

    _cred_expire_timestamp = creds.times.endtime;

    KRB5_RETURN_NOT_OK(krb5_cc_store_cred(g_krb5_context, _ccache, &creds), "store cred failed");

    {
        char *tmp_str = nullptr;
        KRB5_RETURN_NOT_OK(krb5_unparse_name(g_krb5_context, _principal, &tmp_str),
                           "unparse principal name failed");
        auto cleanup_name =
            kudu::MakeScopedCleanup([&]() { krb5_free_unparsed_name(g_krb5_context, tmp_str); });
        _principal_name = tmp_str;
    }

    error_s rc = parse_username_from_principal(_principal, _username_str);
    if (!rc.is_ok()) {
        return rc;
    }
    ddebug("logged in from keytab as %s, local username %s",
           _principal_name.c_str(),
           _username_str.c_str());

    _server_fqdn = dsn_config_get_value_string("kerberos", "server_fqdn", "pegasus", "server fqdn");
    if (_server_fqdn.empty()) {
        return error_s::make(ERR_RUNTIME_ERROR, "invalid server fqdn");
    }

    return error_s::make(ERR_OK);
}

error_s kinit_context::renew_cred() { return error_s::make(ERR_OK); }

#undef KRB5_RETURN_NOT_OK // only used in this anonymous namespace

} // end anonymous namespace

error_s init_kerberos(bool is_server)
{
    // acquire the keytab file from configuration
    std::string keytab_file =
        dsn_config_get_value_string("kerberos", "keytab", "", "absolute path of keytab");
    std::string principal =
        dsn_config_get_value_string("kerberos", "principal", "", "default principal");
    if (keytab_file.empty() || principal.empty()) {
        return error_s::make(ERR_RUNTIME_ERROR, "invalid keytab or principal");
    }

    // setup kerberos envs
    // setenv("KRB5CCNAME", "FILE:/path-to-file/filename", 1);  // use file as krb5_cache
    setenv("KRB5CCNAME", is_server ? "MEMORY:pegasus-server" : "MEMORY:pegasus-client", 1);
    setenv("KRB5_KTNAME", keytab_file.c_str(), 1);
    setenv("KRB5RCACHETYPE", "none", 1);

    g_kinit_ctx.reset(new kinit_context);
    error_s err = g_kinit_ctx->kinit(keytab_file, principal);
    ddebug("after call kinit err = %s", err.description().c_str());

    g_kerberos_lock.reset(new utils::rw_lock_nr);
    // TODO: start a task to update the credential(TGT)
    return err;
}

utils::rw_lock_nr *krb5_cred_lock() { return g_kerberos_lock.get(); }

std::string get_username() { return g_kinit_ctx->username(); }

std::string get_server_fqdn() { return g_kinit_ctx->server_fqdn(); }

} // end namespace security
} // end namespace dsn
