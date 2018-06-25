namespace cpp dsn.security

enum negotiation_status {
    INVALID = 0,
    SASL_SUCC,
    SASL_INITIATE,
    SASL_CHALLENGE,
    SASL_RESPONSE,
    SASL_AUTH_FAIL
}

struct negotiation_message {
    1: negotiation_status status;
    2: string msg;
}
