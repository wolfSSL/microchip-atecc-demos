
#ifndef _TLS_COMMON_H    /* Guard against multiple inclusion */
#define _TLS_COMMON_H

#include <wolfssl/wolfcrypt/port/atmel/atmel.h>

/* Provide C++ Compatibility */
#ifdef __cplusplus
extern "C" {
#endif

typedef struct t_atcert {
    uint32_t signer_ca_size;
    uint8_t signer_ca[521];
    uint8_t signer_ca_pubkey[64];
    uint32_t end_user_size;
    uint8_t end_user[552];
    uint8_t end_user_pubkey[64];
} t_atcert;

extern t_atcert atcert;

int tls_build_signer_ca_cert(void);
int tls_build_end_user_cert(void);
int tls_build_signer_ca_cert_tlstng(void);
int tls_build_end_user_cert_tlstng(void);

/* Provide C++ Compatibility */
#ifdef __cplusplus
}
#endif

#endif /* _TLS_COMMON_H */
