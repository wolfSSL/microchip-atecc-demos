
#ifndef _ATECC_COMMON_H    /* Guard against multiple inclusion */
#define _ATECC_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wolfssl/wolfcrypt/types.h>

int get_608a_enc_key_default(byte* enckey, word16 keysize);
int check_lock_status(void);
int print_info(void);


#ifdef __cplusplus
}
#endif

#endif /* _TLS_COMMON_H */
