#ifndef _APP_H
#define _APP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* application states */
typedef enum
{
    APP_STATE_INIT=0,
    APP_TCPIP_WAIT_FOR_IP,
    APP_STATE_INIT_SNTP,
    APP_STATE_SNTP_WAIT_FOR_TIMESTAMP,
    APP_STATE_TEST_SNTP,
    APP_STATE_608A_INIT,
    APP_STATE_608A_CHECK_LOCK,
    APP_STATE_608A_INFO,
    APP_STATE_WOLFSSL_INIT,
    APP_STATE_WOLFCRYPT_TEST,
    APP_STATE_FINISHED,
    APP_STATE_WAIT,

} APP_STATES;

/* application data */
typedef struct
{
    APP_STATES state;

} APP_DATA;

void APP_Initialize ( void );
void APP_Tasks( void );

#endif /* _APP_H */

#ifdef __cplusplus
}
#endif

