
#ifndef _APP_H
#define _APP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include "net_pres/pres/net_pres_socketapi.h"
#include "library/tcpip/tcpip.h"
#include "configuration.h"

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
    APP_STATE_608A_SETUP_IO_PROTECTION_KEY,
    APP_STATE_WOLFSSL_INIT,
    APP_STATE_LOAD_CERTS,
    APP_STATE_BSD_CREATE_SOCKET,
    APP_STATE_BSD_BIND,
    APP_STATE_BSD_LISTEN,
    APP_STATE_TCP_ACCEPT,
    APP_STATE_TLS_ACCEPT,
    APP_STATE_RECV_DATA,
    APP_STATE_SEND_DATA,
    APP_STATE_SHUTDOWN,
    APP_STATE_ERROR,
    APP_STATE_WAIT

} APP_STATES;

typedef struct
{
    APP_STATES state;
    SOCKET clientSocket;
    SOCKET serverSocket;

} APP_DATA;


void APP_Initialize ( void );
void APP_Tasks( void );

#endif /* _APP_H */

#ifdef __cplusplus
}
#endif

