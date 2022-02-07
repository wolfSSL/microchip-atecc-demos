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
    APP_STATE_DNS_RESOLVE,
    APP_STATE_BSD_SOCKET,
    APP_STATE_BSD_CONNECT,
    APP_STATE_WOLFSSL_INIT,
    APP_STATE_LOAD_CERTS,
    APP_STATE_DO_HANDSHAKE,
    APP_STATE_SEND_HTTP_GET,
    APP_STATE_RECV_RESPONSE,
    APP_STATE_SHUTDOWN,
    APP_STATE_FINISHED,
    APP_STATE_WAIT,

} APP_STATES;

/* application data */
typedef struct
{
    APP_STATES state;
    SOCKET socket;
    char* host;
    char* path;
    uint16_t port;
    struct sockaddr_in addr;

} APP_DATA;

void APP_Initialize ( void );
void APP_Tasks( void );

#endif /* _APP_H */

#ifdef __cplusplus
}
#endif

