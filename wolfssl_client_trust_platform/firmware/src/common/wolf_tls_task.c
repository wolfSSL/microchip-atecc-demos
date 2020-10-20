
#include "app.h"
#include "app.h"
#include "wdrv_winc_client_api.h"
#include "cryptoauthlib.h"
#include <wolfssl/ssl.h>
//#include <wolfssl/wolfcrypt/port/atmel/atmel.h>
#include <wolfssl/certs_test.h>

#define WLAN_AUTH_WPA_PSK
#define WLAN_SSID           "BLADE"
#define WLAN_PSK            "thegarskes"

#define SERVER_HOST         "192.168.0.251"
#define SERVER_PORT         11111

static WOLFSSL*        ssl_client = NULL;
static WOLFSSL_CTX*    ctx_client = NULL;
static WOLFSSL_METHOD* method_client = NULL;
static const char httpGET[] = "GET /index.html HTTP/1.0\r\n\r\n";
static byte reply[80];

static ATCAIfaceCfg atecc608a_0_init_data_TNGTLS = {
       .iface_type            = ATCA_I2C_IFACE,
       .devtype               = ATECC608A,
       .atcai2c.slave_address = 0x6A,
       .atcai2c.bus           = 0,
       .atcai2c.baud          = 400000,
       .wake_delay            = 1500,
       .rx_retries            = 20,
       .cfg_data              = &sercom2_plib_i2c_api
};

/* application states */
typedef enum
{
    EXAMPLE_STATE_EXAMPLE_INIT=0,
    EXAMPLE_STATE_608_INIT,
    EXAMPLE_STATE_608_CHECK_LOCK,
    EXAMPLE_STATE_608_INFO,
    EXAMPLE_STATE_NET_INIT,
    EXAMPLE_STATE_CONNECT,
    EXAMPLE_STATE_CONNECTING,
    EXAMPLE_STATE_CONNECTED,
    EXAMPLE_STATE_WOLFSSL_INIT,
    EXAMPLE_STATE_DNS_RESOLVE,
    EXAMPLE_STATE_BSD_SOCKET,
    EXAMPLE_STATE_BSD_CONNECT,
    EXAMPLE_STATE_LOAD_CERTS,
    EXAMPLE_STATE_DO_HANDSHAKE,
    EXAMPLE_STATE_SEND_HTTP_GET,
    EXAMPLE_STATE_RECV_RESPONSE,
    EXAMPLE_STATE_SHUTDOWN,
    EXAMPLE_STATE_FINISHED,
    EXAMPLE_STATE_DISCONNECT,
    EXAMPLE_STATE_WAIT,
} EXAMPLE_STATE;

static EXAMPLE_STATE g_example_state = EXAMPLE_STATE_EXAMPLE_INIT;


int tls_setup_client_ctx(void)
{
    byte* clientCertChainDer = NULL;
    word32 clientCertChainDerSz = 0;

    method_client = wolfTLSv1_2_client_method();
    if (method_client == NULL) {
        SYS_PRINT("Failed to alloc dynamic buffer\r\n");
        return SSL_FAILURE;
    }
    SYS_PRINT("Created wolfTLSv1_2_client_method()\r\n");

    ctx_client = wolfSSL_CTX_new(method_client);
    if (ctx_client == NULL) {
        SYS_PRINT("Failed to create wolfSSL context\r\n");
        return SSL_FAILURE;
    }
    SYS_PRINT("Created new WOLFSSL_CTX\r\n");

    /* Load root CA certificate used to verify peer. This buffer is set up to
     * verify the wolfSSL example server. The example server should be started
     * using the <wolfssl_root>/certs/server-ecc.pem certificate and
     * <wolfssl_root>/certs/ecc-key.pem private key. */
    if (wolfSSL_CTX_load_verify_buffer(ctx_client, ca_ecc_cert_der_256,
            sizeof_ca_ecc_cert_der_256, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        SYS_PRINT("Failed to load verification certificate!\r\n");
        return SSL_FAILURE;
    }
    SYS_PRINT("Loaded verify cert buffer into WOLFSSL_CTX\r\n");

    /* Concatenate client cert with intermediate signer cert to send chain,
     * peer will have root CA loaded to verify chain */
    clientCertChainDerSz = atcert.end_user_size + atcert.signer_ca_size;
    clientCertChainDer = (byte*)malloc(clientCertChainDerSz);
    memcpy(clientCertChainDer, atcert.end_user, atcert.end_user_size);
    memcpy(clientCertChainDer + atcert.end_user_size,
           atcert.signer_ca, atcert.signer_ca_size);

    if (wolfSSL_CTX_use_certificate_chain_buffer_format(ctx_client,
            clientCertChainDer, clientCertChainDerSz,
            WOLFSSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        SYS_PRINT("Failed to load client certificate chain\r\n");
        free(clientCertChainDer);
        return SSL_FAILURE;
    }
    free(clientCertChainDer);
    SYS_PRINT("Loaded client certificate chain in to WOLFSSL_CTX\r\n");

    /* Enable peer verification */
    wolfSSL_CTX_set_verify(ctx_client, SSL_VERIFY_PEER, NULL);
    atcatls_set_callbacks(ctx_client);

    return SSL_SUCCESS;
}

static void dns_resolve_handler(uint8_t *pu8DomainName, uint32_t u32ServerIP)
{
    char message[128];

    if (u32ServerIP != 0) {
        uint8_t host_ip_address[4];
        host_ip_address[0] = u32ServerIP & 0xFF;
        host_ip_address[1] = (u32ServerIP >> 8) & 0xFF;
        host_ip_address[2] = (u32ServerIP >> 16) & 0xFF;
        host_ip_address[3] = (u32ServerIP >> 24) & 0xFF;

        sprintf(&message[0], "WINC1500 WIFI: DNS lookup:\r\n  Host:       %s\r\n  IP Address: %u.%u.%u.%u",
                (char*)pu8DomainName, host_ip_address[0], host_ip_address[1],
                host_ip_address[2], host_ip_address[3]);
        console_print_message(message);
    }
    else {
        /* An error has occurred */
        console_print_error_message("WINC1500 DNS lookup failed.");
        g_example_state = EXAMPLE_STATE_FINISHED;
    }
}

static void APP_ExampleDHCPAddressEventCallback(DRV_HANDLE handle, uint32_t ipAddress)
{
    char s[20];

    APP_DebugPrintf("IP address is %s\r\n", inet_ntop(AF_INET, &ipAddress, s, sizeof(s)));
}

static void APP_ExampleGetSystemTimeEventCallback(DRV_HANDLE handle, uint32_t time)
{
    if (true == WDRV_WINC_IPLinkActive(handle))
    {
        APP_DebugPrintf("Time %u \r\n", time);
        RTC_Timer32CounterSet(time);
        RTC_Timer32Start();
    }
}

static void wifi_callback_handler(DRV_HANDLE handle, WDRV_WINC_CONN_STATE currentState, WDRV_WINC_CONN_ERROR errorCode)
{
    char message[256];

    if (currentState == WDRV_WINC_CONN_STATE_CONNECTED) {
        APP_DebugPrintf("Wifi Connected\r\n");

    }
    else if (currentState == WDRV_WINC_CONN_STATE_DISCONNECTED) {
        if (g_example_state == CLOUD_STATE_CLOUD_CONNECTED) {
            APP_DebugPrintf("Failed to connect\r\n");
            g_example_state = EXAMPLE_STATE_DISCONNECT;
        }
        else {
            APP_DebugPrintf("Wifi Disconnected\r\n");
            g_example_state = EXAMPLE_STATE_CONNECT;

        }
    }
    else {
        memset(&message[0], 0, sizeof(message));
        sprintf(&message[0], "WINC1500 WIFI: Unknown connection status: %d",
                currentState);
        console_print_error_message(message);
    }
}

static void socket_callback_handler(SOCKET socket, uint8_t messageType, void *pMessage)
{
    tstrSocketConnectMsg *socket_connect_message = NULL;
    tstrSocketRecvMsg *socket_receive_message = NULL;

    switch (messageType) {
    case SOCKET_MSG_CONNECT:
    {
        socket_connect_message = (tstrSocketConnectMsg*)pMessage;

        if (NULL != socket_connect_message) {
            if (socket_connect_message->s8Error == SOCK_ERR_NO_ERROR) {
                g_example_state = EXAMPLE_STATE_CONNECTED;
            }
            else {
                /* An error has occurred */
                APP_DebugPrintf("SOCKET_MSG_CONNECT error %s(%d)\r\n", get_socket_error_name(socket_connect_message->s8Error), socket_connect_message->s8Error);
                g_example_state = EXAMPLE_STATE_DISCONNECT;
            }
        }
        break;
    }
    case SOCKET_MSG_RECV:
    case SOCKET_MSG_RECVFROM:
    {
        
        break;
    }
    case SOCKET_MSG_SEND:
    {
        break;
    }
    default:
        APP_DebugPrintf("%s: unhandled message %d\r\n", __FUNCTION__, (int)messageType);
        break;
    }
}


void APP_ExampleTasks(DRV_HANDLE handle)
{
    SYS_STATUS tcpStatus;
    const char* netName;
    const char* netBiosName;
    struct hostent* hostInfo;
    int i, nNets, ret;
    int atecc_initialized = 0;
    TCPIP_NET_HANDLE netH;
    uint32_t sec = 0;
    ATCA_STATUS status;
    TCPIP_SNTP_RESULT sntpRet;

    switch ( g_example_state )
    {
        case EXAMPLE_STATE_EXAMPLE_INIT:
        {
            APP_DebugPrintf("\r\n");
            APP_DebugPrintf("===========================\r\n");
            APP_DebugPrintf("wolfSSL Client Example\r\n");
            APP_DebugPrintf("===========================\r\n");

            g_example_state = EXAMPLE_STATE_608_INIT;
            break;
        }

        case EXAMPLE_STATE_608_INIT:
        {
            status = atcab_init(&atecc608a_0_init_data_TNGTLS);
            if (status != ATCA_SUCCESS) {
                SYS_PRINT("atcab_init() failed, ret = %d\r\n", status);
                g_example_state = EXAMPLE_STATE_FINISHED;

            } else {
                SYS_PRINT("atcab_init() success\r\n");
                atecc_initialized = 1;
                g_example_state = EXAMPLE_STATE_608_CHECK_LOCK;
            }
            break;
        }

        case EXAMPLE_STATE_608_CHECK_LOCK:
        {
            ret = check_lock_status();
            if (ret != 0) {
                SYS_PRINT("Failed to check lock zone status\r\n");
            }
            g_example_state = EXAMPLE_STATE_608_INFO;
            break;
        }

        case EXAMPLE_STATE_608_INFO:
        {
            ret = print_info();
            if (ret != 0) {
                SYS_PRINT("Failed to print ATECC608A module info\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
            } else {
                g_example_state = EXAMPLE_STATE_NET_INIT;
            }
            break;
        }

        case EXAMPLE_STATE_NET_INIT:
        {
            /* Enable use of DHCP for network configuration, DHCP is the default
                but this also registers the callback for notifications. */
            if ((status = WDRV_WINC_IPUseDHCPSet(handle, &APP_ExampleDHCPAddressEventCallback)) != WDRV_WINC_STATUS_OK) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Initialize the BSS context to use default values. */
            if ((status = WDRV_WINC_BSSCtxSetDefaults(&bssCtx)) != WDRV_WINC_STATUS_OK) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Update BSS context with target SSID for connection. */
            if ((status = WDRV_WINC_BSSCtxSetSSID(&bssCtx, (uint8_t*)WLAN_SSID, strlen(WLAN_SSID))) != WDRV_WINC_STATUS_OK) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /*Initialize the authentication context for WPA. */
            if ((status = WDRV_WINC_AuthCtxSetWPA(&authCtx, (uint8_t*)WLAN_PSK, strlen(WLAN_PSK))) != WDRV_WINC_STATUS_OK) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Initialize the system time callback handler. */
            if ((status = WDRV_WINC_SystemTimeGetCurrent(handle, &APP_ExampleGetSystemTimeEventCallback)) != WDRV_WINC_STATUS_OK) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Register callback handler for DNS resolver . */
            if ((status = WDRV_WINC_SocketRegisterResolverCallback(handle, &dns_resolve_handler)) != WDRV_WINC_STATUS_OK) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Register callback handler for socket events. */
            if ((status = WDRV_WINC_SocketRegisterEventCallback(handle, &socket_callback_handler)) != WDRV_WINC_STATUS_OK) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            g_example_state = EXAMPLE_STATE_CONNECT;
            break;
        }
        case EXAMPLE_STATE_CONNECT:
            /* Connect to the target BSS with the chosen authentication. */
            if (WDRV_WINC_STATUS_OK == WDRV_WINC_BSSConnect(handle, &bssCtx, &authCtx, &wifi_callback_handler)) {
                g_example_state = EXAMPLE_STATE_CONNECTING;
            }
            break;

        case EXAMPLE_STATE_CONNECTING:
            /* Waiting for AP connect */
            break;

        case EXAMPLE_STATE_CONNECTED:
            g_example_state = EXAMPLE_STATE_WOLFSSL_INIT;
            break;

        case EXAMPLE_STATE_WOLFSSL_INIT:
        {
            SYS_PRINT("Initializing wolfSSL\r\n");
            ret = wolfCrypt_ATECC_SetConfig(&atecc608a_0_init_data_TNGTLS);
            if (ret == 0) {
                ret = wolfSSL_Init();
                if (ret != WOLFSSL_SUCCESS) {
                    SYS_PRINT("wolfSSL_Init() failed, ret = %d\r\n", ret);
                    g_example_state = EXAMPLE_STATE_FINISHED;
                } else {

                    /* Uncomment next line to enable debug messages, also need
                     * to recompile wolfSSL with DEBUG_WOLFSSL defined. */
                    /* wolfSSL_Debugging_ON(); */

                    g_example_state = EXAMPLE_STATE_DNS_RESOLVE;
                }
            } else {
                SYS_PRINT("wolfCrypt_ATECC_SetConfig() failed\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
            }
            break;
        }

        case EXAMPLE_STATE_DNS_RESOLVE:
        {
            appData.host = SERVER_HOST;
            appData.port = SERVER_PORT;

            hostInfo = gethostbyname(appData.host);
            if (hostInfo != NULL) {
                SYS_PRINT("gethostbyname(%s) passed\r\n", appData.host);
                memcpy(&appData.addr.sin_addr.S_un.S_addr,
                        *(hostInfo->h_addr_list), sizeof(IPV4_ADDR));
                g_example_state = EXAMPLE_STATE_BSD_SOCKET;
            } else {
                break;
            }
        }

        case EXAMPLE_STATE_BSD_SOCKET:
        {
            int tcpSocket;
            SYS_PRINT("Creating socket\r\n");
            if ((tcpSocket = socket(AF_INET, SOCK_STREAM,
                                    IPPROTO_TCP)) == SOCKET_ERROR) {
                return;
            } else {
                appData.socket = (SOCKET)tcpSocket;
            }
            SYS_PRINT("BSD TCP client: connecting...\r\n");

            g_example_state = EXAMPLE_STATE_BSD_CONNECT;
            break;
        }

        case EXAMPLE_STATE_BSD_CONNECT:
        {
            int addrlen;
            appData.addr.sin_port = appData.port;
            addrlen = sizeof(struct sockaddr);
            if (connect(appData.socket, (struct sockaddr*) &appData.addr,
                        addrlen) < 0) {
                return;
            }
            SYS_PRINT("connect() success, loading certs/keys\r\n");
            g_example_state = EXAMPLE_STATE_LOAD_CERTS;
            break;
        }

        case EXAMPLE_STATE_LOAD_CERTS:
        {
            ret = tls_build_signer_ca_cert_tlstng();
            if (ret != ATCACERT_E_SUCCESS) {
                SYS_PRINT("Failed to build server's signer certificate\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            SYS_PRINT("\r\nBuilt server's signer certificate\r\n");

            ret = tls_build_end_user_cert_tlstng();
            if (ret != ATCACERT_E_SUCCESS) {
                SYS_PRINT("Failed to build client certificate\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            SYS_PRINT("\r\nBuilt client certificate\r\n");

            ret = tls_setup_client_ctx();
            if (ret != SSL_SUCCESS) {
                SYS_PRINT("Failed to load wolfSSL!\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            SYS_PRINT("\r\nLoaded certs into wolfSSL\r\n");

            /* Create new WOLFSSL session */
            ssl_client = wolfSSL_new(ctx_client);
            if (ssl_client == NULL) {
                SYS_PRINT("Unable to create wolfSSL session\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Pass socket descriptor to wolfSSL for I/O */
            wolfSSL_set_fd(ssl_client, appData.socket);
            SYS_PRINT("Registered SOCKET with wolfSSL\r\n");

            g_example_state = EXAMPLE_STATE_DO_HANDSHAKE;
            break;
        }

        case EXAMPLE_STATE_DO_HANDSHAKE:
        {
            if (wolfSSL_connect(ssl_client) != SSL_SUCCESS) {
                int err = wolfSSL_get_error(ssl_client, 0);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* try again */
                    break;
                } else {
                    char buffer[80];
                    SYS_PRINT("wolfSSL_connect() failed, error = %d: %s\r\n",
                            err, wolfSSL_ERR_error_string(err, buffer));
                    g_example_state = EXAMPLE_STATE_FINISHED;
                    break;
                }
            }
            SYS_PRINT("wolfSSL_connect() success!\r\n");

            g_example_state = EXAMPLE_STATE_SEND_HTTP_GET;
            break;
        }

        case EXAMPLE_STATE_SEND_HTTP_GET:
        {
            ret = wolfSSL_write(ssl_client, httpGET, sizeof(httpGET));
            if (ret <= 0) {
                int err = wolfSSL_get_error(ssl_client, 0);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* try again */
                    break;
                } else {
                    char buffer[80];
                    SYS_PRINT("wolfSSL_write() failed, error = %d: %s\r\n",
                            err, wolfSSL_ERR_error_string(err, buffer));
                    g_example_state = EXAMPLE_STATE_FINISHED;
                    break;
                }
            }
            SYS_PRINT("Sent HTTP GET to peer\r\n");

            g_example_state = EXAMPLE_STATE_RECV_RESPONSE;
            break;
        }

        case EXAMPLE_STATE_RECV_RESPONSE:
        {
            memset(reply, 0, sizeof(reply));

            ret = wolfSSL_read(ssl_client, reply, sizeof(reply)-1);
            if (ret <= 0) {
                int err = wolfSSL_get_error(ssl_client, 0);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* try again */
                    break;
                } else {
                    char buffer[80];
                    SYS_PRINT("wolfSSL_read() failed, error = %d: %s\r\n",
                            err, wolfSSL_ERR_error_string(err, buffer));
                    g_example_state = EXAMPLE_STATE_FINISHED;
                    break;
                }
            }
            SYS_PRINT("Response from server:\r\n");
            SYS_PRINT("----------\r\n");
            SYS_PRINT("%s\r\n", reply);
            SYS_PRINT("----------\r\n");

            g_example_state = EXAMPLE_STATE_SHUTDOWN;
            break;
        }

        case EXAMPLE_STATE_SHUTDOWN:
        {
            if (ssl_client != NULL) {
                wolfSSL_shutdown(ssl_client);
                wolfSSL_free(ssl_client);
                SYS_PRINT("Shutdown and freed WOLFSSL session\r\n");
            }
            if (ctx_client != NULL) {
                wolfSSL_CTX_free(ctx_client);
                SYS_PRINT("Freed WOLFSSL_CTX\r\n");
            }
            closesocket(appData.socket);
            SYS_PRINT("\r\nConnection Closed\r\n");

            if (atecc_initialized == 1) {
                atcab_release();
                atecc_initialized = 0;
                SYS_PRINT("Released ECC608A\r\n");
            }

            g_example_state = EXAMPLE_STATE_FINISHED;
            break;
        }

        case EXAMPLE_STATE_FINISHED:
        {
            if (atecc_initialized == 1) {
                atcab_release();
                atecc_initialized = 0;
            }

            wolfSSL_Cleanup();

            g_example_state = EXAMPLE_STATE_DISCONNECT;
            break;
        }

        case EXAMPLE_STATE_DISCONNECT:
        {
            /* Disconnect from the WINC1500 WIFI */
            m2m_wifi_disconnect();
            g_example_state = EXAMPLE_STATE_WAIT;
            break;
        }

        case EXAMPLE_STATE_WAIT:
        {
            break;
        }
    }
}
