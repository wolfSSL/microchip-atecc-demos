
#include "app.h"
#include "definitions.h"
#include "cryptoauthlib.h"
#include "atcacert/atcacert_client.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/port/atmel/atmel.h>
#include <wolfssl/certs_test.h>
#include "tls_common.h"
#include "atecc_common.h"

#define SERVER_PORT 11111

APP_DATA appData;
static int sntpTimestampReady = 0;
static WOLFSSL*        ssl = NULL;
static WOLFSSL_CTX*    ctx = NULL;
static WOLFSSL_METHOD* method = NULL;

ATCAIfaceCfg atecc608a_0_init_data_TNGTLS = {
       .iface_type            = ATCA_I2C_IFACE,
       .devtype               = ATECC608A,
       .atcai2c.slave_address = 0x6A,
       .atcai2c.bus           = 0,
       .atcai2c.baud          = 400000,
       .wake_delay            = 1500,
       .rx_retries            = 20,
       .cfg_data              = &i2c1_plib_api
};

byte input[80];
static const char webServerMsg[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "Content-Length: 141\r\n"
    "\r\n"
    "<html>\r\n"
    "<head>\r\n"
    "<title>Welcome to wolfSSL!</title>\r\n"
    "</head>\r\n"
    "<body>\r\n"
    "<p>wolfSSL has successfully performed handshake!</p>\r\n"
    "</body>\r\n"
    "</html>\r\n";

extern uint8_t io_protection_key[ATECC_KEY_SIZE];

int tls_setup_server_ctx(void)
{
    byte* serverCertChainDer = NULL;
    word32 serverCertChainDerSz = 0;

    method = wolfTLSv1_2_server_method();
    if (method == NULL) {
        SYS_PRINT("Failed to alloc dynamic buffer\r\n");
        return SSL_FAILURE;
    }
    SYS_PRINT("Created wolfTLSv1_2_client_method()\r\n");

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        SYS_PRINT("Failed to create wolfSSL context\r\n");
        return SSL_FAILURE;
    }
    SYS_PRINT("Created new WOLFSSL_CTX\r\n");

    /* Load root CA certificate used to verify peer. This buffer is set up to
     * verify the wolfSSL example client. The example client should be started
     * using the <wolfssl_root>/certs/client-ecc-cert.pem certificate and
     * <wolfssl_root>/ecc-client-key.pem private key. */
    if (wolfSSL_CTX_load_verify_buffer(ctx, cliecc_cert_der_256,
            sizeof_cliecc_cert_der_256, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        SYS_PRINT("Failed to load verification certificate!\r\n");
        return SSL_FAILURE;
    }
    SYS_PRINT("Loaded verify cert buffer into WOLFSSL_CTX\r\n");

    /* Concatenate server cert with intermediate signer cert to send chain,
     * peer will have root CA loaded to verify chain */
    serverCertChainDerSz = atcert.end_user_size + atcert.signer_ca_size;
    serverCertChainDer = (byte*)malloc(serverCertChainDerSz);
    memcpy(serverCertChainDer, atcert.end_user, atcert.end_user_size);
    memcpy(serverCertChainDer + atcert.end_user_size,
           atcert.signer_ca, atcert.signer_ca_size);

    if (wolfSSL_CTX_use_certificate_chain_buffer_format(ctx,
            serverCertChainDer, serverCertChainDerSz,
            WOLFSSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        SYS_PRINT("Failed to load server certificate chain\r\n");
        free(serverCertChainDer);
        return SSL_FAILURE;
    }
    free(serverCertChainDer);
    SYS_PRINT("Loaded server certificate chain in to WOLFSSL_CTX\r\n");

    /* Authenticate peer */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    atcatls_set_callbacks(ctx);

    return SSL_SUCCESS;
}

/* SNTP event callback, sets sntpTimestampReady when receives timestamp */
void sntpEventHandler(TCPIP_SNTP_EVENT evType, const void* evParam)
{
    if (evType < 0) {
        /* error occurred */
        SYS_PRINT("sntpEventHandler: error occurred: %d\r\n", evType);
    } else {
        if (evType == TCPIP_SNTP_EVENT_TSTAMP_OK) {
            SYS_PRINT("Got SUCCESSFUL SNTP timestamp\r\n");
            sntpTimestampReady = 1;
        } else {
            SYS_PRINT("sntpEventHandler: evType = %d\r\n", evType);
        }
    }
}

void APP_Initialize ( void )
{
    appData.state = APP_STATE_INIT;
}

void APP_Tasks ( void )
{
    SYS_STATUS tcpStatus;
    const char* netName;
    const char* netBiosName;
    int i, nNets, ret;
    int atecc_initialized = 0;
    TCPIP_NET_HANDLE netH;
    uint32_t sec = 0;
    ATCA_STATUS status;
    TCPIP_SNTP_RESULT sntpRet;

    switch ( appData.state )
    {
        case APP_STATE_INIT:
        {
            /* wait for TCP/IP stack initialization */
            tcpStatus = TCPIP_STACK_Status(sysObj.tcpip);
            if (tcpStatus < 0) {
                SYS_PRINT("TCP/IP stack initialization failed\r\n");
                appData.state = APP_STATE_ERROR;

            } else if (tcpStatus == SYS_STATUS_READY) {
                /* TCP/IP stack ready, check available interfaces */
                nNets = TCPIP_STACK_NumberOfNetworksGet();

                for (i = 0; i < nNets; i++) {
                    netH = TCPIP_STACK_IndexToNet(i);
                    netName = TCPIP_STACK_NetNameGet(netH);
                    netBiosName = TCPIP_STACK_NetBIOSName(netH);

#if defined(TCPIP_STACK_USE_NBNS)
                    SYS_PRINT("Interface %s on host %s - NBNS enabled\r\n", netName, netBiosName);
#else
                    SYS_PRINT("Interface %s on host %s - NBNS disabled\r\n", netName, netBiosName);
#endif
                }
                appData.state = APP_TCPIP_WAIT_FOR_IP;
            }
            break;
        }

        case APP_TCPIP_WAIT_FOR_IP:
        {
            nNets = TCPIP_STACK_NumberOfNetworksGet();
            for (i = 0; i < nNets; i++) {
                netH = TCPIP_STACK_IndexToNet(i);
                if (!TCPIP_STACK_NetIsReady(netH)) {
                    /* interface not ready net */
                    return;
                }
                IPV4_ADDR ipAddr;
                ipAddr.Val = TCPIP_STACK_NetAddress(netH);
                SYS_PRINT(TCPIP_STACK_NetNameGet(netH));
                SYS_PRINT(" IP Address: ");
                SYS_PRINT("%d.%d.%d.%d \r\n", ipAddr.v[0], ipAddr.v[1], ipAddr.v[2], ipAddr.v[3]);
            }
            /* all interfaces ready, ready to start transactions */

            appData.state = APP_STATE_INIT_SNTP;
            break;
        }

        case APP_STATE_INIT_SNTP:
        {
            /* register SNTP event handler */
            TCPIP_SNTP_HandlerRegister(sntpEventHandler);

            /* force initiate SNTP module to set system time */
            sntpRet = TCPIP_SNTP_ConnectionInitiate();
            if (sntpRet == SNTP_RES_OK) {
                SYS_PRINT("SNTP initiated successfully\r\n");
                appData.state = APP_STATE_SNTP_WAIT_FOR_TIMESTAMP;

            } else {
                SYS_PRINT("SNTP initiation in progress\r\n");
            }
            break;
        }

        case APP_STATE_SNTP_WAIT_FOR_TIMESTAMP:
        {
            if (sntpTimestampReady == 1) {
                appData.state = APP_STATE_TEST_SNTP;
            }
            break;
        }

        case APP_STATE_TEST_SNTP:
        {
            TCPIP_SNTP_TIME_STAMP pTStamp;
            uint32_t pLastUpdate;

            SYS_PRINT("Trying to get seconds from SNTP\r\n");
            sec = TCPIP_SNTP_UTCSecondsGet();
            SYS_PRINT("SNTP seconds = %d\r\n", sec);

            if (sec > 0) {
                appData.state = APP_STATE_608A_INIT;

            } else {
                SYS_PRINT("Getting last timestamp value\r\n");
                sntpRet = TCPIP_SNTP_TimeStampGet(&pTStamp, &pLastUpdate);
                if (sntpRet == SNTP_RES_OK) {
                    appData.state = APP_STATE_608A_INIT;

                } else if (sntpRet == SNTP_RES_TSTAMP_STALE) {
                    SYS_PRINT("Stale timestamp, no recent timestamp\r\n");
                    SYS_PRINT("Last SNTP error = %d\r\n", TCPIP_SNTP_LastErrorGet());
                    appData.state = APP_STATE_ERROR;

                } else if (sntpRet == SNTP_RES_TSTAMP_ERROR) {
                    SYS_PRINT("No available timestamp\r\n");
                    SYS_PRINT("Last SNTP error = %d\r\n", TCPIP_SNTP_LastErrorGet());
                    appData.state = APP_STATE_ERROR;
                }
            }
            break;
        }

        case APP_STATE_608A_INIT:
        {
            status = atcab_init(&atecc608a_0_init_data_TNGTLS);
            if (status != ATCA_SUCCESS) {
                SYS_PRINT("atcab_init() failed, ret = %d\r\n", status);
                appData.state = APP_STATE_ERROR;

            } else {
                SYS_PRINT("atcab_init() success\r\n");
                atecc_initialized = 1;
                appData.state = APP_STATE_608A_CHECK_LOCK;
            }
            break;
        }

        case APP_STATE_608A_CHECK_LOCK:
        {
            ret = check_lock_status();
            if (ret != 0) {
                SYS_PRINT("Failed to check lock zone status\r\n");
            }
            appData.state = APP_STATE_608A_INFO;
            break;
        }

        case APP_STATE_608A_INFO:
        {
            ret = print_info();
            if (ret != 0) {
                SYS_PRINT("Failed to print ATECC608A module info\r\n");
                appData.state = APP_STATE_ERROR;
            } else {
                appData.state = APP_STATE_608A_SETUP_IO_PROTECTION_KEY;
            }
            break;
        }

        case APP_STATE_608A_SETUP_IO_PROTECTION_KEY:
        {
            bool is_locked;

            /* check if IO protection key slot is already locked */
            status = atcab_is_slot_locked(6, &is_locked);
            if (status != ATCA_SUCCESS) {
                SYS_PRINT("Failed check if IO protection key slot locked\r\n");
                appData.state = APP_STATE_ERROR;
                break;
            }

            if (is_locked) {
                SYS_PRINT("IO protection key slot already locked, skipping setup\r\n");
                appData.state = APP_STATE_WOLFSSL_INIT;
                break;
            }

            /* write IO protection key to slot */
            status = atcab_write_zone(ATCA_ZONE_DATA, 6, 0, 0,
                        io_protection_key, ATCA_KEY_SIZE);
            if (status != ATCA_SUCCESS) {
                SYS_PRINT("Failed to write IO protection key to slot\r\n");
                appData.state = APP_STATE_ERROR;
                break;
            }

            /* lock IO protection key slot */
            /*status = atcab_lock_data_slot(6);
            if (status != ATCA_SUCCESS) {
                SYS_PRINT("Failed to lock IO protection key slot\r\n");
                appData.state = APP_STATE_ERROR;
                break;
            }*/

            appData.state = APP_STATE_WOLFSSL_INIT;
            break;
        }

        case APP_STATE_WOLFSSL_INIT:
        {
            SYS_PRINT("Initializing wolfSSL\r\n");
            ret = wolfCrypt_ATECC_SetConfig(&atecc608a_0_init_data_TNGTLS);
            if (ret == 0) {
                ret = wolfSSL_Init();
                if (ret != WOLFSSL_SUCCESS) {
                    SYS_PRINT("wolfSSL_Init() failed, ret = %d\r\n", ret);
                    appData.state = APP_STATE_ERROR;
                } else {

                    /* Uncomment next line to enable debug messages, also need
                     * to recompile wolfSSL with DEBUG_WOLFSSL defined. */
                    /* wolfSSL_Debugging_ON(); */

                    appData.state = APP_STATE_LOAD_CERTS;
                }
            } else {
                SYS_PRINT("wolfCrypt_ATECC_SetConfig() failed\r\n");
                appData.state = APP_STATE_ERROR;
            }
            break;
        }

        case APP_STATE_LOAD_CERTS:
        {
            ret = tls_build_signer_ca_cert_tlstng();
            if (ret != ATCA_SUCCESS) {
                SYS_PRINT("Failed to build server's signer certificate\r\n");
                appData.state = APP_STATE_ERROR;
                break;
            }
            SYS_PRINT("Built server's signer certificate\r\n");

            ret = tls_build_end_user_cert_tlstng();
            if (ret != ATCA_SUCCESS) {
                SYS_PRINT("Failed to build device certificate\r\n");
                appData.state = APP_STATE_ERROR;
                break;
            }
            SYS_PRINT("Built device certificate\r\n");

            ret = tls_setup_server_ctx();
            if (ret != SSL_SUCCESS) {
                SYS_PRINT("Failed to load wolfSSL!\r\n");
                appData.state = APP_STATE_ERROR;
                break;
            }
            SYS_PRINT("Loaded certs into wolfSSL, set up CTX\r\n");

            appData.state = APP_STATE_BSD_CREATE_SOCKET;
            break;
        }

        case APP_STATE_BSD_CREATE_SOCKET:
        {
            SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET)
                return;

            SYS_PRINT("Created server socket\r\n");
            appData.serverSocket = (SOCKET)sock;
            appData.state = APP_STATE_BSD_BIND;
            break;
        }

        case APP_STATE_BSD_BIND:
        {
            struct sockaddr_in addr;
            int addrlen = sizeof(struct sockaddr_in);
            addr.sin_port = SERVER_PORT;
            addr.sin_addr.S_un.S_addr = IP_ADDR_ANY;
            if (bind(appData.serverSocket, (struct sockaddr*)&addr, addrlen) == SOCKET_ERROR)
                return;

            SYS_PRINT("bind() on server socket finished\r\n");
            appData.state = APP_STATE_BSD_LISTEN;
            break;
        }

        case APP_STATE_BSD_LISTEN:
        {
            if (listen(appData.serverSocket, 1) == 0) {
                SYS_PRINT("Waiting for client connection on port: %d\r\n", SERVER_PORT);
                appData.state = APP_STATE_TCP_ACCEPT;
            }
            appData.clientSocket = INVALID_SOCKET;
            break;
        }

        case APP_STATE_TCP_ACCEPT:
        {
            struct sockaddr_in remotePeer;
            int addrlen = sizeof(struct sockaddr_in);

            if (appData.clientSocket == INVALID_SOCKET) {
                appData.clientSocket = accept(appData.serverSocket, (struct sockaddr*)&remotePeer, &addrlen);
            }

            if (appData.clientSocket == INVALID_SOCKET) {
                /* not connected */
                appData.state = APP_STATE_TCP_ACCEPT;
                break;
            }
            SYS_PRINT("Accepted client connection\r\n");

            ssl = wolfSSL_new(ctx);
            if (ssl == NULL) {
                SYS_PRINT("Failed to create WOLFSSL session\r\n");
                appData.state = APP_STATE_SHUTDOWN;
                break;
            }

            wolfSSL_set_fd(ssl, appData.clientSocket);
            SYS_PRINT("Registered SOCKET with WOLFSSL session\r\n");

            appData.state = APP_STATE_TLS_ACCEPT;
            break;
        }

        case APP_STATE_TLS_ACCEPT:
        {
            if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
                int err = wolfSSL_get_error(ssl, 0);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* try again - socket want read or want write */
                    break;
                } else {
                    char buffer[80];
                    SYS_PRINT("wolfSSL_accept() failed, error = %d: %s\r\n",
                            err, wolfSSL_ERR_error_string(err, buffer));
                    appData.state = APP_STATE_SHUTDOWN;
                    break;
                }
            }
            SYS_PRINT("wolfSSL_accept() success!\r\n");
            SYS_PRINT("Waiting for data from client\r\n");

            appData.state = APP_STATE_RECV_DATA;
            break;
        }

        case APP_STATE_RECV_DATA:
        {
            memset(input, 0, sizeof(input));

            ret = wolfSSL_read(ssl, input, sizeof(input)-1);
            if (ret < 0) {
                int err = wolfSSL_get_error(ssl, 0);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* try again - socket want read or want write */
                    break;
                } else {
                    char buffer[80];
                    SYS_PRINT("wolfSSL_read() failed, error = %d: %s\r\n",
                            err, wolfSSL_ERR_error_string(err, buffer));
                    appData.state = APP_STATE_SHUTDOWN;
                    break;
                }
            }

            SYS_PRINT("Message from client:\r\n");
            SYS_PRINT("----------\r\n");
            SYS_PRINT("%s\r\n", input);
            SYS_PRINT("----------\r\n");

            appData.state = APP_STATE_SEND_DATA;
            break;
        }

        case APP_STATE_SEND_DATA:
        {
            /* send back simple HTTP web page */
            ret = wolfSSL_write(ssl, webServerMsg, sizeof(webServerMsg));
            if (ret <= 0) {
                int err = wolfSSL_get_error(ssl, 0);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* try again */
                    break;
                } else {
                    char buffer[80];
                    SYS_PRINT("wolfSSL_write() failed, error = %d: %s\r\n",
                            err, wolfSSL_ERR_error_string(err, buffer));
                    appData.state = APP_STATE_ERROR;
                    break;
                }
            }
            SYS_PRINT("Sent HTTP web page to peer\r\n");

            appData.state = APP_STATE_SHUTDOWN;
            break;
        }

        case APP_STATE_SHUTDOWN:
        {
            if (ssl != NULL) {
                wolfSSL_shutdown(ssl);
                wolfSSL_free(ssl);
                SYS_PRINT("Shutdown and freed WOLFSSL session\r\n");
            }
            closesocket(appData.clientSocket);
            appData.clientSocket = INVALID_SOCKET;
            SYS_PRINT("\r\nConnection Closed\r\n");

            SYS_PRINT("Waiting for client connection on port: %d\r\n", SERVER_PORT);
            appData.state = APP_STATE_TCP_ACCEPT;
            break;
        }

        case APP_STATE_ERROR:
        {
            if (ssl != NULL) {
                wolfSSL_shutdown(ssl);
                wolfSSL_free(ssl);
                ssl = NULL;
                SYS_PRINT("Shutdown and freed WOLFSSL session\r\n");
            }
            if (ctx != NULL) {
                wolfSSL_CTX_free(ctx);
                ctx = NULL;
                SYS_PRINT("Freed WOLFSSL_CTX\r\n");
            }
            closesocket(appData.clientSocket);
            closesocket(appData.serverSocket);
            SYS_PRINT("\r\nConnection Closed\r\n");

            wolfSSL_Cleanup();

            if (atecc_initialized == 1) {
                atcab_release();
                atecc_initialized = 0;
            }
            appData.state = APP_STATE_WAIT;
            break;
        }

        case APP_STATE_WAIT:
        {
            break;
        }
    }
}

