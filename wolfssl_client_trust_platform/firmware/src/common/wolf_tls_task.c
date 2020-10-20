#include "app.h"
#include "wdrv_winc_client_api.h"
#include "cryptoauthlib.h"
#include "tng/tng_atcacert_client.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/port/atmel/atmel.h>

/* force inclusion of 256-bit test certs and keys */
#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256
#include <wolfssl/certs_test.h>

#define WLAN_AUTH_WPA_PSK
#define WLAN_SSID           "BLADE"
#define WLAN_PSK            "thegarskes"

static SOCKET gSock;
static struct sockaddr_in gAddr;
static char* gHost = "192.168.0.251";
static uint16_t gPort = 11111;

static WOLFSSL*        ssl_client = NULL;
static WOLFSSL_CTX*    ctx_client = NULL;
static WOLFSSL_METHOD* method_client = NULL;
static const char httpGET[] = "GET /index.html HTTP/1.0\r\n\r\n";

static WDRV_WINC_AUTH_CONTEXT authCtx;
static WDRV_WINC_BSS_CONTEXT bssCtx;

extern ATCAIfaceCfg atecc608_0_init_data;

typedef struct t_atcert {
    uint32_t signer_ca_size;
    uint8_t  signer_ca[521];
    uint8_t  signer_ca_pubkey[64];
    uint32_t end_user_size;
    uint8_t  end_user[552];
    uint8_t  end_user_pubkey[64];
} t_atcert;

t_atcert atcert = {
    .signer_ca_size = 521,
    .signer_ca = { 0 },
    .signer_ca_pubkey = { 0 },
    .end_user_size = 552,
    .end_user = { 0 },
    .end_user_pubkey = { 0 }
};

/* I/O protection key used with examples */
static uint8_t io_protection_key[ATECC_KEY_SIZE] = {
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
    0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
    0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
};

/* application states */
typedef enum
{
    EXAMPLE_STATE_EXAMPLE_INIT=0,
    EXAMPLE_STATE_608_INIT,
    EXAMPLE_STATE_608_CHECK_LOCK,
    EXAMPLE_STATE_608_INFO,
    EXAMPLE_STATE_608_SETUP_IO_PROTECTION_KEY,
    EXAMPLE_STATE_NET_INIT,
    EXAMPLE_STATE_CONNECT,
    EXAMPLE_STATE_CONNECTING,
    EXAMPLE_STATE_CONNECTED,
    EXAMPLE_STATE_GOT_IP,
    EXAMPLE_STATE_DNS_RESOLVE,
    EXAMPLE_STATE_BSD_SOCKET,
    EXAMPLE_STATE_BSD_CONNECT,
    EXAMPLE_STATE_WOLFSSL_INIT,
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
        APP_DebugPrintf("Failed to alloc dynamic buffer\r\n");
        return SSL_FAILURE;
    }
    APP_DebugPrintf("Created wolfTLSv1_2_client_method()\r\n");

    ctx_client = wolfSSL_CTX_new(method_client);
    if (ctx_client == NULL) {
        APP_DebugPrintf("Failed to create wolfSSL context\r\n");
        return SSL_FAILURE;
    }
    APP_DebugPrintf("Created new WOLFSSL_CTX\r\n");

    /* Load root CA certificate used to verify peer. This buffer is set up to
     * verify the wolfSSL example server. The example server should be started
     * using the <wolfssl_root>/certs/server-ecc.pem certificate and
     * <wolfssl_root>/certs/ecc-key.pem private key. */
    if (wolfSSL_CTX_load_verify_buffer(ctx_client, ca_ecc_cert_der_256,
            sizeof_ca_ecc_cert_der_256, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        APP_DebugPrintf("Failed to load verification certificate!\r\n");
        return SSL_FAILURE;
    }
    APP_DebugPrintf("Loaded verify cert buffer into WOLFSSL_CTX\r\n");

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
        APP_DebugPrintf("Failed to load client certificate chain\r\n");
        free(clientCertChainDer);
        return SSL_FAILURE;
    }
    free(clientCertChainDer);
    APP_DebugPrintf("Loaded client certificate chain in to WOLFSSL_CTX\r\n");

    /* Enable peer verification */
    wolfSSL_CTX_set_verify(ctx_client, SSL_VERIFY_PEER, NULL);
    atcatls_set_callbacks(ctx_client);

    return SSL_SUCCESS;
}

static void dns_resolve_handler(uint8_t *pu8DomainName, uint32_t u32ServerIP)
{
    if (u32ServerIP != 0) {
        uint8_t host_ip_address[4];
        host_ip_address[0] = u32ServerIP & 0xFF;
        host_ip_address[1] = (u32ServerIP >> 8) & 0xFF;
        host_ip_address[2] = (u32ServerIP >> 16) & 0xFF;
        host_ip_address[3] = (u32ServerIP >> 24) & 0xFF;

        APP_DebugPrintf("WINC1500 WIFI: DNS lookup:\r\n"
                        "  Host:       %s\r\n"
                        "  IP Address: %u.%u.%u.%u\r\n",
                (char*)pu8DomainName, 
                host_ip_address[0], host_ip_address[1],
                host_ip_address[2], host_ip_address[3]);

        gAddr.sin_addr.s_addr = u32ServerIP;
                                                        
        g_example_state = EXAMPLE_STATE_BSD_SOCKET;
    }
    else {
        /* An error has occurred */
        APP_DebugPrintf("WINC1500 DNS lookup failed.\r\n");
        g_example_state = EXAMPLE_STATE_FINISHED;
    }
}

static void APP_ExampleDHCPAddressEventCallback(DRV_HANDLE handle, uint32_t ipAddress)
{
    char s[20];

    APP_DebugPrintf("IP address is %s\r\n", inet_ntop(AF_INET, &ipAddress, s, sizeof(s)));
    g_example_state = EXAMPLE_STATE_GOT_IP;
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
    if (currentState == WDRV_WINC_CONN_STATE_CONNECTED) {
        APP_DebugPrintf("Wifi Connected\r\n");
        g_example_state = EXAMPLE_STATE_CONNECTED;
    }
    else if (currentState == WDRV_WINC_CONN_STATE_DISCONNECTED) {
        if (g_example_state == EXAMPLE_STATE_CONNECTED) {
            APP_DebugPrintf("Failed to connect\r\n");
            g_example_state = EXAMPLE_STATE_DISCONNECT;
        }
        else {
            APP_DebugPrintf("Wifi Disconnected\r\n");
            g_example_state = EXAMPLE_STATE_CONNECT;

        }
    }
    else {
        APP_DebugPrintf("WINC1500 WIFI: Unknown connection status: %d\r\n",
                currentState);
    }
}

static void socket_callback_handler(SOCKET socket, uint8_t messageType, void *pMessage)
{
    switch (messageType) {
    case SOCKET_MSG_CONNECT:
    {
        tstrSocketConnectMsg *socket_connect_message = (tstrSocketConnectMsg*)pMessage;

        if (socket_connect_message) {
            if (socket_connect_message->s8Error != SOCK_ERR_NO_ERROR) {
                /* An error has occurred */
                APP_DebugPrintf("SOCKET_MSG_CONNECT error %d\r\n", 
                    socket_connect_message->s8Error);
                g_example_state = EXAMPLE_STATE_SHUTDOWN;
            }
        }
        break;
    }
    case SOCKET_MSG_RECV:
    case SOCKET_MSG_RECVFROM:
    {
        tstrSocketRecvMsg *socket_receive_message = (tstrSocketRecvMsg*)pMessage;;
        (void)socket_receive_message;
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


static int atca_check_lock_status(void)
{
    ATCA_STATUS status;
    bool isLocked = false;

    status = atcab_is_locked(LOCK_ZONE_CONFIG, &isLocked);
    if (status != ATCA_SUCCESS) {
        APP_DebugPrintf("Error reading CONFIG zone lock\r\n");
    } else {
        APP_DebugPrintf("CONFIG zone locked: %s\r\n", isLocked == true ? "yes" : "no");
    }

    status = atcab_is_locked(LOCK_ZONE_DATA, &isLocked);
    if (status != ATCA_SUCCESS) {
        APP_DebugPrintf("Error reading DATA zone lock\r\n");
    } else {
        APP_DebugPrintf("DATA zone locked: %s\r\n", isLocked == true ? "yes" : "no");
    }

    return 0;
}

static int atca_print_info(void)
{
    uint8_t revision[4];
    uint8_t serialnum[ATCA_SERIAL_NUM_SIZE];
    char displaystr[ATCA_SERIAL_NUM_SIZE * 3];
    size_t displaylen = sizeof(displaystr);
    ATCA_STATUS status;

    /* revision info */
    status = atcab_info(revision);
    if (status != ATCA_SUCCESS) {
        APP_DebugPrintf("Failed to get revision information\r\n");
    } else {
        atcab_bin2hex(revision, 4, displaystr, &displaylen);
        APP_DebugPrintf("revision:\r\n%s\r\n", displaystr);
    }

    memset(displaystr, 0, sizeof(displaystr));
    displaylen = sizeof(displaystr);

    status = atcab_read_serial_number(serialnum);
    if (status != ATCA_SUCCESS) {
        APP_DebugPrintf("Failed to get serial number\r\n");
    } else {
        atcab_bin2hex(serialnum, ATCA_SERIAL_NUM_SIZE, displaystr, &displaylen);
        APP_DebugPrintf("serial number:\r\n%s\r\n\n", displaystr);
    }

    return 0;
}

int tls_build_signer_ca_cert_tlstng(void)
{
    int ret = 0;
    size_t maxCertSz = 0;

    /* read signer certificate from ATECC module */
    ret = tng_atcacert_max_signer_cert_size(&maxCertSz);
    if (ret != ATCACERT_E_SUCCESS) {
        APP_DebugPrintf("Failed to get max signer cert size\r\n");
        return ret;
    }

    if (maxCertSz > atcert.signer_ca_size) {
        APP_DebugPrintf("Signer CA cert buffer too small, need to increase: max = %d\r\n", maxCertSz);
        return -1;
    }

    ret = tng_atcacert_read_signer_cert(atcert.signer_ca,
            (size_t*)&atcert.signer_ca_size);
    if (ret != ATCACERT_E_SUCCESS) {
        APP_DebugPrintf("Failed to read signer cert! %x\r\n", ret);
        //return ret;
    }
    else {
        APP_DebugPrintf("Successfully read signer cert\r\n");
        //atcab_printbin_label("\r\nSigner Certificate\r\n",
        //        atcert.signer_ca, atcert.signer_ca_size);
    }

    /* read signer public key from ATECC module */
    ret = tng_atcacert_signer_public_key(atcert.signer_ca_pubkey,
            atcert.signer_ca);
    if (ret != ATCACERT_E_SUCCESS) {
        APP_DebugPrintf("Failed to read signer public key! %d\r\n", ret);
        //return ret;
    }
    else {
        APP_DebugPrintf("Successfully read signer pub key\r\n");
        //atcab_printbin_label("\r\nSigner Public Key\r\n",
        //        atcert.signer_ca_pubkey, sizeof(atcert.signer_ca_pubkey));
    }

    return ret;
}

int tls_build_end_user_cert_tlstng(void)
{
    int ret = 0;
    size_t maxCertSz = 0;

    /* read device certificate from ATECC module */
    ret = tng_atcacert_max_device_cert_size(&maxCertSz);
    if (ret != ATCACERT_E_SUCCESS) {
        APP_DebugPrintf("Failed to get max device cert size\r\n");
        return ret;
    }

    if (maxCertSz > atcert.end_user_size) {
        APP_DebugPrintf("Device cert buffer too small, please increase, max = %d\r\n",
                  maxCertSz);
        return -1;
    }

    ret = tng_atcacert_read_device_cert(atcert.end_user,
            (size_t*)&atcert.end_user_size, NULL);
    if (ret != ATCACERT_E_SUCCESS) {
        APP_DebugPrintf("Failed to read device cert!\r\n");
        //return ret;
    }
    else {
        APP_DebugPrintf("Successfully read device cert\r\n");
        //atcab_printbin_label("\r\nEnd User Certificate\r\n",
        //        atcert.end_user, atcert.end_user_size);
    }

    ret = tng_atcacert_device_public_key(atcert.end_user_pubkey,
            atcert.end_user);
    if (ret != ATCACERT_E_SUCCESS) {
        APP_DebugPrintf("Failed to end user public key!\r\n");
        //return ret;
    }
    else {
        APP_DebugPrintf("Successfully read device pub key\r\n");
        //atcab_printbin_label("\r\nEnd User Public Key\r\n",
        //        atcert.end_user_pubkey, sizeof(atcert.end_user_pubkey));
    }

    return ret;
}

void APP_ExampleTasks(DRV_HANDLE handle)
{
    int8_t status = !0;
    static int atecc_initialized = 0;

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
            status = atcab_init(&atecc608_0_init_data);
            if (status != ATCA_SUCCESS) {
                APP_DebugPrintf("atcab_init() failed, ret = %d\r\n", status);
                g_example_state = EXAMPLE_STATE_FINISHED;

            } else {
                APP_DebugPrintf("atcab_init() success\r\n");
                atecc_initialized = 1;
                g_example_state = EXAMPLE_STATE_608_CHECK_LOCK;
            }
            break;
        }

        case EXAMPLE_STATE_608_CHECK_LOCK:
        {
            status = atca_check_lock_status();
            if (status != 0) {
                APP_DebugPrintf("Failed to check lock zone status\r\n");
            }
            g_example_state = EXAMPLE_STATE_608_INFO;
            break;
        }

        case EXAMPLE_STATE_608_INFO:
        {
            status = atca_print_info();
            if (status != 0) {
                APP_DebugPrintf("Failed to print ATECC608 module info\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
            } else {
                g_example_state = EXAMPLE_STATE_608_SETUP_IO_PROTECTION_KEY;
            }
            break;
        }

        case EXAMPLE_STATE_608_SETUP_IO_PROTECTION_KEY:
        {
            bool is_locked;

            /* check if IO protection key slot is already locked */
            status = atcab_is_slot_locked(6, &is_locked);
            if (status != ATCA_SUCCESS) {
                APP_DebugPrintf("Failed check if IO protection key slot locked\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            if (is_locked) {
                APP_DebugPrintf("IO protection key slot already locked, skipping setup\r\n");
                g_example_state = EXAMPLE_STATE_NET_INIT;
                break;
            }

            /* write IO protection key to slot */
            status = atcab_write_zone(ATCA_ZONE_DATA, 6, 0, 0,
                        io_protection_key, ATCA_KEY_SIZE);
            if (status != ATCA_SUCCESS) {
                APP_DebugPrintf("Failed to write IO protection key to slot\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* lock IO protection key slot */
            /*status = atcab_lock_data_slot(6);
            if (status != ATCA_SUCCESS) {
                APP_DebugPrintf("Failed to lock IO protection key slot\r\n");
                appData.state = APP_STATE_FINISHED;
                break;
            }*/

            g_example_state = EXAMPLE_STATE_NET_INIT;
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
            /* Waiting for IP */
            break;

        case EXAMPLE_STATE_GOT_IP:
            g_example_state = EXAMPLE_STATE_DNS_RESOLVE;
            break;

        case EXAMPLE_STATE_DNS_RESOLVE:
        {
            /* resolution calls dns_resolve_handler */
            memset(&gAddr, 0, sizeof(gAddr));
            gethostbyname(gHost);
            break;
        }

        case EXAMPLE_STATE_BSD_SOCKET:
        {
            int tcpSocket;
            APP_DebugPrintf("Creating socket\r\n");
            tcpSocket = socket(AF_INET, SOCK_STREAM, 1);
            if (tcpSocket < 0) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                return;
            }
            gSock = (SOCKET)tcpSocket;
            APP_DebugPrintf("BSD TCP client: connecting...\r\n");

            g_example_state = EXAMPLE_STATE_BSD_CONNECT;
            break;
        }

        case EXAMPLE_STATE_BSD_CONNECT:
        {
            int addrlen = sizeof(struct sockaddr);
            gAddr.sin_family = AF_INET;
            gAddr.sin_port = _htons(gPort);
            if (connect(gSock, (struct sockaddr*)&gAddr, addrlen) != SOCK_ERR_NO_ERROR) {
                APP_DebugPrintf("WINC1500 WIFI: Failed to connect to %s:%d\r\n", gHost, gPort);
                g_example_state = EXAMPLE_STATE_FINISHED;
                return;
            }
            APP_DebugPrintf("connect() success\r\n");
            g_example_state = EXAMPLE_STATE_WOLFSSL_INIT;
            break;
        }

        case EXAMPLE_STATE_WOLFSSL_INIT:
        {
            APP_DebugPrintf("Initializing wolfSSL\r\n");
            status = wolfCrypt_ATECC_SetConfig(&atecc608_0_init_data);
            if (status == 0) {
                status = wolfSSL_Init();
                if (status != WOLFSSL_SUCCESS) {
                    APP_DebugPrintf("wolfSSL_Init() failed, ret = %d\r\n", status);
                    g_example_state = EXAMPLE_STATE_FINISHED;
                }
                else {
                    /* Uncomment next line to enable debug messages, also need
                     * to recompile wolfSSL with DEBUG_WOLFSSL defined. */
                    /* wolfSSL_Debugging_ON(); */

                    g_example_state = EXAMPLE_STATE_LOAD_CERTS;
                }
            } else {
                APP_DebugPrintf("wolfCrypt_ATECC_SetConfig() failed\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
            }
            break;
        }

        case EXAMPLE_STATE_LOAD_CERTS:
        {
            APP_DebugPrintf("Loading certs/keys\r\n");
            status = tls_build_signer_ca_cert_tlstng();
            if (status != ATCACERT_E_SUCCESS) {
                APP_DebugPrintf("Failed to build server's signer certificate\r\n");
                //g_example_state = EXAMPLE_STATE_FINISHED;
                //break;
            }
            else {
                APP_DebugPrintf("\r\nBuilt server's signer certificate\r\n");
            }

            status = tls_build_end_user_cert_tlstng();
            if (status != ATCACERT_E_SUCCESS) {
                APP_DebugPrintf("Failed to build client certificate\r\n");
                //g_example_state = EXAMPLE_STATE_FINISHED;
                //break;
            }
            else {
                APP_DebugPrintf("\r\nBuilt client certificate\r\n");
            }

            status = tls_setup_client_ctx();
            if (status != SSL_SUCCESS) {
                APP_DebugPrintf("Failed to load wolfSSL!\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            APP_DebugPrintf("\r\nLoaded certs into wolfSSL\r\n");

            /* Create new WOLFSSL session */
            ssl_client = wolfSSL_new(ctx_client);
            if (ssl_client == NULL) {
                APP_DebugPrintf("Unable to create wolfSSL session\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Pass socket descriptor to wolfSSL for I/O */
            wolfSSL_set_fd(ssl_client, gSock);
            APP_DebugPrintf("Registered SOCKET with wolfSSL\r\n");

            g_example_state = EXAMPLE_STATE_DO_HANDSHAKE;
            break;
        }

        case EXAMPLE_STATE_DO_HANDSHAKE:
        {
            status = wolfSSL_connect(ssl_client);
            if (status != WOLFSSL_SUCCESS) {
                int err = wolfSSL_get_error(ssl_client, 0);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* try again */
                    break;
                }
                else {
                    char buffer[80];
                    APP_DebugPrintf("wolfSSL_connect() failed, error = %d: %s\r\n",
                            err, wolfSSL_ERR_error_string(err, buffer));
                    g_example_state = EXAMPLE_STATE_FINISHED;
                    break;
                }
            }
            APP_DebugPrintf("wolfSSL_connect() success!\r\n");

            g_example_state = EXAMPLE_STATE_SEND_HTTP_GET;
            break;
        }

        case EXAMPLE_STATE_SEND_HTTP_GET:
        {
            status = wolfSSL_write(ssl_client, httpGET, sizeof(httpGET));
            if (status <= 0) {
                int err = wolfSSL_get_error(ssl_client, 0);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* try again */
                    break;
                }
                else {
                    char buffer[80];
                    APP_DebugPrintf("wolfSSL_write() failed, error = %d: %s\r\n",
                            err, wolfSSL_ERR_error_string(err, buffer));
                    g_example_state = EXAMPLE_STATE_FINISHED;
                    break;
                }
            }
            APP_DebugPrintf("Sent HTTP GET to peer\r\n");

            g_example_state = EXAMPLE_STATE_RECV_RESPONSE;
            break;
        }

        case EXAMPLE_STATE_RECV_RESPONSE:
        {
            byte reply[80];
            memset(reply, 0, sizeof(reply));

            status = wolfSSL_read(ssl_client, reply, sizeof(reply)-1);
            if (status <= 0) {
                int err = wolfSSL_get_error(ssl_client, 0);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* try again */
                    break;
                }
                else {
                    char buffer[80];
                    APP_DebugPrintf("wolfSSL_read() failed, error = %d: %s\r\n",
                            err, wolfSSL_ERR_error_string(err, buffer));
                    g_example_state = EXAMPLE_STATE_FINISHED;
                    break;
                }
            }
            APP_DebugPrintf("Response from server:\r\n");
            APP_DebugPrintf("----------\r\n");
            APP_DebugPrintf("%s\r\n", reply);
            APP_DebugPrintf("----------\r\n");

            g_example_state = EXAMPLE_STATE_SHUTDOWN;
            break;
        }

        case EXAMPLE_STATE_SHUTDOWN:
        {
            if (ssl_client != NULL) {
                wolfSSL_shutdown(ssl_client);
                wolfSSL_free(ssl_client);
                ssl_client = NULL;
                APP_DebugPrintf("Shutdown and freed WOLFSSL session\r\n");
            }
            if (ctx_client != NULL) {
                wolfSSL_CTX_free(ctx_client);
                ctx_client = NULL;
                APP_DebugPrintf("Freed WOLFSSL_CTX\r\n");
            }
            shutdown(gSock);
            gSock = -1;
            APP_DebugPrintf("\r\nConnection Closed\r\n");

            g_example_state = EXAMPLE_STATE_FINISHED;
            break;
        }

        case EXAMPLE_STATE_FINISHED:
        {
            if (atecc_initialized == 1) {
                atcab_release();
                atecc_initialized = 0;
                APP_DebugPrintf("Released ECC608\r\n");
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
