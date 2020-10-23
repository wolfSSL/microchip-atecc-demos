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

/* Configuration */
/* TODO: Use your AP and TLS server */
#define WLAN_AUTH_WPA_PSK
#ifndef WLAN_SSID
#define WLAN_SSID           "YOUR_SSID"
#endif
#ifndef WLAN_PSK
#define WLAN_PSK            "YOUR_PSK"
#endif
#ifndef SERVER_HOST
#define SERVER_HOST         "192.168.0.251"
#endif
#ifndef SERVER_PORT
#define SERVER_PORT         11111
#endif
#define WIFI_MAX_BUFFER_SIZE 1460

static struct sockaddr_in gAddr;
static char* gHost = SERVER_HOST;
static uint16_t gPort = SERVER_PORT;

static WOLFSSL*        ssl_client = NULL;
static WOLFSSL_CTX*    ctx_client = NULL;
static WOLFSSL_METHOD* method_client = NULL;
static const char httpGET[] = "GET /index.html HTTP/1.0\r\n\r\n";

static WDRV_WINC_AUTH_CONTEXT authCtx;
static WDRV_WINC_BSS_CONTEXT bssCtx;

extern ATCAIfaceCfg atecc608_0_init_data;
static uint8_t gRTCSet = 0;
static uint8_t gTlsSocketBuf[WIFI_MAX_BUFFER_SIZE];

typedef struct SockCbInfo {
    int sd;         /* Socket */

    /* Reader buffer markers */
    int bufRemain;
    int bufPos;     /* Position */
} SockCbInfo;
static SockCbInfo gIoCtx;

typedef struct t_atcert {
    uint32_t signer_ca_size;
    uint8_t  signer_ca[521];
    uint8_t  signer_ca_pubkey[64];
    uint32_t end_user_size;
    uint8_t  end_user[552];
    uint8_t  end_user_pubkey[64];
} t_atcert;

static t_atcert atcert = {
    .signer_ca_size = 521,
    .signer_ca = { 0 },
    .signer_ca_pubkey = { 0 },
    .end_user_size = 552,
    .end_user = { 0 },
    .end_user_pubkey = { 0 }
};

/* application states */
typedef enum
{
    EXAMPLE_STATE_EXAMPLE_INIT=0,
    EXAMPLE_STATE_NET_INIT,
    EXAMPLE_STATE_WIFI_CONNECT,
    EXAMPLE_STATE_WIFI_CONNECTING,
    EXAMPLE_STATE_WIFI_CONNECTED,
    EXAMPLE_STATE_GOT_IP,
    EXAMPLE_STATE_DNS_RESOLVE,
    EXAMPLE_STATE_DNS_RESOLVING,
    EXAMPLE_STATE_DNS_RESOLVED,
    EXAMPLE_STATE_BSD_SOCKET,
    EXAMPLE_STATE_BSD_CONNECT,
    EXAMPLE_STATE_BSD_CONNECTING,
    EXAMPLE_STATE_BSD_CONNECTED,
    EXAMPLE_STATE_WOLFSSL_INIT,
    EXAMPLE_STATE_NTP_WAIT,
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

#if 0
/* from certs/dummy-ecc.pem (as DER) */
static const unsigned char DUMMY_ECC_KEY[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x05, 0x0F, 0xEA, 0xB6, 0x2C, 0x7C,
    0xD3, 0x3C, 0x66, 0x3D, 0x6B, 0x44, 0xD5, 0x8A, 0xD4, 0x1C, 0xF6, 0x2A, 0x35,
    0x49, 0xB2, 0x36, 0x7D, 0xEC, 0xD4, 0xB3, 0x9A, 0x2B, 0x4F, 0x71, 0xC8, 0xD3,
    0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0xA1,
    0x44, 0x03, 0x42, 0x00, 0x04, 0x43, 0x98, 0xF7, 0x33, 0x77, 0xB4, 0x55, 0x02,
    0xF1, 0xF3, 0x79, 0x97, 0x67, 0xED, 0xB5, 0x3A, 0x7A, 0xE1, 0x7C, 0xC6, 0xA8,
    0x23, 0x8B, 0x3A, 0x68, 0x42, 0xDD, 0x68, 0x4F, 0x48, 0x6F, 0x2D, 0x9A, 0x7C,
    0x47, 0x20, 0x1F, 0x13, 0x69, 0x71, 0x05, 0x42, 0x5B, 0x9F, 0x23, 0x7D, 0xE0,
    0xA6, 0x5D, 0xD4, 0x11, 0x44, 0xB1, 0x91, 0x66, 0x50, 0xC0, 0x2C, 0x8C, 0x71,
    0x35, 0x0E, 0x28, 0xB4
};
#endif

/** Socket Status */
#define	SOCKET_STATUS_BIND					(1 << 0)		/* 00000001 */
#define	SOCKET_STATUS_LISTEN				(1 << 1)		/* 00000010 */
#define	SOCKET_STATUS_ACCEPT				(1 << 2)		/* 00000100 */
#define	SOCKET_STATUS_CONNECT				(1 << 3)		/* 00001000 */
#define	SOCKET_STATUS_RECEIVE				(1 << 4)		/* 00010000 */
#define	SOCKET_STATUS_SEND			    	(1 << 5)		/* 00100000 */
#define	SOCKET_STATUS_RECEIVE_FROM	    	(1 << 6)		/* 01000000 */
#define	SOCKET_STATUS_SEND_TO				(1 << 7)		/* 10000000 */
static uint16_t tls_socket_status;
#define ENABLE_SOCKET_STATUS(index)        		(tls_socket_status |= index)
#define DISABLE_SOCKET_STATUS(index)        	(tls_socket_status &= ~index)
#define GET_SOCKET_STATUS(index)        		(tls_socket_status & index)

/* appease libnano */
int _gettimeofday(struct timeval *tv, void *tzvp)
{
    return 0;
}
/* TIME CODE */
/* TODO: Implement real RTC */
/* Optionally you can define NO_ASN_TIME to disable all cert time checks */
static int hw_get_time_sec(void)
{
    return RTC_Timer32CounterGet();
}

/* This is used by wolfCrypt asn.c for cert time checking */
unsigned long my_time(unsigned long* timer)
{
    (void)timer;
    return hw_get_time_sec();
}

#ifndef WOLFCRYPT_ONLY
/* This is used by TLS only */
unsigned int LowResTimer(void)
{
    return hw_get_time_sec();
}
#endif

#ifndef NO_CRYPT_BENCHMARK
/* This is used by wolfCrypt benchmark tool only */
double current_time(int reset)
{
    double time;
	int timeMs = RTC_Timer32CounterGet();
    (void)reset;
    time = (timeMs / 1000); // sec
    time += (double)(timeMs % 1000) / 1000; // ms
    return time;
}
#endif


static int socket_recv_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    SockCbInfo* info = (SockCbInfo*)ctx;
    int recvd = 0;

    /* If nothing in the buffer then do read */
    if (info->bufRemain <= 0) {
	    recvd = (int)recv(info->sd, gTlsSocketBuf, sizeof(gTlsSocketBuf), 0);
        if (recvd == SOCK_ERR_TIMEOUT) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        else if (recvd != SOCK_ERR_NO_ERROR) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        info->bufPos = 0;
        info->bufRemain = sz;

        /* wait for WINC event */
    	while (!GET_SOCKET_STATUS(SOCKET_STATUS_RECEIVE)) {
    		m2m_wifi_handle_events();
    	}
    	DISABLE_SOCKET_STATUS(SOCKET_STATUS_RECEIVE);
        /* Wifi socket recv callback populates info->bufRemain */
        recvd = sz;
	}
    else {
        recvd = info->bufRemain;
    }
	if (sz > recvd) {
	    sz = recvd;
	}

    memcpy(buf, &gTlsSocketBuf[info->bufPos], sz);
    info->bufPos += sz;
    info->bufRemain -= sz;

    APP_DebugPrintf("Recv: %p (%d): recvd %d, remain %d\r\n", buf, sz, recvd, info->bufRemain);

    return recvd;
}

static int socket_send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    SockCbInfo* info = (SockCbInfo*)ctx;
    int sent;
    sent = send(info->sd, buf, sz, 0);

    /* wait for WINC event */
    while (!GET_SOCKET_STATUS(SOCKET_STATUS_SEND)) {
		m2m_wifi_handle_events();
	}
	DISABLE_SOCKET_STATUS(SOCKET_STATUS_SEND);
    
    APP_DebugPrintf("Send: %p (%d): Res %d\r\n", buf, sz, sent);
    if (sent == SOCK_ERR_TIMEOUT) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    else if (sent != SOCK_ERR_NO_ERROR) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return sz;
}

int tls_setup_client_ctx(void)
{
    int status;
    byte* clientCertChainDer = NULL;
    word32 clientCertChainDerSz = 0;

    method_client = wolfTLSv1_2_client_method();
    if (method_client == NULL) {
        APP_DebugPrintf("Failed to alloc dynamic buffer\r\n");
        return WOLFSSL_FAILURE;
    }
    APP_DebugPrintf("Created wolfTLSv1_2_client_method()\r\n");

    ctx_client = wolfSSL_CTX_new(method_client);
    if (ctx_client == NULL) {
        APP_DebugPrintf("Failed to create wolfSSL context\r\n");
        return WOLFSSL_FAILURE;
    }
    APP_DebugPrintf("Created new WOLFSSL_CTX\r\n");

    /* setup socket IO callbacks */
    wolfSSL_CTX_SetIOSend(ctx_client, socket_send_cb);
    wolfSSL_CTX_SetIORecv(ctx_client, socket_recv_cb);

    /* Load root CA certificate used to verify peer. This buffer is set up to
     * verify the wolfSSL example server. The example server should be started
     * using the <wolfssl_root>/certs/server-ecc.pem certificate and
     * <wolfssl_root>/certs/ecc-key.pem private key. */
    status = wolfSSL_CTX_load_verify_buffer(ctx_client, ca_ecc_cert_der_256,
            sizeof_ca_ecc_cert_der_256, SSL_FILETYPE_ASN1);
    if (status != WOLFSSL_SUCCESS) {
        APP_DebugPrintf("Failed to load verification certificate! %d\r\n", status);
        return WOLFSSL_FAILURE;
    }
    APP_DebugPrintf("Loaded verify cert buffer into WOLFSSL_CTX\r\n");

    /* Concatenate client cert with intermediate signer cert to send chain,
     * peer will have root CA loaded to verify chain */
    clientCertChainDerSz = atcert.end_user_size + atcert.signer_ca_size;
    clientCertChainDer = (byte*)malloc(clientCertChainDerSz);
    memcpy(clientCertChainDer, atcert.end_user, atcert.end_user_size);
    memcpy(clientCertChainDer + atcert.end_user_size,
           atcert.signer_ca, atcert.signer_ca_size);

    status = wolfSSL_CTX_use_certificate_chain_buffer_format(ctx_client,
            clientCertChainDer, clientCertChainDerSz,
            WOLFSSL_FILETYPE_ASN1);
    if (status != WOLFSSL_SUCCESS) {
        APP_DebugPrintf("Failed to load client certificate chain! %d\r\n", status);
        free(clientCertChainDer);
        return WOLFSSL_FAILURE;
    }
    free(clientCertChainDer);
    APP_DebugPrintf("Loaded client certificate chain in to WOLFSSL_CTX\r\n");

#if 0
    /* Workaround for TLS mutual authentication */
    /* load dummy private key so wolfSSL knows we want to present a client certificate */
    APP_DebugPrintf("Loading ECC dummy key\r\n");
    /* Private key is on TPM and PK callbacks are used */
    /* TLS client (mutual auth) requires a dummy key loaded (workaround) */
    /* This key is not used because of the registered PK callbacks below */
    status = wolfSSL_CTX_use_PrivateKey_buffer(ctx_client, DUMMY_ECC_KEY, 
        sizeof(DUMMY_ECC_KEY), WOLFSSL_FILETYPE_ASN1);
    if (status != WOLFSSL_SUCCESS) {
        APP_DebugPrintf("Failed to set key! %d\r\n", status);
        return WOLFSSL_FAILURE;
    }
#endif
    
    /* Enable peer verification */
    wolfSSL_CTX_set_verify(ctx_client, WOLFSSL_VERIFY_PEER, NULL);
    atcatls_set_callbacks(ctx_client);

    /* Use ECDHE-ECDSA cipher suite */
    if (wolfSSL_CTX_set_cipher_list(ctx_client, "ECDHE-ECDSA-AES128-GCM-SHA256") != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}

static void dns_resolve_handler(uint8_t *pu8DomainName, uint32_t u32ServerIP)
{
    if (u32ServerIP != 0) {
        uint32_t newIP;
        uint8_t host_ip_address[4];
        host_ip_address[0] = u32ServerIP & 0xFF;
        host_ip_address[1] = (u32ServerIP >> 8) & 0xFF;
        host_ip_address[2] = (u32ServerIP >> 16) & 0xFF;
        host_ip_address[3] = (u32ServerIP >> 24) & 0xFF;

        newIP = _htonl((uint32_t)((host_ip_address[0] << 24) |
                                  (host_ip_address[1] << 16) |
                                  (host_ip_address[2] << 8)  |
                                   host_ip_address[3]));

        if (newIP != gAddr.sin_addr.s_addr) {
            APP_DebugPrintf("WINC1500 WIFI: DNS lookup:\r\n"
                            "  Host:       %s\r\n"
                            "  IP Address: %u.%u.%u.%u\r\n",
                    (char*)pu8DomainName, 
                    host_ip_address[0], host_ip_address[1],
                    host_ip_address[2], host_ip_address[3]);
        }
        gAddr.sin_addr.s_addr = newIP;
        g_example_state = EXAMPLE_STATE_DNS_RESOLVED;
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
    if (WDRV_WINC_IPLinkActive(handle)) {
        APP_DebugPrintf("Time %u\r\n", time);
        RTC_Timer32CounterSet(time);
        RTC_Timer32Start();
        gRTCSet = 1;
    }
}

static void wifi_callback_handler(DRV_HANDLE handle, WDRV_WINC_CONN_STATE currentState, WDRV_WINC_CONN_ERROR errorCode)
{
    if (currentState == WDRV_WINC_CONN_STATE_CONNECTED) {
        APP_DebugPrintf("Wifi Connected\r\n");
        g_example_state = EXAMPLE_STATE_WIFI_CONNECTED;
    }
    else if (currentState == WDRV_WINC_CONN_STATE_DISCONNECTED) {
        if (g_example_state == EXAMPLE_STATE_WIFI_CONNECTING) {
            APP_DebugPrintf("Failed to connect\r\n");
            g_example_state = EXAMPLE_STATE_DISCONNECT;
        }
        else {
            APP_DebugPrintf("Wifi Disconnected\r\n");
            g_example_state = EXAMPLE_STATE_WIFI_CONNECTED;

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
                DISABLE_SOCKET_STATUS(SOCKET_STATUS_CONNECT);

                /* An error has occurred */
                APP_DebugPrintf("WINC1500 WIFI: Failed to connect to %s:%d\r\n", gHost, gPort);
                APP_DebugPrintf("SOCKET_MSG_CONNECT error %d\r\n", 
                    socket_connect_message->s8Error);
                
                g_example_state = EXAMPLE_STATE_SHUTDOWN;
                break;
            }
            else {
                ENABLE_SOCKET_STATUS(SOCKET_STATUS_CONNECT);
            }
        }
        g_example_state = EXAMPLE_STATE_BSD_CONNECTED;
        break;
    }
    case SOCKET_MSG_RECV:
    case SOCKET_MSG_RECVFROM:
    {
        tstrSocketRecvMsg *socket_receive_message = (tstrSocketRecvMsg*)pMessage;;
        (void)socket_receive_message;
        if (socket_receive_message && socket_receive_message->s16BufferSize > 0) {
            gIoCtx.bufRemain = socket_receive_message->s16BufferSize;
			ENABLE_SOCKET_STATUS(SOCKET_STATUS_RECEIVE);
            APP_DebugPrintf("WINC Recv: %d bytes\r\n", socket_receive_message->s16BufferSize);
        }
        else {
            DISABLE_SOCKET_STATUS(SOCKET_STATUS_RECEIVE);
        }
        break;
    }
    case SOCKET_MSG_SEND:
    {
        tstrSocketConnectMsg *socket_send_message = (tstrSocketConnectMsg*)pMessage;
        if (socket_send_message && socket_send_message->s8Error >= 0) {
            ENABLE_SOCKET_STATUS(SOCKET_STATUS_SEND);
        } else {
            DISABLE_SOCKET_STATUS(SOCKET_STATUS_SEND);
        }
        break;
    }
    default:
        APP_DebugPrintf("%s: unhandled message %d\r\n", __FUNCTION__, (int)messageType);
        break;
    }
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
        return ret;
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
        return ret;
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
        return ret;
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
        return ret;
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

            g_example_state = EXAMPLE_STATE_WIFI_CONNECT;
            break;
        }
        case EXAMPLE_STATE_WIFI_CONNECT:
            /* Connect to the target BSS with the chosen authentication. */
            if (WDRV_WINC_STATUS_OK == WDRV_WINC_BSSConnect(handle, &bssCtx, &authCtx, &wifi_callback_handler)) {
                g_example_state = EXAMPLE_STATE_WIFI_CONNECTING;
            }
            break;
        case EXAMPLE_STATE_WIFI_CONNECTING:
            /* Waiting for AP connect */
            break;
        case EXAMPLE_STATE_WIFI_CONNECTED:
            /* Waiting for IP */
            /* Triggered via APP_ExampleDHCPAddressEventCallback */
            break;

        case EXAMPLE_STATE_GOT_IP:
            g_example_state = EXAMPLE_STATE_DNS_RESOLVE;
            break;

        case EXAMPLE_STATE_DNS_RESOLVE:
            /* resolution calls dns_resolve_handler */
            memset(&gAddr, 0, sizeof(gAddr));
            APP_DebugPrintf("DNS Lookup %s\r\n", gHost);
            gethostbyname(gHost);
            g_example_state = EXAMPLE_STATE_DNS_RESOLVING;
            break;
        case EXAMPLE_STATE_DNS_RESOLVING:
            /* Waiting for DNS resolution */
            break;
        case EXAMPLE_STATE_DNS_RESOLVED:
            g_example_state = EXAMPLE_STATE_BSD_SOCKET;
            break;
        case EXAMPLE_STATE_BSD_SOCKET:
        {
            int tcpSocket;
            APP_DebugPrintf("Creating socket\r\n");
            tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (tcpSocket < 0) {
                APP_DebugPrintf("Error creating socket! %d\r\n", status);
                g_example_state = EXAMPLE_STATE_FINISHED;
                return;
            }
            memset(&gIoCtx, 0, sizeof(gIoCtx));
            gIoCtx.sd = tcpSocket;
            g_example_state = EXAMPLE_STATE_BSD_CONNECT;
            break;
        }
        case EXAMPLE_STATE_BSD_CONNECT:
        {
            int addrlen = sizeof(struct sockaddr);
            APP_DebugPrintf("TCP client: connecting...\r\n");
            gAddr.sin_family = AF_INET;
            gAddr.sin_port = _htons(gPort);
            if (connect(gIoCtx.sd, (struct sockaddr*)&gAddr, addrlen) != SOCK_ERR_NO_ERROR) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                return;
            }
            g_example_state = EXAMPLE_STATE_BSD_CONNECTING;
            break;
        }
        case EXAMPLE_STATE_BSD_CONNECTING:
            /* waiting for TCP connect */
            break;
        case EXAMPLE_STATE_BSD_CONNECTED:
            APP_DebugPrintf("connect() success\r\n");
            g_example_state = EXAMPLE_STATE_WOLFSSL_INIT;
            break;

        case EXAMPLE_STATE_WOLFSSL_INIT:
        {
            APP_DebugPrintf("Initializing wolfSSL\r\n");
            status = wolfCrypt_ATECC_SetConfig(&atecc608_0_init_data);
            if (status == 0) {
                /* this calls atmel_init(), which handles setting up the atca device above */
                status = wolfSSL_Init();
                if (status != WOLFSSL_SUCCESS) {
                    APP_DebugPrintf("wolfSSL_Init() failed, ret = %d\r\n", status);
                    g_example_state = EXAMPLE_STATE_FINISHED;
                    break;
                }
            }
            else {
                APP_DebugPrintf("wolfCrypt_ATECC_SetConfig() failed\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            /* Uncomment next line to enable debug messages, also need
                * to recompile wolfSSL with DEBUG_WOLFSSL defined. */
            /* wolfSSL_Debugging_ON(); */

            g_example_state = EXAMPLE_STATE_NTP_WAIT;
            APP_DebugPrintf("Waiting for time\r\n");
            break;
        }
        
        case EXAMPLE_STATE_NTP_WAIT:
            /* waiting for network time to be set via APP_ExampleGetSystemTimeEventCallback */
            /* check if RTC is enabled and running */
            if (gRTCSet) {
                g_example_state = EXAMPLE_STATE_LOAD_CERTS;
            }
            break;

        case EXAMPLE_STATE_LOAD_CERTS:
        {
            APP_DebugPrintf("Loading certs/keys\r\n");
            status = tls_build_signer_ca_cert_tlstng();
            if (status != ATCACERT_E_SUCCESS) {
                APP_DebugPrintf("Failed to build server's signer certificate\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            else {
                APP_DebugPrintf("\r\nBuilt server's signer certificate\r\n");
            }

            status = tls_build_end_user_cert_tlstng();
            if (status != ATCACERT_E_SUCCESS) {
                APP_DebugPrintf("Failed to build client certificate\r\n");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
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
            wolfSSL_SetIOReadCtx(ssl_client, &gIoCtx);
            wolfSSL_SetIOWriteCtx(ssl_client, &gIoCtx);

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
            shutdown(gIoCtx.sd);
            gIoCtx.sd = -1;
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
