/* MQTT Azure Demo for SAMD21, WINC1510 and ATECC */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifdef WOLFMQTT_USER_SETTINGS
#include <stdarg.h>
#include <stdio.h>

#include <wolfmqtt/mqtt_client.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/port/atmel/atmel.h>

/* force inclusion of 256-bit test certs and keys */
#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256
#include <wolfssl/certs_test.h>

#include "app.h"
#include "wdrv_winc_client_api.h"
#include "cryptoauthlib.h"
#include "tng/tng_atcacert_client.h"


/* Configuration */
/* TODO: Use your AP and TLS server */
#define WLAN_AUTH_WPA_PSK
#ifndef WLAN_SSID
#define WLAN_SSID           "YOUR_SSID"
#endif
#ifndef WLAN_PSK
#define WLAN_PSK            "YOUR_PSK"
#endif
#define WIFI_MAX_BUFFER_SIZE 1460

/* Azure Configuration */
/* Reference:
 * https://azure.microsoft.com/en-us/documentation/articles/iot-hub-mqtt-support
 * https://azure.microsoft.com/en-us/documentation/articles/iot-hub-devguide/#mqtt-support
 * https://azure.microsoft.com/en-us/documentation/articles/iot-hub-sas-tokens/#using-sas-tokens-as-a-device
 * https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-mqtt-support
 */
#define MAX_BUFFER_SIZE         1024    /* Maximum size for network read/write callbacks */
#define AZURE_API_VERSION       "?api-version=2018-06-30"
#define AZURE_HOST              "momuno-V2-hub.azure-devices.net"
#define AZURE_DEVICE_ID         "sas-test-wolfssl-websocket"
#define AZURE_KEY               "m+DX8elHtsG3CWHPyeUyLeONpqYSA5SuPX/0SkPFQbs=" /* Base64 Encoded */
#define AZURE_QOS               MQTT_QOS_1 /* Azure IoT Hub does not yet support QoS level 2 */
#define AZURE_CON_TIMEOUT_MS    5000
#define AZURE_KEEP_ALIVE_SEC    60
#define AZURE_CMD_TIMEOUT_MS    30000
#define AZURE_TOKEN_EXPIRY_SEC  (60 * 60 * 1) /* 1 hour */
#define AZURE_TOKEN_SIZE        400
#define PRINT_BUFFER_SIZE       80

#define AZURE_DEVICE_NAME       AZURE_HOST "/devices/" AZURE_DEVICE_ID
#define AZURE_USERNAME          AZURE_HOST "/" AZURE_DEVICE_ID "/" AZURE_API_VERSION
#define AZURE_SIG_FMT           "%s\n%ld"
    /* [device name (URL Encoded)]\n[Expiration sec UTC] */
#define AZURE_PASSWORD_FMT      "SharedAccessSignature sr=%s&sig=%s&se=%ld"
    /* sr=[device name (URL Encoded)]
       sig=[HMAC-SHA256 of AZURE_SIG_FMT using AZURE_KEY (URL Encoded)]
       se=[Expiration sec UTC] */

#define AZURE_MSGS_TOPIC_NAME   "devices/" AZURE_DEVICE_ID "/messages/devicebound/#" /* subscribe */
#define AZURE_EVENT_TOPIC       "devices/" AZURE_DEVICE_ID "/messages/events/" /* publish */

#define USE_DIGIROOT_CA
#ifdef USE_DIGIROOT_CA
/* DigiCert Global Root G3 */
uint8_t kDigiCertRootG3[] = {
0x30, 0x82, 0x02, 0x3F, 0x30, 0x82, 0x01, 0xC5, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x05, 0x55, 0x56, 0xBC, 0xF2, 
0x5E, 0xA4, 0x35, 0x35, 0xC3, 0xA4, 0x0F, 0xD5, 0xAB, 0x45, 0x72, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 
0x04, 0x03, 0x03, 0x30, 0x61, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 
0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6E, 
0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 
0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x17, 0x44, 
0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 
0x47, 0x33, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x33, 0x30, 0x38, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 
0x0D, 0x33, 0x38, 0x30, 0x31, 0x31, 0x35, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x61, 0x31, 0x0B, 0x30, 0x09, 
0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C, 
0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6E, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 
0x0B, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 
0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x17, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x47, 
0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x47, 0x33, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 
0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xDD, 0xA7, 0xD9, 
0xBB, 0x8A, 0xB8, 0x0B, 0xFB, 0x0B, 0x7F, 0x21, 0xD2, 0xF0, 0xBE, 0xBE, 0x73, 0xF3, 0x33, 0x5D, 0x1A, 0xBC, 0x34, 0xEA, 
0xDE, 0xC6, 0x9B, 0xBC, 0xD0, 0x95, 0xF6, 0xF0, 0xCC, 0xD0, 0x0B, 0xBA, 0x61, 0x5B, 0x51, 0x46, 0x7E, 0x9E, 0x2D, 0x9F, 
0xEE, 0x8E, 0x63, 0x0C, 0x17, 0xEC, 0x07, 0x70, 0xF5, 0xCF, 0x84, 0x2E, 0x40, 0x83, 0x9C, 0xE8, 0x3F, 0x41, 0x6D, 0x3B, 
0xAD, 0xD3, 0xA4, 0x14, 0x59, 0x36, 0x78, 0x9D, 0x03, 0x43, 0xEE, 0x10, 0x13, 0x6C, 0x72, 0xDE, 0xAE, 0x88, 0xA7, 0xA1, 
0x6B, 0xB5, 0x43, 0xCE, 0x67, 0xDC, 0x23, 0xFF, 0x03, 0x1C, 0xA3, 0xE2, 0x3E, 0xA3, 0x42, 0x30, 0x40, 0x30, 0x0F, 0x06, 
0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 
0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 
0x14, 0xB3, 0xDB, 0x48, 0xA4, 0xF9, 0xA1, 0xC5, 0xD8, 0xAE, 0x36, 0x41, 0xCC, 0x11, 0x63, 0x69, 0x62, 0x29, 0xBC, 0x4B, 
0xC6, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 
0x00, 0xAD, 0xBC, 0xF2, 0x6C, 0x3F, 0x12, 0x4A, 0xD1, 0x2D, 0x39, 0xC3, 0x0A, 0x09, 0x97, 0x73, 0xF4, 0x88, 0x36, 0x8C, 
0x88, 0x27, 0xBB, 0xE6, 0x88, 0x8D, 0x50, 0x85, 0xA7, 0x63, 0xF9, 0x9E, 0x32, 0xDE, 0x66, 0x93, 0x0F, 0xF1, 0xCC, 0xB1, 
0x09, 0x8F, 0xDD, 0x6C, 0xAB, 0xFA, 0x6B, 0x7F, 0xA0, 0x02, 0x30, 0x39, 0x66, 0x5B, 0xC2, 0x64, 0x8D, 0xB8, 0x9E, 0x50, 
0xDC, 0xA8, 0xD5, 0x49, 0xA2, 0xED, 0xC7, 0xDC, 0xD1, 0x49, 0x7F, 0x17, 0x01, 0xB8, 0xC8, 0x86, 0x8F, 0x4E, 0x8C, 0x88, 
0x2B, 0xA8, 0x9A, 0xA9, 0x8A, 0xC5, 0xD1, 0x00, 0xBD, 0xF8, 0x54, 0xE2, 0x9A, 0xE5, 0x5B, 0x7C, 0xB3, 0x27, 0x17
};
#endif

/* MQTT Example Application states */
typedef enum
{
    EXAMPLE_STATE_EXAMPLE_INIT=0,
    EXAMPLE_STATE_WOLFSSL_INIT,
    EXAMPLE_STATE_NET_INIT,
    EXAMPLE_STATE_MQTT_INIT,
    EXAMPLE_STATE_WIFI_CONNECT,
    EXAMPLE_STATE_WIFI_CONNECTING,
    EXAMPLE_STATE_WIFI_CONNECTED,
    EXAMPLE_STATE_GOT_IP,
    EXAMPLE_STATE_NTP_WAIT,
    EXAMPLE_STATE_SAS_TOKEN,
    EXAMPLE_STATE_NET_CONN,
    EXAMPLE_STATE_MQTT_CONN,
    EXAMPLE_STATE_MQTT_SUB,
    EXAMPLE_STATE_MQTT_PUB,
    EXAMPLE_STATE_MQTT_WAIT,
    EXAMPLE_STATE_MQTT_DIS,
    EXAMPLE_STATE_NET_DIS,
    EXAMPLE_STATE_FINISHED,
    EXAMPLE_STATE_WAIT,
} EXAMPLE_STATE;
static EXAMPLE_STATE g_example_state = EXAMPLE_STATE_EXAMPLE_INIT;

/* MQTT Client context */
typedef struct _MQTTCtx {
    /* client and net containers */
    MqttClient client;
    MqttNet net;

    /* temp mqtt containers */
    MqttConnect connect;
    MqttMessage lwt_msg;
    MqttSubscribe subscribe;
    MqttUnsubscribe unsubscribe;
    MqttTopic topics[1];
    MqttPublish publish;
    MqttDisconnect disconnect;

    /* configuration */
    MqttQoS qos;
    const char* app_name;
    const char* host;
    const char* username;
    const char* password;
    const char* topic_name;
    const char* message;
    const char* pub_file;
    const char* client_id;
    byte *tx_buf, *rx_buf;
    int return_code;
    int use_tls;
    int retain;
    int enable_lwt;
    word32 cmd_timeout_ms;
    word32  start_sec; /* used for keep-alive */
    word16 keep_alive_sec;
    word16 port;
    byte clean_session;
    volatile word16 packetIdLast;

    char sasToken[AZURE_TOKEN_SIZE];
} MQTTCtx;

typedef enum {

    EXAMPLE_STATE_DNS_RESOLVE,
    EXAMPLE_STATE_DNS_RESOLVING,
    EXAMPLE_STATE_DNS_RESOLVED,
    EXAMPLE_STATE_BSD_SOCKET,
    EXAMPLE_STATE_BSD_CONNECT,
    EXAMPLE_STATE_BSD_CONNECTING,
    EXAMPLE_STATE_BSD_CONNECTED
} SOCKET_STATE;


typedef struct _SocketContext {
    SOCKET_STATE state;
    int fd;
    struct sockaddr_in addr;
    uint8_t socketBuf[WIFI_MAX_BUFFER_SIZE];
    MQTTCtx* mqttCtx;

    /* Reader buffer markers */
    int bufRemain;
    int bufPos;     /* Position */
    int8_t s8Error;
} SocketContext;

#undef  PRINTF
#define PRINTF(_f_, ...)  printf( (_f_ "\r\n"), ##__VA_ARGS__)

/* Locals */
static WDRV_WINC_AUTH_CONTEXT authCtx;
static WDRV_WINC_BSS_CONTEXT bssCtx;

extern ATCAIfaceCfg atecc608_0_init_data;
static uint8_t gRTCSet = 0;

static SocketContext* gSockCtx;
static DRV_HANDLE gCurDrvHandle;

/* Encoding Support */
static char mRfc3986[256] = {0};
//static char mHtml5[256] = {0};
static void url_encoder_init(void)
{
    int i;
    for (i = 0; i < 256; i++){
        mRfc3986[i] = XISALNUM( i) || i == '~' || i == '-' || i == '.' || i == '_' ? i : 0;
        //mHtml5[i] = XISALNUM( i) || i == '*' || i == '-' || i == '.' || i == '_' ? i : (i == ' ') ? '+' : 0;
    }
}

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

static void dns_resolve_handler(uint8_t *pu8DomainName, uint32_t u32ServerIP)
{
    if (u32ServerIP != 0 && gSockCtx) {
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

        if (newIP != gSockCtx->addr.sin_addr.s_addr) {
            PRINTF("WINC1500 WIFI: DNS lookup:"
                            "  Host:       %s"
                            "  IP Address: %u.%u.%u.%u",
                    (char*)pu8DomainName, 
                    host_ip_address[0], host_ip_address[1],
                    host_ip_address[2], host_ip_address[3]);
        }
        gSockCtx->addr.sin_addr.s_addr = newIP;
        gSockCtx->state = EXAMPLE_STATE_DNS_RESOLVED;
    }
    else {
        /* An error has occurred */
        PRINTF("WINC1500 DNS lookup failed.");
        g_example_state = EXAMPLE_STATE_FINISHED;
    }
}

static void APP_ExampleDHCPAddressEventCallback(DRV_HANDLE handle, uint32_t ipAddress)
{
    char s[20];
    PRINTF("IP address is %s", inet_ntop(AF_INET, &ipAddress, s, sizeof(s)));
    g_example_state = EXAMPLE_STATE_GOT_IP;
}

static void APP_ExampleGetSystemTimeEventCallback(DRV_HANDLE handle, uint32_t time)
{
    if (WDRV_WINC_IPLinkActive(handle)) {
        PRINTF("Time %u", (unsigned int)time);
        RTC_Timer32CounterSet(time);
        RTC_Timer32Start();
        gRTCSet = 1;
    }
}

static void wifi_callback_handler(DRV_HANDLE handle,
    WDRV_WINC_ASSOC_HANDLE assocHandle,
    WDRV_WINC_CONN_STATE currentState,
    WDRV_WINC_CONN_ERROR errorCode)
{
    if (currentState == WDRV_WINC_CONN_STATE_CONNECTED) {
        PRINTF("Wifi Connected");
        g_example_state = EXAMPLE_STATE_WIFI_CONNECTED;
    }
    else if (currentState == WDRV_WINC_CONN_STATE_DISCONNECTED) {
        if (g_example_state == EXAMPLE_STATE_WIFI_CONNECTING) {
            PRINTF("Failed to connect");
            g_example_state = EXAMPLE_STATE_FINISHED;
        }
        else {
            PRINTF("Wifi Disconnected");
            g_example_state = EXAMPLE_STATE_WIFI_CONNECTED;

        }
    }
    else {
        PRINTF("WINC1500 WIFI: Unknown connection status: %d",
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
                PRINTF("SOCKET_MSG_CONNECT error %d", 
                    socket_connect_message->s8Error);
                
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            else {
                ENABLE_SOCKET_STATUS(SOCKET_STATUS_CONNECT);
            }
        }
        gSockCtx->state = EXAMPLE_STATE_BSD_CONNECTED;
        break;
    }
    case SOCKET_MSG_RECV:
    case SOCKET_MSG_RECVFROM:
    {
        tstrSocketRecvMsg *socket_receive_message = (tstrSocketRecvMsg*)pMessage;;
        if (socket_receive_message && socket_receive_message->s16BufferSize > 0) {
            if (gSockCtx)
                gSockCtx->bufRemain = socket_receive_message->s16BufferSize;
            PRINTF("WINC Recv: %d bytes", socket_receive_message->s16BufferSize);
        }
        else {
            if (gSockCtx)
                gSockCtx->s8Error = SOCK_ERR_TIMEOUT;
            PRINTF("WINC Recv Error");
        }
        ENABLE_SOCKET_STATUS(SOCKET_STATUS_RECEIVE);
        break;
    }
    case SOCKET_MSG_SEND:
    {
        tstrSocketConnectMsg *socket_send_message = (tstrSocketConnectMsg*)pMessage;
        if (socket_send_message && socket_send_message->s8Error != SOCK_ERR_NO_ERROR) {
            if (gSockCtx)
                gSockCtx->s8Error = socket_send_message->s8Error;
            PRINTF("WINC Send: %d", socket_send_message->s8Error);
        }
        ENABLE_SOCKET_STATUS(SOCKET_STATUS_SEND);
        break;
    }
    default:
        PRINTF("%s: unhandled message %d", __FUNCTION__, (int)messageType);
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
        PRINTF("Failed to get max signer cert size");
        return ret;
    }

    if (maxCertSz > atcert.signer_ca_size) {
        PRINTF("Signer CA cert buffer too small, need to increase: max = %d", maxCertSz);
        return -1;
    }

    ret = tng_atcacert_read_signer_cert(atcert.signer_ca,
            (size_t*)&atcert.signer_ca_size);
    if (ret != ATCACERT_E_SUCCESS) {
        PRINTF("Failed to read signer cert! %x", ret);
        return ret;
    }
    else {
        PRINTF("Successfully read signer cert");
        //atcab_printbin_label("Signer Certificate",
        //        atcert.signer_ca, atcert.signer_ca_size);
    }

    /* read signer public key from ATECC module */
    ret = tng_atcacert_signer_public_key(atcert.signer_ca_pubkey,
            atcert.signer_ca);
    if (ret != ATCACERT_E_SUCCESS) {
        PRINTF("Failed to read signer public key! %d", ret);
        return ret;
    }
    else {
        PRINTF("Successfully read signer pub key");
        //atcab_printbin_label("Signer Public Key",
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
        PRINTF("Failed to get max device cert size");
        return ret;
    }

    if (maxCertSz > atcert.end_user_size) {
        PRINTF("Device cert buffer too small, please increase, max = %d",
                  maxCertSz);
        return -1;
    }

    ret = tng_atcacert_read_device_cert(atcert.end_user,
            (size_t*)&atcert.end_user_size, NULL);
    if (ret != ATCACERT_E_SUCCESS) {
        PRINTF("Failed to read device cert!");
        return ret;
    }
    else {
        PRINTF("Successfully read device cert");
        //atcab_printbin_label("End User Certificate",
        //        atcert.end_user, atcert.end_user_size);
    }

    ret = tng_atcacert_device_public_key(atcert.end_user_pubkey,
            atcert.end_user);
    if (ret != ATCACERT_E_SUCCESS) {
        PRINTF("Failed to end user public key!");
        return ret;
    }
    else {
        PRINTF("Successfully read device pub key");
        //atcab_printbin_label("End User Public Key",
        //        atcert.end_user_pubkey, sizeof(atcert.end_user_pubkey));
    }

    return ret;
}

static char* url_encode(char* table, unsigned char *s, char *enc)
{
    for (; *s; s++){
        if (table[*s]) {
            snprintf(enc, 2, "%c", table[*s]);
        }
        else {
            snprintf(enc, 4, "%%%02x", *s);
        }
        while (*++enc); /* locate end */
    }
    return enc;
}

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;

    (void)mqttCtx;

    if (msg_new) {
        /* Determine min size to dump */
        len = msg->topic_name_len;
        if (len > PRINT_BUFFER_SIZE) {
            len = PRINT_BUFFER_SIZE;
        }
        XMEMCPY(buf, msg->topic_name, len);
        buf[len] = '\0'; /* Make sure its null terminated */

        /* Print incoming message */
        PRINTF("MQTT Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);
    }

    /* Print message payload */
    len = msg->buffer_len;
    if (len > PRINT_BUFFER_SIZE) {
        len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->buffer, len);
    buf[len] = '\0'; /* Make sure its null terminated */
    PRINTF("Payload (%d - %d): %s",
        msg->buffer_pos, msg->buffer_pos + len, buf);

    if (msg_done) {
        PRINTF("MQTT Message: Done");
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

static int SasTokenCreate(char* sasToken, int sasTokenLen)
{
    int rc;
    const char* encodedKey = AZURE_KEY;
    byte decodedKey[WC_SHA256_DIGEST_SIZE+1];
    word32 decodedKeyLen = (word32)sizeof(decodedKey);
    char deviceName[150]; /* uri */
    char sigData[200]; /* max uri + expiration */
    byte sig[WC_SHA256_DIGEST_SIZE];
    byte base64Sig[WC_SHA256_DIGEST_SIZE*2];
    word32 base64SigLen = (word32)sizeof(base64Sig);
    byte encodedSig[WC_SHA256_DIGEST_SIZE*4];
    long lTime;
    Hmac hmac;

    if (sasToken == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode Key */
    rc = Base64_Decode((const byte*)encodedKey, (word32)XSTRLEN(encodedKey), decodedKey, &decodedKeyLen);
    if (rc != 0) {
        PRINTF("SasTokenCreate: Decode shared access key failed! %d", rc);
        return rc;
    }

    /* Get time */
    rc = wc_GetTime(&lTime, (word32)sizeof(lTime));
    if (rc != 0) {
        PRINTF("SasTokenCreate: Unable to get time! %d", rc);
        return rc;
    }
    lTime += AZURE_TOKEN_EXPIRY_SEC;

    /* URL encode uri (device name) */
    url_encode(mRfc3986, (byte*)AZURE_DEVICE_NAME, deviceName);

    /* Build signature sting "uri \n expiration" */
    snprintf(sigData, sizeof(sigData), AZURE_SIG_FMT, deviceName, lTime);

    /* HMAC-SHA256 Hash sigData using decoded key */
    rc = wc_HmacSetKey(&hmac, WC_SHA256, decodedKey, decodedKeyLen);
    if (rc < 0) {
        PRINTF("SasTokenCreate: Hmac setkey failed! %d", rc);
        return rc;
    }
    rc = wc_HmacUpdate(&hmac, (byte*)sigData, (word32)XSTRLEN(sigData));
    if (rc < 0) {
        PRINTF("SasTokenCreate: Hmac update failed! %d", rc);
        return rc;
    }
    rc = wc_HmacFinal(&hmac, sig);
    if (rc < 0) {
        PRINTF("SasTokenCreate: Hmac final failed! %d", rc);
        return rc;
    }

    /* Base64 encode signature */
    memset(base64Sig, 0, base64SigLen);
    rc = Base64_Encode_NoNl(sig, sizeof(sig), base64Sig, &base64SigLen);
    if (rc < 0) {
        PRINTF("SasTokenCreate: Encoding sig failed! %d", rc);
        return rc;
    }

    /* URL encode signature */
    url_encode(mRfc3986, base64Sig, (char*)encodedSig);

    /* Build sasToken */
    snprintf(sasToken, sasTokenLen, AZURE_PASSWORD_FMT, deviceName, encodedSig, lTime);
    PRINTF("%s", sasToken);

    return 0;
}

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    int rc = MQTT_CODE_CONTINUE;
    SocketContext* sockCtx = (SocketContext*)context;

    switch ( sockCtx->state ) {
        case EXAMPLE_STATE_DNS_RESOLVE:
            memset(sockCtx, 0, sizeof(SocketContext));
            /* resolution calls dns_resolve_handler */
            PRINTF("DNS Lookup %s", host);
            gethostbyname(host);
            sockCtx->state = EXAMPLE_STATE_DNS_RESOLVING;
            break;
        case EXAMPLE_STATE_DNS_RESOLVING:
            /* Waiting for DNS resolution */
            break;
        case EXAMPLE_STATE_DNS_RESOLVED:
            sockCtx->state = EXAMPLE_STATE_BSD_SOCKET;
            break;
        case EXAMPLE_STATE_BSD_SOCKET:
        {
            int tcpSocket;
            PRINTF("Creating socket");
            tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (tcpSocket < 0) {
                PRINTF("Error creating socket! %d", tcpSocket);
                return MQTT_CODE_ERROR_NETWORK;
            }
            sockCtx->fd = tcpSocket;
            sockCtx->state = EXAMPLE_STATE_BSD_CONNECT;
            break;
        }
        case EXAMPLE_STATE_BSD_CONNECT:
        {
            int addrlen = sizeof(struct sockaddr);
            PRINTF("TCP client: connecting...");
            sockCtx->addr.sin_family = AF_INET;
            sockCtx->addr.sin_port = _htons(port);
            if (connect(sockCtx->fd, (struct sockaddr*)&sockCtx->addr, addrlen) != SOCK_ERR_NO_ERROR) {
                return MQTT_CODE_ERROR_NETWORK;
            }
            sockCtx->state = EXAMPLE_STATE_BSD_CONNECTING;
            break;
        }
        case EXAMPLE_STATE_BSD_CONNECTING:
            /* waiting for TCP connect */
            break;
        case EXAMPLE_STATE_BSD_CONNECTED:
            PRINTF("connect() success");
            rc = MQTT_CODE_SUCCESS;
            break;
    }
    return rc;
}

static int NetRead(void *context, byte* buf, int sz,
    int timeout_ms)
{
    SocketContext *sockCtx = (SocketContext*)context;
    int recvd = 0;

    /* If nothing in the buffer then do read */
    if (sockCtx->bufRemain <= 0) {
        sockCtx->s8Error = SOCK_ERR_NO_ERROR;
	    recvd = (int)recv(sockCtx->fd, sockCtx->socketBuf, sizeof(sockCtx->socketBuf), 0);
        if (recvd == SOCK_ERR_TIMEOUT) {
            return MQTT_CODE_CONTINUE;
        }
        else if (recvd != SOCK_ERR_NO_ERROR) {
            return MQTT_CODE_ERROR_NETWORK;
        }
        sockCtx->bufPos = 0;
        sockCtx->bufRemain = sz;

        /* wait for WINC event */
    	while (!GET_SOCKET_STATUS(SOCKET_STATUS_RECEIVE)) {
    		m2m_wifi_handle_events();
    	}
    	DISABLE_SOCKET_STATUS(SOCKET_STATUS_RECEIVE);

        /* Wifi socket recv callback populates sockCtx->bufRemain */
	}
    recvd = sockCtx->bufRemain;
	if (recvd > sz) {
	    recvd = sz;
	}

    if (sockCtx->s8Error != SOCK_ERR_NO_ERROR) {
        recvd = MQTT_CODE_ERROR_NETWORK;
    }
    else {
        memcpy(buf, &sockCtx->socketBuf[sockCtx->bufPos], recvd);
        sockCtx->bufPos += recvd;
        sockCtx->bufRemain -= recvd;
    }

    PRINTF("Recv: %p (%d): recvd %d, remain %d", buf, sz, recvd, sockCtx->bufRemain);

    return recvd;
}

static int NetWrite(void *context, const byte* buf, int sz,
    int timeout_ms)
{
    SocketContext *sockCtx = (SocketContext*)context;
    int sent;

    sockCtx->s8Error = SOCK_ERR_NO_ERROR;
    sent = send(sockCtx->fd, (byte*)buf, sz, 0);

    /* wait for WINC event */
    while (!GET_SOCKET_STATUS(SOCKET_STATUS_SEND)) {
		m2m_wifi_handle_events();
	}
	DISABLE_SOCKET_STATUS(SOCKET_STATUS_SEND);
    
    PRINTF("Send: %p (%d): Res %d", buf, sz, sent);

    if (sent == SOCK_ERR_TIMEOUT) {
        return MQTT_CODE_CONTINUE;
    }
    else if (sent != SOCK_ERR_NO_ERROR && sockCtx->s8Error != SOCK_ERR_NO_ERROR) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    else {
        sent = sz;
    }
    return sent;
}

static int NetDisconnect(void *context)
{
    SocketContext *sockCtx = (SocketContext*)context;
    if (sockCtx) {
        if (sockCtx->fd >= 0) {
            shutdown(sockCtx->fd);
            sockCtx->fd = -1;
            memset(sockCtx, 0, sizeof(SocketContext));

            PRINTF("Connection Closed");
        }
    }
    return MQTT_CODE_SUCCESS;
}


int MqttClientNet_Init(MqttNet* net, MQTTCtx* mqttCtx)
{
    int8_t status;

    if (net) {
        memset(net, 0, sizeof(MqttNet));
        net->connect = NetConnect;
        net->read = NetRead;
        net->write = NetWrite;
        net->disconnect = NetDisconnect;

        gSockCtx = (SocketContext*)WOLFMQTT_MALLOC(sizeof(SocketContext));
        if (gSockCtx == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        net->context = gSockCtx;
        memset(gSockCtx, 0, sizeof(SocketContext));
        gSockCtx->fd = -1;
        gSockCtx->mqttCtx = mqttCtx;

        /* Enable use of DHCP for network configuration, DHCP is the default
            but this also registers the callback for notifications. */
        if ((status = WDRV_WINC_IPUseDHCPSet(gCurDrvHandle, &APP_ExampleDHCPAddressEventCallback)) != WDRV_WINC_STATUS_OK) {
            return MQTT_CODE_ERROR_NETWORK;
        }

        /* Initialize the BSS context to use default values. */
        if ((status = WDRV_WINC_BSSCtxSetDefaults(&bssCtx)) != WDRV_WINC_STATUS_OK) {
            return MQTT_CODE_ERROR_NETWORK;
        }

        /* Update BSS context with target SSID for connection. */
        if ((status = WDRV_WINC_BSSCtxSetSSID(&bssCtx, (uint8_t*)WLAN_SSID, strlen(WLAN_SSID))) != WDRV_WINC_STATUS_OK) {
            return MQTT_CODE_ERROR_NETWORK;
        }

        /*Initialize the authentication context for WPA. */
        if ((status = WDRV_WINC_AuthCtxSetWPA(&authCtx, (uint8_t*)WLAN_PSK, strlen(WLAN_PSK))) != WDRV_WINC_STATUS_OK) {
            return MQTT_CODE_ERROR_NETWORK;
        }

        /* Initialize the system time callback handler. */
        if ((status = WDRV_WINC_SystemTimeGetCurrent(gCurDrvHandle, &APP_ExampleGetSystemTimeEventCallback)) != WDRV_WINC_STATUS_OK) {
            return MQTT_CODE_ERROR_NETWORK;
        }

        /* Register callback handler for DNS resolver . */
        if ((status = WDRV_WINC_SocketRegisterResolverCallback(gCurDrvHandle, &dns_resolve_handler)) != WDRV_WINC_STATUS_OK) {
            return MQTT_CODE_ERROR_NETWORK;
        }

        /* Register callback handler for socket events. */
        if ((status = WDRV_WINC_SocketRegisterEventCallback(gCurDrvHandle, &socket_callback_handler)) != WDRV_WINC_STATUS_OK) {
            return MQTT_CODE_ERROR_NETWORK;
        }
        
    }

    return MQTT_CODE_SUCCESS;
}

int MqttClientNet_DeInit(MqttNet* net)
{
    if (net) {
        if (net->context) {
            WOLFMQTT_FREE(net->context);
        }
        memset(net, 0, sizeof(MqttNet));
        gSockCtx = NULL;

        /* Disconnect from the WINC1500 WIFI */
        m2m_wifi_disconnect();
    }
    return MQTT_CODE_SUCCESS;
}

static int mqtt_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];
    MQTTCtx *mqttCtx = NULL;
    char appName[PRINT_BUFFER_SIZE] = {0};

    if (store->userCtx != NULL) {
        /* The client.ctx was stored during MqttSocket_Connect. */
        mqttCtx = (MQTTCtx *)store->userCtx;
        XSTRNCPY(appName, " for ", PRINT_BUFFER_SIZE-1);
        XSTRNCAT(appName, mqttCtx->app_name,
                PRINT_BUFFER_SIZE-XSTRLEN(appName)-1);
    }

    PRINTF("MQTT TLS Verify Callback%s: PreVerify %d, Error %d (%s)",
            appName, preverify,
            store->error, store->error != 0 ?
                    wolfSSL_ERR_error_string(store->error, buffer) : "none");
    PRINTF("  Subject's domain name is %s", store->domain);

    if (store->error != 0) {
        /* Allowing to continue */
        /* Should check certificate and return 0 if not okay */
        PRINTF("  Allowing cert anyways");
    }

    /* return non-zero value here to override any errors */
    /* typically this would return preverify to keep incoming error */

    return 1;
}

/* Use this callback to setup TLS certificates and verify callbacks */
static int mqtt_tls_cb(MqttClient* client)
{
    int rc = WOLFSSL_FAILURE;
    int status;
#if 0
    byte* clientCertChainDer = NULL;
    word32 clientCertChainDerSz = 0;
#endif

    client->tls.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (client->tls.ctx) {
        /* default to success */
        rc = WOLFSSL_SUCCESS;

#if 0
        PRINTF("Loading certs/keys");
        status = tls_build_signer_ca_cert_tlstng();
        if (status != ATCACERT_E_SUCCESS) {
            PRINTF("Failed to build server's signer certificate");
            return WOLFSSL_FAILURE;
        }
        else {
            PRINTF("Built server's signer certificate");
        }

        status = tls_build_end_user_cert_tlstng();
        if (status != ATCACERT_E_SUCCESS) {
            PRINTF("Failed to build client certificate");
            return WOLFSSL_FAILURE;
        }
        else {
            PRINTF("Built client certificate");
        }
#endif

#ifdef USE_DIGIROOT_CA
        /* Load root CA certificate used to verify peer */
        status = wolfSSL_CTX_load_verify_buffer(client->tls.ctx, kDigiCertRootG3,
                sizeof(kDigiCertRootG3), SSL_FILETYPE_ASN1);
        if (status != WOLFSSL_SUCCESS) {
            PRINTF("Failed to load verification certificate! %d", status);
            return WOLFSSL_FAILURE;
        }
        PRINTF("Loaded verify cert buffer into WOLFSSL_CTX");
#endif

#if 0
        /* Concatenate client cert with intermediate signer cert to send chain,
        * peer will have root CA loaded to verify chain */
        clientCertChainDerSz = atcert.end_user_size + atcert.signer_ca_size;
        clientCertChainDer = (byte*)malloc(clientCertChainDerSz);
        memcpy(clientCertChainDer, atcert.end_user, atcert.end_user_size);
        memcpy(clientCertChainDer + atcert.end_user_size,
            atcert.signer_ca, atcert.signer_ca_size);

        status = wolfSSL_CTX_use_certificate_chain_buffer_format(client->tls.ctx,
                clientCertChainDer, clientCertChainDerSz,
                WOLFSSL_FILETYPE_ASN1);
        if (status != WOLFSSL_SUCCESS) {
            PRINTF("Failed to load client certificate chain! %d", status);
            free(clientCertChainDer);
            return WOLFSSL_FAILURE;
        }
        free(clientCertChainDer);
        PRINTF("Loaded client certificate chain in to WOLFSSL_CTX");

    #if 0
        /* Workaround for TLS mutual authentication */
        /* load dummy private key so wolfSSL knows we want to present a client certificate */
        PRINTF("Loading ECC dummy key");
        /* Private key is on TPM and PK callbacks are used */
        /* TLS client (mutual auth) requires a dummy key loaded (workaround) */
        /* This key is not used because of the registered PK callbacks below */
        status = wolfSSL_CTX_use_PrivateKey_buffer(client->tls.ctx, DUMMY_ECC_KEY, 
            sizeof(DUMMY_ECC_KEY), WOLFSSL_FILETYPE_ASN1);
        if (status != WOLFSSL_SUCCESS) {
            PRINTF("Failed to set key! %d", status);
            return WOLFSSL_FAILURE;
        }
    #endif
#endif
        (void)status;
        
        /* Enable peer verification */
        /* TODO: Enable WOLFSSL_VERIFY_PEER when RAM resources available */
        wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_NONE, 
            mqtt_tls_verify_cb);
        atcatls_set_callbacks(client->tls.ctx);

        /* Use ECDHE-ECDSA cipher suite */
        if (wolfSSL_CTX_set_cipher_list(client->tls.ctx, "ECDHE-ECDSA-AES128-GCM-SHA256") != WOLFSSL_SUCCESS) {
            return WOLFSSL_FAILURE;
        }
    }

    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}

#ifndef MAX_PACKET_ID
#define MAX_PACKET_ID           ((1 << 16) - 1)
#endif
word16 mqtt_get_packetid(MQTTCtx* mqttCtx)
{
    /* Check rollover */
    if (mqttCtx->packetIdLast >= MAX_PACKET_ID) {
        mqttCtx->packetIdLast = 0;
    }

    return ++mqttCtx->packetIdLast;
}

#ifdef DEBUG_WOLFSSL
static void wolfLogCb(const int logLevel, const char *const logMessage)
{
    PRINTF("WOLF %d: %s", logLevel, logMessage);
}
#endif

void APP_ExampleTasks(DRV_HANDLE handle)
{
    int rc, i;
    static MQTTCtx mqttCtx;

    switch ( g_example_state )
    {
        case EXAMPLE_STATE_EXAMPLE_INIT:
        {
            /* init defaults */
            memset(&mqttCtx, 0, sizeof(MQTTCtx));
            mqttCtx.clean_session = 1;
            mqttCtx.app_name = "azureiothub";
            mqttCtx.host = AZURE_HOST;
            mqttCtx.qos = AZURE_QOS;
            mqttCtx.keep_alive_sec = AZURE_KEEP_ALIVE_SEC;
            mqttCtx.client_id = AZURE_DEVICE_ID;
            mqttCtx.topic_name = AZURE_MSGS_TOPIC_NAME;
            mqttCtx.cmd_timeout_ms = AZURE_CMD_TIMEOUT_MS;
            mqttCtx.use_tls = 1;

            PRINTF("");
            PRINTF("===========================");
            PRINTF("AzureIoTHub Client: QoS %d, Use TLS %d", mqttCtx.qos, mqttCtx.use_tls);
            PRINTF("===========================");

            /* setup tx/rx buffers */
            mqttCtx.tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
            mqttCtx.rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
            if (mqttCtx.tx_buf == NULL || mqttCtx.rx_buf == NULL) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* init URL encode */
            url_encoder_init();

            g_example_state = EXAMPLE_STATE_WOLFSSL_INIT;
            break;
        }

        case EXAMPLE_STATE_WOLFSSL_INIT:
        {
            PRINTF("Initializing wolfSSL");
            rc = wolfCrypt_ATECC_SetConfig(&atecc608_0_init_data);
            if (rc == 0) {
                /* this calls atmel_init(), which handles setting up the atca device above */
                rc = wolfSSL_Init();
                if (rc != WOLFSSL_SUCCESS) {
                    PRINTF("wolfSSL_Init() failed, ret = %d", rc);
                    g_example_state = EXAMPLE_STATE_FINISHED;
                    break;
                }
            }
            else {
                PRINTF("wolfCrypt_ATECC_SetConfig() failed");
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

        #ifdef DEBUG_WOLFSSL
            /* Uncomment next line to enable debug messages, also need
             * to recompile wolfSSL with DEBUG_WOLFSSL defined. */
            wolfSSL_SetLoggingCb(wolfLogCb);
            wolfSSL_Debugging_ON();
        #endif

            g_example_state = EXAMPLE_STATE_NET_INIT;
            break;
        }

        case EXAMPLE_STATE_NET_INIT:
        {
            /* Initialize Network */
            gCurDrvHandle = handle;
            rc = MqttClientNet_Init(&mqttCtx.net, &mqttCtx);
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
            PRINTF("MQTT Net Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            g_example_state = EXAMPLE_STATE_MQTT_INIT;
            break;
        }

        case EXAMPLE_STATE_MQTT_INIT:
        {
            /* Initialize MqttClient structure */
            rc = MqttClient_Init(&mqttCtx.client, &mqttCtx.net, mqtt_message_cb,
                mqttCtx.tx_buf, MAX_BUFFER_SIZE, mqttCtx.rx_buf, MAX_BUFFER_SIZE,
                mqttCtx.cmd_timeout_ms);
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
            PRINTF("MQTT Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            mqttCtx.client.ctx = &mqttCtx;

        #ifdef WOLFMQTT_V5
            /* AWS broker only supports v3.1.1 client */
            mqttCtx.client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
        #endif
            g_example_state = EXAMPLE_STATE_WIFI_CONNECT;
            break;
        }
        case EXAMPLE_STATE_WIFI_CONNECT:
            /* Connect to the target BSS with the chosen authentication. */
            if (WDRV_WINC_STATUS_OK == WDRV_WINC_BSSConnect(gCurDrvHandle, &bssCtx, &authCtx, &wifi_callback_handler)) {
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
            PRINTF("Waiting for network time sync");
            g_example_state = EXAMPLE_STATE_NTP_WAIT;
            break;

        case EXAMPLE_STATE_NTP_WAIT:
            /* waiting for network time to be set via APP_ExampleGetSystemTimeEventCallback */
            /* check if RTC is enabled and running */
            if (gRTCSet) {
                g_example_state = EXAMPLE_STATE_SAS_TOKEN;
            }
            break;

        case EXAMPLE_STATE_SAS_TOKEN:
            /* build sas token for password - uses time, so do after NTP wait */
            rc = SasTokenCreate(mqttCtx.sasToken, AZURE_TOKEN_SIZE);
            if (rc < 0) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            g_example_state = EXAMPLE_STATE_NET_CONN;
            break;

        case EXAMPLE_STATE_NET_CONN:
            /* Connect to broker */
            rc = MqttClient_NetConnect(&mqttCtx.client, mqttCtx.host, mqttCtx.port,
                AZURE_CON_TIMEOUT_MS, mqttCtx.use_tls, mqtt_tls_cb);
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
            PRINTF("MQTT Socket Connect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Build connect packet */
            memset(&mqttCtx.connect, 0, sizeof(MqttConnect));
            mqttCtx.connect.keep_alive_sec = mqttCtx.keep_alive_sec;
            mqttCtx.connect.clean_session = mqttCtx.clean_session;
            mqttCtx.connect.client_id = mqttCtx.client_id;

            /* Last will and testament sent by broker to subscribers
                of topic when broker connection is lost */
            memset(&mqttCtx.lwt_msg, 0, sizeof(mqttCtx.lwt_msg));
            mqttCtx.connect.lwt_msg = &mqttCtx.lwt_msg;
            mqttCtx.connect.enable_lwt = mqttCtx.enable_lwt;
            if (mqttCtx.enable_lwt) {
                /* Send client id in LWT payload */
                mqttCtx.lwt_msg.qos = mqttCtx.qos;
                mqttCtx.lwt_msg.retain = 0;
                mqttCtx.lwt_msg.topic_name = AZURE_EVENT_TOPIC"lwttopic";
                mqttCtx.lwt_msg.buffer = (byte*)mqttCtx.client_id;
                mqttCtx.lwt_msg.total_len = (word16)XSTRLEN(mqttCtx.client_id);
            }

            /* Authentication */
            mqttCtx.connect.username = AZURE_USERNAME;
            mqttCtx.connect.password = mqttCtx.sasToken;

            g_example_state = EXAMPLE_STATE_MQTT_CONN;
            break;

        case EXAMPLE_STATE_MQTT_CONN:
            /* Send Connect and wait for Connect Ack */
            rc = MqttClient_Connect(&mqttCtx.client, &mqttCtx.connect);
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
            PRINTF("MQTT Connect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqttCtx.connect.ack.return_code,
                (mqttCtx.connect.ack.flags &
                    MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            /* Build list of topics */
            mqttCtx.topics[0].topic_filter = mqttCtx.topic_name;
            mqttCtx.topics[0].qos = mqttCtx.qos;

            /* Subscribe Topic */
            memset(&mqttCtx.subscribe, 0, sizeof(MqttSubscribe));
            mqttCtx.subscribe.packet_id = mqtt_get_packetid(&mqttCtx);
            mqttCtx.subscribe.topic_count = sizeof(mqttCtx.topics)/sizeof(MqttTopic);
            mqttCtx.subscribe.topics = mqttCtx.topics;
            g_example_state = EXAMPLE_STATE_MQTT_SUB;
            break;

        case EXAMPLE_STATE_MQTT_SUB:
            rc = MqttClient_Subscribe(&mqttCtx.client, &mqttCtx.subscribe);
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
            PRINTF("MQTT Subscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* show subscribe results */
            for (i = 0; i < mqttCtx.subscribe.topic_count; i++) {
                MqttTopic *topic = &mqttCtx.subscribe.topics[i];
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    topic->topic_filter,
                    topic->qos, topic->return_code);
            }

            /* Publish Topic */
            memset(&mqttCtx.publish, 0, sizeof(MqttPublish));
            mqttCtx.publish.retain = 0;
            mqttCtx.publish.qos = mqttCtx.qos;
            mqttCtx.publish.duplicate = 0;
            mqttCtx.publish.topic_name = AZURE_EVENT_TOPIC;
            mqttCtx.publish.packet_id = mqtt_get_packetid(&mqttCtx);
            mqttCtx.publish.buffer = NULL;
            mqttCtx.publish.total_len = 0;
            g_example_state = EXAMPLE_STATE_MQTT_PUB;
            break;
        
        case EXAMPLE_STATE_MQTT_PUB:
            rc = MqttClient_Publish(&mqttCtx.client, &mqttCtx.publish);
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                mqttCtx.publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }

            /* Read Loop */
            PRINTF("MQTT Waiting for message...");
            g_example_state = EXAMPLE_STATE_MQTT_WAIT;
            break;
        
        case EXAMPLE_STATE_MQTT_WAIT:
            /* Try and read packet */
            rc = MqttClient_WaitMessage(&mqttCtx.client, mqttCtx.cmd_timeout_ms);
             /* check return code */
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
            else if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                /* Keep Alive */
                PRINTF("Keep-alive timeout, sending ping");

                rc = MqttClient_Ping(&mqttCtx.client);
                if (rc == MQTT_CODE_CONTINUE) {
                    break;
                }
                else if (rc != MQTT_CODE_SUCCESS) {
                    PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                        MqttClient_ReturnCodeToString(rc), rc);
                    g_example_state = EXAMPLE_STATE_FINISHED;
                    break;
                }
            }
            else if (rc != MQTT_CODE_SUCCESS) {
                /* There was an error */
                PRINTF("MQTT Message Wait: %s (%d)",
                    MqttClient_ReturnCodeToString(rc), rc);
            }
            g_example_state = EXAMPLE_STATE_MQTT_DIS;
            break;

        case EXAMPLE_STATE_MQTT_DIS:
            /* Disconnect */
            rc = MqttClient_Disconnect(&mqttCtx.client);
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
            PRINTF("MQTT Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                g_example_state = EXAMPLE_STATE_FINISHED;
                break;
            }
            g_example_state = EXAMPLE_STATE_NET_DIS;
            break;

        case EXAMPLE_STATE_NET_DIS:
            rc = MqttClient_NetDisconnect(&mqttCtx.client);
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
            PRINTF("MQTT Socket Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            g_example_state = EXAMPLE_STATE_FINISHED;
            break;

        case EXAMPLE_STATE_FINISHED:
        {            
            /* Free resources */
            if (mqttCtx.tx_buf) WOLFMQTT_FREE(mqttCtx.tx_buf);
            if (mqttCtx.rx_buf) WOLFMQTT_FREE(mqttCtx.rx_buf);

            /* Cleanup network */
            MqttClientNet_DeInit(&mqttCtx.net);
            MqttClient_DeInit(&mqttCtx.client);
            wolfSSL_Cleanup();

            g_example_state = EXAMPLE_STATE_WAIT;
            break;
        }

        case EXAMPLE_STATE_WAIT:
        {
            break;
        }
    }
}

#endif /* WOLFMQTT_USER_SETTINGS */
