#ifndef TLS_COMMON_H_
#define TLS_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/port/atmel/atmel.h>
#include "common/include/nm_common.h"
#include "driver/include/m2m_wifi.h"
#include "socket/include/socket.h"
#include "atcacert/atcacert_def.h"
#include "cryptoauthlib.h"

/** Wi-Fi Settings */
#define MAIN_WLAN_SSID                    "LynxNetwork"				/**< Destination SSID */
#define MAIN_WLAN_PSK                     "7194880886"			/**< Password for Destination SSID */
//#define MAIN_WLAN_SSID                    "AVRGUEST"				/**< Destination SSID */
//#define MAIN_WLAN_PSK                     "MicroController"			/**< Password for Destination SSID */
#define MAIN_WLAN_AUTH                    M2M_WIFI_SEC_WPA_PSK		/**< Security manner */
#define MAIN_WIFI_M2M_BUFFER_SIZE           (1460)

/* I2C address for device communication */
#define FACTORY_INIT_I2C	(uint8_t)(0xC0)		// Initial I2C address is set to 0xC0 in the factory
//#define DEVICE_I2C		FACTORY_INIT_I2C	// Device I2C Address
#define DEVICE_I2C			(uint8_t)(0xB0)		// Device I2C Address

/** Socket Status */
#define	SOCKET_STATUS_BIND					(1 << 0)		/* 00000001 */
#define	SOCKET_STATUS_LISTEN				(1 << 1)		/* 00000010 */
#define	SOCKET_STATUS_ACCEPT				(1 << 2)		/* 00000100 */
#define	SOCKET_STATUS_CONNECT				(1 << 3)		/* 00001000 */
#define	SOCKET_STATUS_RECEIVE				(1 << 4)		/* 00010000 */
#define	SOCKET_STATUS_SEND			    	(1 << 5)		/* 00100000 */
#define	SOCKET_STATUS_RECEIVE_FROM	    	(1 << 6)		/* 01000000 */
#define	SOCKET_STATUS_SEND_TO				(1 << 7)		/* 10000000 */

/** NTP Socket Status */
#define	NTP_SOCKET_STATUS_BIND				(1 << 0)		/* 00000001 */
#define	NTP_SOCKET_STATUS_LISTEN			(1 << 1)		/* 00000010 */
#define	NTP_SOCKET_STATUS_ACCEPT			(1 << 2)		/* 00000100 */
#define	NTP_SOCKET_STATUS_CONNECT			(1 << 3)		/* 00001000 */
#define	NTP_SOCKET_STATUS_RECEIVE			(1 << 4)		/* 00010000 */
#define	NTP_SOCKET_STATUS_SEND			    (1 << 5)		/* 00100000 */
#define	NTP_SOCKET_STATUS_RECEIVE_FROM	    (1 << 6)		/* 01000000 */
#define	NTP_SOCKET_STATUS_SEND_TO			(1 << 7)		/* 10000000 */

#define MAIN_WORLDWIDE_NTP_POOL_HOSTNAME        "pool.ntp.org"
#define MAIN_SERVER_PORT_FOR_UDP                (123)


extern uint16_t tls_socket_status;
extern uint16_t tls_ntp_socket_status;

#define ENABLE_SOCKET_STATUS(index)        		(tls_socket_status |= index)
#define DISABLE_SOCKET_STATUS(index)        	(tls_socket_status &= ~index)
#define GET_SOCKET_STATUS(index)        		(tls_socket_status & index)

#define ENABLE_NTP_SOCKET_STATUS(index)        	(tls_ntp_socket_status |= index)
#define DISABLE_NTP_SOCKET_STATUS(index)        (tls_ntp_socket_status &= ~index)
#define GET_NTP_SOCKET_STATUS(index)        	(tls_ntp_socket_status & index)

typedef int socklen_t;

typedef struct time_date {
    int tm_sec;     /* seconds after the minute [0-60] */
    int tm_min;     /* minutes after the hour [0-59] */
    int tm_hour;    /* hours since midnight [0-23] */
    int tm_mday;    /* day of the month [1-31] */
    int tm_mon;     /* months since January [0-11] */
    int tm_year;    /* years since 1900 */
    int tm_wday;    /* days since Sunday [0-6] */
    int tm_yday;    /* days since January 1 [0-365] */
    int tm_isdst;   /* Daylight Savings Time flag */
    long    tm_gmtoff;  /* offset from CUT in seconds */
    char    *tm_zone;   /* timezone abbreviation */
} t_time_date;

typedef struct SockCbInfo {
    int sd;         /* Socket */

    /* Reader buffer markers */
    int bufRemain;
    int bufPos;     /* Position */
} SockCbInfo;

/* Cert Structure */
typedef struct t_atcert {
    uint32_t signer_ca_size;
    uint8_t signer_ca[512];
    uint8_t signer_ca_pubkey[64];
    uint32_t end_user_size;
    uint8_t end_user[512];
    uint8_t end_user_pubkey[64];
} t_atcert;

extern t_atcert atcert;


int _gettimeofday(struct timeval *__p, void *__tz);

/** Functions prototypes for debugging.	*/
const char* tls_get_socket_string(int callback_status);
//void atcab_printbin_label(const uint8_t* label, const uint8_t* buf, int len);

/** Functions prototypes to communicate to ATECC508A. */
void tls_set_wifi_status(int status);
int tls_get_wifi_status(void);
void tls_wifi_callback(uint8_t u8MsgType, void *pvMsg);
void tls_set_ntp_socket(SOCKET socket);
SOCKET tls_get_ntp_socket(void);
int tls_set_curr_time_and_date(uint32_t secsSince1900);
void tls_get_curr_time_and_date(t_time_date* tm);
int tls_get_ntp_time_and_date(void);
void tls_ntp_socket_cb(SOCKET sock, uint8_t u8Msg, void *pvMsg);
void tls_ntp_resolve_cb(uint8_t *pu8DomainName, uint32_t u32ServerIP);
int tls_send_packet_cb(WOLFSSL* ssl, char *buf, int sz, void *ctx);
int tls_receive_packet_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int tls_compare_date(t_time_date *local, atcacert_tm_utc_t *cert);


/** WolfSSL callback functions to communicate to ATECC508A. */
int tls_create_pms_cb(struct WOLFSSL* ssl, ecc_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx);
int tls_build_signer_ca_cert(void);
int tls_build_end_user_cert(void);
int tls_verify_peer_cert_cb(int preverify, struct WOLFSSL_X509_STORE_CTX *peer_cert);
int tls_sign_certificate_cb(struct WOLFSSL* ssl, const byte* in, word32 inSz, byte* out, word32* outSz,
							const byte* key, word32 keySz, void* ctx);
int tls_verify_signature_cb(struct WOLFSSL* ssl, const byte* sig, word32 sigSz, const byte* hash,
                 			word32 hashSz, const byte* key, word32 keySz, int* result, void* ctx);


#ifdef __cplusplus
}
#endif
#endif /* TLS_COMMON_H_ */
