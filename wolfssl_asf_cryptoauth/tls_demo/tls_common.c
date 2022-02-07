/**
 *
 * \file
 *
 * \brief WINC1500 TLS Client Example.
 *
 * Copyright (c) 2015 Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "asf.h"
#include "tls_common.h"
#include "cryptoauthlib.h"
#include "certs/cert_def_signer_ca.h"
#include "certs/cert_def_end_user.h"
#include "tls/atcatls.h"
#include "tls/atcatls_cfg.h"
#include "atcacert/atcacert_client.h"
#include <stdio.h>

uint16_t tls_socket_status = 0x0000;
uint16_t tls_ntp_socket_status = 0x0000;

static uint8_t wifi_connected = 0;
static SOCKET tls_ntp_socket = -1;
t_time_date curr_time_date;

/** Socket buffer definition. */
static uint8_t gTlsSocketBuf[MAIN_WIFI_M2M_BUFFER_SIZE];


/**
 * \brief Structure to contain certificate information.
 */
t_atcert atcert = {
    .signer_ca_size = 512,
    .signer_ca = { 0 },
    .signer_ca_pubkey = { 0 },
    .end_user_size = 512,
    .end_user = { 0 },
    .end_user_pubkey = { 0 }
};


int _gettimeofday(struct timeval *tv, void *tzvp)
{
    return 0;
}

/**
 * \brief Return string occurred in socket callback  .
 */
const char* tls_get_socket_string(int callback_status)
{
    int status = callback_status;

    if (status < SOCKET_MSG_BIND && status > SOCKET_MSG_RECVFROM) {
        return "UNKNOWN socket event";
    }

    switch (status) {

    case SOCKET_MSG_BIND :
        return "BIND socket event";

    case SOCKET_MSG_LISTEN :
        return "LISTEN socket event";

    case SOCKET_MSG_DNS_RESOLVE :
        return "RESOLVE socket event";

    case SOCKET_MSG_ACCEPT :
        return "ACCEPT socket event";

    case SOCKET_MSG_CONNECT :
        return "CONNECT socket event";

    case SOCKET_MSG_RECV :
        return "RECV socket event";

    case SOCKET_MSG_SEND :
        return "SEND socket event";

    case SOCKET_MSG_SENDTO :
        return "SENDTO socket event";

    case SOCKET_MSG_RECVFROM :
        return "RECVFROM socket event";

    default :
        return "UNKNOWN socket event";
    }
}

/**
 * \brief Set WIFI status.
 */
void tls_set_wifi_status(int status)
{
    wifi_connected = status;
}

/**
 * \brief Get WIFI status.
 */
int tls_get_wifi_status(void)
{
    return wifi_connected;
}

/**
 * \brief WIFI callback to be interrupted.
 */
void tls_wifi_callback(uint8_t u8MsgType, void *pvMsg)
{
	switch (u8MsgType) {
		case M2M_WIFI_RESP_CON_STATE_CHANGED:
		{
			tstrM2mWifiStateChanged *pstrWifiState = (tstrM2mWifiStateChanged *)pvMsg;

			if (pstrWifiState->u8CurrState == M2M_WIFI_CONNECTED) {
				printf("M2M_WIFI_RESP_CON_STATE_CHANGED: CONNECTED\r\n");
			} else if (pstrWifiState->u8CurrState == M2M_WIFI_DISCONNECTED) {
				printf("M2M_WIFI_RESP_CON_STATE_CHANGED: DISCONNECTED\r\n");
				tls_set_wifi_status(M2M_WIFI_DISCONNECTED);
				m2m_wifi_connect((char *)MAIN_WLAN_SSID, sizeof(MAIN_WLAN_SSID),
					MAIN_WLAN_AUTH, (char *)MAIN_WLAN_PSK, M2M_WIFI_CH_ALL);
			}
			break;
		}

		case M2M_WIFI_REQ_DHCP_CONF:
		{
			uint8_t *pu8IPAddress = (uint8_t *)pvMsg;
			tls_set_wifi_status(M2M_WIFI_CONNECTED);
			printf("M2M_WIFI_REQ_DHCP_CONF: IP is %u.%u.%u.%u\r\n",
					pu8IPAddress[0], pu8IPAddress[1], pu8IPAddress[2], pu8IPAddress[3]);
			gethostbyname((uint8_t *)MAIN_WORLDWIDE_NTP_POOL_HOSTNAME);
			break;
		}

		default:
		{
			break;
		}
	}
}

/**
 * \brief Set socket to access to the NTP server.
 */
void tls_set_ntp_socket(SOCKET socket)
{
    tls_ntp_socket = socket;
}

/**
 * \brief Get socket to access to the NTP server.
 */
SOCKET tls_get_ntp_socket(void)
{
    return tls_ntp_socket;
}

/**
 * \brief Set local time and date that came from the NTP server.
 */
int tls_set_curr_time_and_date(uint32_t secsSince1900)
{
    #define YEAR0          1900
    #define EPOCH_YEAR     1970
    #define SECS_DAY       (24L * 60L * 60L)
    #define LEAPYEAR(year) (!((year) % 4) && (((year) % 100) || !((year) %400)))
    #define YEARSIZE(year) (LEAPYEAR(year) ? 366 : 365)

    int ret = 0;
    time_t secs = secsSince1900;
    unsigned long dayclock, dayno;
    int year = EPOCH_YEAR;
    static const int _ytab[2][12] =
    {
        {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
        {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
    };

    dayclock = (unsigned long)secs % SECS_DAY;
    dayno    = (unsigned long)secs / SECS_DAY;

    curr_time_date.tm_sec  = (int) dayclock % 60;
    curr_time_date.tm_min  = (int)(dayclock % 3600) / 60;
    curr_time_date.tm_hour = (int) dayclock / 3600;
    curr_time_date.tm_wday = (int) (dayno + 4) % 7;        /* day 0 a Thursday */

    while(dayno >= (unsigned long)YEARSIZE(year)) {
        dayno -= YEARSIZE(year);
        year++;
    }

    curr_time_date.tm_year = year - YEAR0;
    curr_time_date.tm_yday = (int)dayno;
    curr_time_date.tm_mon  = 0;

    while(dayno >= (unsigned long)_ytab[LEAPYEAR(year)][curr_time_date.tm_mon]) {
        dayno -= _ytab[LEAPYEAR(year)][curr_time_date.tm_mon];
        curr_time_date.tm_mon++;
    }

    curr_time_date.tm_mday  = (int)++dayno;
    curr_time_date.tm_isdst = 0;

    curr_time_date.tm_year += 1900;
    curr_time_date.tm_mon += 1;

	printf("Date of Today : %d / %d / %d\r\n", curr_time_date.tm_year, curr_time_date.tm_mon, curr_time_date.tm_mday);
    return ret;

}

/**
 * \brief Copy received time and date to input param.
 */
void tls_get_curr_time_and_date(t_time_date* tm)
{

    tm->tm_year = curr_time_date.tm_year;
    tm->tm_mon = curr_time_date.tm_mon;
    tm->tm_mday = curr_time_date.tm_mday;
    tm->tm_hour = curr_time_date.tm_hour;
    tm->tm_min = curr_time_date.tm_min;
    tm->tm_sec = curr_time_date.tm_sec;

}


#ifndef WOLFCRYPT_ONLY
/* This is used by TLS only */
unsigned int LowResTimer(void)
{
    return curr_time_date.tm_sec;
}
#endif


/**
 * \brief Access to the NTP server.
 */
int tls_get_ntp_time_and_date(void)
{
	int ret = 0;
	SOCKET ntp_socket = -1;
	struct sockaddr_in addr;

	ntp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (ntp_socket < 0) {
		printf("main: UDP Client Socket Creation Failed.\r\n");
		return -1;
	} else {
		tls_set_ntp_socket(ntp_socket);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = _htonl(0xFFFFFFFF);
	addr.sin_port = _htons(6666);
	if (bind((SOCKET)tls_get_ntp_socket(), (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != 0) {
		printf("binding failed.\r\n");
		close(tls_get_ntp_socket());
		return -1;
	}

	while (!GET_NTP_SOCKET_STATUS(NTP_SOCKET_STATUS_RECEIVE_FROM)) {
		m2m_wifi_handle_events(NULL);
	}

	return ret;
}

/**
 * \brief Callback to get the Data from socket.
 *
 * \param[in] sock socket handler.
 * \param[in] u8Msg Type of Socket notification.
 * \param[in] pvMsg A structure contains notification informations.
 */
void tls_ntp_socket_cb(SOCKET sock, uint8_t u8Msg, void *pvMsg)
{
	/* Check for socket event on socket. */
	int16_t ret;

	switch (u8Msg) {
	case SOCKET_MSG_BIND:
	{
		/* printf("socket_cb: socket_msg_bind!\r\n"); */
		tstrSocketBindMsg *pstrBind = (tstrSocketBindMsg *)pvMsg;
		if (pstrBind && pstrBind->status == 0) {
			ENABLE_NTP_SOCKET_STATUS(NTP_SOCKET_STATUS_BIND);
			ret = recvfrom(sock, gTlsSocketBuf/*gNtpServerSocBuf*/, sizeof(gTlsSocketBuf/*gNtpServerSocBuf*/), 0);
			if (ret != SOCK_ERR_NO_ERROR) {
				printf("socket_cb: recv error!\r\n");
			}
		} else {
		    DISABLE_NTP_SOCKET_STATUS(NTP_SOCKET_STATUS_BIND);
			printf("socket_cb: bind error!\r\n");
		}

		break;
	}

	case SOCKET_MSG_RECVFROM:
	{
		tstrSocketRecvMsg *pstrRx = (tstrSocketRecvMsg *)pvMsg;
		if (pstrRx->pu8Buffer && pstrRx->s16BufferSize) {
			uint8_t packetBuffer[48];
			memcpy(&packetBuffer, pstrRx->pu8Buffer, sizeof(packetBuffer));

   			ENABLE_NTP_SOCKET_STATUS(NTP_SOCKET_STATUS_RECEIVE_FROM);
			if ((packetBuffer[0] & 0x7) != 4) {                   /* expect only server response */
				printf("socket_cb: Expecting response from Server Only!\r\n");
				return;                    /* MODE is not server, abort */
			} else {
				uint32_t secsSince1900 = packetBuffer[40] << 24 |
						packetBuffer[41] << 16 |
						packetBuffer[42] << 8 |
						packetBuffer[43];

				/* Now convert NTP time into everyday time.
				 * Unix time starts on Jan 1 1970. In seconds, that's 2208988800.
				 * Subtract seventy years.
				 */
				const uint32_t seventyYears = 2208988800UL;
				uint32_t epoch = secsSince1900 - seventyYears;
				/* Print the hour, minute and second.
				 * GMT is the time at Greenwich Meridian.
				 */
				tls_set_curr_time_and_date(epoch);

				ret = close(sock);

			}
		} else {
            DISABLE_NTP_SOCKET_STATUS(NTP_SOCKET_STATUS_RECEIVE_FROM);
		}

	}
	break;

	default:
		break;
	}
}

/**
 * \brief Ask date and time to the NTP server.
 */
void tls_ntp_resolve_cb(uint8_t *pu8DomainName, uint32_t u32ServerIP)
{
	struct sockaddr_in addr;
	int8_t cDataBuf[48];
	int16_t ret;

	memset(cDataBuf, 0, sizeof(cDataBuf));
	cDataBuf[0] = '\x1b'; /* time query */


	if (tls_get_ntp_socket() >= 0) {
		/* Set NTP server socket address structure. */
		addr.sin_family = AF_INET;
		addr.sin_port = _htons(MAIN_SERVER_PORT_FOR_UDP);
		addr.sin_addr.s_addr = u32ServerIP;

		/*Send an NTP time query to the NTP server*/
		ret = sendto((SOCKET)tls_get_ntp_socket(), (int8_t *)&cDataBuf, sizeof(cDataBuf), 0, (struct sockaddr *)&addr, sizeof(addr));
		if (ret != M2M_SUCCESS) {
			printf("resolve_cb: failed to send  error!\r\n");
			return;
		}
	}
}

/**
 * \brief Compare today's date and certificate's date.
 */
int tls_compare_date(t_time_date *local, atcacert_tm_utc_t *cert)
{
	uint8_t ret = 0;

    if (local->tm_year > cert->tm_year)
        return 1;

    if (local->tm_year == cert->tm_year && local->tm_mon > cert->tm_mon)
        return 1;

    if (local->tm_year == cert->tm_year && local->tm_mon == cert->tm_mon && local->tm_mday > cert->tm_mday) {
        return 1;
	}

	return ret;
}

int tls_send_packet_cb(WOLFSSL* ssl, char *buf, int sz, void *ctx)
{
    SockCbInfo* info = (SockCbInfo*)ctx;
    int sent = 0;

    sent = (int)send(info->sd, buf, sz, ssl->wflags);

	while (!GET_SOCKET_STATUS(SOCKET_STATUS_SEND)) {
		m2m_wifi_handle_events(NULL);
	}

	DISABLE_SOCKET_STATUS(SOCKET_STATUS_SEND);

    if (sent < 0) {
		printf("Failed to send packet\r\n");
		return -1;
    }
    atcab_printbin_label("\r\nSENT PACKET", (uint8_t*)buf, sent);

    return sent;
}

int tls_receive_packet_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    SockCbInfo* info = (SockCbInfo*)ctx;
    int recvd = 0;

    /* If nothing in the buffer then do read */
    if (info->bufRemain <= 0) {
	    recvd = (int)recv(info->sd, gTlsSocketBuf, sizeof(gTlsSocketBuf), ssl->rflags);
        info->bufRemain = recvd;
        info->bufPos = 0;

    	while (!GET_SOCKET_STATUS(SOCKET_STATUS_RECEIVE)) {
    		m2m_wifi_handle_events(NULL);
    	}

    	DISABLE_SOCKET_STATUS(SOCKET_STATUS_RECEIVE);

        if (recvd < 0) {
            printf("Failed to receive packet\r\n");
    		return -1;
        }
        else if (recvd == 0) {
            printf("Failed to receive packet, Connection closed\r\n");
            return -1;
        }
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

    atcab_printbin_label("\r\nRECEIVED PACKET", (uint8_t*)buf, sz);

    return sz;
}




/**
 * \brief Give enc key to read pms.
 */
static ATCA_STATUS tls_set_enc_key(uint8_t* enckey, int16_t keysize)
{
	//uint8_t i = 0;

	if (enckey == NULL || keysize != ATECC_KEY_SIZE) {
        return -1;
    }

	XMEMSET(enckey, 0xFF, keysize);	// use default values

	return SSL_SUCCESS;
}


/**
 * \brief Create pre master secret using peer's public key and self private key.
 */
 int tls_create_pms_cb(WOLFSSL* ssl, ecc_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx)
{
	int ret = 0;
    ecc_key tmpKey;
	uint8_t key_buffer[ATECC_KEY_SIZE*2];
    uint8_t* qx = &key_buffer[0];
    uint8_t* qy = &key_buffer[ATECC_KEY_SIZE];
    word32 qxLen = ATECC_KEY_SIZE, qyLen = ATECC_KEY_SIZE;

	if (pubKeyDer == NULL || pubKeySz == NULL || out == NULL || outlen == NULL) {
		return BAD_FUNC_ARG;
	}

	(void)ctx;

    XMEMSET(key_buffer, 0, sizeof(key_buffer));

    ret = atcatlsfn_set_get_enckey(tls_set_enc_key);
    if (ret != ATCA_SUCCESS) {
        return -1;
    }

    ret = wc_ecc_init(&tmpKey);
    if (ret != 0) {
        return ret;
    }

	if (side == WOLFSSL_CLIENT_END) {
        /* generate new ephemeral key on device */
        ret = atcatls_create_key(TLS_SLOT_ECDHE_PRIV, key_buffer);
        if (ret == ATCA_SUCCESS) {
            /* convert raw unsigned public key to X.963 format for TLS */
            ret = wc_ecc_import_unsigned(&tmpKey, qx, qy, NULL, ECC_SECP256R1);
            if (ret == 0) {
                ret = wc_ecc_export_x963(&tmpKey, pubKeyDer, pubKeySz);
            }
        }
        (void)qxLen;
        (void)qyLen;
	}
	else if (side == WOLFSSL_SERVER_END) {
        /* import peer's key and export as raw unsigned for hardware */
        ret = wc_ecc_import_x963_ex(pubKeyDer, *pubKeySz, &tmpKey, ECC_SECP256R1);
        if (ret == 0) {
            ret = wc_ecc_export_public_raw(&tmpKey, qx, &qxLen, qy, &qyLen);
        }
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    wc_ecc_free(&tmpKey);

    if (ret != 0) {
        return ret;
    }

    atcab_printbin_label("\r\nPeer's Public Key",
        pubKeyDer, *pubKeySz);

    ret = atcatls_ecdh(TLS_SLOT_ECDHE_PRIV, key_buffer, out);
    if (ret != 0) {
        return ret;
    }
    *outlen = ATECC_KEY_SIZE;

    atcab_printbin_label("\r\nPre Master Secret", out, *outlen);

	return ret;
}


/**
 * \brief build server's signer certificate.
 */
int tls_build_signer_ca_cert(void)
{
	int ret = 0;

	ret = atcacert_read_cert(&g_cert_def_signer_ca, g_signer_root_ca_public_key,
        atcert.signer_ca, (size_t*)&atcert.signer_ca_size);
	if (ret != ATCACERT_E_SUCCESS) {
		printf("Failed to read signer cert!\r\n");
		return ret;
	}
	atcab_printbin_label("\r\nSigner Certficate",
        atcert.signer_ca, atcert.signer_ca_size);

	ret = atcacert_get_subj_public_key(&g_cert_def_signer_ca, atcert.signer_ca,
        atcert.signer_ca_size, atcert.signer_ca_pubkey);
	if (ret != ATCACERT_E_SUCCESS) {
		printf("Failed to read signer public key!\r\n");
		return ret;
	}
	atcab_printbin_label("\r\nSigner Public Key",
        atcert.signer_ca_pubkey, sizeof(atcert.signer_ca_pubkey));

	return ret;
}

/**
 * \brief build server's signer certificate.
 */
int tls_build_end_user_cert(void)
{
	int ret = 0;
	uint8_t device_signature[64];

	ret = atcacert_read_cert(&g_cert_def_end_user, atcert.signer_ca_pubkey,
        atcert.end_user, (size_t*)&atcert.end_user_size);
	if (ret != ATCACERT_E_SUCCESS) {
		printf("Failed to read device cert!\r\n");
		return ret;
	}
	atcab_printbin_label("\r\nEnd User Certificate",
        atcert.end_user, atcert.end_user_size);

	ret = atcacert_get_subj_public_key(&g_cert_def_end_user, atcert.end_user,
        atcert.end_user_size, atcert.end_user_pubkey);
	if (ret != ATCACERT_E_SUCCESS) {
		printf("Failed to read signer public key!\r\n");
		return ret;
	}
	atcab_printbin_label("\r\nEnd User Public Key",
        atcert.end_user_pubkey, sizeof(atcert.end_user_pubkey));

	ret = atcacert_get_signature(&g_cert_def_end_user, atcert.end_user,
        atcert.end_user_size, device_signature);
	if (ret != ATCACERT_E_SUCCESS) {
		printf("Failed to read device cert!\r\n");
		return ret;
	}
	atcab_printbin_label("\r\nEnd User Signature",
        device_signature, sizeof(device_signature));

	return ret;
}

int tls_verify_peer_cert_cb(int preverify, WOLFSSL_X509_STORE_CTX *peer_cert)
{
	int ret = 0;

	ret = atcatls_verify_cert(&g_cert_def_end_user, peer_cert->current_cert->derCert->buffer,
							peer_cert->current_cert->derCert->length, g_signer_ca_public_key);
	if (ret != ATCACERT_E_SUCCESS) {
		printf("Failed to verify device's certificate!\r\n");
		ret = FALSE;
	} else {
		printf("Verified Peer's certificate!\r\n");
		ret = TRUE;
	}

	return ret;
}

/**
 * \brief Sign received digest so far for private key to be proved.
 */
int tls_sign_certificate_cb(WOLFSSL* ssl, const byte* in, word32 inSz,
    byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
	int ret = 0;

	if (in == NULL || out == NULL || outSz == NULL) {
		return BAD_FUNC_ARG;
	}

	ret = atcatls_sign(TLS_SLOT_AUTH_PRIV, in, out);
	if (ret != ATCA_SUCCESS) {
		printf("Failed to sign digest\r\n");
		return -1;
	}

	*outSz = ATECC_KEY_SIZE * 2;
    atcab_printbin_label("\r\nSigned Signature", out, *outSz);

	return ret;
}

/**
 * \brief Verify signature received from peers to prove peer's private key.
 */
int tls_verify_signature_cb(WOLFSSL* ssl, const byte* sig, word32 sigSz,
    const byte* hash, word32 hashSz, const byte* key, word32 keySz,
    int* result, void* ctx)
{
	int ret = 0;
    ecc_key tmpKey;
    uint8_t key_buffer[ATECC_KEY_SIZE*2];
    uint8_t* qx = &key_buffer[0];
    uint8_t* qy = &key_buffer[ATECC_KEY_SIZE];
    word32 qxLen = ATECC_KEY_SIZE, qyLen = ATECC_KEY_SIZE;
    word32 idx = 0;

	if (ssl == NULL || key == NULL || sig == NULL || hash == NULL || result == NULL) {
		return BAD_FUNC_ARG;
	}

    /* import public key and export public as unsigned bin for hardware */
    ret = wc_ecc_init(&tmpKey);
    if (ret == 0) {
        ret = wc_EccPublicKeyDecode(key, &idx, &tmpKey, keySz);
        if (ret == 0) {
            ret = wc_ecc_export_public_raw(&tmpKey, qx, &qxLen, qy, &qyLen);
        }
        wc_ecc_free(&tmpKey);
        (void)qxLen;
        (void)qyLen;
    }

    if (ret != 0) {
        return ret;
    }

    ret = atcatls_verify(hash, sig, key_buffer, (bool*)result);
	if (ret != 0 || (*result != TRUE)) {
		printf("Failed to verify signature!\r\n");
		return VERIFY_SIGN_ERROR;
	}

	if (*result == TRUE)
		printf("Verified : Client's signed certificate!\r\n");

	return ret;
}


#ifdef __cplusplus
}
#endif
