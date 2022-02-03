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

#include "tls_server.h"
#include "tls_common.h"
#include "cryptoauthlib.h"
#include "tls/atcatls.h"
#include "tls/atcatls_cfg.h"
#include "atcacert/atcacert_client.h"

/** \brief Single socket for tls server */
static SOCKET tls_server_socket = -1;
static SOCKET tls_client_socket = -1;

/** \brief TLS objects for server */
static WOLFSSL*        ssl_server    = NULL;
static WOLFSSL_CTX*    ctx_server    = NULL;
static WOLFSSL_METHOD* method_server = NULL;
static SockCbInfo      ioCtx;

/**
 * \brief Try to listen to client's connection with appointed port.
 */
SOCKET tls_listen_client(uint16 port)
{
	struct sockaddr_in addr;

	tls_server_socket = socket(AF_INET, SOCK_STREAM, 0);

	if (tls_server_socket < 0) {
		printf("Failed to assign socket!\r\n");
		return -1;
	}

	/* Initialize socket address structure. */
	addr.sin_family = AF_INET;
	addr.sin_port = _htons(TLS_SERVER_PORT);
	addr.sin_addr.s_addr = 0;

	if (bind(tls_server_socket, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != 0) {
		printf("Failed to bind server socket!\r\n");
		close(tls_server_socket);
		return -1;
	}

	while (!GET_SOCKET_STATUS(SOCKET_STATUS_ACCEPT)) {
		m2m_wifi_handle_events(NULL);
	}

	return tls_server_socket;
}

/**
 * \brief Callback to get the Data from socket.
 */
void tls_server_socket_cb(SOCKET sock, uint8_t u8Msg, void *pvMsg)
{
	printf("Socket Event : %s \r\n", tls_get_socket_string(u8Msg));
	switch (u8Msg) {

		case SOCKET_MSG_BIND:
		{
			tstrSocketBindMsg *pstrBind = (tstrSocketBindMsg *)pvMsg;
			if (pstrBind && pstrBind->status == 0) {
				printf("socket callback : bind success!\r\n");
				ENABLE_SOCKET_STATUS(SOCKET_STATUS_BIND);
				listen(tls_server_socket, 0);
			} else {
				printf("socket callback : bind error!\r\n");
				DISABLE_SOCKET_STATUS(SOCKET_STATUS_BIND);
				close(tls_server_socket);
			}
		}
		break;

		case SOCKET_MSG_LISTEN:
		{
			tstrSocketListenMsg *pstrListen = (tstrSocketListenMsg *)pvMsg;
			if (pstrListen && pstrListen->status == 0) {
				printf("socket callback : listen success!\r\n");
				ENABLE_SOCKET_STATUS(SOCKET_STATUS_LISTEN);
				accept(tls_server_socket, NULL, NULL);
			} else {
				printf("socket callback : listen error!\r\n");
				DISABLE_SOCKET_STATUS(SOCKET_MSG_LISTEN);
				close(tls_server_socket);
			}
		}
		break;

		case SOCKET_MSG_ACCEPT:
		{
			tstrSocketAcceptMsg *pstrAccept = (tstrSocketAcceptMsg *)pvMsg;
			if (pstrAccept) {
				printf("socket callback : accept success!\r\n");
				ENABLE_SOCKET_STATUS(SOCKET_STATUS_ACCEPT);
				accept(tls_server_socket, NULL, NULL);
				tls_client_socket = pstrAccept->sock;
			} else {
				printf("socket callback : accept error!\r\n");
				DISABLE_SOCKET_STATUS(SOCKET_STATUS_ACCEPT);
				close(tls_server_socket);
			}
		}
		break;

		case SOCKET_MSG_CONNECT:
		{
			tstrSocketConnectMsg *pstrConnect = (tstrSocketConnectMsg *)pvMsg;
			if (pstrConnect && pstrConnect->s8Error >= 0) {
				printf("socket callback : connect success!\r\n");
				ENABLE_SOCKET_STATUS(SOCKET_STATUS_CONNECT);
			} else {
				printf("socket callback : connect error!\r\n");
				DISABLE_SOCKET_STATUS(SOCKET_STATUS_CONNECT);
				close(tls_server_socket);
			}
		}
		break;


		case SOCKET_MSG_RECV:
		{
			tstrSocketRecvMsg *pstrRecv = (tstrSocketRecvMsg *)pvMsg;
			if (pstrRecv && pstrRecv->s16BufferSize > 0) {
				printf("socket callback : recv success!\r\n");
				ENABLE_SOCKET_STATUS(SOCKET_STATUS_RECEIVE);
			} else {
				printf("socket callback : recv error!\r\n");
				DISABLE_SOCKET_STATUS(SOCKET_STATUS_RECEIVE);
				close(tls_server_socket);
			}
		}
		break;


		case SOCKET_MSG_SEND:
		{
			tstrSocketConnectMsg *pstrConnect = (tstrSocketConnectMsg *)pvMsg;
			if (pstrConnect && pstrConnect->s8Error >= 0) {
				printf("socket callback : send success!\r\n");
				ENABLE_SOCKET_STATUS(SOCKET_STATUS_SEND);
			} else {
				printf("socket callback : send error!\r\n");
				DISABLE_SOCKET_STATUS(SOCKET_STATUS_SEND);
				close(tls_server_socket);
			}
		}
		break;

	default:
		break;
	}
}

/**
 * \brief Try to send simple message to client.
 */
int tls_send_message(void)
{
    char msg[32] = "Hello Alice!";   /* GET may make bigger */
    int  msg_len = (int)strlen(msg);

    if (wolfSSL_write(ssl_server, msg, msg_len) != msg_len) {
        printf("Failed to send client message!\r\n");
		return SSL_ERROR_SSL;
    }

	printf("\r\n============================================\r\n");
	printf("Sent a encrypted cipher text : %s\r\n", msg);
	printf("============================================\r\n");
	return SSL_SUCCESS;
}

/**
 * \brief Try to receive response from client.
 */
int tls_receive_message(void)
{
	int  msg_len;
	uint8_t msg[80];

    msg_len = wolfSSL_read(ssl_server, msg, sizeof(msg)-1);

	if (msg_len > 0) {
		msg[msg_len] = 0;
		printf("\r\n===================================\r\n");
		printf("Received a plain text : %s\r\n", msg);
		printf("===================================\r\n");
		return SSL_SUCCESS;
	} else {
		printf("Failed to receive msessage\r\n");
		return SSL_ERROR_SSL;
	}
}

/**
 * \brief Get started handshake with client.
 */
int tls_start_handshake(void)
{

	if (wolfSSL_accept(ssl_server) != SSL_SUCCESS) {
        int  err = wolfSSL_get_error(ssl_server, 0);
        char buffer[80];
        printf("Failed to handshake, Error num = %d, %s\r\n", err, wolfSSL_ERR_error_string(err, buffer));
        return SSL_FAILURE;
    }

	return SSL_SUCCESS;
}

/**
 * \brief Load TLS objects, set certificate and cipher suite.
 */
int tls_load_wolfssl_objects(void)
{

	if (wolfSSL_Init() != SSL_SUCCESS) {
    	printf("Failed to initialze wolfSSL!\r\n");
		return SSL_FAILURE;
	}

  	method_server = wolfTLSv1_2_server_method();
	if (method_server == NULL) {
    	printf("Failed to alloc dynamic buffer!\r\n");
		return SSL_FAILURE;
	}

	ctx_server = wolfSSL_CTX_new(method_server);
	if (ctx_server == NULL) {
    	printf("Failed to create wolfssl context!\r\n");
		return SSL_FAILURE;
	}

	if (wolfSSL_CTX_load_verify_buffer(ctx_server, atcert.signer_ca,
		atcert.signer_ca_size, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
		printf("Faile to load verification certificate!\r\n");
		return SSL_FAILURE;
	}

	if (wolfSSL_CTX_use_certificate_buffer(ctx_server, atcert.end_user,
			atcert.end_user_size, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
		printf("Faile to set own certificate!\r\n");
		return SSL_FAILURE;
	}

    if (wolfSSL_CTX_set_cipher_list(ctx_server, SERVER_CIPHER_LIST) != SSL_SUCCESS) {
		printf("unable to set cipher list for client : %s\r\n", SERVER_CIPHER_LIST);
		return SSL_FAILURE;
    }

	wolfSSL_CTX_set_verify(ctx_server, SSL_VERIFY_PEER, tls_verify_peer_cert_cb);
	wolfSSL_CTX_SetEccVerifyCb(ctx_server, tls_verify_signature_cb);
	wolfSSL_CTX_SetEccSharedSecretCb(ctx_server, tls_create_pms_cb);
	wolfSSL_SetIORecv(ctx_server, tls_receive_packet_cb);
	wolfSSL_SetIOSend(ctx_server, tls_send_packet_cb);

	ssl_server = wolfSSL_new(ctx_server);
	if (ssl_server == NULL) {
		printf("unable to get wolfssl context.\r\n");
		return SSL_FAILURE;
	}

    ioCtx.sd = tls_client_socket;
    wolfSSL_SetIOReadCtx(ssl_server, &ioCtx);
    wolfSSL_SetIOWriteCtx(ssl_server, &ioCtx);

	wolfSSL_Debugging_ON();

	return SSL_SUCCESS;
}

/**
 * \brief Shutdown WolfSSL objects.
 */
int tls_release_objects(void)
{
	wolfSSL_shutdown(ssl_server);

	wolfSSL_free(ssl_server);

	wolfSSL_CTX_free(ctx_server);

	close(tls_server_socket);

	printf("Released server objects!\r\n");

	return SSL_SUCCESS;
}

void tls_start_server(void)
{
	int ret = 0;
	tstrWifiInitParam param;

	do {

		printf(STRING_HEADER);

		/* Initialize the BSP. */
		ret = nm_bsp_init();
		if (ret != M2M_SUCCESS) {
			printf("Failed to initialize BSP!\r\n");
			break;
		}

		/* Initialize Wi-Fi parameters structure. */
		memset((uint8_t *)&param, 0, sizeof(tstrWifiInitParam));

		/* Initialize Wi-Fi driver with data and status callbacks. */
		param.pfAppWifiCb = tls_wifi_callback;
		ret = m2m_wifi_init(&param);
		if (ret != M2M_SUCCESS) {
			printf("Failed to register wifi callback!\r\n");
			break;
		}

		/* Initialize socket module */
		socketInit();

#ifdef EXTERNAL_NW
	    /* Register socket callback to communicate with NTP server */
		registerSocketCallback(tls_ntp_socket_cb, tls_ntp_resolve_cb);
#endif

		/* Connect to router. */
		ret = m2m_wifi_connect((char *)MAIN_WLAN_SSID, sizeof(MAIN_WLAN_SSID),
						MAIN_WLAN_AUTH, (char *)MAIN_WLAN_PSK, M2M_WIFI_CH_ALL);
		if (ret != M2M_SUCCESS) {
			printf("Failed to connect to router!\r\n");
	        break;
		}

	    /* Poll connection status with router */
		while (tls_get_wifi_status() != M2M_WIFI_CONNECTED) {
			m2m_wifi_handle_events(NULL);
		}

		printf("WINC is connected to %s successfully!\r\n", MAIN_WLAN_SSID);

#ifdef EXTERNAL_NW
		/* Get date and time information from NTP server */
        if (tls_get_ntp_socket() < 0) {
            if (tls_get_ntp_time_and_date() < 0) {
				printf("failed to set time and date!\r\n");
				break;
            }
        }
#endif
	    /* Register socket callback to communicate with TLS server */
		registerSocketCallback(tls_server_socket_cb, NULL);

		ret = tls_listen_client(TLS_SERVER_PORT);
		if (ret < 0) {
			printf("Failed to create TLS client socket!\r\n");
			break;
		}

		ret = tls_build_signer_ca_cert();
		if (ret != ATCACERT_E_SUCCESS) {
			printf("Failed to build client's signer certificate!\r\n");
			break;
		}

		ret = tls_build_end_user_cert();
		if (ret != ATCACERT_E_SUCCESS) {
			printf("Failed to build server certificate!\r\n");
			break;
		}

		ret = tls_load_wolfssl_objects();
		if (ret != SSL_SUCCESS) {
			printf("Failed to load wolfssl!\r\n");
			break;
		}

		ret = tls_start_handshake();
		if (ret != SSL_SUCCESS) {
			printf("Failed to handshake!\r\n");
			break;
		}

		ret = tls_receive_message();
		if (ret != SSL_SUCCESS) {
			printf("Failed to receive msessage from client!\r\n");
			break;
		}

		ret = tls_send_message();
		if (ret != SSL_SUCCESS) {
			printf("Failed to send msessage to server!\r\n");
			break;
		}

		/* Release initialized objects */
		tls_release_objects();
		atcatls_finish();

	} while(0);

	(ret == SSL_SUCCESS) ? printf(SUCCEED_MSG) : printf(FAILED_MSG);

}

