# CryptoAuth Trust Platform wolfSSL Example

## Hardware

* DM320118: CryptoAuth Trust Platform
* Wifi7click: ATWINC1510

## Software

* MPLAB X v5.40
* Microchip XC32 v2.50 compiler
* Microchip Harmony 3
* cryptoauthlib: v3.2.3
* wolfSSL: v4.5.0

## Building

1. Create a new project for your target board

2. Using the Harmony Configuration tool make sure the following components are selected:

* ATECC608
* wolfSSL
* wolfCrypt
* Trust&Go
* WINC

3. Harmony v3 code generation needs the following changes:

* `src/config/samd21_trust/configuration.h`:

```c
#if 0 /* disabled to save code space */
#define WOLFSSL_ALT_NAMES
#define WOLFSSL_DER_LOAD
#define KEEP_OUR_CERT
#define KEEP_PEER_CERT
#define HAVE_CRL_IO
#define HAVE_IO_TIMEOUT
#endif

/* Because WINC1500 is being used */
-//#define MICROCHIP_TCPIP
+#define MICROCHIP_TCPIP

/* for ATECC public key callbacks */
#define HAVE_PK_CALLBACKS
#define WOLFSSL_ATECC608A
#define WOLFSSL_ATECC_TNGTLS

/* Override Current Time */
/* Allows custom "custom_time()" function to be used for benchmark */
#define WOLFSSL_USER_CURRTIME
#define WOLFSSL_GMTIME
#define USER_TICKS
extern unsigned long my_time(unsigned long* timer);
#define XTIME my_time
```

* Copy the `wolfcrypt/src/port/atmel/atmel.c` and `wolfssl/wolfcrypt/port/atmel/atmel.h` files from wolfSSL.

* `src/config/samd21_trust/library/cryptoauthlib/crypto/hashes/sha2_routines.h`

```c
#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE (32)
#endif
#ifndef SHA256_BLOCK_SIZE
#define SHA256_BLOCK_SIZE  (64)
#endif
```

* Harmony may duplicate the `atecc608_0_init_data` definition and you may have to delete one.


## Running the example

1. Choose the TLS server:

For testing mutual authentication you can use the wolfSSL example server:

```sh
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-opensslextra CFLAGS="-DSHOW_CERTS"
make
# Start server with ECC test key and cert
./examples/server/server -b -d -i -g -x -k ./certs/ecc-key.pem -c ./certs/server-ecc.pem
```

2. Modify the `common/wolf_tls_task.c` or specify as build pre-processor macros:

* `WLAN_SSID`
* `WLAN_PSK`
* `SERVER_HOST`
* `SERVER_PORT`

3. Run the TLS client example:

Example Console Output:

```
===========================
wolfSSL Client Example
===========================
Wifi Connected
IP address is 192.168.0.236
DNS Lookup 192.168.0.251
WINC1500 WIFI: DNS lookup:
  Host:       192.168.0.251
  IP Address: 192.168.0.251
Creating socket
TCP client: connecting...
connect() success
Initializing wolfSSL
Waiting for time
Time 1603289501
Loading certs/keys
Successfully read signer cert
Successfully read signer pub key

Built server's signer certificate
Successfully read device cert
Successfully read device pub key

Built client certificate
Created wolfTLSv1_2_client_method()
Created new WOLFSSL_CTX
Loaded verify cert buffer into WOLFSSL_CTX
Loaded client certificate chain in to WOLFSSL_CTX

Loaded certs into wolfSSL
Send: 0x200030d3 (84): Res 0
WINC Recv: 87 bytes
Recv: 0x20002900 (5): recvd 5, remain 82
Recv: 0x200030d8 (82): recvd 82, remain 0
WINC Recv: 691 bytes
Recv: 0x20002900 (5): recvd 5, remain 686
Recv: 0x200035d8 (686): recvd 686, remain 0
WINC Recv: 153 bytes
Recv: 0x20002900 (5): recvd 5, remain 148
Recv: 0x20003098 (148): recvd 148, remain 0
WINC Recv: 9 bytes
Recv: 0x20002900 (5): recvd 5, remain 4
Recv: 0x20002900 (4): recvd 4, remain 0
Send: 0x200030db (75): Res 0
Send: 0x20002f73 (6): Res 0
Send: 0x200030ab (45): Res 0
WINC Recv: 6 bytes
Recv: 0x20002900 (5): recvd 5, remain 1
Recv: 0x20002900 (1): recvd 1, remain 0
WINC Recv: 45 bytes
Recv: 0x20002900 (5): recvd 5, remain 40
Recv: 0x20003068 (40): recvd 40, remain 0
wolfSSL_connect() success!
Send: 0x2000282b (58): Res 0
Sent HTTP GET to peer
WINC Recv: 254 bytes
Recv: 0x20002900 (5): recvd 5, remain 249
Recv: 0x20002798 (249): recvd 249, remain 0
Response from server:
----------
HTTP/1.1 200 OK
Content-Type: text/html
C
```

Example Server Console Output

```
$ ./examples/server/server -b -d -i -g -x -k ./certs/ecc-key.pem -c ./certs/server-ecc.pem
SSL version is TLSv1.2
SSL cipher suite is TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
SSL curve name is SECP256R1
Client message: GET /index.html HTTP/1.0
```

## Support

For questions please email support@wolfssl.com
