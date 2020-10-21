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

Harmony v3 code generation needs the following changes:

1. `src/config/samd21_trust/configuration.h`:

```c
/* Because WINC1500 is being used */
-//#define MICROCHIP_TCPIP
+#define MICROCHIP_TCPIP
#define WOLFSSL_USER_IO /* use custom IO callbacks */

/* for ATECC public key callbacks */
#define HAVE_PK_CALLBACKS
#define WOLFSSL_ATECC608A
#define WOLFSSL_ATECC_TNGTLS
```

2. Copy the `wolfcrypt/src/port/atmel/atmel.c` and `wolfssl/wolfcrypt/port/atmel/atmel.h` files from wolfSSL.

3. `src/config/samd21_trust/library/cryptoauthlib/crypto/hashes/sha2_routines.h`

```c
#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE (32)
#endif
#ifndef SHA256_BLOCK_SIZE
#define SHA256_BLOCK_SIZE  (64)
#endif
```

## Running the example

1) Choose the TLS server:

For testing mutual authentication you can use the wolfSSL example server:

```sh
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
./autogen.sh
./configure
make
# Start server with ECC test key and cert
./examples/server/server -b -d -i -g -x -k ./certs/ecc-key.pem -c ./certs/server-ecc.pem
```

Or use a public website like `www.google.com`.

2) Run the TLS client example:

Modify the `common/wolf_tls_task.c` or specify as build pre-processor macros:

* `WLAN_SSID`
* `WLAN_PSK`
* `SERVER_HOST`
* `SERVER_PORT`

3) Example Console Output:

```

```

## Support

For questions please email support@wolfssl.com
