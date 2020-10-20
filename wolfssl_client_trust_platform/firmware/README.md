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
#define NO_OLD_WC_NAMES

/* for TLS v1.3 */
#define HAVE_HKDF

/* for ATECC public key callbacks */
#define HAVE_PK_CALLBACKS
#define WOLFSSL_ATECC608A
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

1. Choose the TLS server.
For testing mutual authentication you can use the wolfSSL example server:

```
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-debug --disable-shared && make
# Start start, bind to any network interface, disable peer cert checking and accept multiple connections
./examples/server/server -b -d -i
```

To 
Or use a public website like www.google.com