/* Custom user settings file written for Atmel Port by wolfSSL */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#undef  WOLFSSL_ATMEL
#define WOLFSSL_ATMEL

#undef  WOLFCRYPT_ONLY
//#define WOLFCRYPT_ONLY

#undef  WOLFSSL_GENERAL_ALIGNMENT
#define WOLFSSL_GENERAL_ALIGNMENT   4

#undef  SINGLE_THREADED
#define SINGLE_THREADED

#undef  WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK


/* ------------------------------------------------------------------------- */
/* Hardware */
/* ------------------------------------------------------------------------- */

#undef  WOLFSSL_ATECC508A
#define WOLFSSL_ATECC508A

#undef  WOLFSSL_ATECC508A_TLS
#define WOLFSSL_ATECC508A_TLS

#undef  WOLFSSL_ATECC508A_DEBUG
#define WOLFSSL_ATECC508A_DEBUG

/* SAMD21 - SERCOM2 - PTA08/PTA09 */
#undef  ATECC_I2C_BUS
#define ATECC_I2C_BUS  2


/* ------------------------------------------------------------------------- */
/* Port */
/* ------------------------------------------------------------------------- */

/* Override Current Time */
/* Allows custom "custom_time()" function to be used for benchmark */
#define WOLFSSL_USER_CURRTIME
#define WOLFSSL_GMTIME
#define USER_TICKS

/* enable the built-in atmel.c time support */
#undef  WOLFSSL_ATMEL_TIME
#define WOLFSSL_ATMEL_TIME

/* ------------------------------------------------------------------------- */
/* Network */
/* ------------------------------------------------------------------------- */
#undef  WOLFSSL_USER_IO
#define WOLFSSL_USER_IO


/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
#undef  USE_FAST_MATH
#define USE_FAST_MATH

#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT


/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#undef  KEEP_PEER_CERT
#define KEEP_PEER_CERT

#undef  HAVE_PK_CALLBACKS
#define HAVE_PK_CALLBACKS


/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* ECC */
#if 1
    #undef  HAVE_ECC
    #define HAVE_ECC

    /* Custom Curve Config */
    #undef  ECC_USER_CURVES
    #define ECC_USER_CURVES

    #undef  ECC_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT

    #undef  ALT_ECC_SIZE
    #define ALT_ECC_SIZE
#endif

/* RSA */
#undef NO_RSA
#if 0
    #ifdef USE_FAST_MATH
        /* Maximum math bits (Max RSA key bits * 2) */
        #undef  FP_MAX_BITS
        #define FP_MAX_BITS     4096
    #endif

    /* half as much memory but twice as slow */
    #undef  RSA_LOW_MEM
    //#define RSA_LOW_MEM
#else
    #define NO_RSA
#endif

/* AES */
#undef NO_AES
#if 1
    #undef  HAVE_AESGCM
    #define HAVE_AESGCM

    /* GCM Method: GCM_SMALL, GCM_WORD32 or GCM_TABLE */
    #undef  GCM_SMALL
    #define GCM_SMALL
#else
    #define NO_AES
#endif

/* ChaCha20 / Poly1305 */
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if 0
    #define HAVE_CHACHA
    #define HAVE_POLY1305

    /* Needed for Poly1305 */
    #undef  HAVE_ONE_TIME_AUTH
    #define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 */
#undef HAVE_CURVE25519
#undef HAVE_ED25519
#if 0
    #define HAVE_CURVE25519
    #define HAVE_ED25519

    /* Optionally use small math (less flash usage, but much slower) */
    #if 0
        #define CURVED25519_SMALL
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha */
#undef NO_SHA
#if 1
    /* 1k smaller, but 25% slower */
    //#define USE_SLOW_SHA
#else
    #define NO_SHA
#endif

/* Sha256 */
#undef NO_SHA256
#if 1
#else
    #define NO_SHA256
#endif

/* Sha512 */
#undef WOLFSSL_SHA512
#if 0
    #define WOLFSSL_SHA512

    /* Sha384 */
    #undef  WOLFSSL_SHA384
    #if 1
        #define WOLFSSL_SHA384
    #endif

    /* over twice as small, but 50% slower */
    //#define USE_SLOW_SHA2
#endif

/* MD5 */
#undef  NO_MD5
#if 1
    #define NO_MD5
#endif


/* ------------------------------------------------------------------------- */
/* Benchmark / Test */
/* ------------------------------------------------------------------------- */
/* Use reduced benchmark / test sizes */
#undef  BENCH_EMBEDDED
#define BENCH_EMBEDDED

#undef  USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048

#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256

#undef  NO_CRYPT_TEST
//#define NO_CRYPT_TEST

#undef  NO_CRYPT_BENCHMARK
//#define NO_CRYPT_BENCHMARK


/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
/* To debug: Enable the WOLFSSL_DEBUG and disable NO_ERROR_STRINGS */
#undef  WOLFSSL_DEBUG
//#define WOLFSSL_DEBUG

#undef  NO_ERROR_STRINGS
//#define NO_ERROR_STRINGS

/* Use this to measure / print heap usage (comment out NO_WOLFSSL_MEMORY) */
#undef  USE_WOLFSSL_MEMORY
//#define USE_WOLFSSL_MEMORY
#undef  WOLFSSL_TRACK_MEMORY
//#define WOLFSSL_TRACK_MEMORY
#undef  NO_WOLFSSL_MEMORY
#define NO_WOLFSSL_MEMORY


/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */
/* Use HW RNG Only */
#if 1
    /* Override P-RNG with HW RNG */
    #undef  CUSTOM_RAND_GENERATE_BLOCK
    #define CUSTOM_RAND_GENERATE_BLOCK  atmel_get_random_block
    #ifndef ATMEL_GET_RANDOM_BLOCK_DEFINED
    	int atmel_get_random_block(unsigned char* output, unsigned int sz);
        #define ATMEL_GET_RANDOM_BLOCK_DEFINED
    #endif

/* Use P-RNG + HW RNG (adds 8K) */
#else
    /* Use built-in P-RNG (SHA256 based) with HW RNG */
    #undef  HAVE_HASHDRBG
    #define HAVE_HASHDRBG
#endif


/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#undef  NO_FILESYSTEM
#define NO_FILESYSTEM

#undef  NO_WRITEV
#define NO_WRITEV

#undef  NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#undef  NO_DSA
#define NO_DSA

#undef  NO_DH
#define NO_DH

#undef  NO_DES3
#define NO_DES3

#undef  NO_RC4
#define NO_RC4

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  NO_HC128
#define NO_HC128

#undef  NO_RABBIT
#define NO_RABBIT

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  NO_PWDBASED
#define NO_PWDBASED

#undef  NO_ASN_TIME
//#define NO_ASN_TIME

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
