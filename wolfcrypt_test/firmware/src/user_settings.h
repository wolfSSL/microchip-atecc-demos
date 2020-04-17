/* user_settings.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef _USER_SETTINGS_H    /* Guard against multiple inclusion */
#define _USER_SETTINGS_H

#include "configuration.h"

/*
 * The Microchip Configurator puts wolfSSL and wolfCrypt configuration defines
 * in the following file:
 *
 * microchip-atecc-demos/wolfcrypt_test/firmware/src/config/pic32mz_ef_curiosity_2/configuration.h
 *
 * The configuration.h file has been modified after generation by the
 * Microchip Configurator tool to match the requirements of this sample
 * application.
 *
 * In case the configuration.h defines accidentally get overwritten, they are
 * listed below.
 */

/* ----- wolfSSL Microchip and PIC32 configuration ----- */
//#define MICROCHIP_PIC32
//#define WOLFSSL_MICROCHIP_PIC32MZ
//#define MICROCHIP_HARMONY
//#define MICROCHIP_MPLAB_HARMONY
//#define MICROCHIP_MPLAB_HARMONY_3
//#define MICROCHIP_TCPIP
//#define MICROCHIP_TCPIP_BSD_API
//#define HAVE_MCAPI
//#define NO_PIC32MZ_RNG
//#define NO_PIC32MZ_CRYPT
//#define WOLFSSL_PIC32MZ_HASH

/* ----- wolfSSL ATECC configuration ----- */
//#define WOLFSSL_ATECC608A
//#define WOLFSSL_ATECC_RNG
//#define WOLFSSL_ATECC_TNGTLS
//#define WOLFSSL_ATECC_ECDH_IOENC
//#define ECC_USER_CURVES
//
//extern int get_608a_enc_key_default(unsigned char* enckey, unsigned short keysize);
//#define ATECC_GET_ENC_KEY(enckey, keysize) get_608a_enc_key_default((enckey), (keysize))

/* ----- wolfCrypt algorithm configuration ----- */
//#define USE_FAST_MATH
//#define NO_PWDBASED
//#define WOLF_CRYPTO_CB  // provide call-back support
//#define NO_MD4
//#define WOLFSSL_SHA384
//#define WOLFSSL_SHA512
//#define HAVE_SHA512
//#define WOLFSSL_SHA3
//#define HAVE_HKDF
//#define WOLFSSL_AES_128
//#define WOLFSSL_AES_192
//#define WOLFSSL_AES_256
//#define WOLFSSL_AES_DIRECT
//#define HAVE_AES_DECRYPT
//#define HAVE_AES_ECB
//#define HAVE_AES_CBC
//#define WOLFSSL_AES_COUNTER
//#define HAVE_AESGCM
//#define HAVE_AESCCM
//#define NO_RC4
//#define NO_HC128
//#define NO_RABBIT
//#define HAVE_ECC
//#define NO_DH
//#define NO_DSA
//#define NO_DEV_RANDOM
//#define HAVE_HASHDRBG
//#define WC_NO_HARDEN

/* ----- wolfSSL library configuration ----- */
//#define SIZEOF_LONG_LONG 8
//#define WOLFSSL_ALT_NAMES
//#define WOLFSSL_DER_LOAD
//#define KEEP_OUR_CERT
//#define KEEP_PEER_CERT
//#define HAVE_IO_TIMEOUT
//#define HAVE_FFDHE_2048
//#define HAVE_FFDHE_3072
//#define HAVE_FFDHE_4096
//#define HAVE_FFDHE_6144
//#define HAVE_FFDHE_8192
//#define TFM_NO_ASM
//#define WOLFSSL_NO_ASM
//#define NO_WRITEV
//#define NO_ERROR_STRINGS
//#define NO_FILESYSTEM
//#define SINGLE_THREADED
//#define NO_ERROR_STRINGS
//#define NO_WOLFSSL_MEMORY
//#define HAVE_PK_CALLBACKS

/* ----- wolfSSL and wolfCrypt test and example app configuration ----- */
//#define USE_CERT_BUFFERS_2048
//#define USE_CERT_BUFFERS_256
//#define XPRINTF SYS_PRINT
//#define USE_FLAT_TEST_H
//#define USE_FLAT_BENCHMARK_H
//#define NO_MAIN_DRIVER
//#define BENCH_EMBEDDED
//#define NO_ECC_VECTOR_TEST


#endif /* _USER_SETTINGS_H */

