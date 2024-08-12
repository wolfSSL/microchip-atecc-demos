/*******************************************************************************
  System Configuration Header

  File Name:
    configuration.h

  Summary:
    Build-time configuration header for the system defined by this project.

  Description:
    An MPLAB Project may have multiple configurations.  This file defines the
    build-time options for a single configuration.

  Remarks:
    This configuration header must not define any prototypes or data
    definitions (or include any files that do).  It only provides macro
    definitions for build-time configuration options

*******************************************************************************/

// DOM-IGNORE-BEGIN
/*******************************************************************************
* Copyright (C) 2018 Microchip Technology Inc. and its subsidiaries.
*
* Subject to your compliance with these terms, you may use Microchip software
* and any derivatives exclusively with Microchip products. It is your
* responsibility to comply with third party license terms applicable to your
* use of third party software (including open source software) that may
* accompany Microchip software.
*
* THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
* EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
* WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
* PARTICULAR PURPOSE.
*
* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
* FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN
* ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
* THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
*******************************************************************************/
// DOM-IGNORE-END

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************
/*  This section Includes other configuration headers necessary to completely
    define this configuration.
*/

#include "user.h"
#include "device.h"

// DOM-IGNORE-BEGIN
#ifdef __cplusplus  // Provide C++ Compatibility

extern "C" {

#endif
// DOM-IGNORE-END

// *****************************************************************************
// *****************************************************************************
// Section: System Configuration
// *****************************************************************************
// *****************************************************************************



// *****************************************************************************
// *****************************************************************************
// Section: System Service Configuration
// *****************************************************************************
// *****************************************************************************
/* TIME System Service Configuration Options */
#define SYS_TIME_INDEX_0                            (0)
#define SYS_TIME_MAX_TIMERS                         (5)
#define SYS_TIME_HW_COUNTER_WIDTH                   (32)
#define SYS_TIME_HW_COUNTER_PERIOD                  (0xFFFFFFFFU)
#define SYS_TIME_HW_COUNTER_HALF_PERIOD             (SYS_TIME_HW_COUNTER_PERIOD>>1)
#define SYS_TIME_CPU_CLOCK_FREQUENCY                (48000000)
#define SYS_TIME_COMPARE_UPDATE_EXECUTION_CYCLES    (200)



// *****************************************************************************
// *****************************************************************************
// Section: Driver Configuration
// *****************************************************************************
// *****************************************************************************


// *****************************************************************************
// *****************************************************************************
// Section: Middleware & Other Library Configuration
// *****************************************************************************
// *****************************************************************************

/*** wolfCrypt Library Configuration ***/
#define MICROCHIP_PIC32
#define MICROCHIP_MPLAB_HARMONY
#define MICROCHIP_MPLAB_HARMONY_3
#define HAVE_MCAPI
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define NO_FILESYSTEM
#define WOLF_CRYPTO_CB  // provide call-back support
#define WOLFCRYPT_ONLY

#define BENCH_EMBEDDED
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_256

#define WC_NO_HARDEN
#define SINGLE_THREADED
#define NO_ERROR_STRINGS
#define NO_WOLFSSL_MEMORY
#define NO_MAIN_DRIVER
#define USE_FLAT_TEST_H
#define USE_FLAT_BENCHMARK_H

// ---------- FUNCTIONAL CONFIGURATION START ----------
//#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA224
#define WOLFSSL_AES_128
#define WOLFSSL_AES_192
#define WOLFSSL_AES_256
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_DECRYPT
#define HAVE_AES_ECB
#define HAVE_AES_CBC
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_OFB
#define HAVE_AESGCM
#define HAVE_AESCCM
#define HAVE_ECC
#define ECC_USER_CURVES
#define NO_DEV_RANDOM
#define HAVE_HASHDRBG

#define NO_MD4
#define NO_DH
#define NO_RSA
#define NO_DSA
#define NO_RC4
#define NO_HC128
#define NO_RABBIT
#define NO_PWDBASED

/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
/* 1=Fast (stack)                      (tfm.c)
 * 2=Normal (heap)                     (integer.c)
 * 3-5=Single Precision: only common curves/key sizes:
 *                   (ECC 256/384/521 and RSA/DH 2048/3072/4096)
 *   3=Single Precision C              (sp_c32.c)
 *   4=Single Precision ASM Cortex-M3+ (sp_cortexm.c)
 *   5=Single Precision ASM Cortex-M0  (sp_armthumb.c)
 * 6=Wolf multi-precision C small      (sp_int.c)
 * 7=Wolf multi-precision C big        (sp_int.c)
 */

#define WOLF_CONF_MATH 5
#if defined(WOLF_CONF_MATH) && WOLF_CONF_MATH == 1
    /* fast (stack) math - tfm.c */
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT

    #if !defined(NO_RSA) || !defined(NO_DH)
        /* Maximum math bits (Max DH/RSA key bits * 2) */
        #undef  FP_MAX_BITS
        #define FP_MAX_BITS (2*2048)
    #else
        #undef  FP_MAX_BITS
        #define FP_MAX_BITS (2*256)
    #endif

    /* Optimizations (TFM_ARM, TFM_ASM or none) */
    //#define TFM_NO_ASM
    //#define TFM_ASM
#elif defined(WOLF_CONF_MATH) && WOLF_CONF_MATH == 2
    /* heap math - integer.c */
    #define USE_INTEGER_HEAP_MATH
#elif defined(WOLF_CONF_MATH) && (WOLF_CONF_MATH >= 3)
    /* single precision only */
    #if WOLF_CONF_MATH != 7
        #define WOLFSSL_SP_SMALL      /* use smaller version of code */
    #endif
    #ifndef NO_RSA
        #define WOLFSSL_HAVE_SP_RSA
        //#define WOLFSSL_SP_NO_2048
        //#define WOLFSSL_SP_NO_3072
        //#define WOLFSSL_SP_4096
    #endif
    #ifndef NO_DH
        #define WOLFSSL_HAVE_SP_DH
    #endif
    #ifdef HAVE_ECC
        #define WOLFSSL_HAVE_SP_ECC
        //#define WOLFSSL_SP_NO_256
        //#define WOLFSSL_SP_384
        //#define WOLFSSL_SP_521
    #endif
    #if WOLF_CONF_MATH == 6 || WOLF_CONF_MATH == 7
        #define WOLFSSL_SP_MATH_ALL /* use sp_int.c multi precision math */
    #else
        #define WOLFSSL_SP_MATH    /* disable non-standard curves / key sizes */
    #endif
    #define SP_WORD_SIZE 32 /* force 32-bit mode */

    /* Enable to put all math on stack (no heap) */
    //#define WOLFSSL_SP_NO_MALLOC

    #if WOLF_CONF_MATH == 4 || WOLF_CONF_MATH == 5
        #define WOLFSSL_SP_ASM /* required if using the ASM versions */
        #if WOLF_CONF_MATH == 4
            /* ARM Cortex-M3+ */
            #define WOLFSSL_SP_ARM_CORTEX_M_ASM
        #endif
        #if WOLF_CONF_MATH == 5
            /* Generic ARM Thumb (Cortex-M0) Assembly */
            #define WOLFSSL_SP_ARM_THUMB_ASM
        #endif
    #endif
#endif

/* Symmetric Assembly Speedups */
#if 0
    #define WOLFSSL_ARMASM
    #define WOLFSSL_ARMASM_INLINE
    #define WOLFSSL_ARMASM_NO_HW_CRYPTO
    #define WOLFSSL_ARMASM_NO_NEON
    #define WOLFSSL_ARM_ARCH 6
#endif


/* Override Current Time */
/* Allows custom "custom_time()" function to be used for benchmark */
#define WOLFSSL_USER_CURRTIME
#define WOLFSSL_GMTIME
#define USER_TICKS
extern unsigned long my_time(unsigned long* timer);
#define XTIME my_time

// ---------- FUNCTIONAL CONFIGURATION END ----------



// *****************************************************************************
// *****************************************************************************
// Section: Application Configuration
// *****************************************************************************
// *****************************************************************************


//DOM-IGNORE-BEGIN
#ifdef __cplusplus
}
#endif
//DOM-IGNORE-END

#endif // CONFIGURATION_H
/*******************************************************************************
 End of File
*/
