# CryptoAuth Trust Platform wolfSSL Example

## Hardware

* DM320118: CryptoAuth Trust Platform
* Wifi7click: ATWINC1510

## Software

* MPLAB X v5.40
* Microchip XC32 v2.50 compiler
* Microchip Harmony 3
* cryptoauthlib: v3.1.0
* wolfSSL: v4.5.0

## Building

Harmony v3 code generation alters files and needs the following changes:

`configuration.h`:

```c
-//#define MICROCHIP_TCPIP
+#define MICROCHIP_TCPIP

#define HAVE_HKDF
#define HAVE_PK_CALLBACKS

`atca_config.h`:

```c
/* Enable HAL I2C */
#ifndef ATCA_HAL_I2C
#define ATCA_HAL_I2C
#endif

/** Include Device Support Options */
#define ATCA_ATECC608A_SUPPORT

/* Define generic interfaces to the processor libraries */
#define PLIB_I2C_ERROR          SERCOM_I2C_ERROR
#define PLIB_I2C_ERROR_NONE     SERCOM_I2C_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP SERCOM_I2C_TRANSFER_SETUP

typedef bool (*atca_i2c_plib_read)( uint16_t, uint8_t *, uint32_t );
typedef bool (*atca_i2c_plib_write)( uint16_t, uint8_t *, uint32_t );
typedef bool (*atca_i2c_plib_is_busy)( void );
typedef PLIB_I2C_ERROR (* atca_i2c_error_get)( void );
typedef bool (*atca_i2c_plib_transfer_setup)(PLIB_I2C_TRANSFER_SETUP* setup, uint32_t srcClkFreq);

typedef struct atca_plib_api
{
    atca_i2c_plib_read              read;
    atca_i2c_plib_write             write;
    atca_i2c_plib_is_busy           is_busy;
    atca_i2c_error_get              error_get;
    atca_i2c_plib_transfer_setup    transfer_setup;
} atca_plib_i2c_api_t;

extern atca_plib_i2c_api_t sercom2_plib_i2c_api;

/** Define certificate templates to be supported. */
#define ATCA_TNGTLS_SUPPORT
#define ATCA_TNG_LEGACY_SUPPORT
```
