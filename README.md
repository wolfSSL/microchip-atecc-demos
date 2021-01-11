# wolfSSL ATECC608 Demo Applications

This repository contains a set of demo applications for the [wolfSSL](https://www.wolfssl.com/products/wolfssl/) embedded
SSL/TLS library using the Microchip ATECC608A module. wolfSSL is a lightweight,
embedded SSL/TLS library that supports up to the most current TLS 1.3 and
DTLS 1.2 protocols. These demos use the Microchip ATECC608A Trust&GO module configuration by deafult, but could be easily adapted to be run with either TrustFLEX or TrustCUSTOM modules.

## Copyright Notice

This repository is intended for demo/example purposes only. It includes
driver and middleware code which is copyright of Microchip Technology Inc.

## SAMD21 CryptoAuth Trust Platform Demos (see links)

* wolfMQTT TLS Client: [wolfmqtt_trust_platform](./wolfmqtt_trust_platform)
* wolfSSL TLS Client: [wolfssl_client_trust_platform](./wolfssl_client_trust_platform)

## Software and Hardware Demo Details

The included demo applications have been created for the following development
environment and hardware platform:

**IDE**: MPLABX v5.35 \
**Compiler**: Microchip XC32 v2.30 compiler \
**Harmony**: Microchip Harmony 3 \
**cryptoauthlib**: v3.1.0 \
**wolfSSL**: modified version of 4.3.0

[PIC32MZEF Curiosity 2.0 board (DM320209)](https://www.microchip.com/Developmenttools/ProductDetails/DM320209) \
[LAN8720A PHY Daughter Board (AC320004-3)](https://www.microchip.com/DevelopmentTools/ProductDetails/PartNO/AC320004-3) \
[ATECC608A Trust (DT100104)](https://www.microchip.com/developmenttools/ProductDetails/DT100104) - using TNGTLS (Trust&GO) module


# Overview of Demo Applications

This repository contains the following demo applications. These applications
have been set up to use the pre-configured Microchip Trust&GO ATECC608A
module.

## wolfCrypt Test Application

Located in the "wolfcrypt_test" directory, this application runs the
wolfCrypt cryptography tests and verifies all algorithms are working
correctly on the target platform. See the README.md located in the
"wolfcrypt_test" directory for more details.

## wolfSSL Example Client

Located in the "wolfssl_client" directory, this application makes a simple
TLS 1.2 client connection, sends an HTTP GET message, and prints the server
response that is received. See the README.md located in the "wolfssl_client"
directory for more details.

## wolfSSL Example Server

Located in the "wolfssl_server" directory, this application runs a simple
single-threaded TLS 1.2 server application. This server waits for a client
connection, establishes a secure TLS 1.2 connection, reads a message from
the client, then sends back a simple HTTP web page in response. See the
README.md located in the "wolfssl_server" directory for more details.

# wolfSSL ATECC Build Options

wolfSSL has several build options for customizing the integration of
the library with ATECC508/608A modules. Further documentation can be found in
the README.md located in the wolfSSL library, at:

<wolfssl>/wolfcrypt/src/port/atmel/README.md

**WOLFSSL_ATECC508A** - Enable support for ATECC508A modules. \
**WOLFSSL_ATECC608A** - Enable support for ATECC608A modules using the
Microchip cryptoauthlib library. By default uses wolfSSL's default ATECC slot
configuration settings. ATECC608A slot usage settings can be customized by
implementing a custom slot allocator function (see below), or by enabling
wolfSSL support for pre-configured ATECC608A module such as Trust&GO. \
**WOLFSSL_ATECC_TNGTLS** - Used in addition to WOLFSSL_ATECC608A to enable \
out-of-the-box support and slot configuration for Microchip Trust&GO modules. \
**WOLFSSL_ATECC_PKCB** - Enables support for the reference public key (PK)
callbacks without requiring appliations to manual initialize them. \
**WOLFSSL_ATECC_RNG** - Enable support for using ATECC RNG. \
**WOLFSSL_ATECC_SHA256** - Enable support for using ATECC SHA-256. \
**WOLFSSL_ATECC_ECDH_ENC** - Enable use of atcab_ecdh_enc() for encrypted ECDH
operations. Note that this requires special slot configuration, and in most
cases WOLFSSL_ATECC_ECDH_IOENC should be used instead. \
**WOLFSSL_ATECC_ECDH_IOENC** - Enable use of atcab_ecdh_ioenc() for encrypted
ECDH operations using the ATECC I/O protection key for encryption. \
**WOLFSSL_ATECC_DEBUG** - Enable wolfSSL ATECC debug messages. \
**ATECC_GET_ENC_KEY** - Macro to define your own function for getting the I/O
encryption key. See examples for sample usage.

# Microchip Trust&GO Support

wolfSSL fully supports integration with the pre-configured and provisioned
[Trust&GO TLS](https://www.microchip.com/wwwproducts/en/ATECC608A-TNGTLS)
modules. When using wolfSSL with Trust&GO modules, both WOLFSSL_ATECC608A and
WOLFSSL_ATECC_TNGTLS should be defined when compiling the library sources.
Other defines can be added as needed/required.

The [ATECC608A-TNGTLS datasheet](http://ww1.microchip.com/downloads/en/DeviceDoc/ATECC608A-TNGTLS-CryptoAuthentication-Data-Sheet-DS40002112B.pdf)
can be found on the Microchip website for full module details.

wolfSSL uses the following slot configuration with Trust&GO modules:

* Slot 0 - Device ECC private key, used for ECDSA sign/verify operations
* Slot 2 - ECDH key slot, used for ECDH shared secret generation
* Slot 6 - I/O protection key slot, used to encrypt ECDH shared secret

The examples in this repository use the following ATECC configuration with
to initialize cryptoauthlib and the ATECC608A I2C module:

```
/* configuration for ATECC608A Trust&GO module */
ATCAIfaceCfg atecc608a_0_init_data_TNGTLS = {
       .iface_type            = ATCA_I2C_IFACE,
       .devtype               = ATECC608A,
       .atcai2c.slave_address = 0x6A,
       .atcai2c.bus           = 0,
       .atcai2c.baud          = 400000,
       .wake_delay            = 1500,
       .rx_retries            = 20,
       .cfg_data              = &i2c1_plib_api
};
```

# Microchip TrustFLEX Support

Although these demo applications are set up to use the Microchip Trust&GO
modules by default, they should be easily adaptable to the TrustFLEX modules.
TrustFLEX uses the same slot configuration as Trust&GO, with the main
difference being that custom certificates are used and provisioned to the
module instead of the default Microchip certificates used with Trust&GO.
On the ATECC608A development kits, TrustFLEX modules use a different I2C
address than Trust&GO (0xC6). To connect to these modules, a cryptoauthlib
configuration would need to be used similar to below:

```
/* configuration for ATECC608A TrustFLEX module */
ATCAIfaceCfg atecc608a_0_init_data_TrustFLEX = {
       .iface_type            = ATCA_I2C_IFACE,
       .devtype               = ATECC608A,
       .atcai2c.slave_address = 0xC6,
       .atcai2c.bus           = 0,
       .atcai2c.baud          = 400000,
       .wake_delay            = 1500,
       .rx_retries            = 20,
       .cfg_data              = &i2c1_plib_api
};
```

If using these demo applications with a TrustFLEX module, areas of code that
use the cryptoauthlib TNG APIs will need to be converted to loading the
correct device and signer certificates. For example, in the "wolfssl_client"
and "wolfssl_server" applications, functionality in "common/tls_common.c"
will need to be adjusted. There are reference functions commented out which
can act as a starting point: tls_build_signer_ca_cert() and
tls_build_end_user_cert(), which would replace the Trust&GO specific functions:
tls_build_signer_ca_cert_tlstng() and tls_build_end_user_cert_tlstng().

# Microchip TrustCUSTOM Support

wolfSSL is compatible with Microchip TrustCUSTOM modules through the ability
for users to write and register their own ATECC608A slot allocator function
with wolfSSL. This will allow wolfSSL to use a custom slot definition for
ECDSA and ECDH operations. On ATECC608A development kits, the Microchip
TrustCUSTOM modules use a different I2C address than Trust&GO or TrustFLEX.
The default I2C address for TrustCUSTOM is 0xC0. To connect to these modules,
a cryptoauthlib configuration would need to be used similar to below:

```
/* configuration for ATECC608A TrustCUSTOM module */
ATCAIfaceCfg atecc608a_0_init_data_TrustCUSTOM = {
       .iface_type            = ATCA_I2C_IFACE,
       .devtype               = ATECC608A,
       .atcai2c.slave_address = 0xC0,
       .atcai2c.bus           = 0,
       .atcai2c.baud          = 400000,
       .wake_delay            = 1500,
       .rx_retries            = 20,
       .cfg_data              = &i2c1_plib_api
};
```

# wolfSSL ATECC608A Integration Notes

## wolfSSL ATECC608A Integration Layer

wolfSSL integrates with ATECC608A modules and cryptoauthlib primarily in
the following two source files (header and source):

```
<wolfssl>/wolfssl/wolfcrypt/port/atmel/atmel.h
<wolfssl>/wolfcrypt/src/port/atmel/atmel.c
```

## Custom Slot Allocator

wolfSSL uses a default slot allocation scheme for ATECC508A or ATECC608A
Trust&GO modules. This default slot allocator can be found in atmel.c, and is
called atmel_ecc_alloc(). There is also a default slot free function called
atmel_ecc_free(). The default slot allocator is set up to allow individual
slots to be changed in the existing allocator structure using the following
preprocessor defines:

**ATECC_MAX_SLOT** - Sets the maximum usable slot number \
**ATECC_SLOT_AUTH_PRIV** - Device key, used for ECDSA sign/verify \
**ATECC_SLOT_ECDHE_PRIV** - Ephemeral ECDH key slot \
**ATECC_SLOT_I2C_ENC** - Symmetric I/O protection key \
**ATECC_SLOT_ENC_PARENT** - Key used to encrypt ECDH shared secrets

By default, the wolfSSL Trust&GO configuration (WOLFSSL_ATECC_TNGTLS) uses
the following slots:

```
#define ATECC_MAX_SLOT        (0x8)    /* only use slots 0-7 */
#define ATECC_SLOT_AUTH_PRIV  (0x0)    /* device private key */
#define ATECC_SLOT_ECDHE_PRIV (0x2)    /* ECDHE key slot */
#define ATECC_SLOT_I2C_ENC    (0x06)   /* I/O protection key */
#define ATECC_SLOT_ENC_PARENT (0x6)    /* ECDH encryption key */
```

If the above defines do not allow for enough customization, users can write
a custom slot allocator function to return slot numbers to wolfSSL when
a specific type of operation is requested. A custom slot alloctor and free
function can be registered by using the following function:

```
#include <wolfssl/wolfcrypt/port/atmel/atmel.h>

typedef int  (*atmel_slot_alloc_cb)(int slotType);
ypedef void  (*atmel_slot_dealloc_cb)(int slotId);

int atmel_set_slot_allocator(atmel_slot_alloc_cb alloc,
                             atmel_slot_dealloc_cb dealloc);
```

Custom allocator functions should accept a slotType, which will be requested
by wolfSSL when required by internal ECDSA/ECDH functionality. Possible
slot types are listed in the "atmelSlotType" enum in atmel.h:

```
enum atmelSlotType {
    ATMEL_SLOT_ANY,
    ATMEL_SLOT_ENCKEY,
    ATMEL_SLOT_DEVICE,
    ATMEL_SLOT_ECDHE,
    ATMEL_SLOT_ECDHE_ENC,
};
```

## Setting the ATECC608A I2C configuration with wolfSSL

Before wolfSSL can use and interact with ATECC608A modules over I2C,
applications should provide wolfSSL with the correct ATCAIfaceCfg definition
through the following function:

```
#include <wolfssl/wolfcrypt/port/atmel/atmel.h>

int wolfCrypt_ATECC_SetConfig(ATCAIfaceCfg* cfg);
```

## Setting the Correct I/O Protection Key

Several ATECC608A operations can encrypt the data being transferred via I2C
using the I/O protection key. This key is commonly set up during an initial
pairing between the ATECC608A module an MCU, so that they both share the
same key and can use it to encrypt/decrypt data travelling over the I2C bus.

By default, wolfSSL uses a I/O protection key of all zero's. Applications should
provide wolfSSL with the ability to obtain the actual I/O protection key. They
can do this by defining the following macro to a function that copies the
protection key into the 'enckey' argument array:

```
#define ATECC_GET_ENC_KEY(enckey, keysize) atmel_get_enc_key_default((enckey), (keysize))
```

# Support

For support inquiries and questions, please email support@wolfssl.com.

