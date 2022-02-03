# wolfCrypt Test Application

This demo application runs the wolfCrypt cryptography algorithm tests on
the PIC32MZ leveraging an ATECC608A Trust&GO.

wolfCrypt is the cryptography library that is included in the wolfSSL
embedded SSL/TL library. It includes software implementations of all supported
cryptography algorithms, but can offload algorithm operations to hardware-based
cryptography modules when available and supported. This application demonstrates
that by offloading ECDSA, ECDH, and RNG operations to a Microchip ATECC608A
module over I2C.

## Running the Application

The application is pre-configured for the PIC32MZ EF Curiosity 2.0 board
with LAN Daughter Board and DT100104 ATECC608A I2C mikroBUS module. To run
the application:

1. Install MPLABX, Microchip Harmony 3, and an application to read serial
debug messages on your development machine. On OSX, CoolTerm was used during
development of this demo application.

2. Set up the PIC32 Curiosity board, including installation of the LAN
Daughter Board and ATECC608A DT100104 module.

3. Connect the PIC32 Curiosity board to your development machine using the
TARGET USB and DEBUG USB ports on the board. Connect the LAN daughter board
to an active Ethernet cable.

4. Open the MPLABX project file, located at:

```
microchip-atecc-demos/wolfcrypt_test/firmware/pic32mz_ef_curiosity_2.X
```

5. Adjust IP address, network configuration, and NTP server information to
match your development environment and network setup. Do this by opening the
following file:

```
microchip-atecc-demos/wolfcrypt_test/firmware/src/config/pic32mz_ef_curiosity_2/configuration.h
```

Edit the following defines:

```
TCPIP_NETWORK_DEFAULT_IP_ADDRESS_IDX0
TCPIP_NETWORK_DEFAULT_IP_MASK_IDX0
TCPIP_NETWORK_DEFAULT_GATEWAY_IDX0
TCPIP_NETWORK_DEFAULT_DNS_IDX0
TCPIP_NETWORK_DEFAULT_SECOND_DNS_IDX0
```

Also, edit the NTP time server to one of your choosing. The default server is:

```
#define TCPIP_NTP_SERVER "0.pool.ntp.org"
```

6. In MPLABX, right click on the project and "Set as Main Project", then
build the main project. Project compilation should succeed without errors
or warnings.

7. Open a serial appliation on your development machine and open a connection
to the development board. Serial port settings should match:

```
Baud Rate: 115200
Data Bits: 8
Parity: none
Stop Bits: 1
Flow Control: None
```

8. Debug the project by selecting the Debug->Debug Main Project menu item,
or by using the cooresponding toolbar icon. Output from the test application
should be written to the serial port and show up in your serial application
output.  Output should be similar to the following:

```
Interface PIC32INT on host MCHPBOARD_E     - NBNS disabled
PIC32INT IP Address: 192.168.2.129
SNTP initiated successfully
Got SUCCESSFUL SNTP timestamp
Trying to get seconds from SNTP
SNTP seconds = 1587082998
atcab_init() success
CONFIG zone locked: yes
DATA zone locked: yes
revision:
00 00 60 02
serial number:
01 23 4E 7C AE 66 7E 6E 01

Initializing wolfSSL
Running wolfCrypt tests
------------------------------------------------------------------------------
 wolfSSL version 4.3.0
------------------------------------------------------------------------------
error    test passed!
MEMORY   test passed!
base64   test passed!
asn      test passed!
RANDOM   test passed!
MD5      test passed!
SHA      test passed!
SHA-256  test passed!
SHA-384  test passed!
SHA-512  test passed!
SHA-3    test passed!
Hash     test passed!
HMAC-MD5 test passed!
HMAC-SHA test passed!
HMAC-SHA256 test passed!
HMAC-SHA384 test passed!
HMAC-SHA512 test passed!
HMAC-SHA3   test passed!
HMAC-KDF    test passed!
GMAC     test passed!
DES      test passed!
DES3     test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-GCM  test passed!
AES-CCM  test passed!
RSA      test passed!
ECC      test passed!
logging  test passed!
mutex    test passed!
crypto callback test passed!
Test complete
```

