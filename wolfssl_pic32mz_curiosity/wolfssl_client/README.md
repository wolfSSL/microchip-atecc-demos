# wolfSSL Client Application

This demo application runs a wolfSSL example client on the PIC32MZ
leveraging an ATECC608A Trust&GO module.

wolfSSL is a lightweight, embedded SSL/TLS library that supports the most
current SSL/TLS protocol standards up to TLS 1.3 and DTLS 1.2. wolfSSL is
designed for maximum portability and modularity, with an easy-to-use API and
full feature set.

wolfCrypt, wolfSSL's cryptography library, includes software implementations
of all supported cryptography algorithms, but can offload algorithm operations
to hardware-based cryptography modules when available and supported. This
application demonstrates that ability by offloading ECDSA, ECDH, and RNG
operations to a Microchip ATECC608A module over I2C.

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
microchip-atecc-demos/wolfssl_client/firmware/pic32mz_ef_curiosity_2.X
```

5. Adjust IP address, network configuration, and NTP server information to
match your development environment and network setup. Do this by opening the
following file:

```
microchip-atecc-demos/wolfssl_client/firmware/src/config/pic32mz_ef_curiosity_2/configuration.h
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

6. This application will try to connect to a TLS 1.2 server, send an HTTP
GET message, then print the server respose received. In order for it to make
a successful connection, an example TLS 1.2 server should be available for
testing.

This demo was developed by testing against the wolfSSL example
server application, which ships with the wolfSSL library (available for
download from the [wolfSSL website](https://www.wolfssl.com)). For full
details about configuring and compiling wolfSSL on desktop platforms, reference
the [wolfSSL Manual](https://www.wolfssl.com/docs/wolfssl-manual/). Simple
instructions for compiling and running the wolfSSL example server on a
Unix/Linux environment are shown below.

wolfSSL uses the autoconf system for compilation on Unix/Linux environments. To
compile a default build of wolfSSL and start the example server for use with
this demo, follow the steps below:

```
$ cd wolfssl-X.X.X
$ ./configure
$ make
$ make check

$ ./examples/server/server -v 3 -b -p 11111 -c ./certs/server-ecc.pem -k ./certs/ecc-key.pem -A <microchip-atecc-demos>/certs/CryptoAuthenticationRootCA002.pem
```

This will start the example server on port 11111 using the wolfSSL example ECC
server certificate and key file. It will also load the Microchip Crypto
Authentication Root CA 002 as a trusted root CA in order to authenticate the
client device.

7. Adjust the server IP and port in the client application to match your
server example endpoint. In the following file, set the **SERVER_HOST** and
**SERVER_PORT** variables accordingly:

```
microchip-atecc-demos/wolfssl_client/firmware/src/app.c
```

8. Open a serial appliation on your development machine and open a connection
to the development board. Serial port settings should match:

```
Baud Rate: 115200
Data Bits: 8
Parity: none
Stop Bits: 1
Flow Control: None
```

9. In MPLABX, right click on the project and "Set as Main Project", then
build the main project. Project compilation should succeed without errors
or warnings.

10. Debug the project by selecting the Debug->Debug Main Project menu item,
or by using the cooresponding toolbar icon. Output from the test application
should be written to the serial port and show up in your serial application
output.  Output should be similar to the following:

```
TCP/IP Stack: Initialization Started

TCP/IP Stack: Initialization Ended - success

Interface PIC32INT on host MCHPBOARD_E     - NBNS disabled
PIC32INT IP Address: 192.168.2.129
SNTP initiated successfully
Got SUCCESSFUL SNTP timestamp
Trying to get seconds from SNTP
SNTP seconds = 1587138992
atcab_init() success
CONFIG zone locked: yes
DATA zone locked: yes
revision:
00 00 60 02
serial number:
01 23 4E 7C AE 66 7E 6E 01

IO protection key slot already locked, skipping setup
Initializing wolfSSL
gethostbyname(192.168.2.229) passed
Creating socket
BSD TCP client: connecting...
connect() success, loading certs/keys
Successfully read signer cert
Successfully read signer pub key

Built server's signer certificate
Successfully read device cert
Successfully read device pub key

Built client certificate
Created wolfTLSv1_2_client_method()
Created new WOLFSSL_CTX
Loaded verify cert buffer into WOLFSSL_CTX
Loaded client cert into WOLFSSL_CTX

Random Number4D 2D 8A E3 E2 92 44 FA F4 FE 6F 33 73 DC 77 8B
78 98 D8 FB 88 89 4D 5F BA C7 49 7F CF 38 D5 61
F1 5B AB 4E 64 A8 57 55 42 02 42 AB B7 57 51 F5
49 FC CC A6

Loaded certs into wolfSSL
Registered SOCKET with wolfSSL
wolfSSL_connect() success!
Sent HTTP GET to peer
Response from server:
----------
HTTP/1.1 200 OK
Content-Type: text/html
Connection: close
Content-Length: 14
----------
Shutdown and freed WOLFSSL session
Freed WOLFSSL_CTX

Connection Closed
```

