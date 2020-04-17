# wolfSSL Server Application

This demo application runs a wolfSSL example TLS server on the PIC32MZ
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
microchip-atecc-demos/wolfssl_server/firmware/pic32mz_ef_curiosity_2.X
```

5. Adjust IP address, network configuration, and NTP server information to
match your development environment and network setup. Do this by opening the
following file:

```
microchip-atecc-demos/wolfssl_server/firmware/src/config/pic32mz_ef_curiosity_2/configuration.h
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

6. Adjust the port in the server application to match your desired port, if
different than the default. The default port is 11111, and can be changed in
the following file by editing the **SERVER_PORT** define:

```
microchip-atecc-demos/wolfssl_server/firmware/src/app.c
```

7. Open a serial appliation on your development machine and open a connection
to the development board. Serial port settings should match:

```
Baud Rate: 115200
Data Bits: 8
Parity: none
Stop Bits: 1
Flow Control: None
```

8. In MPLABX, right click on the project and "Set as Main Project", then
build the main project. Project compilation should succeed without errors
or warnings.

9. Debug the project by selecting the Debug->Debug Main Project menu item,
or by using the cooresponding toolbar icon. Output from the test application
should be written to the serial port and show up in your serial application
output. You should see the server waiting for a client connection at this
point.

10. This application will start up a simple TLS 1.2 server on the PIC32MZ
device. It will wait for a client connection, set up a secure TLS connection,
wait for a messaage from the client, then send back a simple HTTP web page
in response. After sending the response, the server will shut down the TLS
session and wait for another client connection.

This demo was developed by testing against the wolfSSL example client
application, which ships with the wolfSSL library (available for download
from the [wolfSSL website](https://www.wolfssl.com)). For full details about
configuring and compiling wolfSSL on desktop platforms, reference the
[wolfSSL Manual](https://www.wolfssl.com/docs/wolfssl-manual/). Simple
instructions for compiling and running the wolfSSL example client on a
Unix/Linux environment are shown below.

wolfSSL uses the autoconf system for compilation on Unix/Linux environments. To
compile a default build of wolfSSL and start the example client for use with
this demo, follow the steps below:

```
$ cd wolfssl-X.X.X
$ ./configure
$ make
$ make check

$ ./examples/client/client -h <board_ip> -p 11111 -c ./certs/client-ecc-cert.pem -k ./certs/ecc-client-key.pem -A <microchip-atecc-demos>/certs/CryptoAuthenticationRootCA002.pem -C
```

This will start the example client, connecting to the board IP address on
port 11111. It will use the example ECC client certificate and key that wolfSSL
ships with, and load the Microchip Crypto Authentication Root CA 002 as a
trusted root CA in order to authenticate the server device.

After the client makes a connection to the server, output from the board
serial port should be similar to the following:

```
TCP/IP Stack: Initialization Started

TCP/IP Stack: Initialization Ended - success

Interface PIC32INT on host MCHPBOARD_E     - NBNS disabled
PIC32INT IP Address: 192.168.2.129
SNTP initiated successfully
Got SUCCESSFUL SNTP timestamp
Trying to get seconds from SNTP
SNTP seconds = 1587150929
atcab_init() success
CONFIG zone locked: yes
DATA zone locked: yes
revision:
00 00 60 02
serial number:
01 23 DC 5C 8C 24 13 28 01

Initializing wolfSSL
Successfully read signer cert
Successfully read signer pub key
Built server's signer certificate
Successfully read device cert
Successfully read device pub key
Built device certificate
Created wolfTLSv1_2_client_method()
Created new WOLFSSL_CTX
Loaded verify cert buffer into WOLFSSL_CTX
Loaded server certificate chain in to WOLFSSL_CTX
Loaded certs into wolfSSL, set up CTX
Created server socket
bind() on server socket finished
Waiting for client connection on port: 11111
Accepted client connection
Registered SOCKET with WOLFSSL session
wolfSSL_accept() success!
Waiting for data from client
Message from client:
----------
GET /index.html HTTP/1.0


----------
Sent HTTP web page to peer
Shutdown and freed WOLFSSL session

Connection Closed
Waiting for client connection on port: 11111
```

