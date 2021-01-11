# CryptoAuth Trust Platform wolfMQTT Example

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

1. Create a new project for your target board

2. Using the Harmony Configuration tool make sure the following components are selected:

* ATECC608
  - Click on the Instance 0 and choose interface type -> "Trust & Go: TLS"
* Trust&Go
  - Choose TNGTLS Certificates and Legacy Trust Certificates.
* wolfSSL
* wolfCrypt
* wolfMQTT
* WINC

3. Harmony v3 code generation needs a few changes

See wolmqtt_trust_platform_patch.diff and apply using `patch -p1 < wolfmqtt_trust_platform_patch.diff`.


## Running the example


1. Modify the `common/wolf_mqtt_task.c` or specify as build pre-processor macros:

* `WLAN_SSID`
* `WLAN_PSK`

2. Setup the Azure IoT Hub settings or use our example settings:

* `AZURE_HOST`
* `AZURE_DEVICE_ID`
* `AZURE_KEY`

3. Run the Azure IoT Hub MQTT client example:

Example Console Output:

```
===========================
AzureIoTHub Client: QoS 1, Use TLS 1
===========================
Initializing wolfSSL
MQTT Net Init: Success (0)
MQTT Init: Success (0)
Wifi Connected
IP address is 192.168.0.236
Waiting for network time sync
Time 1610402250
SharedAccessSignature sr=momuno-V2-hub.azure-devices.net%2fdevices%2fsas-test-wolfssl-websocket&sig=iEvUhC%2bXHBQCWIc4DO4Q1QP6MO%2fLFgRmbAwCO%2fd5P8s%3d&se=1610405850
DNS Lookup momuno-V2-hub.azure-devices.net
WINC1500 WIFI: DNS lookup:  Host:       momuno-V2-hub.azure-devices.net  IP Address: 52.185.70.163
Creating socket
TCP client: connecting...
connect() success
Loaded verify cert buffer into WOLFSSL_CTX
MQTT TLS Setup (1)
Send: 0x2000341b (90): Res 0
WINC Recv: 1380 bytes
Recv: 0x20002a38 (5): recvd 5, remain 1375
Recv: 0x20003420 (88): recvd 88, remain 1287
Recv: 0x20002a38 (5): recvd 5, remain 1282
Recv: 0x20003610 (1809): recvd 1282, remain 0
WINC Recv: 752 bytes
Recv: 0x20003b12 (527): recvd 527, remain 225
MQTT TLS Verify Callback for azureiothub: PreVerify 1, Error 0 (none)
  Subject's domain name is DigiCert Global Root G3
MQTT TLS Verify Callback for azureiothub: PreVerify 1, Error 0 (none)
  Subject's domain name is *.azure-devices.net
Recv: 0x20002a38 (5): recvd 5, remain 220
Recv: 0x20004168 (148): recvd 148, remain 72
Recv: 0x20002a38 (5): recvd 5, remain 67
Recv: 0x20003440 (58): recvd 58, remain 9
Recv: 0x20002a38 (5): recvd 5, remain 4
Recv: 0x20002a38 (4): recvd 4, remain 0
Send: 0x2000346b (12): Res 0
Send: 0x2000342b (75): Res 0
Send: 0x2000346b (6): Res 0
Send: 0x200037bb (45): Res 0
WINC Recv: 51 bytes
Recv: 0x20002a38 (5): recvd 5, remain 46
Recv: 0x20002a38 (1): recvd 1, remain 45
Recv: 0x20002a38 (5): recvd 5, remain 40
Recv: 0x20003428 (40): recvd 40, remain 0
MQTT Socket Connect: Success (0)
WINC Send: 1
Send: 0x20002ea3 (322): Res 0
WINC Recv: 33 bytes
Recv: 0x20002a38 (5): recvd 5, remain 28
Recv: 0x20003008 (28): recvd 28, remain 0
MQTT Connect: Success (0)
MQTT Connect Ack: Return Code 0, Session Present 0
Send: 0x20002f8b (93): Res 0
WINC Recv: 34 bytes
Recv: 0x20002a38 (5): recvd 5, remain 29
Recv: 0x20003008 (29): recvd 29, remain 0
MQTT Subscribe: Success (0)
  Topic devices/sas-test-wolfssl-websocket/messages/devicebound/#, Qos 1, Return Code 1
Send: 0x20002f93 (86): Res 0
WINC Recv: 33 bytes
Recv: 0x20002a38 (5): recvd 5, remain 28
Recv: 0x20003008 (28): recvd 28, remain 0
MQTT Publish: Topic devices/sas-test-wolfssl-websocket/messages/events/, Success (0)
MQTT Waiting for message...
```

## Support

For questions please email support@wolfssl.com
