# wolfSSL Client Example for Atmel ATECC508A

This example demonstrates the wolfSSL TLS Client with the Atmel ATECC508 ECC 256-bit hardware accelerator. This uses IO callbacks and UART to perform TLS.

## Installation
### Setup

The Atmel ATECC508A chips come from the factory un-programmed and need to be provisioned. Atmel provided us code as reference which exists in `cryptoauthlib/certs/provision.c`. The function is `atcatls_device_provision` and can be called more than once. If the device is not provisioned it will set it up with default slot settings. If its already provisioned it will skip.

Install the ATECC508A to EXT2 or EXT3 and the WINC1500 to EXT1. ATECC508A is configured to use I2C bus 2 on PTA8/PTA9.

The programming interface is SWD. The SAMD21 Xplained Pro board has a built in J-Link programmer.

You can configure your UART port in "config/conf_uart_serial.h" as either the UART at EXT2/EXT3 (PTB11 and PTB10 - default) or the EDBG CDC UART. The default baud rate is 115200. Use terminal software such as CoolTerm or Putty to interface to the console.

### Building

The wolfSSL client example is setup to be built from a terminal using GCC ARM and a Makefile in the `wolfssl_client/build/gcc` directory.

Example:

```
cd wolfssl_client/build/gcc
make
...
LN      wolfssl_client_flash.elf
SIZE    wolfssl_client_flash.elf
wolfssl_client_flash.elf  :
section              size         addr
.text              0x8410          0x0
.relocate            0xa8   0x20000000
.bss                 0xec   0x200000a8
.stack             0x4004   0x20000194
.ARM.attributes      0x28          0x0
.comment             0x6e          0x0
.debug_info       0x1f15b          0x0
.debug_abbrev      0x2a49          0x0
.debug_aranges      0x7b0          0x0
.debug_ranges       0x670          0x0
.debug_macro      0x1bc17          0x0
.debug_line        0xc4ea          0x0
.debug_str        0x8f62a          0x0
.debug_frame       0x262c          0x0
Total             0xe8d59


   text    data     bss     dec     hex filename
 0x8410    0xa8  0x40f0   50600    c5a8 wolfssl_client_flash.elf
```

### Programming
Use the resulting wolfssl_client_flash.bin to program your micro-controller using JTAG.

Using edgb (see included `wolfssl_client/build/gcc/flash.sh` script):
`edbg -bpv -t atmel_cm0p -f ./wolfssl_client_flash.bin`

### Debugging

GDB with pipe (see included `wolfcrypt_test/build/gcc/debug.sh` script):
`arm-none-eabi-gdb wolfssl_client_flash.elf -ex 'target remote | openocd -c "gdb_port pipe;" -f ../../../ASF/sam0/utils/openocd/atmel_samd21_xplained_pro.cfg'
load`

GDB with remote port:
`openocd -c "gdb_port 9993;" -f ../../../ASF/sam0/utils/openocd/atmel_samd21_xplained_pro.cfg`
`arm-none-eabi-gdb wolfssl_client_flash.elf -ex 'target remote localhost:9993'`
`load`
`c`

### Tools

https://github.com/ataradov/edbg.git
cd edbg
make all

### Support

For questions email us at support@wolfssl.com
