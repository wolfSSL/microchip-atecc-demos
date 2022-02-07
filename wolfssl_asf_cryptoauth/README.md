# wolfSSL / wolfCrypt demonstration package for Atmel ATECC508A

## Package Contents

This package contains the following:

1. Atmel Studio client / server TLS examples using PK_CALLBACKS. See [tls_demo/README.md](./tls_demo/README.md)
2. Atmel ASF Framework wolfCrypt example using GCC ARM Makefile. See [wolfcrypt_test/README.md](./wolfcrypt_test/README.md)
3. Atmel ASF Framework wolfSSL Client example using GCC ARM Makefile. See [wolfssl_client/README.md](./wolfssl_client/README.md)


## Benchmarks

Software only implementation (SAMD21 48Mhz Cortex-M0, Fast Math TFM-ASM):

```
ECC  256 key generation  3123.000 milliseconds, avg over 5 iterations
EC-DHE   key agreement   3117.000 milliseconds, avg over 5 iterations
EC-DSA   sign   time     1997.000 milliseconds, avg over 5 iterations
EC-DSA   verify time     5057.000 milliseconds, avg over 5 iterations
```

ATECC508A HW accelerated implementation:

```
ECC  256 key generation  144.400 milliseconds, avg over 5 iterations
EC-DHE   key agreement   134.200 milliseconds, avg over 5 iterations
EC-DSA   sign   time     293.400 milliseconds, avg over 5 iterations
EC-DSA   verify time     208.400 milliseconds, avg over 5 iterations
```

For reference the benchmarks for RNG, AES, MD5, SHA and SHA256 are:

```
RNG      25 kB took 0.784 seconds,    0.031 MB/s (coming from the ATECC508A)
AES      25 kB took 0.177 seconds,    0.138 MB/s
MD5      25 kB took 0.050 seconds,    0.488 MB/s
SHA      25 kB took 0.141 seconds,    0.173 MB/s
SHA-256  25 kB took 0.352 seconds,    0.069 MB/s
```

### Support

For questions email us at support@wolfssl.com
