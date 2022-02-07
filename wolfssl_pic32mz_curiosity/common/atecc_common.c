
#include "definitions.h"
#include "cryptoauthlib.h"
#include "atcacert/atcacert_client.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/port/atmel/atmel.h"
#include "atecc_common.h"

/* I/O protection key used with examples */
uint8_t io_protection_key[ATECC_KEY_SIZE] = {
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
    0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
    0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
};

int get_608a_enc_key_default(byte* enckey, word16 keysize)
{
    if (enckey == NULL || keysize != ATECC_KEY_SIZE) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(enckey, io_protection_key, ATECC_KEY_SIZE);

    return 0;
}

int check_lock_status(void)
{
    ATCA_STATUS status;
    bool isLocked = false;

    status = atcab_is_locked(LOCK_ZONE_CONFIG, &isLocked);
    if (status != ATCA_SUCCESS) {
        SYS_PRINT("Error reading CONFIG zone lock\r\n");
    } else {
        SYS_PRINT("CONFIG zone locked: %s\r\n", isLocked == true ? "yes" : "no");
    }

    status = atcab_is_locked(LOCK_ZONE_DATA, &isLocked);
    if (status != ATCA_SUCCESS) {
        SYS_PRINT("Error reading DATA zone lock\r\n");
    } else {
        SYS_PRINT("DATA zone locked: %s\r\n", isLocked == true ? "yes" : "no");
    }

    return 0;
}

int print_info(void)
{
    uint8_t revision[4];
    uint8_t serialnum[ATCA_SERIAL_NUM_SIZE];
    char displaystr[ATCA_SERIAL_NUM_SIZE * 3];
    size_t displaylen = sizeof(displaystr);
    ATCA_STATUS status;

    /* revision info */
    status = atcab_info(revision);
    if (status != ATCA_SUCCESS) {
        SYS_PRINT("Failed to get revision information\r\n");
    } else {
        atcab_bin2hex(revision, 4, displaystr, &displaylen);
        SYS_PRINT("revision:\r\n%s\r\n", displaystr);
    }

    memset(displaystr, 0, sizeof(displaystr));
    displaylen = sizeof(displaystr);

    status = atcab_read_serial_number(serialnum);
    if (status != ATCA_SUCCESS) {
        SYS_PRINT("Failed to get serial number\r\n");
    } else {
        atcab_bin2hex(serialnum, ATCA_SERIAL_NUM_SIZE, displaystr, &displaylen);
        SYS_PRINT("serial number:\r\n%s\r\n\n", displaystr);
    }

    return 0;
}
