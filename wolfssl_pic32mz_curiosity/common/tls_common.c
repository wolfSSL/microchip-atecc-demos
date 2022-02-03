
#include "definitions.h"
#include "cryptoauthlib.h"
#include "atcacert/atcacert_client.h"
#include "wolfssl/certs_test.h"
#include "wolfssl/ssl.h"
#include "tls_common.h"
#include "tng_atcacert_client.h"

t_atcert atcert = {
    .signer_ca_size = 521,
    .signer_ca = { 0 },
    .signer_ca_pubkey = { 0 },
    .end_user_size = 552,
    .end_user = { 0 },
    .end_user_pubkey = { 0 }
};

int tls_build_signer_ca_cert_tlstng(void)
{
    int ret = 0;
    size_t maxCertSz = 0;

    /* read signer certificate from ATECC module */
    ret = tng_atcacert_max_signer_cert_size(&maxCertSz);
    if (ret != ATCACERT_E_SUCCESS) {
        SYS_PRINT("Failed to get max signer cert size\r\n");
        return ret;
    }

    if (maxCertSz > atcert.signer_ca_size) {
        SYS_PRINT("Signer CA cert buffer too small, need to increase: max = %d\r\n", maxCertSz);
        return -1;
    }

    ret = tng_atcacert_read_signer_cert(atcert.signer_ca,
            (size_t*)&atcert.signer_ca_size);
    if (ret != ATCACERT_E_SUCCESS) {
        SYS_PRINT("Failed to read signer cert!\r\n");
        return ret;
    }
    SYS_PRINT("Successfully read signer cert\r\n");
    //atcab_printbin_label("\r\nSigner Certificate\r\n",
    //        atcert.signer_ca, atcert.signer_ca_size);

    /* read signer public key from ATECC module */
    ret = tng_atcacert_signer_public_key(atcert.signer_ca_pubkey,
            atcert.signer_ca);
    if (ret != ATCACERT_E_SUCCESS) {
        SYS_PRINT("Failed to read signer public key!\r\n");
        return ret;
    }
    SYS_PRINT("Successfully read signer pub key\r\n");
    //atcab_printbin_label("\r\nSigner Public Key\r\n",
    //        atcert.signer_ca_pubkey, sizeof(atcert.signer_ca_pubkey));

    return ret;
}

/*
 * If not using Trust&GO, application may need logic similar to below to
 * read the signer certificate from the ATECC608A module.
 */
/*int tls_build_signer_ca_cert(void)
{
    int ret = 0;

    ret = atcacert_read_cert(&g_cert_def_1_signer,
                             (const __uint8_t*)provisioning_root_public_key,
                             atcert.signer_ca, (size_t*)&atcert.signer_ca_size);
    if (ret != ATCA_SUCCESS) {
        SYS_PRINT("Failed to read signer cert!\r\n");
        return ret;
    }
    atcab_printbin_label("\r\nSigner Certificate\r\n",
            atcert.signer_ca, atcert.signer_ca_size);

    ret = atcacert_get_subj_public_key(&g_cert_def_1_signer, atcert.signer_ca,
            atcert.signer_ca_size, atcert.signer_ca_pubkey);
    if (ret != ATCA_SUCCESS) {
        SYS_PRINT("Failed to read signer public key!\r\n");
        return ret;
    }
    atcab_printbin_label("\r\nSigner Public Key\r\n",
            atcert.signer_ca_pubkey, sizeof(atcert.signer_ca_pubkey));

    return ret;
}*/


int tls_build_end_user_cert_tlstng(void)
{
    int ret = 0;
    size_t maxCertSz = 0;

    /* read device certificate from ATECC module */
    ret = tng_atcacert_max_device_cert_size(&maxCertSz);
    if (ret != ATCACERT_E_SUCCESS) {
        SYS_PRINT("Failed to get max device cert size\r\n");
        return ret;
    }

    if (maxCertSz > atcert.end_user_size) {
        SYS_PRINT("Device cert buffer too small, please increase, max = %d\r\n",
                  maxCertSz);
        return -1;
    }

    ret = tng_atcacert_read_device_cert(atcert.end_user,
            (size_t*)&atcert.end_user_size, NULL);
    if (ret != ATCACERT_E_SUCCESS) {
        SYS_PRINT("Failed to read device cert!\r\n");
        return ret;
    }
    SYS_PRINT("Successfully read device cert\r\n");
    //atcab_printbin_label("\r\nEnd User Certificate\r\n",
    //        atcert.end_user, atcert.end_user_size);

    ret = tng_atcacert_device_public_key(atcert.end_user_pubkey,
            atcert.end_user);
    if (ret != ATCACERT_E_SUCCESS) {
        SYS_PRINT("Failed to end user public key!\r\n");
        return ret;
    }
    SYS_PRINT("Successfully read device pub key\r\n");
    //atcab_printbin_label("\r\nEnd User Public Key\r\n",
    //        atcert.end_user_pubkey, sizeof(atcert.end_user_pubkey));

    return ret;
}

/*
 * If not using Trust&GO, application may need logic similar to below to
 * read the device certificate from the ATECC608A module.
 */
/*int tls_build_end_user_cert(void)
{
    int ret = 0;
    uint8_t device_signature[64];

    ret = atcacert_read_cert(&g_cert_def_2_device, atcert.signer_ca_pubkey,
            atcert.end_user, (size_t*)&atcert.end_user_size);
    if (ret != ATCA_SUCCESS) {
        SYS_PRINT("Failed to read device cert!\r\n");
        return ret;
    }
    atcab_printbin_label("\r\nEnd User Certificate\r\n",
            atcert.end_user, atcert.end_user_size);

    ret = atcacert_get_subj_public_key(&g_cert_def_2_device, atcert.end_user,
            atcert.end_user_size, atcert.end_user_pubkey);
    if (ret != ATCA_SUCCESS) {
        SYS_PRINT("Failed to end user public key!\r\n");
        return ret;
    }
    atcab_printbin_label("\r\nEnd User Public Key\r\n",
            atcert.end_user_pubkey, sizeof(atcert.end_user_pubkey));

    ret = atcacert_get_signature(&g_cert_def_2_device, atcert.end_user,
            atcert.end_user_size, device_signature);
    if (ret != ATCA_SUCCESS) {
        SYS_PRINT("Failed to end user signature!\r\n");
        return ret;
    }
    atcab_printbin_label("\r\nEnd User Signature\r\n",
            device_signature, sizeof(device_signature));

    return ret;
}*/

