
#include "app.h"
#include "definitions.h"
#include "cryptoauthlib.h"
#include "atecc_common.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/port/atmel/atmel.h>

APP_DATA appData;
int sntpTimestampReady = 0;

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

int wolfcrypt_test(void* args);

/* SNTP event callback, sets sntpTimestampReady when receives timestamp */
void sntpEventHandler(TCPIP_SNTP_EVENT evType, const void* evParam)
{
    if (evType < 0) {
        /* error occurred */
        SYS_PRINT("sntpEventHandler: error occurred: %d\r\n", evType);
    } else {
        if (evType == TCPIP_SNTP_EVENT_TSTAMP_OK) {
            SYS_PRINT("Got SUCCESSFUL SNTP timestamp\r\n");
            sntpTimestampReady = 1;
        } else {
            SYS_PRINT("sntpEventHandler: evType = %d\r\n", evType);
        }
    }
}

void APP_Initialize ( void )
{
    appData.state = APP_STATE_INIT;
}

void APP_Tasks ( void )
{
    SYS_STATUS tcpStatus;
    const char* netName;
    const char* netBiosName;
    int i, nNets, ret;
    int atecc_initialized = 0;
    TCPIP_NET_HANDLE netH;
    uint32_t sec = 0;
    ATCA_STATUS status;
    TCPIP_SNTP_RESULT sntpRet;

    switch ( appData.state )
    {
        case APP_STATE_INIT:
        {
            /* wait for TCP/IP stack initialization */
            tcpStatus = TCPIP_STACK_Status(sysObj.tcpip);
            if (tcpStatus < 0) {
                SYS_PRINT("TCP/IP stack initialization failed\r\n");
                appData.state = APP_STATE_FINISHED;
                
            } else if (tcpStatus == SYS_STATUS_READY) {
                /* TCP/IP stack ready, check available interfaces */
                nNets = TCPIP_STACK_NumberOfNetworksGet();

                for (i = 0; i < nNets; i++) {
                    netH = TCPIP_STACK_IndexToNet(i);
                    netName = TCPIP_STACK_NetNameGet(netH);
                    netBiosName = TCPIP_STACK_NetBIOSName(netH);

#if defined(TCPIP_STACK_USE_NBNS)
                    SYS_PRINT("Interface %s on host %s - NBNS enabled\r\n", netName, netBiosName);
#else
                    SYS_PRINT("Interface %s on host %s - NBNS disabled\r\n", netName, netBiosName);
#endif
                }
                appData.state = APP_TCPIP_WAIT_FOR_IP;
            }
            break;
        }

        case APP_TCPIP_WAIT_FOR_IP:
        {
            nNets = TCPIP_STACK_NumberOfNetworksGet();
            for (i = 0; i < nNets; i++) {
                netH = TCPIP_STACK_IndexToNet(i);
                if (!TCPIP_STACK_NetIsReady(netH)) {
                    /* interface not ready net */
                    return;
                }
                IPV4_ADDR ipAddr;
                ipAddr.Val = TCPIP_STACK_NetAddress(netH);
                SYS_PRINT(TCPIP_STACK_NetNameGet(netH));
                SYS_PRINT(" IP Address: ");
                SYS_PRINT("%d.%d.%d.%d \r\n", ipAddr.v[0], ipAddr.v[1], ipAddr.v[2], ipAddr.v[3]);
            }
            /* all interfaces ready, ready to start transactions */

            appData.state = APP_STATE_INIT_SNTP;
            break;
        }

        case APP_STATE_INIT_SNTP:
        {
            /* register SNTP event handler */
            TCPIP_SNTP_HandlerRegister(sntpEventHandler);

            /* force initiate SNTP module to set system time */
            sntpRet = TCPIP_SNTP_ConnectionInitiate();
            if (sntpRet == SNTP_RES_OK) {
                SYS_PRINT("SNTP initiated successfully\r\n");
                appData.state = APP_STATE_SNTP_WAIT_FOR_TIMESTAMP;

            } else {
                SYS_PRINT("SNTP initiation in progress\r\n");
            }
            break;
        }

        case APP_STATE_SNTP_WAIT_FOR_TIMESTAMP:
        {
            if (sntpTimestampReady == 1) {
                appData.state = APP_STATE_TEST_SNTP;
            }
            break;
        }

        case APP_STATE_TEST_SNTP:
        {
            TCPIP_SNTP_TIME_STAMP pTStamp;
            uint32_t pLastUpdate;

            SYS_PRINT("Trying to get seconds from SNTP\r\n");
            sec = TCPIP_SNTP_UTCSecondsGet();
            SYS_PRINT("SNTP seconds = %d\r\n", sec);

            if (sec > 0) {
                appData.state = APP_STATE_608A_INIT;
                
            } else {
                SYS_PRINT("Getting last timestamp value\r\n");
                sntpRet = TCPIP_SNTP_TimeStampGet(&pTStamp, &pLastUpdate);
                if (sntpRet == SNTP_RES_OK) {
                    appData.state = APP_STATE_608A_INIT;
                    
                } else if (sntpRet == SNTP_RES_TSTAMP_STALE) {
                    SYS_PRINT("Stale timestamp, no recent timestamp\r\n");
                    SYS_PRINT("Last SNTP error = %d\r\n", TCPIP_SNTP_LastErrorGet());
                    appData.state = APP_STATE_FINISHED;
                    
                } else if (sntpRet == SNTP_RES_TSTAMP_ERROR) {
                    SYS_PRINT("No available timestamp\r\n");
                    SYS_PRINT("Last SNTP error = %d\r\n", TCPIP_SNTP_LastErrorGet());
                    appData.state = APP_STATE_FINISHED;
                }
            }
            break;
        }

        case APP_STATE_608A_INIT:
        {
            status = atcab_init(&atecc608a_0_init_data_TNGTLS);
            if (status != ATCA_SUCCESS) {
                SYS_PRINT("atcab_init() failed, ret = %d\r\n", status);
                appData.state = APP_STATE_FINISHED;
                
            } else {
                SYS_PRINT("atcab_init() success\r\n");
                atecc_initialized = 1;
                appData.state = APP_STATE_608A_CHECK_LOCK;
            }
            break;
        }

        case APP_STATE_608A_CHECK_LOCK:
        {
            ret = check_lock_status();
            if (ret != 0) {
                SYS_PRINT("Failed to check lock zone status\r\n");
            }
            appData.state = APP_STATE_608A_INFO;
            break;
        }

        case APP_STATE_608A_INFO:
        {
            ret = print_info();
            if (ret != 0) {
                SYS_PRINT("Failed to print ATECC608A module info\r\n");
                appData.state = APP_STATE_FINISHED;
            } else {
                appData.state = APP_STATE_WOLFSSL_INIT;
            }
            break;
        }

        case APP_STATE_WOLFSSL_INIT:
        {
            SYS_PRINT("Initializing wolfSSL\r\n");
            ret = wolfCrypt_ATECC_SetConfig(&atecc608a_0_init_data_TNGTLS);
            if (ret == 0) {
                ret = wolfCrypt_Init();
                if (ret != 0) {
                    SYS_PRINT("wolfSSL_Init() failed, ret = %d\r\n", ret);
                    appData.state = APP_STATE_FINISHED;
                } else {
                    appData.state = APP_STATE_WOLFCRYPT_TEST;
                }
            } else {
                SYS_PRINT("wolfCrypt_ATECC_SetConfig() failed\r\n");
                appData.state = APP_STATE_FINISHED;
            }
            break;
        }

        case APP_STATE_WOLFCRYPT_TEST:
        {
            SYS_PRINT("Running wolfCrypt tests\r\n");
            ret = wolfcrypt_test(NULL);
            if (ret != 0) {
                SYS_PRINT("wolfCrypt test failed, ret = %d\r\n", ret);
            }
            appData.state = APP_STATE_FINISHED;
            break;
        }

        case APP_STATE_FINISHED:
        {
            if (atecc_initialized == 1) {
                atcab_release();
                atecc_initialized = 0;
            }

            /* release wolfSSL library memory */
            wolfCrypt_Cleanup();

            appData.state = APP_STATE_WAIT;
            break;
        }

        case APP_STATE_WAIT:
        {
            break;
        }
    }
}

