/*******************************************************************************
  WINC Wireless Driver SPI Communication Support

  File Name:
    wdrv_winc_spi.c

  Summary:
    WINC Wireless Driver SPI Communications Support

  Description:
    Supports SPI communications to the WINC module.
 *******************************************************************************/

//DOM-IGNORE-BEGIN
/*
Copyright (C) 2019-22, Microchip Technology Inc., and its subsidiaries. All rights reserved.

The software and documentation is provided by microchip and its contributors
"as is" and any express, implied or statutory warranties, including, but not
limited to, the implied warranties of merchantability, fitness for a particular
purpose and non-infringement of third party intellectual property rights are
disclaimed to the fullest extent permitted by law. In no event shall microchip
or its contributors be liable for any direct, indirect, incidental, special,
exemplary, or consequential damages (including, but not limited to, procurement
of substitute goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether in contract,
strict liability, or tort (including negligence or otherwise) arising in any way
out of the use of the software and documentation, even if advised of the
possibility of such damage.

Except as expressly permitted hereunder and subject to the applicable license terms
for any third-party software incorporated in the software and any applicable open
source software license terms, no license or other rights, whether express or
implied, are granted under any patent or other intellectual property rights of
Microchip or any third party.
*/

#include "configuration.h"
#include "definitions.h"
#include "osal/osal.h"
#include "wdrv_winc_common.h"
#include "wdrv_winc_spi.h"

// *****************************************************************************
// *****************************************************************************
// Section: Data Type Definitions
// *****************************************************************************
// *****************************************************************************

typedef struct
{
    /* This is the SPI configuration. */
    WDRV_WINC_SPI_CFG       cfg;
    OSAL_SEM_HANDLE_TYPE    txSyncSem;
    OSAL_SEM_HANDLE_TYPE    rxSyncSem;
} WDRV_WINC_SPIDCPT;

// *****************************************************************************
// *****************************************************************************
// Section: Global Data
// *****************************************************************************
// *****************************************************************************

static WDRV_WINC_SPIDCPT spiDcpt;

// *****************************************************************************
// *****************************************************************************
// Section: File scope functions
// *****************************************************************************
// *****************************************************************************

static void _DRV_SPI_PlibCallbackHandler(uintptr_t contextHandle)
{
    OSAL_SEM_PostISR((OSAL_SEM_HANDLE_TYPE*)contextHandle);
}

//*******************************************************************************
/*
  Function:
    bool WDRV_WINC_SPISend(void* pTransmitData, size_t txSize)

  Summary:
    Sends data out to the module through the SPI bus.

  Description:
    This function sends data out to the module through the SPI bus.

  Remarks:
    See wdrv_winc_spi.h for usage information.
 */

bool WDRV_WINC_SPISend(void* pTransmitData, size_t txSize)
{
    if ((NULL == spiDcpt.cfg.callbackRegister) || (NULL == spiDcpt.cfg.writeRead))
    {
        return false;
    }

    spiDcpt.cfg.callbackRegister(_DRV_SPI_PlibCallbackHandler, (uintptr_t)&spiDcpt.txSyncSem);
    spiDcpt.cfg.writeRead(pTransmitData, txSize, NULL, 0);

    while (OSAL_RESULT_FALSE == OSAL_SEM_Pend(&spiDcpt.txSyncSem, OSAL_WAIT_FOREVER))
    {
    }

    return true;
}

//*******************************************************************************
/*
  Function:
    bool WDRV_WINC_SPIReceive(void* pReceiveData, size_t rxSize)

  Summary:
    Receives data from the module through the SPI bus.

  Description:
    This function receives data from the module through the SPI bus.

  Remarks:
    See wdrv_winc_spi.h for usage information.
 */

bool WDRV_WINC_SPIReceive(void* pReceiveData, size_t rxSize)
{
    static uint8_t dummy = 0;

    if ((NULL == spiDcpt.cfg.callbackRegister) || (NULL == spiDcpt.cfg.writeRead))
    {
        return false;
    }

    spiDcpt.cfg.callbackRegister(_DRV_SPI_PlibCallbackHandler, (uintptr_t)&spiDcpt.rxSyncSem);
    spiDcpt.cfg.writeRead(&dummy, 1, pReceiveData, rxSize);

    while (OSAL_RESULT_FALSE == OSAL_SEM_Pend(&spiDcpt.rxSyncSem, OSAL_WAIT_FOREVER))
    {
    }

    return true;
}

//*******************************************************************************
/*
  Function:
    bool WDRV_WINC_SPIOpen(void)

  Summary:
    Opens the SPI object for the WiFi driver.

  Description:
    This function opens the SPI object for the WiFi driver.

  Remarks:
    See wdrv_winc_spi.h for usage information.
 */

bool WDRV_WINC_SPIOpen(void)
{
    if (OSAL_RESULT_TRUE != OSAL_SEM_Create(&spiDcpt.txSyncSem, OSAL_SEM_TYPE_COUNTING, 10, 0))
    {
        return false;
    }

    if (OSAL_RESULT_TRUE != OSAL_SEM_Create(&spiDcpt.rxSyncSem, OSAL_SEM_TYPE_COUNTING, 10, 0))
    {
        return false;
    }

    return true;
}

//*******************************************************************************
/*
  Function:
    void WDRV_WINC_SPIInitialize(const WDRV_WINC_SPI_CFG *const pInitData)

  Summary:
    Initializes the SPI object for the WiFi driver.

  Description:
    This function initializes the SPI object for the WiFi driver.

  Remarks:
    See wdrv_winc_spi.h for usage information.
 */

void WDRV_WINC_SPIInitialize(const WDRV_WINC_SPI_CFG *const pInitData)
{
    if (NULL == pInitData)
    {
        return;
    }

    memcpy(&spiDcpt.cfg, pInitData, sizeof(WDRV_WINC_SPI_CFG));
}

//*******************************************************************************
/*
  Function:
    void WDRV_WINC_SPIDeinitialize(void)

  Summary:
    Deinitializes the SPI object for the WiFi driver.

  Description:
    This function deinitializes the SPI object for the WiFi driver.

  Remarks:
    See wdrv_winc_spi.h for usage information.
 */

void WDRV_WINC_SPIDeinitialize(void)
{
    OSAL_SEM_Post(&spiDcpt.txSyncSem);
    OSAL_SEM_Delete(&spiDcpt.txSyncSem);

    OSAL_SEM_Post(&spiDcpt.rxSyncSem);
    OSAL_SEM_Delete(&spiDcpt.rxSyncSem);
}

//DOM-IGNORE-END
