/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app.c

  Summary:
    This file contains the source code for the MPLAB Harmony application.

  Description:
    This file contains the source code for the MPLAB Harmony application.  It
    implements the logic of the application's state machine and it may call
    API routines of other MPLAB Harmony modules in the system, such as drivers,
    system services, and middleware.  However, it does not call any of the
    system interfaces (such as the "Initialize" and "Tasks" functions) of any of
    the modules in the system or make any assumptions about when those functions
    are called.  That is the responsibility of the configuration-specific system
    files.
 *******************************************************************************/

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include "app.h"
#include "definitions.h"

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include "test.h"
#include "benchmark.h"


// *****************************************************************************
// *****************************************************************************
// Section: Global Data Definitions
// *****************************************************************************
// *****************************************************************************

// *****************************************************************************
/* Application Data

  Summary:
    Holds application data

  Description:
    This structure holds the application's data.

  Remarks:
    This structure should be initialized by the APP_Initialize function.

    Application strings and buffers are be defined outside this structure.
*/

APP_DATA appData;


typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

static func_args args = { 0 } ;

// *****************************************************************************
// *****************************************************************************
// Section: Application Callback Functions
// *****************************************************************************
// *****************************************************************************

/* TODO:  Add any necessary callback functions.
*/

// *****************************************************************************
// *****************************************************************************
// Section: Application Local Functions
// *****************************************************************************
// *****************************************************************************


/* TODO:  Add any necessary local functions.
*/


// *****************************************************************************
// *****************************************************************************
// Section: Application Initialization and State Machine Functions
// *****************************************************************************
// *****************************************************************************

/*******************************************************************************
  Function:
    void APP_Initialize ( void )

  Remarks:
    See prototype in app.h.
 */

void APP_Initialize ( void )
{
    /* Place the App state machine in its initial state. */
    appData.state = APP_STATE_INIT;



    /* TODO: Initialize your application's state machine and other
     * parameters.
     */
}


/* appease libnano */
int _gettimeofday(struct timeval *tv, void *tzvp)
{
    return 0;
}
/* TIME CODE */
/* TODO: Implement real RTC */
/* Optionally you can define NO_ASN_TIME to disable all cert time checks */
static int hw_get_time_sec(void)
{
    return RTC_Timer32CounterGet();
}

/* This is used by wolfCrypt asn.c for cert time checking */
unsigned long my_time(unsigned long* timer)
{
    (void)timer;
    return hw_get_time_sec();
}

#ifndef WOLFCRYPT_ONLY
/* This is used by TLS only */
unsigned int LowResTimer(void)
{
    return hw_get_time_sec();
}
#endif

#ifndef NO_CRYPT_BENCHMARK
/* This is used by wolfCrypt benchmark tool only */
double current_time(int reset)
{
    uint32_t period = RTC_Timer32FrequencyGet();
    uint32_t counter = RTC_Timer32CounterGet();
    (void)reset;
    /* return seconds as a double */
    return ((double)counter / period);
}
#endif


/******************************************************************************
  Function:
    void APP_Tasks ( void )

  Remarks:
    See prototype in app.h.
 */

void APP_Tasks ( void )
{

    /* Check the application's current state. */
    switch ( appData.state )
    {
        /* Application's initial state. */
        case APP_STATE_INIT:
        {
            bool appInitialized = true;


            if (appInitialized)
            {

                appData.state = APP_STATE_SERVICE_TASKS;
            }
            break;
        }

        case APP_STATE_SERVICE_TASKS:
        {
            int ret;
            wolfCrypt_Init();
        #ifndef NO_CRYPT_TEST
            printf("\nCrypt Test\n");
            wolfcrypt_test(&args);
            ret = args.return_code;
            printf("Crypt Test: Return code %d\n", ret);
        #endif
        #ifndef NO_CRYPT_BENCHMARK
            printf("\nBenchmark Test\n");
            benchmark_test(&args);
            ret = args.return_code;
            printf("Benchmark Test: Return code %d\n", ret);
        #endif
            wolfCrypt_Cleanup();

            break;
        }

        /* TODO: implement your application state machine.*/


        /* The default state should never be executed. */
        default:
        {
            /* TODO: Handle error in application's state machine. */
            break;
        }
    }
}


/*******************************************************************************
 End of File
 */
