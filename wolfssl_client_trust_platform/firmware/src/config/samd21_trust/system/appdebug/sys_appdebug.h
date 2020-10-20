/*******************************************************************************
  App Debug System Service Header File

  Company:
    Microchip Technology Inc.

  File Name:
    sys_appdebug.h

  Summary:
    This header file provides prototypes and definitions for the App Debug System Service.

  Description:
    This header file provides function prototypes and data type definitions for
    the application. 
*******************************************************************************/

//DOM-IGNORE-BEGIN
/*******************************************************************************
Copyright (C) 2020 released Microchip Technology Inc.  All rights reserved.

Microchip licenses to you the right to use, modify, copy and distribute
Software only when embedded on a Microchip microcontroller or digital signal
controller that is integrated into your product or third party product
(pursuant to the sublicense terms in the accompanying license agreement).

You should refer to the license agreement accompanying this Software for
additional information regarding your rights and obligations.

SOFTWARE AND DOCUMENTATION ARE PROVIDED AS IS WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION, ANY WARRANTY OF
MERCHANTABILITY, TITLE, NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.
IN NO EVENT SHALL MICROCHIP OR ITS LICENSORS BE LIABLE OR OBLIGATED UNDER
CONTRACT, NEGLIGENCE, STRICT LIABILITY, CONTRIBUTION, BREACH OF WARRANTY, OR
OTHER LEGAL EQUITABLE THEORY ANY DIRECT OR INDIRECT DAMAGES OR EXPENSES
INCLUDING BUT NOT LIMITED TO ANY INCIDENTAL, SPECIAL, INDIRECT, PUNITIVE OR
CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA, COST OF PROCUREMENT OF
SUBSTITUTE GOODS, TECHNOLOGY, SERVICES, OR ANY CLAIMS BY THIRD PARTIES
(INCLUDING BUT NOT LIMITED TO ANY DEFENSE THEREOF), OR OTHER SIMILAR COSTS.
 *******************************************************************************/
//DOM-IGNORE-END

#ifndef SYS_APPDEBUG_H
#define SYS_APPDEBUG_H

#include "definitions.h"

// DOM-IGNORE-BEGIN
#ifdef __cplusplus  // Provide C++ Compatibility

extern "C" {

#endif
// DOM-IGNORE-END 


#ifdef SYS_APPDEBUG_ENABLE

// *****************************************************************************
// *****************************************************************************
// Section: Data Types and Constants
// *****************************************************************************
// *****************************************************************************

// *****************************************************************************
/* APP_LOG_LVL_DISABLE

  Summary:
    App Debug Service Logging Disabled 

  Remarks:
    None.
*/
#define APP_LOG_LVL_DISABLE 	0x0

// *****************************************************************************
/* APP_LOG_ERROR_LVL

  Summary:
    App Debug Service Error Log Level 

  Remarks:
    None.
*/
#define APP_LOG_ERROR_LVL 		0x1

// *****************************************************************************
/* APP_LOG_DBG_LVL

  Summary:
    App Debug Service Debug Log Level 

  Remarks:
    None.
*/
#define APP_LOG_DBG_LVL 		0x2

// *****************************************************************************
/* APP_LOG_INFO_LVL

  Summary:
    App Debug Service Info Log Level 

  Remarks:
    None.
*/
#define APP_LOG_INFO_LVL 		0x4

// *****************************************************************************
/* APP_LOG_FN_EE_LVL

  Summary:
    App Debug Service Service Entry/ Exit Log Level 

  Remarks:
    None.
*/
#define APP_LOG_FN_EE_LVL 		0x8

// DOM-IGNORE-END


// *****************************************************************************
/* SYS_APPDEBUG_MAX_NUM_OF_USERS

  Summary:
    Number of instances of App Debug Service supported

  Remarks:
    None.
*/
#define SYS_APPDEBUG_MAX_NUM_OF_USERS       8


// *****************************************************************************
/* SYS Debug Initialize structure

  Summary:
    Defines the data required to initialize the app debug system service.

  Description:
    This structure defines the data required to initialize the app debug system 
    service.

  Remarks:
    None.
*/
typedef struct
{
    /* Initial system Log level setting. */
    unsigned int                 logLevel;

    /* Initial system Log level setting. */
    unsigned int                 logFlow;

    /* Initial system Log level setting. */
    const char                        *prefixString;
} SYS_APPDEBUG_CONFIG;

// *****************************************************************************
/* System App Debug Control Message values

  Summary:
    Identifies the control message for which the User has called the SYS_APPDEBUG_CtrlMsg().

  Remarks:
    None.
*/
typedef enum {
	SYS_APPDEBUG_CTRL_MSG_TYPE_SET_LEVEL,
	SYS_APPDEBUG_CTRL_MSG_TYPE_SET_FLOW,
} SYS_APPDEBUG_CtrlMsgType;

// *****************************************************************************
/* System App Debug Return values

  Summary:
    Identifies the return values for the Sys App Debug APIs.

  Remarks:
    None.
*/
typedef enum {    
	SYS_APPDEBUG_SUCCESS = 0,		// Success
	SYS_APPDEBUG_FAILURE = -1,    	// Failure
} SYS_APPDEBUG_RESULT;

// *****************************************************************************
// *****************************************************************************
// Section: Initialization functions
// *****************************************************************************
// *****************************************************************************
// *****************************************************************************
// *****************************************************************************
/* Function:
       int32_t SYS_APPDEBUG_Initialize()

	Summary:
      Returns success/ failure for initialization of data structures of the 
	  App Debug service

	Description:
       This function is used for initializing the data structures of the 
	   App Debug service and is called from within the System Task.

	Parameters:
		index    		- NULL; reserved for future use<br>
		init 			- NULL; reserved for future use<br>

	Returns:
		SYS_APPDEBUG_SUCCESS - Indicates the data structures were initialized successfully
		SYS_APPDEBUG_FAILURE - Indicates that it failed to initialize the data structures

	Example:
       <code>
		if( SYS_APPDEBUG_Initialize(NULL, NULL) == SYS_APPDEBUG_SUCCESS)
		{
		}
       </code>

	Remarks:
		If the Net system service is enabled using MHC, then auto generated code will take care of system task execution.
  */
SYS_MODULE_OBJ SYS_APPDEBUG_Initialize( const SYS_MODULE_INDEX index,
                                   const SYS_MODULE_INIT * const init );

// *****************************************************************************
/* Function:
       int32_t SYS_APPDEBUG_Deinitialize()

  Summary:
      Returns success/ failure for deinitialization of data structures of the 
	  App Debug service

  Description:
       This function is used for deinitializing the data structures of the 
	   App Debug service and is called from within the System Task.

  Parameters:
       None<br>

   Returns:
		SYS_APPDEBUG_SUCCESS - Indicates the data structures were deinitialized successfully
		SYS_APPDEBUG_FAILURE - Indicates that it failed to deinitialize the data structures.

  Example:
       <code>
		if( SYS_APPDEBUG_Deinitialize() == SYS_APPDEBUG_SUCCESS)
		{
		}
       </code>

  Remarks:
		If the Net system service is enabled using MHC, then auto generated code will take care of system task execution.
  */
int32_t	SYS_APPDEBUG_Deinitialize();

// *****************************************************************************
// *****************************************************************************
// Section: Setup functions
// *****************************************************************************
// *****************************************************************************
/* Function:
    SYS_MODULE_OBJ SYS_APPDEBUG_Open (SYS_APPDEBUG_CONFIG *cfg)

   Summary:
        Open an instance of the System App Debug service.

   Description:
        This function initializes the instance of the System App Debug Service.

   Parameters:
       cfg    		- Configuration with which the App Debug Service needs to be opened<br>

   Returns:If successful, returns a valid handle to an object. Otherwise, it
        returns SYS_MODULE_OBJ_INVALID.

   Example:
        <code>

		SYS_APPDEBUG_CONFIG    	g_AppDebugServCfg;
		SYS_MODULE_OBJ 		g_AppDebugServHandle;

		memset(&g_AppDebugServCfg, 0, sizeof(g_AppDebugServCfg));
		g_AppDebugServCfg.logLevel |= APP_LOG_ERROR_LVL;
		g_AppDebugServCfg.prefixString = "MY_APP";
		g_AppDebugServCfg.logFlow |= 0x1;
		
		g_AppDebugServHandle = SYS_NET_Open(&g_AppDebugServCfg);                
        if (g_AppDebugServHandle == SYS_MODULE_OBJ_INVALID)
        {
            // Handle error
        }
        </code>

  Remarks:
        This routine should be called everytime a user wants to open a new NET socket
*/
SYS_MODULE_OBJ  SYS_APPDEBUG_Open(SYS_APPDEBUG_CONFIG *cfg);

// *****************************************************************************
/* Function:
   void SYS_APPDEBUG_Close ( SYS_MODULE_OBJ object )

  Summary:
       Close the specific module instance of the SYS App Debug service

  Description:
       This function clsoes the specific module instance disabling its
       operation. Resets all of the internal data structures and fields for the 
	   specified instance to the default settings.

  Precondition:
       The SYS_APPDEBUG_Open function should have been called before calling
       this function.

  Parameters:
       object   - SYS App Debug object handle, returned from SYS_APPDEBUG_Open<br>

  Returns:
       None.

  Example:
        <code>
        // Handle "objSysAppDebug" value must have been returned from SYS_APPDEBUG_Open.

        SYS_APPDEBUG_Close (objSysAppDebug);
        </code>

  Remarks:
       Once the Open operation has been called, the Close operation must be called 
	   before the Open operation can be called again.
*/
void  SYS_APPDEBUG_Close(SYS_MODULE_OBJ obj);

// *****************************************************************************
/* Function:
       int32_t SYS_APPDEBUG_CtrlMsg(SYS_MODULE_OBJ obj, 
				SYS_APPDEBUG_CtrlMsgType eCtrlMsgType, void *data, uint16_t len)

  Summary:
      Returns success/ failure for the flow/ level set operation asked by the user.

  Description:
       This function is used for setting the value of floe/ level for the 
	   app debug logs.

  Precondition:
       SYS_APPDEBUG_Open should have been called.

  Parameters:
       obj  	- SYS App Debug object handle, returned from SYS_APPDEBUG_Open<br>
	   eCtrlMsgType - valid Msg Type - SYS_APPDEBUG_CtrlMsgType<br>
       data		- valid data buffer pointer based on the Msg Type<br>
	   len		- length of the data buffer the pointer is pointing to<br>

  Returns:
		SYS_APPDEBUG_SUCCESS - Indicates that the Request was catered to successfully
		SYS_APPDEBUG_FAILURE - Indicates that the Request failed

  Example:
       <code>
       // Handle "objSysAppDebug" value must have been returned from SYS_APPDEBUG_Open.	   
		uint32_t logLevel = 0x3;
		if( SYS_APPDEBUG_CtrlMsg(objSysAppDebug, SYS_APPDEBUG_CTRL_MSG_TYPE_SET_LEVEL, &logLevel, 4) == SYS_APPDEBUG_SUCCESS)
		{
		}
       </code>

  Remarks:
       None.
  */
int32_t	SYS_APPDEBUG_CtrlMsg(SYS_MODULE_OBJ hdl, SYS_APPDEBUG_CtrlMsgType eCtrlMsgType, void *data, uint16_t len);

void SYS_APPDEBUG_PRINT(SYS_MODULE_OBJ obj, 
                        uint32_t flow, 
                        uint32_t level, 
                        const char *function, 
                        uint32_t linenum, 
                        char *msg, ...);
void SYS_APPDEBUG_PRINT_FN_ENTER(SYS_MODULE_OBJ obj, 
                        uint32_t flow, 
                        const char *function, 
                        uint32_t linenum);
void SYS_APPDEBUG_PRINT_FN_EXIT(SYS_MODULE_OBJ obj, 
                        uint32_t flow, 
                        const char *function, 
                        uint32_t linenum);

// *****************************************************************************
/* SYS_APPDEBUG_ERR_PRINT

  Summary:
    Used for logging Error Level Logs

  Description:
       This macro function is used for logging error level logs.

  Precondition:
       SYS_APPDEBUG_Open should have been called.

  Parameters:
       obj  	- SYS App Debug object handle, returned from SYS_APPDEBUG_Open<br>
	   flow 	- valid flow defined by the User, log will come only if this flow is enabled<br>
       data		- valid string<br>
	   ...		- any variable arguments if present<br>

  Returns:
       None.

  Example:
       <code>
       // Handle "objSysAppDebug" value must have been returned from SYS_APPDEBUG_Open.	   
	   SYS_APPDEBUG_ERR_PRINT(objSysAppDebug, MY_APP_FLOW_DATA, "Failed to allocate memory of size %d", size);
       </code>

  Remarks:
       None.
*/

#define SYS_APPDEBUG_ERR_PRINT(obj, flow, fmt, ...)      SYS_APPDEBUG_PRINT(obj, flow, APP_LOG_ERROR_LVL, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

// *****************************************************************************
/* SYS_APPDEBUG_DBG_PRINT

  Summary:
    Used for logging Debug Level Logs

  Description:
       This macro function is used for logging debug level logs.

  Precondition:
       SYS_APPDEBUG_Open should have been called.

  Parameters:
       obj  	- SYS App Debug object handle, returned from SYS_APPDEBUG_Open<br>
	   flow 	- valid flow defined by the User, log will come only if this flow is enabled<br>
       data		- valid string<br>
	   ...		- any variable arguments if present<br>

  Returns:
       None.

  Example:
       <code>
       // Handle "objSysAppDebug" value must have been returned from SYS_APPDEBUG_Open.	   
	   SYS_APPDEBUG_DBG_PRINT(objSysAppDebug, MY_APP_FLOW_DATA, "memory allocation reached Threshold");
       </code>

  Remarks:
       None.
*/

#define SYS_APPDEBUG_DBG_PRINT(obj, flow, fmt, ...)      SYS_APPDEBUG_PRINT(obj, flow, APP_LOG_DBG_LVL, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

// *****************************************************************************
/* SYS_APPDEBUG_INFO_PRINT

  Summary:
    Used for logging Info Level Logs

  Description:
       This macro function is used for logging info level logs.

  Precondition:
       SYS_APPDEBUG_Open should have been called.

  Parameters:
       obj  	- SYS App Debug object handle, returned from SYS_APPDEBUG_Open<br>
	   flow 	- valid flow defined by the User, log will come only if this flow is enabled<br>
       data		- valid string<br>
	   ...		- any variable arguments if present<br>

  Returns:
       None.

  Example:
       <code>
       // Handle "objSysAppDebug" value must have been returned from SYS_APPDEBUG_Open.	   
	   SYS_APPDEBUG_INFO_PRINT(objSysAppDebug, MY_APP_FLOW_DATA, "Allocate memory of size %d", size);
       </code>

  Remarks:
       None.
*/

#define SYS_APPDEBUG_INFO_PRINT(obj, flow, fmt, ...)     SYS_APPDEBUG_PRINT(obj, flow, APP_LOG_INFO_LVL, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

// *****************************************************************************
/* SYS_APPDEBUG_FN_ENTER_PRINT

  Summary:
    Used for logging Function Entry Logs

  Description:
       This macro function is used for logging function entry level logs.

  Precondition:
       SYS_APPDEBUG_Open should have been called.

  Parameters:
       obj  	- SYS App Debug object handle, returned from SYS_APPDEBUG_Open<br>
	   flow 	- valid flow defined by the User, log will come only if this flow is enabled<br>
       data		- valid string<br>
	   ...		- any variable arguments if present<br>

  Returns:
       None.

  Example:
       <code>
       // Handle "objSysAppDebug" value must have been returned from SYS_APPDEBUG_Open.	   
	   SYS_APPDEBUG_FN_ENTER_PRINT(objSysAppDebug, MY_APP_FLOW_DATA);
       </code>

  Remarks:
       None.
*/

#define SYS_APPDEBUG_FN_ENTER_PRINT(obj, flow)       SYS_APPDEBUG_PRINT_FN_ENTER(obj, flow, __FUNCTION__, __LINE__)

// *****************************************************************************
/* SYS_APPDEBUG_FN_EXIT_PRINT

  Summary:
    Used for logging Function Exit Logs

  Description:
       This macro function is used for logging function exit level logs.

  Precondition:
       SYS_APPDEBUG_Open should have been called.

  Parameters:
       obj  	- SYS App Debug object handle, returned from SYS_APPDEBUG_Open<br>
	   flow 	- valid flow defined by the User, log will come only if this flow is enabled<br>
       data		- valid string<br>
	   ...		- any variable arguments if present<br>

  Returns:
       None.

  Example:
       <code>
       // Handle "objSysAppDebug" value must have been returned from SYS_APPDEBUG_Open.	   
	   SYS_APPDEBUG_FN_EXIT_PRINT(objSysAppDebug, MY_APP_FLOW_DATA);
       </code>

  Remarks:
       None.
*/

#define SYS_APPDEBUG_FN_EXIT_PRINT(obj, flow)    SYS_APPDEBUG_PRINT_FN_EXIT(obj, flow, __FUNCTION__, __LINE__)

#endif

        
//DOM-IGNORE-BEGIN
#ifdef __cplusplus
}
#endif
//DOM-IGNORE-END

#endif /* SYS_APP_DEBUG_H */


/*******************************************************************************
 End of File
 */

