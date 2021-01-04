#ifndef _APP_MQTT_TASK_H_
#define _APP_MQTT_TASK_H_

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include "configuration.h"
#include "definitions.h" 
#include "tcpip/tcpip.h"
#include "wolfmqtt/mqtt_client.h"


// TODO: add MQTT task definitions here 

// *****************************************************************************
// *****************************************************************************
// Section: External Declarations
// *****************************************************************************
// *****************************************************************************

bool        APP_MQTT_Init(void);

void        APP_MQTT_Task(void);


#endif /* _APP_MQTT_TASK_H_ */

//DOM-IGNORE-BEGIN
#ifdef __cplusplus
}
#endif
//DOM-IGNORE-END

/*******************************************************************************
 End of File
 */

